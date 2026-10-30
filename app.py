"""Flask front end: ownership verification, rate limiting, scan endpoint."""
import os
import secrets
import socket
import time
from collections import defaultdict, deque
from urllib.parse import urlparse

import dns.resolver
import requests
from flask import Flask, jsonify, render_template, request, session
from werkzeug.middleware.proxy_fix import ProxyFix

import scanner

app = Flask(__name__)
# Behind Render's proxy: trust one hop so request.remote_addr is the real client IP.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    MAX_CONTENT_LENGTH=4 * 1024,
)

RATE_LIMIT = 5          # requests
RATE_WINDOW = 60        # seconds
_hits = defaultdict(deque)


def rate_limited(key: str) -> bool:
    now = time.time()
    q = _hits[key]
    while q and now - q[0] > RATE_WINDOW:
        q.popleft()
    if len(q) >= RATE_LIMIT:
        return True
    q.append(now)
    return False


@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    return resp


def host_of(url: str) -> str:
    u = urlparse(url if "://" in url else "https://" + url)
    return (u.hostname or "").lower()


def check_ownership(url: str, token: str):
    """Return (ok, message). Accept a DNS TXT record or a token file."""
    host = host_of(url)
    expected = f"vulnscan-verify={token}"
    try:
        for rdata in dns.resolver.resolve(f"_vulnscan.{host}", "TXT", lifetime=5):
            if expected in b"".join(rdata.strings).decode(errors="ignore"):
                return True, "DNS TXT record found."
    except Exception:
        pass
    for scheme in ("https", "http"):
        try:
            r, _ = scanner.safe_get(f"{scheme}://{host}/.well-known/vulnscan-{token}.txt")
            if r.status_code == 200 and token in r.content.decode(errors="ignore"):
                return True, "Verification file found."
        except Exception:
            continue
    return False, "Verification not found yet."


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/challenge")
def challenge():
    data = request.get_json(silent=True) or {}
    host = host_of(data.get("url", ""))
    if not host:
        return jsonify(error="Enter a valid URL."), 400
    tokens = session.setdefault("tokens", {})
    token = tokens.get(host) or secrets.token_urlsafe(16)
    tokens[host] = token
    session.modified = True
    return jsonify(host=host, token=token,
                   dns_record=f"_vulnscan.{host}  TXT  \"vulnscan-verify={token}\"",
                   file_path=f"/.well-known/vulnscan-{token}.txt",
                   file_content=token)


@app.post("/api/scan")
def scan_endpoint():
    ip = request.remote_addr or "unknown"
    if rate_limited(ip):
        return jsonify(error="Too many requests. Try again in a minute."), 429
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if "://" not in url:
        url = "https://" + url
    host = host_of(url)
    token = session.get("tokens", {}).get(host)
    if not token:
        return jsonify(error="Request a verification challenge for this site first."), 400
    ok, msg = check_ownership(url, token)
    if not ok:
        return jsonify(error=f"Ownership not verified. {msg}"), 403
    try:
        return jsonify(scanner.scan(url))
    except scanner.UnsafeTarget as e:
        return jsonify(error=str(e)), 400
    except requests.RequestException as e:
        return jsonify(error=f"Could not reach the site: {type(e).__name__}"), 502


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    host = "0.0.0.0" if os.environ.get("PORT") else "127.0.0.1"
    app.run(host=host, port=port, debug=False)
