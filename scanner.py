"""Passive website security scanner.

Only performs ordinary GET/HEAD requests and inspects responses. It does not
fuzz inputs, send exploit payloads, or attempt authentication.
"""
import ipaddress
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin

import requests

TIMEOUT = 8
MAX_REDIRECTS = 4
MAX_BYTES = 512 * 1024
USER_AGENT = "PassiveSecScanner/1.0 (+owner-verified scan)"

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


class UnsafeTarget(Exception):
    pass


def validate_target(url: str):
    """Return (parsed_url, ip) or raise UnsafeTarget. Blocks SSRF targets."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise UnsafeTarget("Only http and https URLs are allowed.")
    if not parsed.hostname:
        raise UnsafeTarget("URL has no hostname.")
    if parsed.username or parsed.password:
        raise UnsafeTarget("Credentials in URLs are not allowed.")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port not in (80, 443, 8080, 8443):
        raise UnsafeTarget("Only ports 80, 443, 8080 and 8443 are allowed.")
    try:
        infos = socket.getaddrinfo(parsed.hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise UnsafeTarget("Hostname could not be resolved.")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
                or ip.is_reserved or ip.is_unspecified):
            raise UnsafeTarget("Target resolves to a non-public address.")
    return parsed, infos[0][4][0]


def safe_get(url: str):
    """GET with manual redirect handling so every hop is re-validated."""
    for _ in range(MAX_REDIRECTS + 1):
        validate_target(url)
        resp = requests.get(
            url, timeout=TIMEOUT, allow_redirects=False, stream=True,
            headers={"User-Agent": USER_AGENT},
        )
        if resp.is_redirect or resp.is_permanent_redirect:
            loc = resp.headers.get("Location")
            resp.close()
            if not loc:
                raise UnsafeTarget("Redirect without Location header.")
            url = urljoin(url, loc)
            continue
        body = b""
        for chunk in resp.iter_content(8192):
            body += chunk
            if len(body) >= MAX_BYTES:
                break
        resp.close()
        resp._content = body
        return resp, url
    raise UnsafeTarget("Too many redirects.")


def finding(sev, title, detail, fix=""):
    return {"severity": sev, "title": title, "detail": detail, "fix": fix}


def check_headers(resp, final_url):
    out = []
    h = {k.lower(): v for k, v in resp.headers.items()}
    https = final_url.startswith("https://")

    if https and "strict-transport-security" not in h:
        out.append(finding("medium", "Missing HSTS",
                           "No Strict-Transport-Security header.",
                           "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"))
    csp = h.get("content-security-policy")
    if not csp:
        out.append(finding("medium", "Missing Content-Security-Policy",
                           "No CSP header, so injected scripts are not restricted.",
                           "Define a CSP, e.g. default-src 'self'."))
    elif "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
        out.append(finding("low", "Weak Content-Security-Policy",
                           "CSP allows 'unsafe-inline' or 'unsafe-eval'.",
                           "Use nonces or hashes instead."))
    if "x-frame-options" not in h and not (csp and "frame-ancestors" in csp):
        out.append(finding("low", "Clickjacking protection missing",
                           "No X-Frame-Options or CSP frame-ancestors.",
                           "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'."))
    if h.get("x-content-type-options", "").lower() != "nosniff":
        out.append(finding("low", "Missing X-Content-Type-Options",
                           "MIME sniffing is not disabled.",
                           "Add X-Content-Type-Options: nosniff"))
    if "referrer-policy" not in h:
        out.append(finding("info", "Missing Referrer-Policy", "",
                           "Add Referrer-Policy: strict-origin-when-cross-origin"))
    if "permissions-policy" not in h:
        out.append(finding("info", "Missing Permissions-Policy", "",
                           "Restrict browser features you do not use."))
    if "access-control-allow-origin" in h and h["access-control-allow-origin"] == "*" \
            and h.get("access-control-allow-credentials", "").lower() == "true":
        out.append(finding("high", "Dangerous CORS configuration",
                           "Wildcard origin combined with credentials.",
                           "Reflect only an explicit allowlist of origins."))
    server = h.get("server", "")
    if any(ch.isdigit() for ch in server):
        out.append(finding("low", "Server version disclosed",
                           f"Server header reveals: {server}",
                           "Hide version details in server config."))
    if "x-powered-by" in h:
        out.append(finding("low", "Technology disclosed",
                           f"X-Powered-By: {h['x-powered-by']}",
                           "Remove the X-Powered-By header."))
    return out


def check_cookies(resp, final_url):
    out = []
    raw = resp.raw.headers.get_all("Set-Cookie") if hasattr(resp.raw.headers, "get_all") else []
    for c in raw or []:
        name = c.split("=", 1)[0]
        low = c.lower()
        missing = []
        if final_url.startswith("https://") and "secure" not in low:
            missing.append("Secure")
        if "httponly" not in low:
            missing.append("HttpOnly")
        if "samesite" not in low:
            missing.append("SameSite")
        if missing:
            out.append(finding("medium" if "Secure" in missing or "HttpOnly" in missing else "low",
                               f"Cookie '{name}' missing flags",
                               "Missing: " + ", ".join(missing),
                               "Set Secure; HttpOnly; SameSite=Lax (or Strict)."))
    return out


def check_tls(parsed):
    out = []
    if parsed.scheme != "https":
        return [finding("high", "Site not served over HTTPS",
                        "The scanned URL uses plain HTTP.",
                        "Serve the site over HTTPS and redirect HTTP to it.")]
    host = parsed.hostname
    port = parsed.port or 443
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert()
                version = s.version()
        exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days = (exp - datetime.now(timezone.utc)).days
        if days < 0:
            out.append(finding("high", "Certificate expired", f"Expired {-days} days ago.", "Renew the certificate."))
        elif days < 14:
            out.append(finding("medium", "Certificate expiring soon", f"{days} days left.", "Renew soon."))
        else:
            out.append(finding("info", "Certificate valid", f"{days} days until expiry."))
        if version in ("TLSv1", "TLSv1.1", "SSLv3"):
            out.append(finding("high", "Outdated TLS version", f"Negotiated {version}.", "Require TLS 1.2+."))
        else:
            out.append(finding("info", "TLS version", f"Negotiated {version}."))
    except ssl.SSLCertVerificationError as e:
        out.append(finding("high", "Certificate verification failed", str(e.verify_message),
                           "Install a valid certificate from a trusted CA."))
    except (OSError, ssl.SSLError) as e:
        out.append(finding("medium", "TLS check failed", str(e)))
    return out


SENSITIVE_PATHS = [
    ("/.git/HEAD", "ref:", "Exposed .git repository", "high"),
    ("/.env", "=", "Exposed .env file", "high"),
    ("/.DS_Store", "\x00Bud1", "Exposed .DS_Store", "low"),
    ("/backup.zip", None, "Possible backup archive", "medium"),
    ("/phpinfo.php", "phpinfo", "phpinfo page exposed", "medium"),
    ("/server-status", "Apache Server Status", "Apache server-status exposed", "medium"),
]


def check_exposed_files(base_url):
    out = []
    for path, marker, title, sev in SENSITIVE_PATHS:
        url = urljoin(base_url, path)
        try:
            r, _ = safe_get(url)
        except Exception:
            continue
        if r.status_code != 200:
            continue
        ctype = r.headers.get("Content-Type", "")
        text = r.content[:2000].decode("latin-1", errors="ignore")
        if marker is None:
            if "zip" in ctype or "octet-stream" in ctype:
                out.append(finding(sev, title, f"{path} returned a downloadable file.", "Remove it from the web root."))
        elif marker in text and "html" not in ctype.lower().split(";")[0] or (marker in text and path.endswith(".php")):
            out.append(finding(sev, title, f"{path} is publicly readable.", "Block or remove this path."))
    return out


def check_mixed_content(resp, final_url):
    if not final_url.startswith("https://"):
        return []
    text = resp.content.decode("utf-8", errors="ignore").lower()
    hits = text.count('src="http://') + text.count("src='http://") + text.count('href="http://')
    if hits:
        return [finding("medium", "Mixed content", f"About {hits} http:// resource references on an HTTPS page.",
                        "Load all resources over HTTPS.")]
    return []


def scan(url: str):
    parsed, _ = validate_target(url)
    resp, final_url = safe_get(url)
    findings = []
    findings += check_tls(urlparse(final_url))
    findings += check_headers(resp, final_url)
    findings += check_cookies(resp, final_url)
    findings += check_mixed_content(resp, final_url)
    findings += check_exposed_files(final_url)
    findings.sort(key=lambda f: SEVERITY_ORDER[f["severity"]])
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITY_ORDER}
    return {"target": url, "final_url": final_url, "status": resp.status_code,
            "counts": counts, "findings": findings}
