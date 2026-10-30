# Passive Site Scanner

A small Flask app that checks a website for common security misconfigurations.
It only sends ordinary GET requests and reads the responses. No fuzzing, no exploit payloads.

## Run

    pip install -r requirements.txt
    SECRET_KEY=change-me COOKIE_SECURE=0 python app.py   # http://127.0.0.1:5000

Set COOKIE_SECURE=1 when serving over HTTPS.

## What it checks
- TLS: HTTPS in use, certificate expiry, negotiated protocol version
- Headers: HSTS, CSP, clickjacking, nosniff, referrer/permissions policy, CORS, version disclosure
- Cookies: Secure, HttpOnly, SameSite
- Mixed content on HTTPS pages
- Exposed files: .git, .env, .DS_Store, backup.zip, phpinfo, server-status

## Safety built in
- Ownership verification first: a DNS TXT record (`_vulnscan.<host>`) or a file at `/.well-known/vulnscan-<token>.txt`
- SSRF protection: private, loopback, link-local and reserved addresses are refused, and every redirect hop is re-validated
- Only ports 80, 443, 8080, 8443; response size and redirect limits; per-IP rate limit (5/min)
- Strict security headers on the app itself

## Known limits
- Rate limiting and tokens are in-process; use Redis and a proper session store behind multiple workers
- Hostname is resolved at validation time and again at request time (DNS rebinding window); pin the IP for production
- Run behind a reverse proxy and set trusted proxy headers so rate limiting sees real client IPs

## Tests

    python test_scan.py
