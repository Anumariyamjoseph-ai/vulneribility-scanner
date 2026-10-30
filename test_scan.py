import scanner, app

# SSRF guard
for u in ["http://127.0.0.1/", "http://localhost/", "http://169.254.169.254/latest/meta-data/",
          "http://10.0.0.1/", "ftp://example.com/", "http://user:pw@example.com/", "http://example.com:22/"]:
    try:
        scanner.validate_target(u); print("NOT BLOCKED", u)
    except scanner.UnsafeTarget as e:
        print("blocked:", u, "->", e)

# Header checks on a fake response
class R: 
    headers = {"Server": "nginx/1.18.0", "X-Powered-By": "PHP/7.4"}
for f in scanner.check_headers(R(), "https://x.test/"):
    print(f["severity"], f["title"])

# Flask routes
c = app.app.test_client()
print(c.get("/").status_code)
print(c.post("/api/scan", json={"url": "example.com"}).get_json())
print(c.post("/api/challenge", json={"url": "example.com"}).get_json()["file_path"])
print(c.post("/api/scan", json={"url": "example.com"}).get_json())
