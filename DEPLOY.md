# Put the scanner online (no install needed)

Everything below is done in your web browser.

1. Create a free account at github.com (skip if you have one).
2. Click "+" > "New repository". Name it `site-scanner`, set it to Private, click "Create repository".
3. Click "uploading an existing file". Unzip vulnscan.zip on your computer, then drag in everything inside the
   vulnscan folder (app.py, scanner.py, requirements.txt, render.yaml, the templates folder, etc.).
   Click "Commit changes".
4. Create a free account at render.com using "Sign in with GitHub".
5. Click "New +" > "Blueprint", pick your `site-scanner` repository, and click "Apply".
   Render reads render.yaml and sets everything up. The first build takes a few minutes.
6. When it says "Live", open the `https://...onrender.com` link shown at the top. That is your scanner.

Notes
- The free plan sleeps after ~15 minutes idle, so the first load afterward takes about 30 seconds.
- Keep the repository Private. The scanner is meant for sites you own.
- Do not share the link publicly without adding a login; anyone with the link can use it (ownership
  verification still stops them scanning sites they don't control).
