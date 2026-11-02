

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse

app = FastAPI()

SAFE_FILE = Path(__file__).with_name("sample_download.txt")
if not SAFE_FILE.exists():
    SAFE_FILE.write_text("harmless sample file for download testing\n", encoding="utf-8")


PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Download Lab</title>
  <style>
    body { font-family: Georgia, serif; max-width: 40rem; margin: 3rem auto; padding: 0 1rem; }
    a, button { display: block; margin: 0.75rem 0; font-size: 1.1rem; }
    .legit { color: #0a5; }
    .sketchy { color: #a30; }
  </style>
</head>
<body>
  <h1>Download Lab</h1>
  <p>Mix of real and misleading download controls for BrowserCap.</p>

  <!-- Legitimate same-origin download -->
  <a class="legit" href="/files/document.txt" download>Download File</a>

  <!-- Looks like a download; actually leaves the site -->
  <a class="sketchy" href="https://example.com/ads">Download Now</a>

  <!-- Looks like a download; opens a popup to another domain -->
  <button class="sketchy" type="button"
    onclick="window.open('https://example.com/offer', '_blank', 'width=400,height=300')">
    Free Download
  </button>

  <!-- Redirect chain labeled as install -->
  <a class="sketchy" href="/redirect">Install Now</a>

  <!-- Real download via button + JS navigation -->
  <button class="legit" type="button"
    onclick="window.location.href='/files/document.txt'">
    Get File
  </button>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def home():
    return PAGE


@app.get("/files/document.txt")
def real_download():
    return FileResponse(
        SAFE_FILE,
        filename="document.txt",
        media_type="application/octet-stream",
    )


@app.get("/redirect")
def serve_redirect():

    return RedirectResponse(url="/redirect2", status_code=302)


@app.get("/redirect2")
def serve_redirect2():
    return RedirectResponse(url="https://example.com/", status_code=303)
