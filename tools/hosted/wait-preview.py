"""Bounded readiness check for the owned local QA server."""
import time
import urllib.error
import urllib.request

deadline = time.monotonic() + 5
while True:
    try:
        with urllib.request.urlopen("http://127.0.0.1:4173/ip/", timeout=1) as response:
            if response.status == 200:
                break
    except (urllib.error.URLError, TimeoutError):
        pass
    if time.monotonic() >= deadline:
        raise SystemExit("local preview did not become ready")
    time.sleep(0.1)
