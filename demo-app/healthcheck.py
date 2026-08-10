from urllib.request import urlopen


with urlopen("http://127.0.0.1:5000/health", timeout=2) as response:
    raise SystemExit(0 if response.status == 200 else 1)
