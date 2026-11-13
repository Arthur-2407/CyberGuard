import urllib.request
import urllib.error

endpoints = ['/', '/json', '/json/list', '/json/version', '/json/protocol']
for ep in endpoints:
    url = f"http://127.0.0.1:9222{ep}"
    req = urllib.request.Request(url, headers={'Host': 'localhost:9222', 'User-Agent': 'Mozilla/5.0'})
    try:
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            data = resp.read().decode('utf-8', errors='replace')
            print(f"URL {ep} -> Status {resp.status}, Body len {len(data)}: {data[:120]}")
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='replace')
        print(f"URL {ep} -> HTTPError {e.code}: {body[:100]}")
    except Exception as e:
        print(f"URL {ep} -> Error: {e}")

