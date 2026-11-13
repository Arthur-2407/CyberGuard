import sys
from chrome_cdp_client import ChromeCDPClient

cdp = ChromeCDPClient()
targets = cdp.get_targets()
print(f"Total targets: {len(targets)}")
for t in targets:
    if t.get('type') == 'page':
        tid = t.get('targetId', '')[:8]
        title = t.get('title', '')
        url = t.get('url', '')
        print(f"PAGE [{tid}]: {title} | {url}")
cdp.close()

