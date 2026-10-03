"""
download_asvspoof.py — Resumable downloader for official ASVspoof 2019 LA dataset.

Dataset Source: Zenodo Record 6906306
File: LA.zip (7,640,952,520 bytes)
Target Destination: D:\\BPUT\\data\\asvspoof2019\\LA.zip
"""

import os
import sys
import time
import hashlib
from pathlib import Path
import httpx

ZENODO_LA_URL = "https://zenodo.org/api/records/6906306/files/LA.zip/content"
EXPECTED_SIZE = 7640952520

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data" / "asvspoof2019"
DATA_DIR.mkdir(parents=True, exist_ok=True)
ARCHIVE_PATH = DATA_DIR / "LA.zip"


def download():
    existing_bytes = ARCHIVE_PATH.stat().st_size if ARCHIVE_PATH.exists() else 0
    if existing_bytes == EXPECTED_SIZE:
        print(f"LA.zip already fully downloaded ({existing_bytes} bytes).")
        return

    headers = {}
    if existing_bytes > 0:
        print(f"Resuming download from byte {existing_bytes}...")
        headers["Range"] = f"bytes={existing_bytes}-"
    else:
        print(f"Starting download of LA.zip ({EXPECTED_SIZE / (1024**3):.2f} GB)...")

    start_time = time.time()
    last_log_time = start_time
    last_log_bytes = existing_bytes

    with httpx.Client(follow_redirects=True, timeout=httpx.Timeout(connect=30.0, read=120.0, write=30.0, pool=30.0)) as client:
        with client.stream("GET", ZENODO_LA_URL, headers=headers) as response:
            if response.status_code not in (200, 206):
                raise RuntimeError(f"Download failed with HTTP {response.status_code}: {response.text[:200]}")

            mode = "ab" if existing_bytes > 0 else "wb"
            with open(ARCHIVE_PATH, mode) as f:
                for chunk in response.iter_bytes(chunk_size=1048576):  # 1 MB chunk
                    f.write(chunk)
                    existing_bytes += len(chunk)
                    now = time.time()
                    if now - last_log_time >= 15.0:
                        speed = (existing_bytes - last_log_bytes) / (now - last_log_time) / (1024 * 1024)
                        pct = (existing_bytes / EXPECTED_SIZE) * 100
                        print(f"Downloaded: {existing_bytes / (1024**3):.2f} GB / {EXPECTED_SIZE / (1024**3):.2f} GB ({pct:.1f}%) — {speed:.2f} MB/s")
                        last_log_time = now
                        last_log_bytes = existing_bytes

    total_time = time.time() - start_time
    print(f"Download finished in {total_time:.1f}s. Total size: {ARCHIVE_PATH.stat().st_size} bytes.")


if __name__ == "__main__":
    download()
