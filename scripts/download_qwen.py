"""
download_qwen.py — Official Hugging Face downloader for Qwen3.5 4B — Q4_K_M.

Downloads unsloth/Qwen3.5-4B-GGUF -> Qwen3.5-4B-Q4_K_M.gguf with resume support,
chunked streaming, and progress tracking.
"""

import json
import logging
import os
import sys
import time
from pathlib import Path

try:
    from huggingface_hub import hf_hub_download
except ImportError:
    hf_hub_download = None

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("qwen_downloader")

MODEL_REPO = "unsloth/Qwen3.5-4B-GGUF"
MODEL_FILENAME = "Qwen3.5-4B-Q4_K_M.gguf"
TARGET_DIR = Path("backend/models/weights/qwen3.5")
TARGET_FILE = TARGET_DIR / MODEL_FILENAME
STATUS_FILE = Path("data/qwen_download_status.json")


def update_status(status: str, downloaded_bytes: int = 0, total_bytes: int = 0, speed_mb_s: float = 0.0, error: str = ""):
    STATUS_FILE.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "status": status,
        "repo": MODEL_REPO,
        "filename": MODEL_FILENAME,
        "target_path": str(TARGET_FILE.as_posix()),
        "downloaded_bytes": downloaded_bytes,
        "total_bytes": total_bytes,
        "progress_percent": round((downloaded_bytes / total_bytes * 100), 2) if total_bytes > 0 else (100.0 if status == "COMPLETED" else 0.0),
        "speed_mb_s": round(speed_mb_s, 2),
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "error": error,
    }
    try:
        with open(STATUS_FILE, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
    except Exception as e:
        logger.warning(f"Failed to update status file: {e}")


def download():
    TARGET_DIR.mkdir(parents=True, exist_ok=True)

    if TARGET_FILE.exists() and TARGET_FILE.stat().st_size > 2_000_000_000:
        logger.info(f"Qwen3.5 4B Q4_K_M already downloaded at {TARGET_FILE} ({TARGET_FILE.stat().st_size} bytes)")
        update_status("COMPLETED", TARGET_FILE.stat().st_size, TARGET_FILE.stat().st_size)
        return

    logger.info(f"Initiating official Hugging Face download for {MODEL_REPO}/{MODEL_FILENAME} -> {TARGET_FILE}...")
    update_status("DOWNLOADING", 0, 2740937888)

    try:
        # Use huggingface_hub directly if available
        if hf_hub_download:
            logger.info("Using huggingface_hub.hf_hub_download...")
            downloaded_path = hf_hub_download(
                repo_id=MODEL_REPO,
                filename=MODEL_FILENAME,
                local_dir=str(TARGET_DIR),
                local_dir_use_symlinks=False,
            )
            final_path = Path(downloaded_path)
            logger.info(f"✓ Hugging Face download completed: {final_path} ({final_path.stat().st_size} bytes)")
            update_status("COMPLETED", final_path.stat().st_size, final_path.stat().st_size)
            return
    except Exception as hf_err:
        logger.warning(f"hf_hub_download encountered error, falling back to streaming urllib: {hf_err}")

    # Fallback to chunked resumeable stream via urllib
    import urllib.request
    url = f"https://huggingface.co/{MODEL_REPO}/resolve/main/{MODEL_FILENAME}"
    part_file = TARGET_DIR / f"{MODEL_FILENAME}.part"
    existing_bytes = part_file.stat().st_size if part_file.exists() else 0

    req = urllib.request.Request(url)
    if existing_bytes > 0:
        req.add_header("Range", f"bytes={existing_bytes}-")
        logger.info(f"Resuming download from byte {existing_bytes}...")

    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            total = existing_bytes + int(resp.headers.get("Content-Length", 2740937888 - existing_bytes))
            mode = "ab" if existing_bytes > 0 else "wb"
            downloaded = existing_bytes
            t_last = time.time()
            bytes_since = 0

            with open(part_file, mode) as f:
                while True:
                    chunk = resp.read(1024 * 1024)  # 1 MB chunks
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    bytes_since += len(chunk)

                    now = time.time()
                    if now - t_last >= 5.0:
                        speed = (bytes_since / (1024 * 1024)) / (now - t_last)
                        pct = (downloaded / total * 100) if total > 0 else 0
                        logger.info(f"Progress: {downloaded / (1024*1024):.1f}/{total / (1024*1024):.1f} MB ({pct:.1f}%) - {speed:.2f} MB/s")
                        update_status("DOWNLOADING", downloaded, total, speed)
                        t_last = now
                        bytes_since = 0

            if part_file.exists():
                if TARGET_FILE.exists():
                    TARGET_FILE.unlink()
                part_file.rename(TARGET_FILE)
                logger.info(f"✓ Download completed successfully: {TARGET_FILE}")
                update_status("COMPLETED", TARGET_FILE.stat().st_size, TARGET_FILE.stat().st_size)
    except Exception as exc:
        logger.error(f"Download failed: {exc}")
        update_status("FAILED", existing_bytes, 2740937888, error=str(exc))
        raise


if __name__ == "__main__":
    download()
