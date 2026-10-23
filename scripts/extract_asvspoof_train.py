"""
extract_asvspoof_train.py — Extracts genuine ASVspoof 2019 LA FLAC audio files from the archive stream
and writes disjoint speaker-split training and validation protocols.
"""

import io
import struct
import zlib
from pathlib import Path
import soundfile as sf

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ZIP_PATH = PROJECT_ROOT / "data" / "asvspoof2019" / "LA.zip"
PROTO_PATH = PROJECT_ROOT / "data" / "asvspoof2019" / "protocols" / "ASVspoof2019.LA.cm.train.trn.txt"

OUT_DIR = PROJECT_ROOT / "data" / "asvspoof2019" / "extracted"
OUT_AUDIO_DIR = OUT_DIR / "flac"
OUT_AUDIO_DIR.mkdir(parents=True, exist_ok=True)

# Parse protocol lines
proto_rows = {}
with open(PROTO_PATH, "r", encoding="utf-8") as f:
    for line in f:
        parts = line.strip().split()
        if len(parts) >= 5:
            spk, audio_id, env, attack, key = parts[0], parts[1], parts[2], parts[3], parts[4].lower()
            proto_rows[audio_id] = (spk, attack, key)

train_speakers = {
    "LA_0079", "LA_0080", "LA_0081", "LA_0082", "LA_0083",
    "LA_0084", "LA_0085", "LA_0086", "LA_0087", "LA_0088",
    "LA_0089", "LA_0090", "LA_0091", "LA_0092", "LA_0093",
}
val_speakers = {"LA_0094", "LA_0095", "LA_0096", "LA_0097", "LA_0098"}

train_extracted = []
val_extracted = []

print("Scanning and extracting from LA.zip...")
with open(ZIP_PATH, "rb") as f:
    while True:
        sig = f.read(4)
        if len(sig) < 4 or sig != b"PK\x03\x04":
            break
        header = f.read(26)
        if len(header) < 26:
            break
        ver, flags, method, mod_time, mod_date, crc32, comp_size, uncomp_size, name_len, extra_len = struct.unpack("<HHHHHIIIHH", header)
        name = f.read(name_len).decode("utf-8", errors="replace")
        f.seek(extra_len, io.SEEK_CUR)
        raw = f.read(comp_size)

        if len(raw) < comp_size:
            print("Reached active write boundary of streaming LA.zip.")
            break

        if name.endswith(".flac"):
            stem = Path(name).stem
            if stem in proto_rows:
                spk, attack, key = proto_rows[stem]
                is_train = spk in train_speakers
                is_val = spk in val_speakers

                if is_train or is_val:
                    dest = OUT_AUDIO_DIR / f"{stem}.flac"
                    if not dest.exists():
                        try:
                            data = zlib.decompress(raw, -15) if method == 8 else raw
                            with open(dest, "wb") as out_f:
                                out_f.write(data)
                        except Exception as e:
                            print(f"Skipping incomplete file {stem}: {e}")
                            continue

                    row = f"{spk} {stem} - {attack} {key}\n"
                    if is_train:
                        train_extracted.append((stem, spk, key, row))
                    else:
                        val_extracted.append((stem, spk, key, row))

train_bonafide = sum(1 for x in train_extracted if x[2] == "bonafide")
train_spoof = sum(1 for x in train_extracted if x[2] == "spoof")
val_bonafide = sum(1 for x in val_extracted if x[2] == "bonafide")
val_spoof = sum(1 for x in val_extracted if x[2] == "spoof")

print(f"Train extracted: {len(train_extracted)} (bonafide={train_bonafide}, spoof={train_spoof}) across {len(train_speakers)} speakers")
print(f"Val extracted: {len(val_extracted)} (bonafide={val_bonafide}, spoof={val_spoof}) across {len(val_speakers)} speakers")

train_proto = OUT_DIR / "train_protocol.txt"
val_proto = OUT_DIR / "val_protocol.txt"

with open(train_proto, "w", encoding="utf-8") as f:
    for x in train_extracted:
        f.write(x[3])

with open(val_proto, "w", encoding="utf-8") as f:
    for x in val_extracted:
        f.write(x[3])

print(f"Wrote {train_proto} and {val_proto}")
