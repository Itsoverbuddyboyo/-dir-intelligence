import csv
import hashlib
import io
import json
import os
import re
import shutil
import urllib.request
import zipfile

from datetime import datetime, timezone
from pathlib import Path

API_KEY = os.environ.get("MB_AUTH_KEY")

if not API_KEY:
    raise RuntimeError("Missing MB_AUTH_KEY secret")

EXPORT_URL = (
    f"https://mb-api.abuse.ch/v2/files/exports/"
    f"{API_KEY}/full.csv.zip"
)

DOWNLOAD = Path("full.csv.zip")
OUTPUT = Path("database")
TEMP = Path("database_staging")

# Download the full historical export.
print("Downloading full MalwareBazaar export...")

request = urllib.request.Request(
    EXPORT_URL,
    headers={"User-Agent": "DIR-Intelligence/1.0"}
)

with urllib.request.urlopen(request, timeout=300) as response:
    with DOWNLOAD.open("wb") as file:
        shutil.copyfileobj(response, file)

print(f"Downloaded: {DOWNLOAD.stat().st_size:,} bytes")

# Open and inspect the ZIP archive.
with zipfile.ZipFile(DOWNLOAD) as archive:
    csv_files = [
        name for name in archive.namelist()
        if name.lower().endswith(".csv")
        and not name.startswith("__MACOSX/")
    ]

    if len(csv_files) != 1:
        raise RuntimeError(
            f"Expected one CSV file, found {len(csv_files)}"
        )

    print(f"Reading: {csv_files[0]}")

    shards = {
        character: set()
        for character in "0123456789abcdef"
    }

    with archive.open(csv_files[0]) as raw:
        text = io.TextIOWrapper(raw, encoding="utf-8-sig")
        reader = csv.DictReader(text)

        if not reader.fieldnames:
            raise RuntimeError("CSV has no header")

        columns = {
            name.strip().lower(): name
            for name in reader.fieldnames
            if name
        }

        sha_column = (
            columns.get("sha256_hash")
            or columns.get("sha256")
        )

        if not sha_column:
            raise RuntimeError(
                f"SHA-256 column not found: {reader.fieldnames}"
            )

        print(f"Using column: {sha_column}")

        total_rows = 0
        invalid_rows = 0

        for row in reader:
            total_rows += 1

            value = (row.get(sha_column) or "").strip().lower()

            if not re.fullmatch(r"[a-f0-9]{64}", value):
                invalid_rows += 1
                continue

            shards[value[0]].add(value)

            if total_rows % 100000 == 0:
                print(f"Processed {total_rows:,} records...")

# Reject unexpectedly empty or malformed exports.
total_hashes = sum(len(values) for values in shards.values())

if total_hashes == 0:
    raise RuntimeError("No valid SHA-256 hashes found!")

if total_rows == 0 or invalid_rows > total_rows * 0.01:
    raise RuntimeError("Export failed validation!")

print(f"Valid unique hashes: {total_hashes:,}")
print(f"Invalid rows: {invalid_rows:,}")

# Build a fresh database directory.
if TEMP.exists():
    shutil.rmtree(TEMP)

TEMP.mkdir()

manifest = {
    "version": 1,
    "source": "MalwareBazaar",
    "format": "sha256-text-shards",
    "generated": datetime.now(timezone.utc).isoformat(),
    "hash_count": total_hashes,
    "shards": {}
}

# Write 16 independently verifiable hash files.
for character, values in shards.items():
    filename = f"{character}.txt"
    path = TEMP / filename

    digest = hashlib.sha256()

    with path.open("wb") as file:
        for value in sorted(values):
            line = (value + "\n").encode("ascii")
            file.write(line)
            digest.update(line)

    manifest["shards"][filename] = {
        "count": len(values),
        "sha256": digest.hexdigest(),
        "size": path.stat().st_size
    }

    print(f"{filename}: {len(values):,} hashes")

# Write the manifest.
(TEMP / "manifest.json").write_text(
    json.dumps(manifest, indent=2),
    encoding="utf-8"
)

# Publish the completed directory locally.
if OUTPUT.exists():
    shutil.rmtree(OUTPUT)

TEMP.rename(OUTPUT)

DOWNLOAD.unlink(missing_ok=True)

print("\nFULL DATABASE IMPORT COMPLETED")
print(f"Total unique hashes: {total_hashes:,}")
print(f"Database location: {OUTPUT.resolve()}")
