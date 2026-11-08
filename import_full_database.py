
import csv
import hashlib
import http.client
import json
import os
import re
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile

from datetime import datetime, timezone
from pathlib import Path


# ============================================================
# CONFIGURATION
# ============================================================

API_KEY = os.environ.get("MB_AUTH_KEY")

EXPORT_URL = (
    "https://mb-api.abuse.ch/v2/files/exports/"
    f"{API_KEY}/full.csv.zip"
)

DATABASE_DIR = Path("database")

DOWNLOAD_ATTEMPTS = 5
CHUNK_SIZE = 1024 * 1024
MAX_INVALID_RATIO = 0.01

SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")
SHARD_NAMES = [f"{i:x}.txt" for i in range(16)]


# ============================================================
# DOWNLOAD
# ============================================================

def download_export(destination: Path) -> None:
    """
    Download the export with retries.

    Every failed attempt is discarded completely. A download is
    accepted only after it finishes and passes ZIP integrity checks.
    """

    if not API_KEY:
        raise RuntimeError(
            "MB_AUTH_KEY is missing. Check your GitHub repository secret."
        )

    for attempt in range(1, DOWNLOAD_ATTEMPTS + 1):
        print(
            f"Downloading full MalwareBazaar export "
            f"(attempt {attempt}/{DOWNLOAD_ATTEMPTS})..."
        )

        destination.unlink(missing_ok=True)

        request = urllib.request.Request(
            EXPORT_URL,
            headers={
                "User-Agent": "DIR-Intelligence-Importer/1.0",
                "Accept": "application/zip, application/octet-stream, */*",
            },
            method="GET",
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=120,
            ) as response:

                status = response.status

                if status != 200:
                    raise RuntimeError(
                        f"Export server returned HTTP {status}."
                    )

                total_bytes = 0

                with destination.open("wb") as output:
                    while True:
                        chunk = response.read(CHUNK_SIZE)

                        if not chunk:
                            break

                        output.write(chunk)
                        total_bytes += len(chunk)

            if total_bytes == 0:
                raise RuntimeError("The server returned an empty file.")

            print(f"Downloaded {total_bytes:,} bytes.")

            if not zipfile.is_zipfile(destination):
                raise RuntimeError(
                    "The downloaded response is not a valid ZIP archive. "
                    "The export endpoint may have returned an error response."
                )

            with zipfile.ZipFile(destination, "r") as archive:
                bad_file = archive.testzip()

                if bad_file is not None:
                    raise RuntimeError(
                        f"ZIP integrity check failed: {bad_file}"
                    )

            print("ZIP download verified.")
            return

        except (
            http.client.IncompleteRead,
            urllib.error.URLError,
            TimeoutError,
            ConnectionError,
            OSError,
            zipfile.BadZipFile,
            RuntimeError,
        ) as error:

            destination.unlink(missing_ok=True)

            # Do not print the original URL: it contains the API key.
            print(
                f"Download attempt {attempt} failed: "
                f"{type(error).__name__}: {str(error)[:250]}"
            )

            if attempt == DOWNLOAD_ATTEMPTS:
                raise RuntimeError(
                    "Could not download a complete, valid export after "
                    f"{DOWNLOAD_ATTEMPTS} attempts. "
                    "Check the export endpoint and MalwareBazaar access."
                ) from None

            delay = min(15 * attempt, 60)
            print(f"Retrying in {delay} seconds...")
            time.sleep(delay)


# ============================================================
# EXTRACT HASHES
# ============================================================

def extract_hashes(archive_path: Path):
    """
    Read SHA-256 hashes from the CSV inside the ZIP.

    Hashes are separated into 16 shards based on their first
    hexadecimal character.
    """

    shards = {
        f"{character}.txt": set()
        for character in "0123456789abcdef"
    }

    invalid_rows = 0
    total_rows = 0

    with zipfile.ZipFile(archive_path, "r") as archive:
        csv_files = [
            name
            for name in archive.namelist()
            if name.lower().endswith(".csv")
        ]

        if len(csv_files) != 1:
            raise RuntimeError(
                "Expected exactly one CSV file in the export ZIP, "
                f"but found {len(csv_files)}."
            )

        csv_name = csv_files[0]
        print(f"Reading {csv_name}...")

        with archive.open(csv_name, "r") as raw_file:
            import io

            text_file = io.TextIOWrapper(
                raw_file,
                encoding="utf-8-sig",
                errors="replace",
                newline="",
            )

            reader = csv.DictReader(text_file)

            if not reader.fieldnames:
                raise RuntimeError("The CSV has no header row.")

            normalized_columns = {
                column.strip().lower(): column
                for column in reader.fieldnames
                if column
            }

            hash_column = (
                normalized_columns.get("sha256_hash")
                or normalized_columns.get("sha256")
            )

            if not hash_column:
                raise RuntimeError(
                    "Could not find a SHA-256 column. "
                    f"CSV columns: {reader.fieldnames}"
                )

            for row in reader:
                total_rows += 1

                value = (row.get(hash_column) or "").strip()

                if not SHA256_PATTERN.fullmatch(value):
                    invalid_rows += 1
                    continue

                value = value.lower()
                shard_name = value[0] + ".txt"

                shards[shard_name].add(value)

                if total_rows % 250000 == 0:
                    print(
                        f"Processed {total_rows:,} rows..."
                    )

    unique_count = sum(len(values) for values in shards.values())

    if unique_count == 0:
        raise RuntimeError(
            "No valid SHA-256 hashes were found. "
            "The export may have an unexpected format."
        )

    invalid_ratio = (
        invalid_rows / total_rows
        if total_rows
        else 1.0
    )

    if invalid_ratio > MAX_INVALID_RATIO:
        raise RuntimeError(
            f"Too many invalid rows: {invalid_rows:,} "
            f"out of {total_rows:,}."
        )

    print()
    print(f"Rows processed: {total_rows:,}")
    print(f"Invalid rows: {invalid_rows:,}")
    print(f"Unique SHA-256 hashes: {unique_count:,}")

    return shards, unique_count, total_rows, invalid_rows


# ============================================================
# BUILD DATABASE
# ============================================================

def build_database(
    shards,
    unique_count,
    total_rows,
    invalid_rows,
    output_dir: Path,
):
    output_dir.mkdir(parents=True, exist_ok=True)

    shard_metadata = {}

    for shard_name in SHARD_NAMES:
        hashes = sorted(shards[shard_name])
        shard_path = output_dir / shard_name

        content = (
            "\n".join(hashes) + "\n"
            if hashes
            else ""
        )

        encoded = content.encode("ascii")
        shard_path.write_bytes(encoded)

        shard_metadata[shard_name] = {
            "count": len(hashes),
            "size": len(encoded),
            "sha256": hashlib.sha256(encoded).hexdigest(),
        }

        print(
            f"{shard_name}: {len(hashes):,} hashes, "
            f"{len(encoded):,} bytes"
        )

    manifest = {
        "version": 1,
        "source": "MalwareBazaar",
        "updated": datetime.now(timezone.utc).isoformat(),
        "hash_count": unique_count,
        "rows_processed": total_rows,
        "invalid_rows": invalid_rows,
        "shards": shard_metadata,
    }

    manifest_path = output_dir / "manifest.json"

    manifest_path.write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )

    print()
    print("Database files generated.")


# ============================================================
# VERIFY DATABASE
# ============================================================

def verify_database(directory: Path) -> None:
    manifest_path = directory / "manifest.json"

    if not manifest_path.exists():
        raise RuntimeError("Manifest is missing.")

    manifest = json.loads(
        manifest_path.read_text(encoding="utf-8")
    )

    if len(manifest["shards"]) != 16:
        raise RuntimeError("Expected exactly 16 shards.")

    total_hashes = 0
    total_size = 0

    for shard_name in SHARD_NAMES:
        path = directory / shard_name

        if not path.exists():
            raise RuntimeError(f"Missing shard: {shard_name}")

        info = manifest["shards"].get(shard_name)

        if info is None:
            raise RuntimeError(
                f"Missing manifest entry: {shard_name}"
            )

        content = path.read_bytes()

        if len(content) != info["size"]:
            raise RuntimeError(
                f"Incorrect file size: {shard_name}"
            )

        actual_digest = hashlib.sha256(content).hexdigest()

        if actual_digest != info["sha256"]:
            raise RuntimeError(
                f"Checksum mismatch: {shard_name}"
            )

        lines = content.splitlines()

        if len(lines) != info["count"]:
            raise RuntimeError(
                f"Hash count mismatch: {shard_name}"
            )

        for value in lines:
            decoded = value.decode("ascii")

            if not SHA256_PATTERN.fullmatch(decoded):
                raise RuntimeError(
                    f"Invalid hash in {shard_name}"
                )

            if decoded[0] != shard_name[0]:
                raise RuntimeError(
                    f"Hash stored in wrong shard: {shard_name}"
                )

        total_hashes += len(lines)
        total_size += len(content)

    if total_hashes != manifest["hash_count"]:
        raise RuntimeError("Total hash count does not match manifest.")

    if total_size >= 900 * 1024 * 1024:
        raise RuntimeError(
            "Database exceeds the configured 900 MB safety limit."
        )

    print()
    print("DATABASE VERIFIED")
    print(f"Total hashes: {total_hashes:,}")
    print(f"Total shard size: {total_size:,} bytes")


# ============================================================
# MAIN
# ============================================================

def main():
    if not API_KEY:
        raise RuntimeError(
            "MB_AUTH_KEY is not configured in the environment."
        )

    temporary_root = Path(
        tempfile.mkdtemp(prefix="dir-import-")
    )

    archive_path = temporary_root / "full.csv.zip"
    staging_dir = temporary_root / "database"

    try:
        download_export(archive_path)

        shards, unique_count, total_rows, invalid_rows = (
            extract_hashes(archive_path)
        )

        build_database(
            shards,
            unique_count,
            total_rows,
            invalid_rows,
            staging_dir,
        )

        verify_database(staging_dir)

        # Only replace the existing database after the new one
        # has downloaded, extracted, and passed verification.
        backup_dir = temporary_root / "database-backup"

        if DATABASE_DIR.exists():
            DATABASE_DIR.rename(backup_dir)

        try:
            staging_dir.rename(DATABASE_DIR)
        except Exception:
            if backup_dir.exists() and not DATABASE_DIR.exists():
                backup_dir.rename(DATABASE_DIR)
            raise

        print()
        print("Full database import completed successfully.")

    finally:
        shutil.rmtree(temporary_root, ignore_errors=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print()
        print(f"IMPORT FAILED: {error}")
        sys.exit(1)
