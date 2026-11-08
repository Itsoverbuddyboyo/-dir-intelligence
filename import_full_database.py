
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

if not API_KEY:
    raise RuntimeError("MB_AUTH_KEY environment variable is missing.")

EXPORT_URL = (
    "https://mb-api.abuse.ch/v2/files/exports/"
    f"{API_KEY}/full.csv.zip"
)

DATABASE_DIR = Path("database")

RANGE_CHUNK_SIZE = 4 * 1024 * 1024
CHUNK_RETRIES = 8
CHUNK_READ_SIZE = 256 * 1024

RETRY_BASE_DELAY = 3
MAX_RETRY_DELAY = 20

MAX_INVALID_RATIO = 0.01
DOWNLOAD_TIMEOUT = 90

SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")

CONTENT_RANGE_PATTERN = re.compile(
    r"^bytes\s+(\d+)-(\d+)/(\d+|\*)$",
    re.IGNORECASE,
)

SHARD_NAMES = [
    f"{character}.txt"
    for character in "0123456789abcdef"
]


# ============================================================
# GENERAL UTILITIES
# ============================================================

def remove_path(path):
    if not path.exists():
        return

    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()


def calculate_sha256(path):
    digest = hashlib.sha256()

    with path.open("rb") as file:
        while True:
            chunk = file.read(1024 * 1024)

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()


# ============================================================
# ZIP VERIFICATION
# ============================================================

def verify_zip(path):
    print("Verifying downloaded ZIP archive...")

    if not path.exists():
        raise RuntimeError("Downloaded archive does not exist.")

    if path.stat().st_size == 0:
        raise RuntimeError("Downloaded archive is empty.")

    if not zipfile.is_zipfile(path):
        raise RuntimeError("Downloaded file is not a valid ZIP archive.")

    with zipfile.ZipFile(path, "r") as archive:
        csv_files = [
            name
            for name in archive.namelist()
            if name.lower().endswith(".csv")
        ]

        if len(csv_files) != 1:
            raise RuntimeError(
                f"Expected exactly one CSV file, found {len(csv_files)}."
            )

        corrupted_file = archive.testzip()

        if corrupted_file is not None:
            raise RuntimeError(
                f"ZIP integrity check failed: {corrupted_file}"
            )

    print("ZIP integrity verified.")


# ============================================================
# RANGE-BASED DOWNLOAD
# ============================================================

def read_response_fully(response, expected_size):
    chunks = []
    received = 0

    while received < expected_size:
        remaining = expected_size - received

        chunk = response.read(
            min(CHUNK_READ_SIZE, remaining)
        )

        if not chunk:
            raise http.client.IncompleteRead(
                b"".join(chunks),
                expected_size - received,
            )

        chunks.append(chunk)
        received += len(chunk)

    return b"".join(chunks)


def download_export(destination):
    print("Starting MalwareBazaar full database download...")

    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    downloaded = 0
    archive_size = None

    etag = None
    last_modified = None

    with destination.open("wb") as output:

        while archive_size is None or downloaded < archive_size:

            start = downloaded

            if archive_size is None:
                end = start + RANGE_CHUNK_SIZE - 1
            else:
                end = min(
                    start + RANGE_CHUNK_SIZE - 1,
                    archive_size - 1,
                )

            expected_chunk_size = end - start + 1

            successful = False
            last_error = None

            for attempt in range(1, CHUNK_RETRIES + 1):

                print(
                    f"Requesting bytes {start}-{end} "
                    f"(attempt {attempt}/{CHUNK_RETRIES})..."
                )

                headers = {
                    "Range": f"bytes={start}-{end}",
                    "Accept-Encoding": "identity",
                    "User-Agent": "DIR-MalwareBazaar-Importer/1.0",
                }

                if etag:
                    headers["If-Range"] = etag
                elif last_modified:
                    headers["If-Range"] = last_modified

                request = urllib.request.Request(
                    EXPORT_URL,
                    headers=headers,
                )

                try:
                    with urllib.request.urlopen(
                        request,
                        timeout=DOWNLOAD_TIMEOUT,
                    ) as response:

                        if response.status != 206:
                            raise RuntimeError(
                                f"Expected HTTP 206, got "
                                f"{response.status}."
                            )

                        content_range = response.headers.get(
                            "Content-Range"
                        )

                        if not content_range:
                            raise RuntimeError(
                                "Missing Content-Range header."
                            )

                        match = CONTENT_RANGE_PATTERN.fullmatch(
                            content_range.strip()
                        )

                        if not match:
                            raise RuntimeError(
                                f"Invalid Content-Range: {content_range}"
                            )

                        actual_start = int(match.group(1))
                        actual_end = int(match.group(2))
                        actual_total = match.group(3)

                        if actual_start != start:
                            raise RuntimeError(
                                f"Unexpected range start: {actual_start}"
                            )

                        if actual_end != end:
                            raise RuntimeError(
                                f"Unexpected range end: {actual_end}"
                            )

                        if actual_total == "*":
                            raise RuntimeError(
                                "Server did not provide archive size."
                            )

                        actual_total = int(actual_total)

                        if archive_size is None:
                            archive_size = actual_total

                            print(
                                f"Archive size: {archive_size:,} bytes "
                                f"({archive_size / 1024 / 1024:.2f} MiB)"
                            )

                        elif actual_total != archive_size:
                            raise RuntimeError(
                                "Archive size changed during download."
                            )

                        if end >= archive_size:
                            raise RuntimeError(
                                "Requested range exceeds archive size."
                            )

                        response_etag = response.headers.get("ETag")
                        response_modified = response.headers.get(
                            "Last-Modified"
                        )

                        if response_etag:
                            etag = response_etag

                        if response_modified:
                            last_modified = response_modified

                        content_length = response.headers.get(
                            "Content-Length"
                        )

                        if content_length is not None:
                            if int(content_length) != expected_chunk_size:
                                raise RuntimeError(
                                    "Unexpected Content-Length."
                                )

                        chunk_data = read_response_fully(
                            response,
                            expected_chunk_size,
                        )

                        if len(chunk_data) != expected_chunk_size:
                            raise RuntimeError(
                                "Downloaded chunk has incorrect size."
                            )

                        output.write(chunk_data)
                        output.flush()
                        os.fsync(output.fileno())

                        downloaded += len(chunk_data)

                        successful = True

                        percentage = (
                            downloaded / archive_size
                        ) * 100

                        print(
                            f"Download progress: "
                            f"{downloaded:,} / {archive_size:,} bytes "
                            f"({percentage:.1f}%)"
                        )

                        break

                except (
                    urllib.error.URLError,
                    urllib.error.HTTPError,
                    http.client.HTTPException,
                    TimeoutError,
                    OSError,
                    RuntimeError,
                    ValueError,
                ) as error:

                    last_error = error

                    print(
                        f"Download attempt failed: "
                        f"{type(error).__name__}: {error}"
                    )

                    if attempt < CHUNK_RETRIES:
                        delay = min(
                            RETRY_BASE_DELAY * attempt,
                            MAX_RETRY_DELAY,
                        )

                        print(f"Retrying in {delay} seconds...")
                        time.sleep(delay)

            if not successful:
                raise RuntimeError(
                    f"Failed downloading bytes {start}-{end} "
                    f"after {CHUNK_RETRIES} attempts. "
                    f"Last error: {last_error}"
                )

    actual_size = destination.stat().st_size

    if actual_size != archive_size:
        raise RuntimeError(
            f"Final download size mismatch: "
            f"{actual_size} != {archive_size}"
        )

    print(f"Download finished: {actual_size:,} bytes.")

    verify_zip(destination)

    print("Download successful.")

    return destination


# ============================================================
# SHA-256 NORMALIZATION
# ============================================================

def normalize_hash(value):
    if value is None:
        return ""

    value = value.strip()

    # MalwareBazaar's exported CSV can contain literal
    # quotation marks inside the parsed field.
    #
    # Remove surrounding quotation marks before validation.

    value = value.strip('"').strip("'").strip()

    # Remove an unexpected BOM if present.

    value = value.lstrip("\ufeff").strip()

    return value.lower()


# ============================================================
# CSV EXTRACTION
# ============================================================

def extract_hashes(archive_path):
    print("Extracting SHA-256 hashes...")
    print("Reading full.csv...")

    shards = {
        name: set()
        for name in SHARD_NAMES
    }

    total_rows = 0
    empty_rows = 0
    invalid_rows = 0

    sample_values = []

    with zipfile.ZipFile(archive_path, "r") as archive:

        csv_files = [
            name
            for name in archive.namelist()
            if name.lower().endswith(".csv")
        ]

        if len(csv_files) != 1:
            raise RuntimeError(
                "Expected exactly one CSV file in the archive."
            )

        csv_name = csv_files[0]

        with archive.open(csv_name, "r") as raw_file:

            import io

            text_file = io.TextIOWrapper(
                raw_file,
                encoding="utf-8-sig",
                errors="replace",
                newline="",
            )

            reader = csv.reader(text_file)

            header = None
            hash_index = None
            hash_column = None

            # ------------------------------------------------
            # Find the CSV header.
            # ------------------------------------------------

            for row in reader:

                cleaned = [
                    value.strip().lstrip("#").strip()
                    for value in row
                ]

                normalized = [
                    value.lower()
                    for value in cleaned
                ]

                if "sha256_hash" in normalized:
                    hash_index = normalized.index("sha256_hash")
                    hash_column = cleaned[hash_index]
                    header = cleaned
                    break

                if "sha256" in normalized:
                    hash_index = normalized.index("sha256")
                    hash_column = cleaned[hash_index]
                    header = cleaned
                    break

            if header is None:
                raise RuntimeError(
                    "Could not find SHA-256 column in CSV."
                )

            print("Found CSV header successfully.")
            print(f"SHA-256 column: {hash_column}")
            print(f"Columns found: {len(header)}")
            print(f"SHA-256 column index: {hash_index}")

            # ------------------------------------------------
            # IMPORTANT:
            # Continue using the SAME reader.
            # Do not create a second reader on text_file.
            # ------------------------------------------------

            for row in reader:

                if hash_index >= len(row):
                    empty_rows += 1
                    continue

                raw_value = row[hash_index]

                if not raw_value or not raw_value.strip():
                    empty_rows += 1
                    continue

                total_rows += 1

                value = normalize_hash(raw_value)

                if len(sample_values) < 5:
                    sample_values.append({
                        "raw_value": raw_value[:100],
                        "normalized_value": value,
                        "normalized_length": len(value),
                    })

                if not SHA256_PATTERN.fullmatch(value):
                    invalid_rows += 1
                    continue

                shard_name = value[0] + ".txt"

                shards[shard_name].add(value)

                if total_rows % 250000 == 0:
                    unique_count = sum(
                        len(values)
                        for values in shards.values()
                    )

                    print(
                        f"Processed {total_rows:,} rows | "
                        f"{unique_count:,} unique hashes"
                    )

    unique_count = sum(
        len(values)
        for values in shards.values()
    )

    print()
    print("CSV parsing diagnostics:")
    print(f"Rows containing a nonempty hash field: {total_rows:,}")
    print(f"Empty hash fields: {empty_rows:,}")
    print(f"Invalid hash values: {invalid_rows:,}")
    print(f"Unique valid SHA-256 hashes: {unique_count:,}")

    print("Sample normalized values:")

    for sample in sample_values:
        print(json.dumps(sample))

    if unique_count == 0:
        raise RuntimeError(
            "No valid SHA-256 hashes were extracted. "
            "See CSV parsing diagnostics above."
        )

    invalid_ratio = (
        invalid_rows / total_rows
        if total_rows
        else 1.0
    )

    if invalid_ratio > MAX_INVALID_RATIO:
        raise RuntimeError(
            f"Invalid hash ratio too high: "
            f"{invalid_ratio:.2%} "
            f"(maximum {MAX_INVALID_RATIO:.2%})."
        )

    print()
    print("SHA-256 extraction successful.")
    print(f"Total rows processed: {total_rows:,}")
    print(f"Unique hashes extracted: {unique_count:,}")

    return shards, total_rows, invalid_rows


# ============================================================
# DATABASE BUILDING
# ============================================================

def build_database(
    shards,
    total_rows,
    invalid_rows,
    staging_dir,
):
    print()
    print("Building 16-shard database...")

    remove_path(staging_dir)
    staging_dir.mkdir(parents=True, exist_ok=True)

    shard_manifest = {}
    total_hashes = 0
    total_size = 0

    for shard_name in SHARD_NAMES:

        hashes = sorted(shards[shard_name])

        shard_path = staging_dir / shard_name

        with shard_path.open(
            "w",
            encoding="ascii",
            newline="\n",
        ) as file:

            for value in hashes:
                file.write(value + "\n")

        size = shard_path.stat().st_size
        checksum = calculate_sha256(shard_path)

        shard_manifest[shard_name] = {
            "count": len(hashes),
            "size": size,
            "sha256": checksum,
        }

        total_hashes += len(hashes)
        total_size += size

        print(
            f"{shard_name}: "
            f"{len(hashes):,} hashes | "
            f"{size:,} bytes"
        )

    manifest = {
        "version": 1,
        "source": "MalwareBazaar",
        "updated": datetime.now(timezone.utc).isoformat(),
        "hash_type": "SHA-256",
        "hash_count": total_hashes,
        "rows_processed": total_rows,
        "invalid_rows": invalid_rows,
        "shards": shard_manifest,
    }

    manifest_path = staging_dir / "manifest.json"

    with manifest_path.open(
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            manifest,
            file,
            indent=2,
        )

    print()
    print(f"Total unique hashes: {total_hashes:,}")
    print(f"Total shard size: {total_size:,} bytes")
    print("Manifest created.")

    return manifest


# ============================================================
# DATABASE VERIFICATION
# ============================================================

def verify_database(database_dir):
    print()
    print("Verifying generated database...")

    manifest_path = database_dir / "manifest.json"

    if not manifest_path.exists():
        raise RuntimeError("manifest.json is missing.")

    with manifest_path.open(
        "r",
        encoding="utf-8",
    ) as file:

        manifest = json.load(file)

    shard_manifest = manifest.get("shards")

    if not isinstance(shard_manifest, dict):
        raise RuntimeError("Invalid shard manifest.")

    if set(shard_manifest.keys()) != set(SHARD_NAMES):
        raise RuntimeError(
            "Manifest does not contain exactly 16 expected shards."
        )

    total_hashes = 0
    total_size = 0

    for shard_name in SHARD_NAMES:

        shard_path = database_dir / shard_name

        if not shard_path.exists():
            raise RuntimeError(
                f"Missing shard: {shard_name}"
            )

        expected = shard_manifest[shard_name]

        actual_size = shard_path.stat().st_size
        actual_checksum = calculate_sha256(shard_path)

        if actual_size != expected["size"]:
            raise RuntimeError(
                f"Size mismatch in {shard_name}."
            )

        if actual_checksum != expected["sha256"]:
            raise RuntimeError(
                f"Checksum mismatch in {shard_name}."
            )

        shard_count = 0

        with shard_path.open(
            "r",
            encoding="ascii",
        ) as file:

            for line in file:

                value = line.strip()

                if not SHA256_PATTERN.fullmatch(value):
                    raise RuntimeError(
                        f"Invalid SHA-256 value in {shard_name}: "
                        f"{value}"
                    )

                if value[0] + ".txt" != shard_name:
                    raise RuntimeError(
                        f"Incorrect shard prefix in {shard_name}."
                    )

                shard_count += 1

        if shard_count != expected["count"]:
            raise RuntimeError(
                f"Hash count mismatch in {shard_name}."
            )

        total_hashes += shard_count
        total_size += actual_size

        print(
            f"Verified {shard_name}: "
            f"{shard_count:,} hashes"
        )

    if total_hashes != manifest["hash_count"]:
        raise RuntimeError(
            "Total hash count does not match manifest."
        )

    if total_size >= 900 * 1024 * 1024:
        raise RuntimeError(
            "Database exceeds the 900 MiB safety limit."
        )

    print()
    print("DATABASE VERIFIED")
    print(f"Total hashes: {total_hashes:,}")
    print(f"Total shard size: {total_size:,} bytes")

    return True


# ============================================================
# SAFE DATABASE REPLACEMENT
# ============================================================

def replace_database(staging_dir):
    backup_dir = DATABASE_DIR.with_name(
        DATABASE_DIR.name + ".backup"
    )

    print()
    print("Installing verified database...")

    remove_path(backup_dir)

    had_previous_database = DATABASE_DIR.exists()

    if had_previous_database:
        print("Preserving previous database as backup.")
        os.replace(DATABASE_DIR, backup_dir)

    try:
        os.replace(staging_dir, DATABASE_DIR)

    except Exception:

        print("Database installation failed.")

        if had_previous_database and backup_dir.exists():
            print("Restoring previous database.")
            os.replace(backup_dir, DATABASE_DIR)

        raise

    if backup_dir.exists():
        remove_path(backup_dir)

    print("Database installed successfully.")


# ============================================================
# MAIN
# ============================================================

def main():
    print("=" * 60)
    print("D.I.R. - MALWAREBAZAAR FULL DATABASE IMPORT")
    print("=" * 60)

    temp_root = Path(
        tempfile.mkdtemp(prefix="dir_malwarebazaar_")
    )

    archive_path = temp_root / "full.csv.zip"

    staging_dir = DATABASE_DIR.with_name(
        DATABASE_DIR.name + ".staging"
    )

    try:

        # 1. Download full export.

        download_export(archive_path)

        # 2. Extract and validate hashes.

        shards, total_rows, invalid_rows = extract_hashes(
            archive_path
        )

        # 3. Build staging database.

        build_database(
            shards,
            total_rows,
            invalid_rows,
            staging_dir,
        )

        # 4. Verify every shard and manifest.

        verify_database(staging_dir)

        # 5. Replace previous database.

        replace_database(staging_dir)

        print()
        print("=" * 60)
        print("IMPORT COMPLETED SUCCESSFULLY")
        print("=" * 60)

    except Exception:

        remove_path(staging_dir)

        raise

    finally:

        remove_path(temp_root)


if __name__ == "__main__":

    try:
        main()

    except KeyboardInterrupt:
        print("\nImport interrupted.")
        sys.exit(1)

    except Exception as error:
        print()
        print(f"IMPORT FAILED: {error}")
        sys.exit(1)
