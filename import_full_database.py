
import csv
import hashlib
import http.client
import io
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

RANGE_CHUNK_SIZE = 4 * 1024 * 1024  # 4 MiB
CHUNK_RETRIES = 8
CHUNK_READ_SIZE = 256 * 1024

RETRY_BASE_DELAY = 3
MAX_RETRY_DELAY = 20

MAX_INVALID_RATIO = 0.01
DOWNLOAD_TIMEOUT = 90

SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")

CONTENT_RANGE_PATTERN = re.compile(
    r"^bytes\s+(\d+)-(\d+)/(\d+|\*)$",
    re.IGNORECASE
)

SHARD_NAMES = [
    f"{character}.txt"
    for character in "0123456789abcdef"
]


# ============================================================
# ZIP VALIDATION
# ============================================================

def verify_zip(path: Path) -> bool:

    if not path.exists() or path.stat().st_size == 0:
        return False

    try:

        if not zipfile.is_zipfile(path):
            return False

        with zipfile.ZipFile(path, "r") as archive:

            csv_files = [
                name
                for name in archive.namelist()
                if name.lower().endswith(".csv")
            ]

            if len(csv_files) != 1:
                return False

            if archive.testzip() is not None:
                return False

        return True

    except (
        OSError,
        zipfile.BadZipFile,
        EOFError
    ):
        return False


# ============================================================
# DOWNLOAD
# ============================================================

def download_export(destination: Path) -> None:

    if not API_KEY:
        raise RuntimeError(
            "MB_AUTH_KEY is missing. "
            "Check your GitHub repository secret."
        )

    destination.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    offset = 0
    total_bytes = None
    validator = None

    print()
    print("Starting chunk-based MalwareBazaar download...")
    print(
        f"Chunk size: "
        f"{RANGE_CHUNK_SIZE // (1024 * 1024)} MiB"
    )

    with destination.open("wb") as output:

        while total_bytes is None or offset < total_bytes:

            requested_end = (
                offset + RANGE_CHUNK_SIZE - 1
            )

            chunk_data = None
            last_error = None

            for attempt in range(
                1,
                CHUNK_RETRIES + 1
            ):

                headers = {
                    "User-Agent": "DIR-Intelligence-Importer/3.0",
                    "Accept": (
                        "application/zip, "
                        "application/octet-stream, */*"
                    ),
                    "Accept-Encoding": "identity",
                    "Range": f"bytes={offset}-{requested_end}",
                }

                if validator:
                    headers["If-Range"] = validator

                request = urllib.request.Request(
                    EXPORT_URL,
                    headers=headers,
                    method="GET",
                )

                response = None

                try:

                    print(
                        f"\nRequesting bytes "
                        f"{offset:,}-{requested_end:,} "
                        f"(attempt {attempt}/{CHUNK_RETRIES})..."
                    )

                    response = urllib.request.urlopen(
                        request,
                        timeout=DOWNLOAD_TIMEOUT,
                    )

                    if response.status != 206:
                        raise RuntimeError(
                            f"Expected HTTP 206, received "
                            f"HTTP {response.status}. "
                            "The server did not honor the Range request."
                        )

                    content_range = response.headers.get(
                        "Content-Range",
                        ""
                    )

                    match = CONTENT_RANGE_PATTERN.fullmatch(
                        content_range.strip()
                    )

                    if not match:
                        raise RuntimeError(
                            f"Invalid Content-Range: "
                            f"{content_range!r}"
                        )

                    range_start = int(match.group(1))
                    range_end = int(match.group(2))

                    response_total = (
                        int(match.group(3))
                        if match.group(3) != "*"
                        else None
                    )

                    if response_total is None:
                        raise RuntimeError(
                            "Server did not provide "
                            "the total archive size."
                        )

                    if range_start != offset:
                        raise RuntimeError(
                            f"Wrong range start: {range_start:,}; "
                            f"expected {offset:,}."
                        )

                    if response_total <= offset:
                        raise RuntimeError(
                            "Invalid total archive size."
                        )

                    expected_end = min(
                        requested_end,
                        response_total - 1
                    )

                    if range_end != expected_end:
                        raise RuntimeError(
                            f"Wrong range end: {range_end:,}; "
                            f"expected {expected_end:,}."
                        )

                    if total_bytes is None:

                        total_bytes = response_total

                        print(
                            f"Archive size: {total_bytes:,} bytes "
                            f"({total_bytes / (1024 * 1024):.2f} MiB)"
                        )

                    elif response_total != total_bytes:
                        raise RuntimeError(
                            "Archive size changed between requests."
                        )

                    response_validator = (
                        response.headers.get("ETag")
                        or response.headers.get("Last-Modified")
                    )

                    if validator and response_validator:

                        if response_validator != validator:
                            raise RuntimeError(
                                "Archive validator changed "
                                "between chunks."
                            )

                    elif response_validator:
                        validator = response_validator

                    expected_length = (
                        range_end - range_start + 1
                    )

                    content_length = response.headers.get(
                        "Content-Length"
                    )

                    if content_length is not None:

                        if int(content_length) != expected_length:
                            raise ConnectionError(
                                "Incorrect Content-Length: "
                                f"{content_length}, expected "
                                f"{expected_length}."
                            )

                    data = bytearray()

                    while len(data) < expected_length:

                        remaining = (
                            expected_length - len(data)
                        )

                        try:

                            part = response.read(
                                min(
                                    CHUNK_READ_SIZE,
                                    remaining
                                )
                            )

                        except http.client.IncompleteRead as error:

                            if error.partial:
                                data.extend(error.partial)

                            raise ConnectionError(
                                "Incomplete chunk response: "
                                f"{len(data):,}/"
                                f"{expected_length:,} bytes."
                            ) from error

                        if not part:
                            raise ConnectionError(
                                "Connection ended prematurely: "
                                f"{len(data):,}/"
                                f"{expected_length:,} bytes."
                            )

                        data.extend(part)

                    if len(data) != expected_length:
                        raise ConnectionError(
                            "Chunk size mismatch."
                        )

                    chunk_data = data
                    break

                except urllib.error.HTTPError as error:

                    if error.code in (
                        400,
                        401,
                        403,
                        404
                    ):
                        raise RuntimeError(
                            f"MalwareBazaar rejected the request: "
                            f"HTTP {error.code}."
                        ) from error

                    last_error = (
                        f"HTTP {error.code}: {error.reason}"
                    )

                except (
                    urllib.error.URLError,
                    TimeoutError,
                    ConnectionError,
                    http.client.HTTPException,
                    OSError,
                    RuntimeError,
                    ValueError,
                ) as error:

                    last_error = (
                        f"{type(error).__name__}: "
                        f"{str(error)[:250]}"
                    )

                finally:

                    if response is not None:
                        response.close()

                print(f"Chunk failed: {last_error}")

                if attempt < CHUNK_RETRIES:

                    delay = min(
                        RETRY_BASE_DELAY * attempt,
                        MAX_RETRY_DELAY
                    )

                    print(
                        f"Retrying this chunk in "
                        f"{delay} seconds..."
                    )

                    time.sleep(delay)

            if chunk_data is None:
                raise RuntimeError(
                    f"Failed to download chunk at byte "
                    f"{offset:,} after {CHUNK_RETRIES} attempts. "
                    f"Last error: {last_error}"
                )

            output.write(chunk_data)
            output.flush()

            os.fsync(output.fileno())

            offset += len(chunk_data)

            percentage = (
                offset / total_bytes * 100
            )

            print(
                f"Download progress: {offset:,} / "
                f"{total_bytes:,} bytes ({percentage:.1f}%)"
            )

    actual_size = destination.stat().st_size

    if actual_size != total_bytes:
        raise RuntimeError(
            f"Final download size mismatch: "
            f"{actual_size:,} != {total_bytes:,}."
        )

    print()
    print(
        f"Download finished: {actual_size:,} bytes."
    )

    if not verify_zip(destination):
        raise RuntimeError(
            "Downloaded archive failed ZIP integrity verification."
        )

    print("ZIP integrity verified.")
    print("Download successful.")


# ============================================================
# EXTRACT HASHES
# ============================================================

def extract_hashes(archive_path: Path):

    shards = {
        f"{character}.txt": set()
        for character in "0123456789abcdef"
    }

    invalid_rows = 0
    total_rows = 0

    print()
    print("Extracting SHA-256 hashes...")

    with zipfile.ZipFile(
        archive_path,
        "r"
    ) as archive:

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

        with archive.open(
            csv_name,
            "r"
        ) as raw_file:

            text_file = io.TextIOWrapper(
                raw_file,
                encoding="utf-8-sig",
                errors="replace",
                newline="",
            )

            csv_reader = csv.reader(text_file)

            # ------------------------------------------------
            # FIND THE REAL HEADER
            # MalwareBazaar exports can contain a banner
            # before the actual CSV header.
            # ------------------------------------------------

            header = None
            hash_column = None

            for row in csv_reader:

                cleaned = [
                    value.strip().lstrip("#").strip()
                    for value in row
                ]

                normalized = {
                    value.lower(): value
                    for value in cleaned
                    if value
                }

                candidate = (
                    normalized.get("sha256_hash")
                    or normalized.get("sha256")
                )

                if candidate:

                    header = cleaned
                    hash_column = candidate

                    break

            if header is None:
                raise RuntimeError(
                    "Could not find the SHA-256 header "
                    "after scanning the CSV preamble."
                )

            print(
                "Found CSV header successfully."
            )

            print(
                f"SHA-256 column: {hash_column}"
            )

            print(
                f"Columns found: {len(header)}"
            )

            # Continue reading immediately after the header.
            reader = csv.DictReader(
                text_file,
                fieldnames=header,
            )

            for row in reader:

                value = (
                    row.get(hash_column) or ""
                ).strip()

                if not value:
                    continue

                total_rows += 1

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

    unique_count = sum(
        len(values)
        for values in shards.values()
    )

    if unique_count == 0:
        raise RuntimeError(
            "No valid SHA-256 hashes were found."
        )

    invalid_ratio = (
        invalid_rows / total_rows
        if total_rows
        else 1.0
    )

    if invalid_ratio > MAX_INVALID_RATIO:
        raise RuntimeError(
            f"Too many invalid rows: "
            f"{invalid_rows:,} out of {total_rows:,}."
        )

    print()
    print(
        f"Rows processed: {total_rows:,}"
    )

    print(
        f"Invalid rows: {invalid_rows:,}"
    )

    print(
        f"Unique SHA-256 hashes: {unique_count:,}"
    )

    return (
        shards,
        unique_count,
        total_rows,
        invalid_rows
    )


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

    output_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    shard_metadata = {}

    print()
    print("Building 16 database shards...")

    for shard_name in SHARD_NAMES:

        hashes = sorted(
            shards[shard_name]
        )

        shard_path = (
            output_dir / shard_name
        )

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
            "sha256": hashlib.sha256(
                encoded
            ).hexdigest(),
        }

        print(
            f"{shard_name}: "
            f"{len(hashes):,} hashes, "
            f"{len(encoded):,} bytes"
        )

    manifest = {
        "version": 1,
        "source": "MalwareBazaar",
        "updated": datetime.now(
            timezone.utc
        ).isoformat(),
        "hash_count": unique_count,
        "rows_processed": total_rows,
        "invalid_rows": invalid_rows,
        "shards": shard_metadata,
    }

    manifest_path = (
        output_dir / "manifest.json"
    )

    manifest_path.write_text(
        json.dumps(
            manifest,
            indent=2
        ) + "\n",
        encoding="utf-8",
    )

    print()
    print("Database files generated.")


# ============================================================
# VERIFY DATABASE
# ============================================================

def verify_database(directory: Path) -> None:

    manifest_path = (
        directory / "manifest.json"
    )

    if not manifest_path.exists():
        raise RuntimeError(
            "Manifest is missing."
        )

    manifest = json.loads(
        manifest_path.read_text(
            encoding="utf-8"
        )
    )

    if len(manifest["shards"]) != 16:
        raise RuntimeError(
            "Expected exactly 16 shards."
        )

    total_hashes = 0
    total_size = 0

    for shard_name in SHARD_NAMES:

        path = directory / shard_name

        if not path.exists():
            raise RuntimeError(
                f"Missing shard: {shard_name}"
            )

        info = manifest["shards"].get(
            shard_name
        )

        if info is None:
            raise RuntimeError(
                f"Missing manifest entry: {shard_name}"
            )

        content = path.read_bytes()

        if len(content) != info["size"]:
            raise RuntimeError(
                f"Incorrect file size: {shard_name}"
            )

        actual_digest = hashlib.sha256(
            content
        ).hexdigest()

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
        raise RuntimeError(
            "Total hash count does not match manifest."
        )

    if total_size >= 900 * 1024 * 1024:
        raise RuntimeError(
            "Database exceeds the configured 900 MB safety limit."
        )

    print()
    print("DATABASE VERIFIED")

    print(
        f"Total hashes: {total_hashes:,}"
    )

    print(
        f"Total shard size: {total_size:,} bytes"
    )


# ============================================================
# MAIN
# ============================================================

def main():

    if not API_KEY:
        raise RuntimeError(
            "MB_AUTH_KEY is not configured in the environment."
        )

    temporary_root = Path(
        tempfile.mkdtemp(
            prefix="dir-import-"
        )
    )

    archive_path = (
        temporary_root / "full.csv.zip"
    )

    staging_dir = (
        temporary_root / "database"
    )

    try:

        # 1. Download the complete export.
        download_export(archive_path)

        # 2. Extract SHA-256 hashes.
        (
            shards,
            unique_count,
            total_rows,
            invalid_rows
        ) = extract_hashes(archive_path)

        # 3. Build the new database.
        build_database(
            shards,
            unique_count,
            total_rows,
            invalid_rows,
            staging_dir,
        )

        # 4. Verify every shard and checksum.
        verify_database(staging_dir)

        # 5. Safely replace the existing database.
        backup_dir = (
            temporary_root / "database-backup"
        )

        if DATABASE_DIR.exists():
            DATABASE_DIR.rename(backup_dir)

        try:

            staging_dir.rename(
                DATABASE_DIR
            )

        except Exception:

            if (
                backup_dir.exists()
                and not DATABASE_DIR.exists()
            ):
                backup_dir.rename(
                    DATABASE_DIR
                )

            raise

        print()
        print(
            "Full database import completed successfully."
        )

    finally:

        shutil.rmtree(
            temporary_root,
            ignore_errors=True
        )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    try:

        main()

    except Exception as error:

        print()
        print(f"IMPORT FAILED: {error}")

        sys.exit(1)
