
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

DOWNLOAD_ATTEMPTS = 8
CHUNK_SIZE = 256 * 1024
PROGRESS_INTERVAL = 8 * 1024 * 1024
RETRY_BASE_DELAY = 10
MAX_RETRY_DELAY = 90
MAX_INVALID_RATIO = 0.01
DOWNLOAD_TIMEOUT = 120

SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")
CONTENT_RANGE_PATTERN = re.compile(
    r"^bytes\s+(\d+)-(\d+)/(\d+|\*)$",
    re.IGNORECASE
)

SHARD_NAMES = [f"{i:x}.txt" for i in range(16)]


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
                name for name in archive.namelist()
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

    validator = None
    last_error = None
    last_progress = 0

    for attempt in range(1, DOWNLOAD_ATTEMPTS + 1):

        # Recover immediately if the previous attempt actually
        # completed the archive before encountering an error.

        if verify_zip(destination):
            print("Existing partial download is a valid ZIP.")
            print("ZIP download verified.")
            return

        offset = (
            destination.stat().st_size
            if destination.exists()
            else 0
        )

        headers = {
            "User-Agent": "DIR-Intelligence-Importer/2.0",
            "Accept": "application/zip, application/octet-stream, */*",
            "Accept-Encoding": "identity",
        }

        if offset > 0:
            headers["Range"] = f"bytes={offset}-"

            if validator:
                headers["If-Range"] = validator

        request = urllib.request.Request(
            EXPORT_URL,
            headers=headers,
            method="GET",
        )

        print()
        print(
            f"Download attempt {attempt}/{DOWNLOAD_ATTEMPTS}"
        )

        if offset:
            print(
                f"Resuming from {offset:,} bytes..."
            )
        else:
            print("Starting download...")

        response = None

        try:

            response = urllib.request.urlopen(
                request,
                timeout=DOWNLOAD_TIMEOUT,
            )

            status = response.status

            # ------------------------------------------------
            # HANDLE SERVER RESPONSE
            # ------------------------------------------------

            if status == 206:

                content_range = response.headers.get(
                    "Content-Range", ""
                )

                match = CONTENT_RANGE_PATTERN.fullmatch(
                    content_range.strip()
                )

                if not match:
                    raise RuntimeError(
                        "Server returned an invalid Content-Range."
                    )

                range_start = int(match.group(1))
                range_end = int(match.group(2))

                total_bytes = (
                    int(match.group(3))
                    if match.group(3) != "*"
                    else None
                )

                if range_start != offset:
                    raise RuntimeError(
                        "Server resumed from an unexpected byte "
                        f"position: {range_start:,}, expected "
                        f"{offset:,}."
                    )

                if range_end < range_start:
                    raise RuntimeError(
                        "Invalid Content-Range boundaries."
                    )

                if total_bytes is not None:
                    if range_end >= total_bytes:
                        raise RuntimeError(
                            "Invalid Content-Range total size."
                        )

                mode = "ab"

                print(
                    "Server supports resumable downloads."
                )

            elif status == 200:

                # Server ignored Range or does not support it.
                # Restart safely instead of appending a full ZIP
                # to an existing partial ZIP.

                if offset:
                    print(
                        "Server does not honor Range requests. "
                        "Restarting download from zero."
                    )

                offset = 0
                mode = "wb"

                content_length = response.headers.get(
                    "Content-Length"
                )

                total_bytes = (
                    int(content_length)
                    if content_length
                    else None
                )

            else:
                raise RuntimeError(
                    f"Unexpected HTTP status: {status}"
                )

            # ------------------------------------------------
            # REMEMBER DOWNLOAD VALIDATOR
            # ------------------------------------------------

            etag = response.headers.get("ETag")
            last_modified = response.headers.get(
                "Last-Modified"
            )

            if etag:
                validator = etag
            elif last_modified:
                validator = last_modified

            # ------------------------------------------------
            # DOWNLOAD STREAM
            # ------------------------------------------------

            downloaded = offset
            last_progress = downloaded

            expected_remaining = (
                total_bytes - offset
                if total_bytes is not None
                else None
            )

            with destination.open(mode) as output:

                while True:

                    try:
                        chunk = response.read(CHUNK_SIZE)

                    except http.client.IncompleteRead as error:

                        # Crucial: preserve bytes already received
                        # by urllib before attempting another request.

                        partial = error.partial

                        if partial:
                            output.write(partial)
                            downloaded += len(partial)

                        output.flush()

                        raise ConnectionError(
                            "Incomplete HTTP response. "
                            f"Preserved {len(partial):,} additional "
                            "bytes for resumption."
                        ) from error

                    if not chunk:
                        break

                    output.write(chunk)
                    downloaded += len(chunk)

                    if (
                        downloaded - last_progress
                        >= PROGRESS_INTERVAL
                    ):

                        if total_bytes:
                            percentage = (
                                downloaded / total_bytes
                            ) * 100

                            print(
                                f"Download progress: "
                                f"{downloaded:,} / "
                                f"{total_bytes:,} bytes "
                                f"({percentage:.1f}%)"
                            )

                        else:
                            print(
                                f"Downloaded: {downloaded:,} bytes"
                            )

                        last_progress = downloaded

                output.flush()
                os.fsync(output.fileno())

            # ------------------------------------------------
            # CHECK DOWNLOAD LENGTH
            # ------------------------------------------------

            if total_bytes is not None:

                actual_size = destination.stat().st_size

                if actual_size != total_bytes:

                    raise ConnectionError(
                        "Download size mismatch: "
                        f"received {actual_size:,} bytes, "
                        f"expected {total_bytes:,} bytes."
                    )

            print()
            print(
                f"Download finished: "
                f"{destination.stat().st_size:,} bytes."
            )

            # ------------------------------------------------
            # VERIFY ZIP
            # ------------------------------------------------

            if not verify_zip(destination):

                raise RuntimeError(
                    "Downloaded file failed ZIP validation."
                )

            print("ZIP integrity verified.")
            print("Download successful.")

            return

        except urllib.error.HTTPError as error:

            last_error = (
                f"HTTP {error.code}: {error.reason}"
            )

            # 416 can mean that the saved file already contains
            # the entire resource. Verify before discarding it.

            if error.code == 416 and verify_zip(destination):

                print(
                    "Server reports requested range unavailable, "
                    "but the existing archive is valid."
                )

                return

            # If the server refuses Range, discard the partial
            # file and allow the next attempt to start fresh.

            if error.code == 416:
                destination.unlink(missing_ok=True)
                validator = None

            print(f"Download failed: {last_error}")

        except (
            urllib.error.URLError,
            TimeoutError,
            ConnectionError,
            http.client.HTTPException,
            OSError,
            zipfile.BadZipFile,
            RuntimeError,
        ) as error:

            last_error = (
                f"{type(error).__name__}: {str(error)[:250]}"
            )

            print(f"Download failed: {last_error}")

        finally:

            if response is not None:
                response.close()

        if attempt == DOWNLOAD_ATTEMPTS:
            break

        # Keep the partial archive. The next request will attempt
        # to resume it using HTTP Range.

        remaining = (
            destination.stat().st_size
            if destination.exists()
            else 0
        )

        print(
            f"Preserved {remaining:,} bytes."
        )

        delay = min(
            RETRY_BASE_DELAY * attempt,
            MAX_RETRY_DELAY
        )

        print(
            f"Retrying in {delay} seconds..."
        )

        time.sleep(delay)

    raise RuntimeError(
        "Could not download a complete, valid export after "
        f"{DOWNLOAD_ATTEMPTS} attempts. "
        f"Last error: {last_error}. "
        "Check MalwareBazaar access and Range support."
    )


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

            text_file = io.TextIOWrapper(
                raw_file,
                encoding="utf-8-sig",
                errors="replace",
                newline="",
            )

            reader = csv.DictReader(text_file)

            if not reader.fieldnames:
                raise RuntimeError(
                    "The CSV has no header row."
                )

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

                value = (
                    row.get(hash_column) or ""
                ).strip()

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

        # 1. Download complete export.
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

        # 5. Safely replace existing database.
        backup_dir = temporary_root / "database-backup"

        if DATABASE_DIR.exists():
            DATABASE_DIR.rename(backup_dir)

        try:

            staging_dir.rename(DATABASE_DIR)

        except Exception:

            if (
                backup_dir.exists()
                and not DATABASE_DIR.exists()
            ):
                backup_dir.rename(DATABASE_DIR)

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
