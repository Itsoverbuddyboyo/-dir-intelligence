import json
import os
import re
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

API_URL = "https://mb-api.abuse.ch/api/v1/"
DATABASE = Path("hashes.json")

API_KEY = os.environ.get("MB_AUTH_KEY")

if not API_KEY:
    raise RuntimeError("MB_AUTH_KEY secret is missing!")

# Download the latest MalwareBazaar additions.
request = urllib.request.Request(
    API_URL,
    data=urllib.parse.urlencode({
        "query": "get_recent",
        "selector": "time"
    }).encode(),
    headers={
        "Auth-Key": API_KEY,
        "User-Agent": "DIR-Intelligence-Updater/1.0"
    }
)

with urllib.request.urlopen(request, timeout=60) as response:
    result = json.loads(response.read().decode("utf-8"))

status = result.get("query_status")

if status == "ok":
    records = result.get("data", [])
elif status == "no_results":
    records = []
else:
    raise RuntimeError(f"MalwareBazaar API error: {status}")

# Validate incoming SHA-256 hashes.
new_hashes = set()

for record in records:
    sha256 = record.get("sha256_hash", "")

    if isinstance(sha256, str) and re.fullmatch(
        r"[a-fA-F0-9]{64}", sha256
    ):
        new_hashes.add(sha256.lower())

# Load the existing database.
if DATABASE.exists():
    database = json.loads(DATABASE.read_text(encoding="utf-8"))

    if not isinstance(database, dict):
        raise RuntimeError("Invalid existing database!")

    existing = database.get("hashes", [])

    if not isinstance(existing, list):
        raise RuntimeError("Invalid hashes array!")

    if any(
        not isinstance(h, str)
        or not re.fullmatch(r"[a-fA-F0-9]{64}", h)
        for h in existing
    ):
        raise RuntimeError("Existing database contains invalid hashes!")

    hashes = {h.lower() for h in existing}
else:
    hashes = set()

# Merge new intelligence without deleting old entries.
before = len(hashes)
hashes.update(new_hashes)

# Generate the updated database.
output = {
    "version": 1,
    "source": "MalwareBazaar",
    "updated": datetime.now(timezone.utc).isoformat(),
    "hash_count": len(hashes),
    "hashes": sorted(hashes)
}

# Write atomically to avoid partially written databases.
temporary = DATABASE.with_suffix(".tmp")

temporary.write_text(
    json.dumps(output, separators=(",", ":")),
    encoding="utf-8"
)

temporary.replace(DATABASE)

print(f"New hashes: {len(hashes) - before}")
print(f"Total hashes: {len(hashes)}")
print("Database successfully updated.")
