import json
from datetime import datetime, timezone
from pathlib import Path

audit_file = Path(__file__).parent / "audit.jsonl"

def log(user, op, path, allowed, reason):
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "user": str(user)[:100], 
        "op": op,
        "path": path,
        "allowed": allowed,
        "reason": reason,
    }
    with open(audit_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")