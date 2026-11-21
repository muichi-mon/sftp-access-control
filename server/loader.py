import base64
import csv
import json
import logging
from pathlib import Path

log = logging.getLogger("sftp.loader")

DATA_DIR = Path(__file__).parent / "data"

class DataError(Exception):
    """A data file is missing or has something wrong in it."""

def read_json(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))

def read_csv(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    return [{key.strip(): value.strip() for key, value in row.items()} for row in rows]

def clean_prefix(prefix):
    if not prefix.startswith("/"):
        raise DataError(f"path {prefix!r} must start with '/'")
    return prefix.rstrip("/") or "/"

def load_data(data_dir=DATA_DIR):
    d = Path(data_dir)
    name = ""

    try:
        name = "users.json"
        users = {}
        for u in read_json(d / name):
            users[u["username"]] = {
                "salt": base64.b64decode(u["salt"], validate=True),
                "password_hash": base64.b64decode(u["password_hash"], validate=True),
                "n": int(u["n"]), "r": int(u["r"]), "p": int(u["p"]), "dklen": int(u["dklen"]),
            }
        if not users:
            raise DataError("file has no entries")
        log.info("loaded %s", name)

        name = "user_roles.json"
        user_roles = read_json(d / name)
        log.info("loaded %s", name)
        name = "role_perms.csv"
        role_perms = {}
        for row in read_csv(d / name):
            role = row.pop("role")
            prefix = clean_prefix(row.pop("prefix"))
            actions = set()
            for action, value in row.items():
                if value not in ("", "y"):
                    raise DataError(f"{action} of {role} on {prefix} must be 'y' or empty, not {value!r}")
                if value == "y":
                    actions.add(action)
            if role not in role_perms:
                role_perms[role] = {}
            if prefix in role_perms[role]:
                raise DataError(f"{role} on {prefix} appears twice")
            role_perms[role][prefix] = actions
        if not role_perms:
            raise DataError("file has no entries")
        log.info("loaded %s", name)

        name = "mac_labels.json"
        mac = read_json(d / name)
        mac["labels"] = {clean_prefix(p): level for p, level in mac["labels"].items()}
        for level in list(mac["labels"].values()) + list(mac["users"].values()):
            if level not in mac["levels"]:
                raise DataError(f"{level!r} is not one of the levels")
        for user in mac["users"]:
            if user not in users:
                raise DataError(f"unknown user {user!r}")
        log.info("loaded %s", name)

        name = "dac_owners.csv"
        dac = {}
        for row in read_csv(d / name):
            if row["owner"] not in users:
                raise DataError(f"owner {row['owner']!r} is not a known user")
            dac[clean_prefix(row["prefix"])] = {
                "owner": row["owner"],
                "group": row["group"],
                "dir_mode": int(row["dir_mode"], 8),
                "file_mode": int(row["file_mode"], 8),
            }
        if not dac:
            raise DataError("file has no entries")
        log.info("loaded %s", name)

        name = "user_roles.json"
        for user, roles in user_roles.items():
            if user not in users:
                raise DataError(f"unknown user {user!r}")
            for role in roles:
                if role not in role_perms:
                    raise DataError(f"{user!r} has role {role!r}, which is not in role_perms.csv")

    except FileNotFoundError:
        raise DataError(f"{name}: file not found in {d}") from None
    except DataError as e:
        raise DataError(f"{name}: {e}") from None
    except (KeyError, TypeError, ValueError, AttributeError, csv.Error) as e:
        raise DataError(f"{name}: file is malformed ({type(e).__name__}: {e})") from None

    return {"users": users, "user_roles": user_roles, "role_perms": role_perms, "mac": mac, "dac": dac}