import base64
import getpass
import hashlib
import hmac
import json
import os
import sys
import time
import audit

N, R, P, DKLEN = 16384, 8, 1, 32
maxem = 64 * 1024 * 1024  
min_length = 8
max_fails = 5
lock_seconds = 60

_failed = {}                
_locked_until = {}

_dummy = {"salt": bytes(16), "n": N, "r": R, "p": P, "dklen": DKLEN}

def _scrypt(password, params):
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=params["salt"], n=params["n"], r=params["r"], p=params["p"],
        dklen=params["dklen"], maxmem=maxem,
    )

def make_user(username, password):
    if len(password) < min_length:
        raise ValueError(f"password must be at least {min_length} characters")
    params = {"salt": os.urandom(16), "n": N, "r": R, "p": P, "dklen": DKLEN}
    digest = _scrypt(password, params)
    return {
        "username": username,
        "salt": base64.b64encode(params["salt"]).decode(),
        "password_hash": base64.b64encode(digest).decode(),
        "n": N, "r": R, "p": P, "dklen": DKLEN,
    }

def check_password(users, username, password):
    user = users.get(username)

    if user and time.monotonic() < _locked_until.get(username, 0):
        audit.log(username, "login", None, False, "account locked")
        return False

    candidate = _scrypt(password, user or _dummy)
    if user and hmac.compare_digest(candidate, user["password_hash"]):
        _failed.pop(username, None)
        audit.log(username, "login", None, True, "ok")
        return True

    if not user:
        audit.log(username, "login", None, False, "unknown user")
        return False

    _failed[username] = _failed.get(username, 0) + 1
    reason = "wrong password"
    if _failed[username] >= max_fails:
        _locked_until[username] = time.monotonic() + lock_seconds
        _failed[username] = 0
        reason = f"wrong password, account locked for {lock_seconds}s"
    audit.log(username, "login", None, False, reason)
    return False

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python server/auth.py <username>")
    pw = getpass.getpass("Password: ")
    if pw != getpass.getpass("Repeat password: "):
        sys.exit("The two passwords are different.")
    try:
        print(json.dumps(make_user(sys.argv[1], pw), indent=2))
    except ValueError as e:
        sys.exit(str(e))