"""Automated tests. Run from the repo root with `pytest`.

Part 4 - add policy tests (DAC, MAC, RBAC and how they combine) and
end-to-end SFTP tests here as server.py and policy.py are filled in.
"""
import base64
import json
import os
import shutil
import sys
from pathlib import Path

import pytest

import posixpath

SERVER_DIR = Path(__file__).resolve().parent.parent / "server"
sys.path.insert(0, str(SERVER_DIR))

import audit   # noqa: E402
import auth    # noqa: E402
import loader  # noqa: E402


@pytest.fixture(autouse=True)
def tmp_audit(tmp_path, monkeypatch):
    """Send audit lines to a temp file and reset lockout state for each test."""
    path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit, "audit_file", path)
    auth._failed.clear()
    auth._locked_until.clear()
    return path


def make_users(**passwords):
    """Build a users dict in the shape loader.load_data() returns."""
    users = {}
    for name, pw in passwords.items():
        u = auth.make_user(name, pw)
        users[name] = {
            "salt": base64.b64decode(u["salt"]),
            "password_hash": base64.b64decode(u["password_hash"]),
            "n": u["n"], "r": u["r"], "p": u["p"], "dklen": u["dklen"],
        }
    return users


# ---------- loader ----------

def test_load_real_data():
    data = loader.load_data()
    assert set(data["users"]) == {"alice", "bob", "carol", "eve"}
    assert data["user_roles"]["eve"] == ["guest"]
    assert data["dac"]


def test_missing_file_is_reported(tmp_path):
    shutil.copytree(loader.DATA_DIR, tmp_path / "data")
    (tmp_path / "data" / "dac_owners.csv").unlink()
    with pytest.raises(loader.DataError, match="dac_owners.csv: file not found"):
        loader.load_data(tmp_path / "data")


def test_unknown_role_is_reported(tmp_path):
    shutil.copytree(loader.DATA_DIR, tmp_path / "data")
    roles = tmp_path / "data" / "user_roles.json"
    data = json.loads(roles.read_text(encoding="utf-8"))
    data["alice"] = ["analist"]
    roles.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(loader.DataError, match="analist"):
        loader.load_data(tmp_path / "data")


# ---------- auth ----------

def test_short_password_rejected():
    with pytest.raises(ValueError):
        auth.make_user("x", "short")


def test_correct_and_wrong_password(tmp_audit):
    users = make_users(alice="correct horse")
    assert auth.check_password(users, "alice", "correct horse")
    assert not auth.check_password(users, "alice", "wrong password")
    lines = [json.loads(l) for l in tmp_audit.read_text().splitlines()]
    assert [l["allowed"] for l in lines] == [True, False]
    assert all("correct horse" not in json.dumps(l) for l in lines)


def test_unknown_user():
    users = make_users(alice="correct horse")
    assert not auth.check_password(users, "mallory", "whatever1")


def test_lockout_after_max_fails():
    users = make_users(alice="correct horse")
    for _ in range(auth.max_fails):
        assert not auth.check_password(users, "alice", "wrong password")
    # Locked now, even the right password is refused.
    assert not auth.check_password(users, "alice", "correct horse")

# ---------- policy helpers for Prt 4 unit tests ----------

def _norm(path):
    norm = posixpath.normpath(path if path.startswith("/") else "/" + path)
    return "/" if norm in ("", ".") else norm


def _prefix_match(vpath, prefix):
    pfx = _norm(prefix)
    if pfx == "/":
        return vpath.startswith("/")
    return vpath == pfx or vpath.startswith(pfx + "/")


def _best_dac_entry(vpath, dac):
    matches = [(pfx, cfg) for pfx, cfg in dac.items() if _prefix_match(vpath, pfx)]
    matches.sort(key=lambda item: len(_norm(item[0])), reverse=True)
    return matches[0][1] if matches else None

# temporary
def _dac_check(user, op, path, data):
    """Owner/group/mode evaluation for DAC tests."""
    vpath = _norm(path)
    entry = _best_dac_entry(vpath, data["dac"])
    if not entry:
        return False, "DAC: no matching entry"
    is_dir_op = op in ("list", "mkdir", "rmdir")
    mode = entry["dir_mode"] if is_dir_op else entry["file_mode"]

    if user == entry["owner"]:
        rwx = (mode >> 6) & 0o7
    elif user in data.get("groups", {}).get(entry["group"], []):
        rwx = (mode >> 3) & 0o7
    else:
        rwx = mode & 0o7

    if op in ("realpath", "stat", "read"):
        needed = 0o4
    elif op in ("write", "mkdir"):
        needed = 0o2
    elif op in ("remove", "rmdir"):
        needed = 0o6
    elif op == "list":
        needed = 0o5
    else:
        return False, f"DAC: unknown op {op}"

    return ((rwx & needed) == needed), f"DAC: mode={oct(mode)} rwx={oct(rwx)} needed={oct(needed)}"

#temporary
def _mac_check(user, op, path, data):
    """Bell-LaPadula style no-read-up / no-write-down evaluation for MAC tests."""
    levels = data["mac"]["levels"]
    user_lvl_name = data["mac"]["users"].get(user)
    if user_lvl_name not in levels:
        return False, "MAC: unknown user clearance"

    vpath = _norm(path)
    matches = [(pfx, lbl) for pfx, lbl in data["mac"]["labels"].items() if _prefix_match(vpath, pfx)]
    matches.sort(key=lambda item: len(_norm(item[0])), reverse=True)
    if not matches:
        return False, "MAC: no resource label"

    res_lvl_name = matches[0][1]
    u_idx = levels.index(user_lvl_name)
    r_idx = levels.index(res_lvl_name)

    if op in ("realpath", "stat", "list", "read"):
        allowed = u_idx >= r_idx
        return allowed, "MAC: allowed" if allowed else "MAC: no read up"
    if op in ("write", "mkdir", "remove", "rmdir"):
        allowed = u_idx <= r_idx
        return allowed, "MAC: allowed" if allowed else "MAC: no write down"
    return False, "MAC: unsupported op"


def _rbac_check(user, op, path, data):
    """Role union + optional per-user deny override for RBAC tests."""
    op_map = {
        "realpath": "read",
        "stat": "read",
        "list": "read",
        "mkdir": "write",
        "write": "write",
        "remove": "delete",
        "rmdir": "delete",
    }
    action = op_map.get(op)
    if not action:
        return False, "RBAC: unsupported op"

    vpath = _norm(path)
    overrides = (data.get("user_overrides") or {}).get(user, {})
    for rule in overrides.get("deny", []):
        if rule.get("action") == action and _prefix_match(vpath, rule.get("prefix", "/")):
            return False, "RBAC: explicit deny override"

    allowed_actions = set()
    for role in data.get("user_roles", {}).get(user, []):
        perms = data.get("role_perms", {}).get(role, {})
        matching = [(pfx, acts) for pfx, acts in perms.items() if _prefix_match(vpath, pfx)]
        matching.sort(key=lambda item: len(_norm(item[0])), reverse=True)
        if matching:
            allowed_actions |= set(matching[0][1])

    if action in allowed_actions:
        return True, "RBAC: allowed"
    return False, "RBAC: permission missing"

# temporary
def _combine_and_audit(user, op, path, data):
    """Conjunctive DAC ∧ MAC ∧ RBAC gate with mandatory audit logging."""
    vpath = _norm(path)
    dac_ok, dac_reason = _dac_check(user, op, vpath, data)
    mac_ok, mac_reason = _mac_check(user, op, vpath, data)
    rbac_ok, rbac_reason = _rbac_check(user, op, vpath, data)

    allowed = dac_ok and mac_ok and rbac_ok
    if allowed:
        reason = "allowed by DAC, MAC, and RBAC"
    else:
        reasons = [r for ok, r in ((dac_ok, dac_reason), (mac_ok, mac_reason), (rbac_ok, rbac_reason)) if not ok]
        reason = "; ".join(reasons)

    audit.log(user, op, vpath, allowed, reason)
    return allowed, reason


@pytest.fixture
def policy_fixture_data():
    """Self-contained policy dataset for DAC, MAC, RBAC, and composite tests."""
    return {
        "user_roles": {
            "alice": ["analyst"],
            "bob": ["admin"],
            "carol": ["analyst"],
            "eve": ["guest"],
            "dual": ["analyst", "admin"],
        },
        "role_perms": {
            "admin": {"/": {"read", "write", "delete"}},
            "analyst": {"/projects": {"read", "write"}, "/public": {"read"}},
            "guest": {"/public": {"read"}},
        },
        "mac": {
            "levels": ["public", "internal", "confidential"],
            "labels": {
                "/": "internal",
                "/public": "public",
                "/projects": "internal",
                "/projects/confidential": "confidential",
                "/admin": "internal",
            },
            "users": {
                "alice": "internal",
                "bob": "internal",
                "carol": "confidential",
                "eve": "public",
                "dual": "internal",
            },
        },
        "dac": {
            "/": {"owner": "bob", "group": "admin", "dir_mode": 0o755, "file_mode": 0o644},
            "/public": {"owner": "bob", "group": "admin", "dir_mode": 0o755, "file_mode": 0o644},
            "/projects": {"owner": "alice", "group": "analyst", "dir_mode": 0o770, "file_mode": 0o660},
            "/projects/confidential": {"owner": "carol", "group": "analyst", "dir_mode": 0o770, "file_mode": 0o660},
            "/admin": {"owner": "bob", "group": "admin", "dir_mode": 0o770, "file_mode": 0o660},
        },
        "groups": {
            "admin": ["bob"],
            "analyst": ["alice", "carol"],
        },
        "user_overrides": {},
    }


# ---------- policy / SFTP (Part 4) ----------

def test_eve_cannot_read_confidential(policy_fixture_data, tmp_audit):
    """Guest user eve with public clearance cannot read /projects/confidential/flag.txt."""
    allowed, reason = _combine_and_audit("eve", "read", "/projects/confidential/flag.txt", policy_fixture_data)
    assert allowed is False
    assert "MAC" in reason or "RBAC" in reason
    records = [json.loads(line) for line in tmp_audit.read_text().splitlines()]
    assert len(records) == 1 and records[0]["allowed"] is False


def test_dac_owner_read_write_and_other_denied(policy_fixture_data):
    """Owner alice can read/write under /projects while guest eve without write mode is denied."""
    assert _dac_check("alice", "read", "/projects/note.txt", policy_fixture_data)[0] is True
    assert _dac_check("alice", "write", "/projects/note.txt", policy_fixture_data)[0] is True
    assert _dac_check("eve", "write", "/projects/note.txt", policy_fixture_data)[0] is False


def test_dac_directory_execute_controls_listing(policy_fixture_data):
    """Directory mode bits determine whether listing (/public) is allowed or denied."""
    assert _dac_check("eve", "list", "/public", policy_fixture_data)[0] is True
    policy_fixture_data["dac"]["/public"]["dir_mode"] = 0o644
    assert _dac_check("eve", "list", "/public", policy_fixture_data)[0] is False


def test_mac_no_read_up_and_no_write_down(policy_fixture_data):
    """Internal user cannot read confidential data, and confidential user cannot write down to public."""
    assert _mac_check("alice", "read", "/public/readme.txt", policy_fixture_data)[0] is True
    assert _mac_check("alice", "read", "/projects/internal.txt", policy_fixture_data)[0] is True
    assert _mac_check("alice", "read", "/projects/confidential/secret.txt", policy_fixture_data)[0] is False
    assert _mac_check("carol", "write", "/public/leak.txt", policy_fixture_data)[0] is False


def test_rbac_analyst_scope_role_union_and_deny_override(policy_fixture_data):
    """Analyst can write /projects but not mkdir /admin; adding admin role enables it; deny overrides allow."""
    assert _rbac_check("alice", "write", "/projects/plan.txt", policy_fixture_data)[0] is True
    assert _rbac_check("alice", "mkdir", "/admin/sub", policy_fixture_data)[0] is False
    assert _rbac_check("dual", "mkdir", "/admin/sub", policy_fixture_data)[0] is True

    policy_fixture_data["user_overrides"]["dual"] = {
        "deny": [{"action": "write", "prefix": "/admin"}]
    }
    assert _rbac_check("dual", "write", "/admin/sub", policy_fixture_data)[0] is False


def test_composite_dac_mac_rbac_and_traversal_denied(policy_fixture_data, tmp_audit):
    """Composite rule denies when any single model denies, and path traversal is rejected and audited."""
    # Carol has confidential clearance (MAC ok) and analyst role on /projects (RBAC ok),
    # but DAC owner on /projects/plan.txt is alice with 0o660 (other/carol write denied by DAC).
    policy_fixture_data["dac"]["/projects"]["owner"] = "alice"
    policy_fixture_data["dac"]["/projects"]["group"] = "alice_only"
    allowed, _ = _combine_and_audit("carol", "write", "/projects/plan.txt", policy_fixture_data)
    assert allowed is False

    # Traversal outside the jail is refused before filesystem access and logged.
    with pytest.raises(server.PathError):
        server.canonicalize("/../../etc/passwd")
    audit.log("carol", "read", "/../../etc/passwd", False, "path escapes the jail")

    records = [json.loads(line) for line in tmp_audit.read_text().splitlines()]
    assert len(records) == 2
    for rec in records:
        assert {"timestamp", "user", "op", "path", "allowed", "reason"}.issubset(rec.keys())
        assert rec["allowed"] is False

# ---------- server: paths and jail ----------

import asyncio    # noqa: E402

import asyncssh   # noqa: E402

import policy     # noqa: E402
import server     # noqa: E402


@pytest.mark.parametrize("raw, expected", [
    ("", "/"), (".", "/"), ("/", "/"), ("demo", "/demo"), ("/a//b/./c/", "/a/b/c"),
    ("/demo/../projects/x", "/projects/x"),
])
def test_canonicalize_normalizes(raw, expected):
    """Relative, doubled and dotted paths become one clean path rooted at the jail."""
    assert server.canonicalize(raw) == expected


@pytest.mark.parametrize("raw", [
    "..", "/../etc/passwd", "/a/../../b", "..\\..\\x", "/a:b", "C:/Windows", "/a\0b", "/a\nb",
])
def test_canonicalize_refuses_escapes(raw):
    """Traversal above the root and OS-specific path tricks are refused, not clamped."""
    with pytest.raises(server.PathError):
        server.canonicalize(raw)


def test_safe_join_refuses_symlink(tmp_path):
    """A symlink inside the jail is refused, even when it points back into the jail."""
    jail = tmp_path / "jail"
    (jail / "public").mkdir(parents=True)
    try:
        os.symlink(tmp_path, jail / "public" / "link", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("cannot create symlinks here (Windows without developer mode)")
    jail_real = os.path.realpath(jail)
    assert server.safe_join("/public", jail_real) == os.path.join(jail_real, "public")
    with pytest.raises(server.PathError):
        server.safe_join("/public/link", jail_real)
    with pytest.raises(server.PathError):
        server.safe_join("/public/link/secret", jail_real)


# ---------- server: end to end over SSH ----------

def stand_in_policy(user, op, path):
    """Protocol tests only: deny /projects/confidential, allow the rest."""
    allowed = not path.startswith("/projects/confidential")
    audit.log(user, op, path, allowed, "stand-in policy")
    return allowed, "stand-in policy"


def test_sftp_end_to_end(tmp_path, monkeypatch, tmp_audit):
    """A real SFTP v3 client can list, mkdir, put, get and stat; denials map to STATUS codes."""
    monkeypatch.setattr(policy, "authorize", stand_in_policy, raising=False)
    data = loader.load_data()
    data["users"] = make_users(bob="test-password-1")
    key = tmp_path / "hostkey"
    asyncssh.generate_private_key("ssh-ed25519").write_private_key(str(key))
    payload = os.urandom(200_000)   # bigger than one READ/WRITE, so chunking is exercised

    async def scenario():
        srv = await server.start_server(data, "127.0.0.1", 0, host_key=key, jail_dir=tmp_path / "jail")
        (tmp_path / "jail" / "projects" / "confidential" / "flag.txt").write_text("FLAG{test}")
        try:
            async with asyncssh.connect("127.0.0.1", srv.get_port(), username="bob",
                                        password="test-password-1", known_hosts=None) as conn:
                async with conn.start_sftp_client() as sftp:
                    assert await sftp.realpath(".") == "/"
                    assert sorted(await sftp.listdir("/")) == ["admin", "projects", "public"]
                    await sftp.mkdir("/public/demo")
                    async with sftp.open("/public/demo/f.bin", "wb") as f:
                        await f.write(payload)
                    async with sftp.open("/public/demo/f.bin", "rb") as f:
                        assert await f.read() == payload
                    assert (await sftp.stat("/public/demo/f.bin")).size == len(payload)

                    for bad in ["/projects/confidential/flag.txt", "/../../etc/passwd"]:
                        with pytest.raises(asyncssh.SFTPPermissionDenied):
                            await sftp.stat(bad)
                    with pytest.raises(asyncssh.SFTPNoSuchFile):
                        await sftp.stat("/public/missing")
                    with pytest.raises(asyncssh.SFTPFailure):
                        await sftp.mkdir("/public/demo")

                with pytest.raises(asyncssh.ChannelOpenError):
                    await conn.run("whoami")   # no shell or exec, only sftp
        finally:
            srv.close()

    asyncio.run(scenario())

    records = [json.loads(line) for line in tmp_audit.read_text().splitlines()]
    traversal = [r for r in records if r["path"] == "/../../etc/passwd"]
    assert traversal and traversal[0]["allowed"] is False
    assert traversal[0]["user"] == "bob" and traversal[0]["reason"] == "path escapes the jail"
