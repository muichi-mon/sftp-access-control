"""Automated tests. Run from the repo root with `pytest`.

Part 4 - add policy tests (DAC, MAC, RBAC and how they combine) and
end-to-end SFTP tests here as server.py and policy.py are filled in.
"""
import asyncio
import base64
import json
import os
import posixpath
import shutil
import sys
from pathlib import Path

import asyncssh
import pytest

SERVER_DIR = Path(__file__).resolve().parent.parent / "server"
sys.path.insert(0, str(SERVER_DIR))

import audit   # noqa: E402
import auth    # noqa: E402
import loader  # noqa: E402
import policy  # noqa: E402
import server  # noqa: E402


@pytest.fixture(autouse=True)
def tmp_audit(tmp_path, monkeypatch):
    """Send audit lines to a temp file and reset lockout state for each test."""
    path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit, "audit_file", path)
    auth._failed.clear()
    auth._locked_until.clear()
    policy.init(None)
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
    """Real policy and user data files load cleanly with expected users and roles."""
    data = loader.load_data()
    assert set(data["users"]) == {"alice", "bob", "carol", "eve"}
    assert data["user_roles"]["eve"] == ["guest"]
    assert data["dac"]


def test_missing_file_is_reported(tmp_path):
    """Missing required data file raises DataError with the missing filename."""
    shutil.copytree(loader.DATA_DIR, tmp_path / "data")
    (tmp_path / "data" / "dac_owners.csv").unlink()
    with pytest.raises(loader.DataError, match="dac_owners.csv: file not found"):
        loader.load_data(tmp_path / "data")


def test_unknown_role_is_reported(tmp_path):
    """Role assigned in user_roles.json that is missing from role_perms.csv raises DataError."""
    shutil.copytree(loader.DATA_DIR, tmp_path / "data")
    roles = tmp_path / "data" / "user_roles.json"
    data = json.loads(roles.read_text(encoding="utf-8"))
    data["alice"] = ["analist"]
    roles.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(loader.DataError, match="analist"):
        loader.load_data(tmp_path / "data")


# ---------- auth ----------

def test_short_password_rejected():
    """Passwords shorter than the minimum policy length are rejected."""
    with pytest.raises(ValueError):
        auth.make_user("x", "short")


def test_correct_and_wrong_password(tmp_audit):
    """Valid password succeeds, wrong password fails, and neither logs plaintext secrets."""
    users = make_users(alice="correct horse")
    assert auth.check_password(users, "alice", "correct horse")
    assert not auth.check_password(users, "alice", "wrong password")
    lines = [json.loads(line) for line in tmp_audit.read_text().splitlines()]
    assert [line["allowed"] for line in lines] == [True, False]
    assert all("correct horse" not in json.dumps(line) for line in lines)


def test_unknown_user():
    """Authentication returns False for a username not present in users."""
    users = make_users(alice="correct horse")
    assert not auth.check_password(users, "mallory", "whatever1")


def test_lockout_after_max_fails():
    """Repeated failed logins lock the account even when the right password is supplied."""
    users = make_users(alice="correct horse")
    for _ in range(auth.max_fails):
        assert not auth.check_password(users, "alice", "wrong password")
    assert not auth.check_password(users, "alice", "correct horse")


# ---------- policy helpers for Prt 4 unit tests ----------

def _norm(path):
    """Normalize a virtual SFTP path relative to '/'."""
    norm = posixpath.normpath(path if path.startswith("/") else "/" + path)
    return "/" if norm in ("", ".") else norm


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
    """Guest user eve with public clearance is denied reading /projects/confidential/flag.txt and audited."""
    policy.init(policy_fixture_data)
    allowed, _reason = policy.authorize("eve", "read", "/projects/confidential/flag.txt")
    assert allowed is False
    records = [json.loads(line) for line in tmp_audit.read_text().splitlines()]
    assert len(records) == 1
    assert records[0]["user"] == "eve"
    assert records[0]["op"] == "read"
    assert records[0]["path"] == "/projects/confidential/flag.txt"
    assert records[0]["allowed"] is False


def test_dac_owner_read_write_and_other_denied(policy_fixture_data):
    """Owner alice can read/write under /projects while eve without write permission is denied."""
    policy.init(policy_fixture_data)
    assert policy.check_dac("alice", "read", "/projects/note.txt")[0] is True
    assert policy.check_dac("alice", "write", "/projects/note.txt")[0] is True
    assert policy.check_dac("eve", "write", "/projects/note.txt")[0] is False


def test_dac_directory_execute_controls_listing(policy_fixture_data):
    """Directory x bit controls ls (list) but, by design, not stat, which needs only r."""
    policy.init(policy_fixture_data)
    assert policy.check_dac("eve", "list", "/public")[0] is True
    assert policy.check_dac("eve", "stat", "/public")[0] is True
    policy_fixture_data["dac"]["/public"]["dir_mode"] = 0o644   # other: r--, no x
    assert policy.check_dac("eve", "list", "/public")[0] is False
    assert policy.check_dac("eve", "stat", "/public")[0] is True
    policy_fixture_data["dac"]["/public"]["dir_mode"] = 0o640   # other: ---, no r
    assert policy.check_dac("eve", "stat", "/public")[0] is False


def test_mac_no_read_up_and_no_write_down(policy_fixture_data):
    """Internal user cannot read confidential data, and confidential user cannot write down to public."""
    policy.init(policy_fixture_data)
    assert policy.check_mac("alice", "read", "/public/readme.txt")[0] is True
    assert policy.check_mac("alice", "read", "/projects/internal.txt")[0] is True
    assert policy.check_mac("alice", "read", "/projects/confidential/secret.txt")[0] is False
    assert policy.check_mac("carol", "write", "/public/leak.txt")[0] is False


def test_rbac_analyst_scope_role_union_and_deny_override(policy_fixture_data):
    """Analyst can write /projects but not mkdir /admin; union with admin enables it; deny overrides allow."""
    policy.init(policy_fixture_data)
    assert policy.check_rbac("alice", "read", "/projects/plan.txt")[0] is True
    assert policy.check_rbac("alice", "write", "/projects/plan.txt")[0] is True
    assert policy.check_rbac("alice", "mkdir", "/admin/sub")[0] is False
    assert policy.check_rbac("dual", "mkdir", "/admin/sub")[0] is True

    policy_fixture_data["user_overrides"]["dual"] = {
        "deny": [{"action": "write", "prefix": "/admin"}]
    }
    assert policy.check_rbac("dual", "write", "/admin/sub")[0] is False


def test_composite_dac_allows_mac_denies(policy_fixture_data):
    """DAC and RBAC allow alice to read the confidential file but MAC denies, so the final decision is deny."""
    policy.init(policy_fixture_data)
    path = "/projects/confidential/flag.txt"
    assert policy.check_dac("alice", "read", path)[0] is True     # group analyst, 660
    assert policy.check_rbac("alice", "read", path)[0] is True    # analyst on /projects
    assert policy.check_mac("alice", "read", path)[0] is False    # internal < confidential
    allowed, reason = policy.authorize("alice", "read", path)
    assert allowed is False
    assert "MAC" in reason and "DAC" not in reason and "RBAC" not in reason


def test_composite_mac_allows_dac_denies(policy_fixture_data):
    """MAC and RBAC allow bob to read /projects but DAC denies (he is "other"), so the final decision is deny."""
    policy.init(policy_fixture_data)
    path = "/projects/plan.txt"
    assert policy.check_mac("bob", "read", path)[0] is True       # internal = internal
    assert policy.check_rbac("bob", "read", path)[0] is True      # admin on /
    assert policy.check_dac("bob", "read", path)[0] is False      # other on 660
    allowed, reason = policy.authorize("bob", "read", path)
    assert allowed is False
    assert "DAC" in reason and "MAC" not in reason and "RBAC" not in reason


def test_composite_all_allow(policy_fixture_data, tmp_audit):
    """Only when DAC, MAC and RBAC all allow is the request allowed, and the allow is audited with every field."""
    policy.init(policy_fixture_data)
    allowed, _ = policy.authorize("alice", "read", "/projects/plan.txt")
    assert allowed is True
    records = [json.loads(line) for line in tmp_audit.read_text().splitlines()]
    assert len(records) == 1
    assert set(records[0]) == {"timestamp", "user", "op", "path", "allowed", "reason"}
    assert records[0]["user"] == "alice" and records[0]["allowed"] is True


def test_traversal_denied_before_policy_and_audited(policy_fixture_data, tmp_path, tmp_audit):
    """A traversal attempt is refused by the server's resolve step, never reaches policy, and is audited as denied."""
    policy.init(policy_fixture_data)
    jail = tmp_path / "jail"
    jail.mkdir()
    session = server.SFTPSession(channel=None, user="bob", jail_real=os.path.realpath(jail))
    with pytest.raises(server.PathError):
        session.resolve("read", "/../../etc/passwd")
    records = [json.loads(line) for line in tmp_audit.read_text().splitlines()]
    assert len(records) == 1   # only the server's record: policy was never asked
    rec = records[0]
    assert set(rec) == {"timestamp", "user", "op", "path", "allowed", "reason"}
    assert rec["user"] == "bob" and rec["op"] == "read"
    assert rec["path"] == "/../../etc/passwd"
    assert rec["allowed"] is False and rec["reason"] == "path escapes the jail"


# ---------- server: paths and jail ----------

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


def test_sftp_end_to_end_real_policy(tmp_path, tmp_audit):
    """End-to-end SFTP enforces policy.authorize() for allowed and denied operations and audits both."""
    data = loader.load_data()
    data["users"] = make_users(eve="eve-pass-1")
    key = tmp_path / "hostkey"
    asyncssh.generate_private_key("ssh-ed25519").write_private_key(str(key))

    async def scenario():
        srv = await server.start_server(data, "127.0.0.1", 0, host_key=key, jail_dir=tmp_path / "jail")
        (tmp_path / "jail" / "public" / "hello.txt").write_text("hello")
        (tmp_path / "jail" / "projects" / "confidential" / "flag.txt").write_text("FLAG{secret}")
        try:
            async with asyncssh.connect("127.0.0.1", srv.get_port(), username="eve",
                                        password="eve-pass-1", known_hosts=None) as conn:
                async with conn.start_sftp_client() as sftp:
                    async with sftp.open("/public/hello.txt", "rb") as f:
                        assert await f.read() == b"hello"
                    with pytest.raises(asyncssh.SFTPPermissionDenied):
                        await sftp.stat("/projects/confidential/flag.txt")
        finally:
            srv.close()

    asyncio.run(scenario())

    records = [json.loads(line) for line in tmp_audit.read_text().splitlines()]
    assert any(r["user"] == "eve" and r["path"] == "/public/hello.txt" and r["allowed"] is True for r in records)
    assert any(r["user"] == "eve" and r["path"] == "/projects/confidential/flag.txt" and r["allowed"] is False for r in records)