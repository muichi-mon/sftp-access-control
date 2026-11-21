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


# ---------- policy / SFTP (Part 4) ----------

@pytest.mark.skip(reason="policy.authorize() not implemented yet")
def test_eve_cannot_read_confidential():
    pass


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
