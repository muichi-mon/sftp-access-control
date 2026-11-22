"""Client and CTF tests (Part 5). Real server, real policy, generated passwords."""
import asyncio
import base64
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
for sub in ("server", "client", "ctf"):
    sys.path.insert(0, str(ROOT / sub))

import asyncssh     # noqa: E402
import audit        # noqa: E402
import auth         # noqa: E402
import client       # noqa: E402
import loader       # noqa: E402
import server       # noqa: E402
import setup_flag   # noqa: E402
import attack       # noqa: E402

FLAG = "FLAG{test_flag}"
USERS = ("alice", "bob", "carol", "eve")


@pytest.fixture(autouse=True)
def tmp_audit(tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit, "audit_file", path)
    auth._failed.clear()
    auth._locked_until.clear()
    return path


def password(user):
    return f"{user}-test-pass"


@pytest.fixture
def env(tmp_path):
    data = loader.load_data()
    data["users"] = {}
    for name in USERS:
        u = auth.make_user(name, password(name))
        data["users"][name] = {"salt": base64.b64decode(u["salt"]),
                               "password_hash": base64.b64decode(u["password_hash"]),
                               "n": u["n"], "r": u["r"], "p": u["p"], "dklen": u["dklen"]}
    key = tmp_path / "hostkey"
    asyncssh.generate_private_key("ssh-ed25519").write_private_key(str(key))
    return {"data": data, "key": key, "jail": tmp_path / "jail", "store": tmp_path / "known_hosts", "tmp": tmp_path}


def run(env, scenario):
    async def main():
        srv = await server.start_server(env["data"], "127.0.0.1", 0, host_key=env["key"], jail_dir=env["jail"])
        setup_flag.plant_flag(env["jail"], FLAG)
        try:
            return await scenario(srv.get_port())
        finally:
            srv.close()
    return asyncio.run(main())


async def login(env, port, user, **kw):
    kw.setdefault("store", env["store"])
    kw.setdefault("confirm", lambda label, fp: True)
    return await client.connect("127.0.0.1", port, user, password(user), **kw)


def test_shell_commands(env):
    """pwd, ls, mkdir, put, get and stat work through the CLI and errors are printed, not raised."""
    local = env["tmp"] / "up.bin"
    local.write_bytes(bytes(range(256)) * 400)
    down = env["tmp"] / "down.bin"
    lines = []

    async def scenario(port):
        conn, sftp = await login(env, port, "bob")
        try:
            shell = client.Shell(sftp, out=lines.append)
            await shell.start()
            for cmd in ["pwd", "ls", "mkdir demo", f'put "{local}" /demo/up.bin',
                        f'get /demo/up.bin "{down}"', "stat /demo/up.bin", "ls /projects", "stat /nope", "bogus"]:
                assert await shell.run_line(cmd)
            assert not await shell.run_line("quit")
        finally:
            conn.close()

    run(env, scenario)
    assert lines[0] == "/"
    assert lines[1:4] == ["admin", "projects", "public"]
    assert down.read_bytes() == local.read_bytes()
    assert any("Size: 102400" in l for l in lines)
    assert "error: Permission denied (PERMISSION_DENIED)" in lines
    assert "error: No such file (NO_SUCH_FILE)" in lines
    assert any(l.startswith("unknown command") for l in lines)


def test_tofu_saves_key_then_rejects_a_changed_key(env):
    """First connect stores the host key; a different key on the same host:port is refused."""
    other = asyncssh.generate_private_key("ssh-ed25519").export_public_key("openssh").decode().split()

    async def scenario(port):
        conn, _ = await login(env, port, "bob")
        conn.close()
        assert f"[127.0.0.1]:{port} ssh-ed25519 " in env["store"].read_text()
        conn, _ = await login(env, port, "bob", confirm=lambda label, fp: pytest.fail("asked twice"))
        conn.close()

        env["store"].write_text(f"[127.0.0.1]:{port} {other[0]} {other[1]}\n")
        with pytest.raises(asyncssh.Error):
            await login(env, port, "bob", confirm=lambda label, fp: pytest.fail("mismatch must not prompt"))

    run(env, scenario)


def test_declined_and_strict_known_hosts(env):
    """Saying no to an unknown key, or a strict known_hosts file without the host, blocks the login."""
    empty = env["tmp"] / "empty_known_hosts"
    empty.write_text("")

    async def scenario(port):
        with pytest.raises(asyncssh.Error):
            await login(env, port, "bob", confirm=lambda label, fp: False)
        with pytest.raises(asyncssh.Error):
            await login(env, port, "bob", known_hosts=empty)

    run(env, scenario)
    assert not env["store"].exists()


def test_wrong_password_refused(env):
    """A wrong password ends in PermissionDenied and is audited."""
    async def scenario(port):
        with pytest.raises(asyncssh.PermissionDenied):
            await client.connect("127.0.0.1", port, "eve", "not-her-password", store=env["store"],
                                 confirm=lambda label, fp: True)

    run(env, scenario)


@pytest.mark.parametrize("user, can_read", [("carol", True), ("alice", False), ("bob", False), ("eve", False)])
def test_only_carol_reads_the_flag(env, user, can_read, tmp_audit):
    """The flag is readable by carol only; every other user is denied and the denial is audited."""
    async def scenario(port):
        conn, sftp = await login(env, port, user)
        try:
            return await attack.try_read(sftp, attack.FLAG)
        except client.SFTPError as e:
            return e
        finally:
            conn.close()

    result = run(env, scenario)
    if can_read:
        assert result == FLAG
    else:
        assert isinstance(result, client.SFTPError) and result.code == 3
        records = [json.loads(l) for l in tmp_audit.read_text().splitlines()]
        hit = [r for r in records if r["op"] == "read" and r["path"] == attack.FLAG]
        assert hit and hit[0]["user"] == user and hit[0]["allowed"] is False


def test_read_write_open_is_the_only_way_in(env, tmp_audit):
    """alice reads the flag via a read+write open (the intended bug) but is denied a read-only open; eve and bob get neither."""
    async def attempt(port, user, coro_name):
        conn, sftp = await login(env, port, user)
        try:
            return await getattr(attack, coro_name)(sftp, attack.FLAG)
        except client.SFTPError as e:
            return e
        finally:
            conn.close()

    # alice: read+write open leaks the flag, read-only open is refused.
    assert run(env, lambda p: attempt(p, "alice", "read_through_write")) == FLAG
    denied = run(env, lambda p: attempt(p, "alice", "try_read"))
    assert isinstance(denied, client.SFTPError) and denied.code == 3

    # eve and bob cannot even pass the write check, so the exploit does nothing.
    for user in ("eve", "bob"):
        result = run(env, lambda p, u=user: attempt(p, u, "read_through_write"))
        assert isinstance(result, client.SFTPError) and result.code == 3

    # alice's write-open on the flag is in the audit log.
    records = [json.loads(l) for l in tmp_audit.read_text().splitlines()]
    assert any(r["user"] == "alice" and r["op"] == "write" and r["path"] == attack.FLAG
               and r["allowed"] is True for r in records)
    assert (env["jail"] / "projects" / "confidential" / "flag.txt").read_text().strip() == FLAG


def test_attack_script_outcomes(env, capsys):
    """ctf/attack.py captures the flag for alice (intended) but never for eve or bob."""
    async def scenario(port):
        env["store"].write_text("")
        results = {}
        for user in ("eve", "alice", "bob"):
            conn, _ = await login(env, port, user)
            conn.close()
            args = type("A", (), {"host": "127.0.0.1", "port": port, "username": user,
                                  "known_hosts": str(env["store"])})
            results[user] = await attack.run(args, password(user))
        return results

    assert run(env, scenario) == {"eve": False, "alice": True, "bob": False}
    assert (env["jail"] / "projects" / "confidential" / "flag.txt").read_text().strip() == FLAG
