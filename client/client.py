"""SFTP v3 client.

Usage: python client/client.py --host 127.0.0.1 --port 2222 --username bob

asyncssh only opens the SSH connection and the "sftp" subsystem channel.
The SFTP packets are built and parsed here.
"""
import argparse
import asyncio
import getpass
import os
import posixpath
import shlex
import stat
import struct
import sys
import time
from pathlib import Path

import asyncssh

CLIENT_DIR = Path(__file__).resolve().parent
KNOWN_HOSTS = CLIENT_DIR / "known_hosts"

SSH_FXP_INIT = 1
SSH_FXP_VERSION = 2
SSH_FXP_OPEN = 3
SSH_FXP_CLOSE = 4
SSH_FXP_READ = 5
SSH_FXP_WRITE = 6
SSH_FXP_LSTAT = 7
SSH_FXP_FSTAT = 8
SSH_FXP_OPENDIR = 11
SSH_FXP_READDIR = 12
SSH_FXP_MKDIR = 14
SSH_FXP_REALPATH = 16
SSH_FXP_STAT = 17
SSH_FXP_STATUS = 101
SSH_FXP_HANDLE = 102
SSH_FXP_DATA = 103
SSH_FXP_NAME = 104
SSH_FXP_ATTRS = 105

SSH_FX_OK = 0
SSH_FX_EOF = 1

STATUS_NAMES = {
    0: "OK", 1: "EOF", 2: "NO_SUCH_FILE", 3: "PERMISSION_DENIED", 4: "FAILURE",
    5: "BAD_MESSAGE", 6: "NO_CONNECTION", 7: "CONNECTION_LOST", 8: "OP_UNSUPPORTED",
}

SSH_FXF_READ = 0x01
SSH_FXF_WRITE = 0x02
SSH_FXF_CREAT = 0x08
SSH_FXF_TRUNC = 0x10

ATTR_SIZE = 0x01
ATTR_UIDGID = 0x02
ATTR_PERMISSIONS = 0x04
ATTR_ACMODTIME = 0x08
ATTR_EXTENDED = 0x80000000

CHUNK = 32 * 1024
MAX_PACKET = 1024 * 1024


class SFTPError(Exception):
    def __init__(self, code, message=""):
        super().__init__(message)
        self.code = code
        self.message = message or STATUS_NAMES.get(code, "error")

    def __str__(self):
        return f"{self.message} ({STATUS_NAMES.get(self.code, self.code)})"


class ProtocolError(Exception):
    pass


class Usage(Exception):
    pass


def u32(n):
    return struct.pack(">I", n)


def u64(n):
    return struct.pack(">Q", n)


def sstr(value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    return u32(len(value)) + value


class Reader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def take(self, n):
        if self.pos + n > len(self.data):
            raise ProtocolError("reply too short")
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def u32(self):
        return struct.unpack(">I", self.take(4))[0]

    def u64(self):
        return struct.unpack(">Q", self.take(8))[0]

    def string(self):
        return self.take(self.u32())

    def text(self):
        return self.string().decode("utf-8", "replace")

    def attrs(self):
        flags = self.u32()
        a = {}
        if flags & ATTR_SIZE:
            a["size"] = self.u64()
        if flags & ATTR_UIDGID:
            a["uid"], a["gid"] = self.u32(), self.u32()
        if flags & ATTR_PERMISSIONS:
            a["permissions"] = self.u32()
        if flags & ATTR_ACMODTIME:
            a["atime"], a["mtime"] = self.u32(), self.u32()
        if flags & ATTR_EXTENDED:
            for _ in range(self.u32()):
                self.string()
                self.string()
        return a


class SFTP:
    """One request at a time, so every reply must carry the id we just sent."""

    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.next_id = 0
        self.version = None

    async def _send(self, msg_type, payload):
        body = bytes([msg_type]) + payload
        self.writer.write(u32(len(body)) + body)
        await self.writer.drain()

    async def _recv(self):
        length = struct.unpack(">I", await self.reader.readexactly(4))[0]
        if length < 1 or length > MAX_PACKET:
            raise ProtocolError(f"bad reply length {length}")
        body = await self.reader.readexactly(length)
        return body[0], Reader(body[1:])

    async def init(self):
        await self._send(SSH_FXP_INIT, u32(3))
        msg_type, r = await self._recv()
        if msg_type != SSH_FXP_VERSION:
            raise ProtocolError("server did not answer INIT with VERSION")
        self.version = r.u32()
        if self.version != 3:
            raise ProtocolError(f"server speaks SFTP version {self.version}, need 3")

    async def request(self, msg_type, payload=b""):
        self.next_id = (self.next_id + 1) & 0xFFFFFFFF
        req_id = self.next_id
        await self._send(msg_type, u32(req_id) + payload)
        reply_type, r = await self._recv()
        if r.u32() != req_id:
            raise ProtocolError("reply id does not match request id")
        if reply_type == SSH_FXP_STATUS:
            code, message = r.u32(), r.text()
            if code != SSH_FX_OK:
                raise SFTPError(code, message)
        return reply_type, r

    async def _expect(self, want, msg_type, payload):
        reply_type, r = await self.request(msg_type, payload)
        if reply_type != want:
            raise ProtocolError(f"unexpected reply type {reply_type}")
        return r

    async def realpath(self, path):
        r = await self._expect(SSH_FXP_NAME, SSH_FXP_REALPATH, sstr(path))
        if r.u32() < 1:
            raise ProtocolError("empty NAME reply")
        return r.text()

    async def stat(self, path):
        return (await self._expect(SSH_FXP_ATTRS, SSH_FXP_STAT, sstr(path))).attrs()

    async def lstat(self, path):
        return (await self._expect(SSH_FXP_ATTRS, SSH_FXP_LSTAT, sstr(path))).attrs()

    async def fstat(self, handle):
        return (await self._expect(SSH_FXP_ATTRS, SSH_FXP_FSTAT, sstr(handle))).attrs()

    async def mkdir(self, path):
        await self._expect(SSH_FXP_STATUS, SSH_FXP_MKDIR, sstr(path) + u32(0))

    async def open(self, path, pflags):
        return (await self._expect(SSH_FXP_HANDLE, SSH_FXP_OPEN, sstr(path) + u32(pflags) + u32(0))).string()

    async def opendir(self, path):
        return (await self._expect(SSH_FXP_HANDLE, SSH_FXP_OPENDIR, sstr(path))).string()

    async def close(self, handle):
        await self._expect(SSH_FXP_STATUS, SSH_FXP_CLOSE, sstr(handle))

    async def read(self, handle, offset, length):
        """Returns b"" at end of file."""
        try:
            r = await self._expect(SSH_FXP_DATA, SSH_FXP_READ, sstr(handle) + u64(offset) + u32(length))
        except SFTPError as e:
            if e.code == SSH_FX_EOF:
                return b""
            raise
        return r.string()

    async def write(self, handle, offset, data):
        await self._expect(SSH_FXP_STATUS, SSH_FXP_WRITE, sstr(handle) + u64(offset) + sstr(data))

    async def listdir(self, path):
        handle = await self.opendir(path)
        entries = []
        try:
            while True:
                try:
                    r = await self._expect(SSH_FXP_NAME, SSH_FXP_READDIR, sstr(handle))
                except SFTPError as e:
                    if e.code == SSH_FX_EOF:
                        break
                    raise
                for _ in range(r.u32()):
                    entries.append((r.text(), r.text(), r.attrs()))
        finally:
            await self.close(handle)
        return sorted(entries)

    async def get(self, rpath, lpath):
        handle = await self.open(rpath, SSH_FXF_READ)
        total = 0
        try:
            with open(lpath, "wb") as f:
                while True:
                    data = await self.read(handle, total, CHUNK)
                    if not data:
                        break
                    f.write(data)
                    total += len(data)
        except BaseException:
            try:
                os.remove(lpath)
            except OSError:
                pass
            raise
        finally:
            await self.close(handle)
        return total

    async def put(self, lpath, rpath):
        with open(lpath, "rb") as f:
            handle = await self.open(rpath, SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_TRUNC)
            total = 0
            try:
                while True:
                    data = f.read(CHUNK)
                    if not data:
                        break
                    await self.write(handle, total, data)
                    total += len(data)
            finally:
                await self.close(handle)
        return total


# host key check: trust on first use, stored in OpenSSH known_hosts format

def host_label(host, port):
    return host if port == 22 else f"[{host}]:{port}"


def load_known_hosts(path):
    known = {}
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return known
    for line in lines:
        parts = line.split()
        if len(parts) >= 3 and not line.startswith("#"):
            known.setdefault(parts[0], set()).add((parts[1], parts[2]))
    return known


def key_entry(key):
    alg, b64 = key.export_public_key("openssh").decode().split()[:2]
    return alg, b64


def ask_user(label, fingerprint):
    print(f"The authenticity of host '{label}' can't be established.")
    print(f"ED25519 key fingerprint is {fingerprint}.")
    try:
        answer = input("Are you sure you want to continue connecting (yes/no)? ")
    except EOFError:
        return False
    return answer.strip().lower() in ("y", "yes")


class TofuClient(asyncssh.SSHClient):
    def __init__(self, label, store, confirm):
        self.label = label
        self.store = Path(store)
        self.confirm = confirm
        self.mismatch = False

    def validate_host_public_key(self, host, addr, port, key):
        entry = key_entry(key)
        seen = load_known_hosts(self.store).get(self.label)
        if seen:
            if entry in seen:
                return True
            self.mismatch = True
            print("@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@", file=sys.stderr)
            print(f"Host key for {self.label} is now {key.get_fingerprint()}, which does not match "
                  f"{self.store}. Refusing to connect.", file=sys.stderr)
            return False
        if not self.confirm(self.label, key.get_fingerprint()):
            return False
        self.store.parent.mkdir(parents=True, exist_ok=True)
        with open(self.store, "a", encoding="utf-8") as f:
            f.write(f"{self.label} {entry[0]} {entry[1]}\n")
        print(f"Warning: permanently added '{self.label}' to {self.store}.")
        return True


async def connect(host, port, username, password, known_hosts=None, store=None, confirm=ask_user):
    """Open the SSH connection and the sftp subsystem. Returns (conn, SFTP).

    known_hosts given -> strict check against that file (asyncssh does it).
    Otherwise -> TOFU with our own store.
    """
    options = dict(username=username, password=password, preferred_auth="password,keyboard-interactive",
                   client_keys=None, agent_path=None, encoding=None)
    if known_hosts:
        conn = await asyncssh.connect(host, port, known_hosts=str(known_hosts), **options)
    else:
        label = host_label(host, port)
        store = store or KNOWN_HOSTS
        conn = await asyncssh.connect(host, port, known_hosts=([], [], []),
                                      client_factory=lambda: TofuClient(label, store, confirm), **options)
    try:
        writer, reader, _ = await conn.open_session(subsystem="sftp", encoding=None)
        sftp = SFTP(reader, writer)
        await sftp.init()
    except BaseException:
        conn.close()
        raise
    return conn, sftp


# CLI

def fmt_time(t):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t))


def fmt_attrs(path, a):
    lines = [f"  File: {path}"]
    mode = a.get("permissions")
    if mode is not None:
        kind = "directory" if stat.S_ISDIR(mode) else "regular file" if stat.S_ISREG(mode) else "other"
        lines.append(f"  Type: {kind}")
        lines.append(f"  Mode: {stat.filemode(mode)} ({oct(stat.S_IMODE(mode))})")
    if "size" in a:
        lines.append(f"  Size: {a['size']}")
    if "uid" in a:
        lines.append(f"  Uid: {a['uid']}  Gid: {a['gid']}")
    if "mtime" in a:
        lines.append(f"Modify: {fmt_time(a['mtime'])}")
        lines.append(f"Access: {fmt_time(a['atime'])}")
    return "\n".join(lines)


HELP = """commands:
  pwd                     print remote directory
  cd <path>               change remote directory
  ls [-l] [path]          list a directory
  mkdir <path>            create a directory
  stat <path>             show attributes
  get <rpath> [lpath]     download
  put <lpath> [rpath]     upload
  help                    this text
  quit                    exit"""


class Shell:
    def __init__(self, sftp, out=print):
        self.sftp = sftp
        self.cwd = "/"
        self.out = out

    def remote(self, path):
        return posixpath.join(self.cwd, path)

    async def start(self):
        self.cwd = await self.sftp.realpath(".")

    async def run_line(self, line):
        """Run one command. Returns False on quit."""
        try:
            args = shlex.split(line, posix=True)
        except ValueError as e:
            self.out(f"error: {e}")
            return True
        if not args:
            return True
        cmd, args = args[0], args[1:]
        if cmd in ("quit", "exit", "bye"):
            return False
        handler = getattr(self, "cmd_" + cmd, None)
        if handler is None:
            self.out(f"unknown command: {cmd} (try 'help')")
            return True
        try:
            await handler(args)
        except SFTPError as e:
            self.out(f"error: {e}")
        except Usage:
            self.out("usage error, see 'help'")
        except OSError as e:
            self.out(f"local error: {e.strerror or e}")
        return True

    async def cmd_help(self, args):
        self.out(HELP)

    async def cmd_pwd(self, args):
        self.out(self.cwd)

    async def cmd_cd(self, args):
        path = await self.sftp.realpath(self.remote(args[0] if args else "/"))
        a = await self.sftp.stat(path)
        if not stat.S_ISDIR(a.get("permissions", 0)):
            self.out(f"error: {path} is not a directory")
            return
        self.cwd = path

    async def cmd_ls(self, args):
        long = "-l" in args
        args = [a for a in args if a != "-l"]
        if len(args) > 1:
            raise Usage
        for name, longname, _ in await self.sftp.listdir(self.remote(args[0] if args else ".")):
            self.out(longname if long else name)

    async def cmd_mkdir(self, args):
        if len(args) != 1:
            raise Usage
        await self.sftp.mkdir(self.remote(args[0]))

    async def cmd_stat(self, args):
        if len(args) != 1:
            raise Usage
        self.out(fmt_attrs(args[0], await self.sftp.stat(self.remote(args[0]))))

    async def cmd_get(self, args):
        if len(args) not in (1, 2):
            raise Usage
        rpath = self.remote(args[0])
        lpath = args[1] if len(args) == 2 else posixpath.basename(rpath.rstrip("/"))
        if not lpath or lpath in (".", ".."):
            self.out("error: give a local file name")
            return
        if os.path.isdir(lpath):
            lpath = os.path.join(lpath, posixpath.basename(rpath))
        n = await self.sftp.get(rpath, lpath)
        self.out(f"{rpath} -> {lpath} ({n} bytes)")

    async def cmd_put(self, args):
        if len(args) not in (1, 2):
            raise Usage
        lpath = args[0]
        if not os.path.isfile(lpath):
            self.out(f"error: {lpath} is not a local file")
            return
        rpath = self.remote(args[1] if len(args) == 2 else os.path.basename(lpath))
        try:
            if stat.S_ISDIR((await self.sftp.stat(rpath)).get("permissions", 0)):
                rpath = posixpath.join(rpath, os.path.basename(lpath))
        except SFTPError:
            pass
        n = await self.sftp.put(lpath, rpath)
        self.out(f"{lpath} -> {rpath} ({n} bytes)")


async def repl(shell, interactive):
    loop = asyncio.get_running_loop()
    while True:
        try:
            if interactive:
                line = await loop.run_in_executor(None, input, "sftp> ")
            else:
                line = await loop.run_in_executor(None, sys.stdin.readline)
                if not line:
                    break
                line = line.rstrip("\n")
                print(f"sftp> {line}")
        except EOFError:
            break
        if not await shell.run_line(line):
            break


async def main_async(args):
    conn = None
    for attempt in range(3):
        password = getpass.getpass(f"{args.username}@{args.host}'s password: ")
        try:
            conn, sftp = await connect(args.host, args.port, args.username, password,
                                       known_hosts=args.known_hosts)
            break
        except asyncssh.PermissionDenied:
            print("Permission denied, please try again.", file=sys.stderr)
    if conn is None:
        return 1
    try:
        shell = Shell(sftp)
        await shell.start()
        print(f"Connected to {args.host}.")
        await repl(shell, sys.stdin.isatty())
    except (asyncssh.Error, ConnectionError, asyncio.IncompleteReadError):
        print("Connection to server lost.", file=sys.stderr)
        return 1
    except ProtocolError as e:
        print(f"Protocol error: {e}", file=sys.stderr)
        return 1
    finally:
        conn.close()
    return 0


def main():
    parser = argparse.ArgumentParser(description="SFTP v3 client")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--username", required=True)
    parser.add_argument("--known-hosts", help="pre-provisioned known_hosts file (strict check, no TOFU)")
    args = parser.parse_args()
    try:
        code = asyncio.run(main_async(args))
    except KeyboardInterrupt:
        code = 130
    except (OSError, asyncssh.Error) as e:
        print(f"Could not connect: {e}", file=sys.stderr)
        code = 1
    sys.exit(code)


if __name__ == "__main__":
    main()
