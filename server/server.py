"""SSH transport + SFTP v3 handling.

Part 1 - Server protocol and hardening.

asyncssh gives us the SSH layer (key exchange, encryption, channels, the password
exchange). Everything inside the "sftp" subsystem is our own code: packet framing,
request IDs, the handle table and the replies.

Every request that names a path goes through the same steps, in this order:

    1. canonicalize()      SFTP path -> clean POSIX path rooted at "/" (the jail)
    2. safe_join()         POSIX path -> OS path inside sftp_root, refusing anything
                           that resolves somewhere else (symlinks, case tricks, ...)
    3. policy.authorize()  DAC + MAC + RBAC decision, audited by policy.py
    4. the filesystem call

Contract with policy.py (Parts 3 and 4):
    policy.init(data)                  optional, called once at startup with the
                                       dict returned by loader.load_data()
    policy.authorize(user, op, path)   -> (allowed: bool, reason: str)
        path is the canonical SFTP path, e.g. "/projects/confidential/flag.txt"
        op is one of OPS below.
If authorize() is missing or raises, the request is denied (default deny).
"""
import argparse
import asyncio
import errno
import logging
import os
import secrets
import stat
import struct
import sys
import time
from pathlib import Path

import asyncssh

import audit
import auth
import loader
import policy

log = logging.getLogger("sftp.server")

SERVER_DIR = Path(__file__).resolve().parent
JAIL_DIR = SERVER_DIR / "sftp_root"
HOST_KEY = SERVER_DIR / "ssh_host_ed25519_key"

# Operations passed to policy.authorize().
OPS = ("realpath", "stat", "list", "mkdir", "read", "write", "remove", "rmdir")

# ---------------------------------------------------------------- protocol constants
SSH_FXP_INIT = 1
SSH_FXP_VERSION = 2
SSH_FXP_OPEN = 3
SSH_FXP_CLOSE = 4
SSH_FXP_READ = 5
SSH_FXP_WRITE = 6
SSH_FXP_LSTAT = 7
SSH_FXP_FSTAT = 8
SSH_FXP_SETSTAT = 9
SSH_FXP_FSETSTAT = 10
SSH_FXP_OPENDIR = 11
SSH_FXP_READDIR = 12
SSH_FXP_REMOVE = 13
SSH_FXP_MKDIR = 14
SSH_FXP_RMDIR = 15
SSH_FXP_REALPATH = 16
SSH_FXP_STAT = 17
SSH_FXP_STATUS = 101
SSH_FXP_HANDLE = 102
SSH_FXP_DATA = 103
SSH_FXP_NAME = 104
SSH_FXP_ATTRS = 105

SSH_FX_OK = 0
SSH_FX_EOF = 1
SSH_FX_NO_SUCH_FILE = 2
SSH_FX_PERMISSION_DENIED = 3
SSH_FX_FAILURE = 4
SSH_FX_BAD_MESSAGE = 5
SSH_FX_OP_UNSUPPORTED = 8

SSH_FXF_READ = 0x01
SSH_FXF_WRITE = 0x02
SSH_FXF_APPEND = 0x04
SSH_FXF_CREAT = 0x08
SSH_FXF_TRUNC = 0x10
SSH_FXF_EXCL = 0x20

ATTR_SIZE = 0x01
ATTR_UIDGID = 0x02
ATTR_PERMISSIONS = 0x04
ATTR_ACMODTIME = 0x08
ATTR_EXTENDED = 0x80000000

# ---------------------------------------------------------------- limits
MAX_PACKET = 256 * 1024 + 1024   # biggest packet we accept (OpenSSH writes 32 KiB chunks)
MAX_READ = 64 * 1024             # biggest DATA reply; clients cope with short reads
MAX_HANDLES = 64                 # open handles per session, so a client cannot exhaust fds
READDIR_BATCH = 100              # names per READDIR reply
MAX_PATH = 4096

# Windows maps these names to devices, whatever the directory or extension.
WIN_RESERVED = {"CON", "PRN", "AUX", "NUL",
                *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}


class BadMessage(Exception):
    """The packet is truncated or malformed."""


class ProtocolError(Exception):
    """The client broke the framing; the session is closed."""


class PathError(Exception):
    """The path is not allowed before policy is even asked (jail, bad characters)."""


class Denied(Exception):
    """policy.authorize() said no."""


class SFTPStatus(Exception):
    """Reply to the current request with this STATUS code and message."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


# ---------------------------------------------------------------- wire encoding
def u32(n):
    return struct.pack(">I", n & 0xFFFFFFFF)


def u64(n):
    return struct.pack(">Q", n & 0xFFFFFFFFFFFFFFFF)


def sstr(value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    return u32(len(value)) + value


class Packet:
    """Reads SFTP fields from the body of one packet."""

    def __init__(self, data):
        self.data = data
        self.pos = 0

    def take(self, n):
        if n < 0 or self.pos + n > len(self.data):
            raise BadMessage("packet too short")
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def u32(self):
        return struct.unpack(">I", self.take(4))[0]

    def u64(self):
        return struct.unpack(">Q", self.take(8))[0]

    def string(self):
        return self.take(self.u32())

    def path(self):
        raw = self.string()
        if len(raw) > MAX_PATH:
            raise BadMessage("path too long")
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            raise BadMessage("path is not valid UTF-8") from None

    def attrs(self):
        """Parse an ATTRS block. We read it to stay in sync but do not apply it:
        ownership and modes come from the DAC data, not from the client."""
        flags = self.u32()
        attrs = {}
        if flags & ATTR_SIZE:
            attrs["size"] = self.u64()
        if flags & ATTR_UIDGID:
            attrs["uid"], attrs["gid"] = self.u32(), self.u32()
        if flags & ATTR_PERMISSIONS:
            attrs["permissions"] = self.u32()
        if flags & ATTR_ACMODTIME:
            attrs["atime"], attrs["mtime"] = self.u32(), self.u32()
        if flags & ATTR_EXTENDED:
            for _ in range(self.u32()):
                self.string()
                self.string()
        return attrs


def encode_attrs(st):
    flags = ATTR_SIZE | ATTR_PERMISSIONS | ATTR_ACMODTIME
    return (u32(flags) + u64(st.st_size) + u32(st.st_mode)
            + u32(int(st.st_atime)) + u32(int(st.st_mtime)))


def longname(name, st):
    """The `ls -l` style line that OpenSSH prints for `ls -l`."""
    when = time.strftime("%b %d %H:%M", time.localtime(st.st_mtime))
    return f"{stat.filemode(st.st_mode)}    1 0        0        {st.st_size:>8} {when} {name}"


# ---------------------------------------------------------------- paths
def canonicalize(raw):
    """Turn a client path into a clean absolute POSIX path inside the jail.

    Relative paths start at "/" (every user's home is the jail root). "." and empty
    parts are dropped and ".." goes up one level, but going above "/" is refused
    instead of silently clamped, so traversal attempts show up in the audit log.
    Backslashes, colons and control characters are refused because on Windows they
    would change the meaning of the path once it reaches the OS.
    """
    if "\0" in raw:
        raise PathError("NUL byte in path")
    parts = []
    for part in raw.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if not parts:
                raise PathError("path escapes the jail")
            parts.pop()
            continue
        if any(c in "\\:" or ord(c) < 32 for c in part):
            raise PathError("illegal character in path")
        if os.name == "nt" and (part[-1] in " ." or part.split(".")[0].upper() in WIN_RESERVED):
            raise PathError("name not allowed on this server")
        parts.append(part)
    return "/" + "/".join(parts)


def safe_join(vpath, jail_real):
    """Map a canonical SFTP path to the OS path inside the jail.

    The OS path is resolved with realpath() and must come back exactly as built.
    That refuses symlinks anywhere on the way (in or out of the jail), and on
    Windows also case variants, 8.3 short names and device names, which would
    otherwise reach a file under a different name than the one policy checked.
    """
    parts = [p for p in vpath.split("/") if p]
    expected = os.path.join(jail_real, *parts)
    if os.path.realpath(expected) != expected:
        raise PathError("path resolves outside its name (link or alias)")
    return expected


def map_os_error(exc):
    """OSError -> SFTP STATUS, without leaking server-side paths."""
    if isinstance(exc, FileNotFoundError):
        return SSH_FX_NO_SUCH_FILE, "No such file"
    if isinstance(exc, PermissionError):
        return SSH_FX_PERMISSION_DENIED, "Permission denied"
    if isinstance(exc, FileExistsError):
        return SSH_FX_FAILURE, "File already exists"
    if isinstance(exc, NotADirectoryError):
        return SSH_FX_NO_SUCH_FILE, "Not a directory"
    if isinstance(exc, IsADirectoryError):
        return SSH_FX_FAILURE, "Is a directory"
    if exc.errno == errno.ENOTEMPTY:
        return SSH_FX_FAILURE, "Directory not empty"
    return SSH_FX_FAILURE, "Operation failed"


# ---------------------------------------------------------------- SFTP session
class SFTPSession:
    """One SFTP subsystem on one SSH channel."""

    def __init__(self, channel, user, jail_real):
        self.channel = channel   # SFTPChannel: readexactly(), write(), drain(), exit()
        self.user = user
        self.jail_real = jail_real
        self.handles = {}
        self.handlers = {
            SSH_FXP_REALPATH: self.do_realpath,
            SSH_FXP_STAT: self.do_stat,
            SSH_FXP_LSTAT: self.do_lstat,
            SSH_FXP_FSTAT: self.do_fstat,
            SSH_FXP_OPENDIR: self.do_opendir,
            SSH_FXP_READDIR: self.do_readdir,
            SSH_FXP_MKDIR: self.do_mkdir,
            SSH_FXP_RMDIR: self.do_rmdir,
            SSH_FXP_REMOVE: self.do_remove,
            SSH_FXP_OPEN: self.do_open,
            SSH_FXP_READ: self.do_read,
            SSH_FXP_WRITE: self.do_write,
            SSH_FXP_CLOSE: self.do_close,
        }

    # ---- framing
    async def read_packet(self):
        length = struct.unpack(">I", await self.channel.readexactly(4))[0]
        if length < 1 or length > MAX_PACKET:
            raise ProtocolError(f"bad packet length {length}")
        return await self.channel.readexactly(length)

    async def send(self, msg_type, payload):
        body = bytes([msg_type]) + payload
        self.channel.write(u32(len(body)) + body)
        await self.channel.drain()

    async def send_status(self, req_id, code, message=""):
        await self.send(SSH_FXP_STATUS, u32(req_id) + u32(code) + sstr(message) + sstr(""))

    # ---- main loop
    async def run(self):
        try:
            first = await self.read_packet()
            if first[0] != SSH_FXP_INIT or len(first) < 5:
                raise ProtocolError("first packet was not INIT")
            client_version = struct.unpack(">I", first[1:5])[0]
            log.info("%s: SFTP session started (client version %d)", self.user, client_version)
            # We speak version 3 only and advertise no extensions.
            await self.send(SSH_FXP_VERSION, u32(3))
            while True:
                await self.dispatch(await self.read_packet())
        except (asyncio.IncompleteReadError, ConnectionError, BrokenPipeError):
            pass   # client went away
        except ProtocolError as e:
            log.warning("%s: closing session: %s", self.user, e)
        except asyncssh.Error as e:
            log.info("%s: session ended: %s", self.user, e)
        finally:
            self.close_all()
            log.info("%s: SFTP session closed", self.user)
            self.channel.exit(0)

    async def dispatch(self, body):
        msg_type = body[0]
        if len(body) < 5:
            raise ProtocolError("packet has no request id")
        req_id = struct.unpack(">I", body[1:5])[0]
        handler = self.handlers.get(msg_type)
        if handler is None:
            # SETSTAT, RENAME, READLINK, SYMLINK, EXTENDED, unknown: not offered.
            await self.send_status(req_id, SSH_FX_OP_UNSUPPORTED, "Operation not supported")
            return
        try:
            await handler(req_id, Packet(body[5:]))
        except SFTPStatus as s:
            await self.send_status(req_id, s.code, s.message)
        except (Denied, PathError):
            await self.send_status(req_id, SSH_FX_PERMISSION_DENIED, "Permission denied")
        except BadMessage as e:
            await self.send_status(req_id, SSH_FX_BAD_MESSAGE, str(e))
        except OSError as e:
            await self.send_status(req_id, *map_os_error(e))
        except Exception:
            log.exception("%s: internal error on message type %d", self.user, msg_type)
            await self.send_status(req_id, SSH_FX_FAILURE, "Internal error")

    # ---- the gate
    def authorize(self, op, vpath):
        check = getattr(policy, "authorize", None)
        if check is None:
            audit.log(self.user, op, vpath, False, "no policy loaded (default deny)")
            raise Denied()
        try:
            allowed, _reason = check(self.user, op, vpath)
        except Exception:
            log.exception("policy.authorize() failed for %s %s", op, vpath)
            audit.log(self.user, op, vpath, False, "policy error (default deny)")
            raise Denied() from None
        if allowed is not True:
            raise Denied()

    def resolve(self, op, raw):
        """canonicalize -> jail -> authorize. Returns (sftp path, OS path)."""
        try:
            vpath = canonicalize(raw)
            os_path = safe_join(vpath, self.jail_real)
        except PathError as e:
            # policy never sees this request, so we audit it here.
            audit.log(self.user, op, raw[:256], False, str(e))
            raise
        self.authorize(op, vpath)
        return vpath, os_path

    # ---- handles
    def new_handle(self, record):
        if len(self.handles) >= MAX_HANDLES:
            if record["kind"] == "file":
                os.close(record["fd"])
            raise SFTPStatus(SSH_FX_FAILURE, "Too many open handles")
        handle = secrets.token_hex(8).encode()
        self.handles[handle] = record
        return handle

    def get_handle(self, p, kind):
        record = self.handles.get(p.string())
        if record is None or record["kind"] != kind:
            raise SFTPStatus(SSH_FX_FAILURE, "Invalid handle")
        return record

    def close_all(self):
        for record in self.handles.values():
            if record["kind"] == "file":
                try:
                    os.close(record["fd"])
                except OSError:
                    pass
        self.handles.clear()

    # ---- requests
    async def do_realpath(self, req_id, p):
        vpath, _ = self.resolve("realpath", p.path())
        await self.send(SSH_FXP_NAME, u32(req_id) + u32(1) + sstr(vpath) + sstr(vpath) + u32(0))

    async def do_stat(self, req_id, p):
        _, os_path = self.resolve("stat", p.path())
        await self.send(SSH_FXP_ATTRS, u32(req_id) + encode_attrs(os.stat(os_path)))

    async def do_lstat(self, req_id, p):
        # safe_join already refuses links, so LSTAT and STAT see the same thing.
        _, os_path = self.resolve("stat", p.path())
        await self.send(SSH_FXP_ATTRS, u32(req_id) + encode_attrs(os.lstat(os_path)))

    async def do_fstat(self, req_id, p):
        # The handle was authorized at OPEN; FSTAT only works on file handles.
        record = self.get_handle(p, "file")
        await self.send(SSH_FXP_ATTRS, u32(req_id) + encode_attrs(os.fstat(record["fd"])))

    async def do_opendir(self, req_id, p):
        vpath, os_path = self.resolve("list", p.path())
        if not stat.S_ISDIR(os.stat(os_path).st_mode):
            raise SFTPStatus(SSH_FX_FAILURE, "Not a directory")
        entries = []
        with os.scandir(os_path) as it:
            for entry in it:
                if entry.is_symlink():
                    continue   # never show what we would refuse to open
                try:
                    entries.append((entry.name, entry.stat(follow_symlinks=False)))
                except OSError:
                    continue
        entries.sort()
        handle = self.new_handle({"kind": "dir", "path": vpath, "entries": entries})
        await self.send(SSH_FXP_HANDLE, u32(req_id) + sstr(handle))

    async def do_readdir(self, req_id, p):
        record = self.get_handle(p, "dir")
        batch = record["entries"][:READDIR_BATCH]
        if not batch:
            raise SFTPStatus(SSH_FX_EOF, "End of directory")
        del record["entries"][:READDIR_BATCH]
        payload = u32(req_id) + u32(len(batch))
        for name, st in batch:
            payload += sstr(name) + sstr(longname(name, st)) + encode_attrs(st)
        await self.send(SSH_FXP_NAME, payload)

    async def do_mkdir(self, req_id, p):
        raw = p.path()
        p.attrs()   # mode from the client is ignored; DAC data decides
        vpath, os_path = self.resolve("mkdir", raw)
        if vpath == "/":
            raise SFTPStatus(SSH_FX_FAILURE, "File already exists")
        os.mkdir(os_path)
        await self.send_status(req_id, SSH_FX_OK, "Success")

    async def do_rmdir(self, req_id, p):
        vpath, os_path = self.resolve("rmdir", p.path())
        if vpath == "/":
            raise Denied()
        os.rmdir(os_path)
        await self.send_status(req_id, SSH_FX_OK, "Success")

    async def do_remove(self, req_id, p):
        _, os_path = self.resolve("remove", p.path())
        if not stat.S_ISREG(os.lstat(os_path).st_mode):
            raise SFTPStatus(SSH_FX_FAILURE, "Not a regular file")
        os.remove(os_path)
        await self.send_status(req_id, SSH_FX_OK, "Success")

    async def do_open(self, req_id, p):
        raw = p.path()
        pflags = p.u32()
        p.attrs()
        reading = bool(pflags & SSH_FXF_READ)
        writing = bool(pflags & (SSH_FXF_WRITE | SSH_FXF_APPEND | SSH_FXF_CREAT | SSH_FXF_TRUNC))
        if not (reading or writing):
            raise BadMessage("open needs READ or WRITE")

        # One op per access mode; a read/write open needs both.
        vpath, os_path = self.resolve("read" if reading else "write", raw)
        if reading and writing:
            self.authorize("write", vpath)

        flags = os.O_RDWR if reading and writing else os.O_WRONLY if writing else os.O_RDONLY
        if pflags & SSH_FXF_APPEND:
            flags |= os.O_APPEND
        if pflags & SSH_FXF_CREAT:
            flags |= os.O_CREAT
            if pflags & SSH_FXF_EXCL:
                flags |= os.O_EXCL
        if pflags & SSH_FXF_TRUNC:
            flags |= os.O_TRUNC
        # O_NOFOLLOW closes the gap between the jail check and the open (POSIX);
        # O_BINARY stops Windows from rewriting line endings.
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOCTTY", 0)

        fd = os.open(os_path, flags, 0o644)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise SFTPStatus(SSH_FX_FAILURE, "Not a regular file")
        except BaseException:
            os.close(fd)
            raise
        handle = self.new_handle({"kind": "file", "fd": fd, "path": vpath,
                                  "read": reading, "write": writing,
                                  "append": bool(pflags & SSH_FXF_APPEND)})
        await self.send(SSH_FXP_HANDLE, u32(req_id) + sstr(handle))

    async def do_read(self, req_id, p):
        record = self.get_handle(p, "file")
        offset, length = p.u64(), p.u32()
        if not record["read"]:
            raise SFTPStatus(SSH_FX_PERMISSION_DENIED, "Handle not open for reading")
        os.lseek(record["fd"], offset, os.SEEK_SET)
        data = os.read(record["fd"], min(length, MAX_READ))
        if not data:
            raise SFTPStatus(SSH_FX_EOF, "End of file")
        await self.send(SSH_FXP_DATA, u32(req_id) + sstr(data))

    async def do_write(self, req_id, p):
        record = self.get_handle(p, "file")
        offset, data = p.u64(), p.string()
        if not record["write"]:
            raise SFTPStatus(SSH_FX_PERMISSION_DENIED, "Handle not open for writing")
        fd = record["fd"]
        if not record["append"]:
            os.lseek(fd, offset, os.SEEK_SET)
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        await self.send_status(req_id, SSH_FX_OK, "Success")

    async def do_close(self, req_id, p):
        record = self.handles.pop(p.string(), None)
        if record is None:
            raise SFTPStatus(SSH_FX_FAILURE, "Invalid handle")
        if record["kind"] == "file":
            os.close(record["fd"])
        await self.send_status(req_id, SSH_FX_OK, "Success")


# ---------------------------------------------------------------- SSH layer
class SFTPChannel(asyncssh.SSHServerSession):
    """Low-level asyncssh session on one SSH channel.

    asyncssh's high-level API always hands the "sftp" subsystem to its own SFTP
    server, so we take the raw channel bytes here instead and feed them to our
    SFTPSession. Only the sftp subsystem is accepted: no shell, exec or pty.
    """

    HIGH_WATER = 1024 * 1024   # stop reading from the client above 1 MiB buffered

    def __init__(self, user, jail_real):
        self.user = user
        self.jail_real = jail_real
        self.chan = None
        self.buf = bytearray()
        self.eof = False
        self.closed = False
        self.paused = False
        self.data_ready = asyncio.Event()
        self.can_write = asyncio.Event()
        self.can_write.set()
        self.task = None

    # ---- asyncssh callbacks
    def connection_made(self, chan):
        self.chan = chan

    def pty_requested(self, term_type, term_size, term_modes):
        return False

    def shell_requested(self):
        return False

    def exec_requested(self, command):
        return False

    def subsystem_requested(self, subsystem):
        return subsystem == "sftp"

    def session_started(self):
        self.task = asyncio.ensure_future(SFTPSession(self, self.user, self.jail_real).run())

    def data_received(self, data, datatype):
        if datatype is not None:
            return   # extended data (stderr) has no meaning for SFTP
        self.buf += data
        self.data_ready.set()
        if len(self.buf) > self.HIGH_WATER and not self.paused:
            self.chan.pause_reading()   # SSH flow control pushes back on the client
            self.paused = True

    def eof_received(self):
        self.eof = True
        self.data_ready.set()
        return False

    def connection_lost(self, exc):
        self.eof = self.closed = True
        self.data_ready.set()
        self.can_write.set()

    def pause_writing(self):
        self.can_write.clear()

    def resume_writing(self):
        self.can_write.set()

    # ---- stream interface used by SFTPSession
    async def readexactly(self, n):
        while len(self.buf) < n:
            if self.eof:
                raise asyncio.IncompleteReadError(bytes(self.buf), n)
            self.data_ready.clear()
            await self.data_ready.wait()
        chunk = bytes(self.buf[:n])
        del self.buf[:n]
        if self.paused and len(self.buf) < self.HIGH_WATER // 2:
            self.chan.resume_reading()
            self.paused = False
        return chunk

    def write(self, data):
        if self.closed:
            raise ConnectionError("channel closed")
        self.chan.write(data)

    async def drain(self):
        await self.can_write.wait()
        if self.closed:
            raise ConnectionError("channel closed")

    def exit(self, status):
        if not self.closed:
            try:
                self.chan.exit(status)
            except (OSError, asyncssh.Error):
                pass


class SSHServer(asyncssh.SSHServer):
    """Password login only; public keys, forwarding, shells and exec are off."""

    def __init__(self, users, jail_real):
        self.users = users
        self.jail_real = jail_real
        self.conn = None
        self.peer = None

    def connection_made(self, conn):
        self.conn = conn
        self.peer = conn.get_extra_info("peername")
        log.info("connection from %s", self.peer)

    def session_requested(self):
        return SFTPChannel(self.conn.get_extra_info("username"), self.jail_real)

    def connection_lost(self, exc):
        log.info("connection from %s closed%s", self.peer, f" ({exc})" if exc else "")

    def begin_auth(self, username):
        return True   # always require authentication

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        return auth.check_password(self.users, username, password)



def prepare_jail(data, jail_dir=JAIL_DIR):
    """Create the jail and one directory per policy prefix, so the folders that
    the labels and owners describe exist under exactly that name."""
    jail_dir.mkdir(exist_ok=True)
    jail_real = os.path.realpath(jail_dir)
    prefixes = set(data["dac"]) | set(data["mac"]["labels"])
    for role_prefixes in data["role_perms"].values():
        prefixes |= set(role_prefixes)
    for prefix in sorted(prefixes):
        vpath = canonicalize(prefix)
        if vpath != "/":
            os.makedirs(safe_join(vpath, jail_real), exist_ok=True)
    log.info("jail ready at %s", jail_real)
    return jail_real


async def start_server(data, host, port, host_key=HOST_KEY, jail_dir=JAIL_DIR):
    jail_real = prepare_jail(data, Path(jail_dir))
    if hasattr(policy, "init"):
        policy.init(data)
    if not hasattr(policy, "authorize"):
        log.warning("policy.authorize() is missing: every request will be denied")
    return await asyncssh.create_server(
        lambda: SSHServer(data["users"], jail_real), host, port,
        server_host_keys=[str(host_key)],
        encoding=None,          # binary channel: SFTP packets, not text
        agent_forwarding=False,
        x11_forwarding=False,
        allow_pty=False,
        login_timeout=60,
    )


def main():
    parser = argparse.ArgumentParser(description="SFTP v3 server with DAC, MAC and RBAC")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2222)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")

    try:
        data = loader.load_data()
    except loader.DataError as e:
        sys.exit(f"Startup failed: {e}")
    if not HOST_KEY.is_file():
        sys.exit(f"Startup failed: host key {HOST_KEY} not found. "
                 f"Create it with: ssh-keygen -t ed25519 -N '' -f server/ssh_host_ed25519_key")

    async def serve():
        try:
            server = await start_server(data, args.host, args.port)
        except (OSError, asyncssh.Error, ValueError) as e:
            sys.exit(f"Startup failed: {e}")
        log.info("listening on %s:%d", args.host, args.port)
        async with server:
            await server.wait_closed()

    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        log.info("server stopped")


if __name__ == "__main__":
    main()
