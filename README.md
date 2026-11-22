# SFTP over SSH with DAC, MAC and RBAC

A small SFTP v3 server and client. SSH itself (encryption, key exchange, channels) comes from
`asyncssh`; the SFTP layer, the login check and the access control are our own code.

```
server/
  server.py      SSH transport + SFTP v3 handling
  auth.py        password hashing, login check, lockout
  audit.py       writes audit.jsonl (one JSON line per event)
  loader.py      reads and checks the data files at startup
  policy.py      authorize(): DAC, MAC, RBAC
  data/          the static users, roles, labels and owners
  sftp_root/     the jail (created at runtime; initially empty)
client/client.py SFTP client
tests/test_sftp.py  pytest tests
ctf/             flag setup
CTF_writeup.pdf  CTF write-up
```

## Who does what

| Part | Area | Files |
|------|------|-------|
| 1 | Server protocol and hardening | `server/server.py` |
| 2 | Authentication, audit and integration | `server/auth.py`, `server/audit.py`, `server/loader.py`, `server/data/`, README |
| 3 | Policy core: `authorize()`, DAC, MAC, audit of decisions | `server/policy.py` |
| 4 | RBAC, how the 3 models combine, tests | `server/policy.py`, `tests/` |
| 5 | Client and CTF | `client/client.py`, `ctf/`, `CTF_writeup.pdf` |

## How to run

You need Python 3.9 or newer. Install the packages with `pip install -r requirements.txt`.

**1. Make the host key (once).** On macOS/Linux:

```
ssh-keygen -t ed25519 -N '' -f server/ssh_host_ed25519_key
```

On Windows (PowerShell, `ssh-keygen` comes with Windows 10+) leave the passphrase empty by pressing Enter twice:

```
ssh-keygen -t ed25519 -f server\ssh_host_ed25519_key
```

**2. Start the server.** `python3 server/server.py` (Windows: `py server\server.py`).
It reads all data files first and logs each one. You should see something like this
(the exact prefix depends on how `server.py` sets up logging):

```
INFO:sftp.loader:loaded users.json
INFO:sftp.loader:loaded user_roles.json
INFO:sftp.loader:loaded role_perms.csv
INFO:sftp.loader:loaded mac_labels.json
INFO:sftp.loader:loaded dac_owners.csv
```

If a data file is missing or broken, the server stops right away with one readable line, for example:

```
Startup failed: user_roles.json: 'alice' has role 'analist', which is not in role_perms.csv
```

**3. Connect.**

```
python3 client/client.py --host 127.0.0.1 --port 2222 --username bob
sftp -P 2222 bob@127.0.0.1        # OpenSSH check
```

On Windows: `py client\client.py --host 127.0.0.1 --port 2222 --username bob`.

The first time, the client shows the server's host key fingerprint and asks you to accept it
(trust on first use). The key is saved to `client/known_hosts`. If the server ever shows a
different key, the client refuses to connect. To skip TOFU and only trust a file you made
yourself, pass `--known-hosts path/to/file` (OpenSSH format, e.g. `[127.0.0.1]:2222 ssh-ed25519 AAAA...`).

Commands: `pwd`, `cd`, `ls [-l] [path]`, `mkdir`, `stat`, `get <rpath> [lpath]`, `put <lpath> [rpath]`,
`help`, `quit`. Paths are relative to the current remote folder. A session as bob:

```
bob@127.0.0.1's password:
The authenticity of host '[127.0.0.1]:2222' can't be established.
ED25519 key fingerprint is SHA256:F4FWnHL+OKeQeXvJqMvl31XnHUgMtk0ThHmwiyx+Qnk.
Are you sure you want to continue connecting (yes/no)? yes
Warning: permanently added '[127.0.0.1]:2222' to client/known_hosts.
Connected to 127.0.0.1.
sftp> pwd
/
sftp> ls
admin
projects
public
sftp> mkdir demo
sftp> stat /
  File: /
  Type: directory
  Mode: drwxrwxrwx (0o777)
  Size: 0
Modify: 2026-11-22 19:21:33
Access: 2026-11-22 19:21:33
sftp> put README.md /demo/README.md
README.md -> /demo/README.md (15 bytes)
sftp> get /demo/README.md ./README.copy.md
/demo/README.md -> ./README.copy.md (15 bytes)
sftp> ls -l /demo
-rw-rw-rw-    1 0        0              15 Nov 22 19:21 README.md
sftp> ls /projects
error: Permission denied (PERMISSION_DENIED)
sftp> stat /nope
error: No such file (NO_SUCH_FILE)
sftp> mkdir demo
error: File already exists (FAILURE)
sftp> quit
```

The client builds the SFTP v3 packets itself. asyncssh is only used for the SSH connection and
to open the `sftp` subsystem channel. It sends one request at a time and checks that every reply
has the request id it sent.

**OpenSSH interop.** Tested with OpenSSH_9.7p1 (the one that comes with Windows):

```
Connected to 127.0.0.1.
sftp> pwd
Remote working directory: /
sftp> ls
admin     projects  public
sftp> mkdir demo
sftp> put README.md /demo/README.md
Uploading README.md to /demo/README.md
sftp> get /demo/README.md copy.md
Fetching /demo/README.md to copy.md
sftp> ls -l /demo
-rw-rw-rw-    1 0        0              15 Nov 22 19:47 README.md
sftp> ls /projects
Can't ls: "/projects" not found
```

OpenSSH `sftp` has no `stat` command, so `stat .` answers "Invalid command" from the OpenSSH client
itself; use `ls -l` instead. OpenSSH also prints "not found" for any failed stat, also when our server
answered PERMISSION_DENIED (the audit log shows the real reason).

## Predefined users

Users, roles and clearances are fixed. There is no way to create or delete them while the
server runs; you edit the files in `server/data/` and restart. The passwords are **not** in
this README. `users.json` only stores salted hashes.

| User  | Role    | Clearance    | Intended powers and limits |
|-------|---------|--------------|----------------------------|
| alice | analyst | internal     | Reads and writes in `/projects` (she owns it). Reads `/public`. Cannot read `/projects/confidential` (MAC: no read up). Cannot touch `/admin` (RBAC). |
| bob   | admin   | internal     | RBAC lets him do everything, and he owns `/`, `/public` and `/admin`. But he is not in the `analyst` group, so DAC keeps him out of `/projects`, and MAC keeps him away from anything confidential. |
| carol | analyst | confidential | Owns `/projects/confidential` and can read everything in `/projects`. MAC (no write down) stops her from writing into `/projects` or `/public`. |
| eve   | guest   | public       | Can only read `/public`. Everything else is denied. She is the attacker in the CTF. |

To add or change a user, run `python server/auth.py <username>`. It asks for a password
(at least 8 characters) and prints the JSON entry to paste into `users.json`.

## Data files (`server/data/`)

All five files are required and are read once at startup.

| File | Content |
|------|---------|
| `users.json` | List of users: `username`, `salt` and `password_hash` (base64), and the scrypt settings `n, r, p, dklen`. |
| `user_roles.json` | `{"alice": ["analyst"], ...}` |
| `role_perms.csv` | `role,prefix,read,write,delete`. A `y` in an action column grants it, empty means no. Extra action columns can be added. |
| `mac_labels.json` | `levels` (lowest first), `labels` (path prefix → level) and `users` (user → clearance). |
| `dac_owners.csv` | `prefix,owner,group,dir_mode,file_mode`. Modes are octal, like `755`. A user is in the group named after each of their roles. |

On load we check that every user, role and level mentioned in one file exists in the others,
that prefixes start with `/`, and that modes and `y` cells are valid.

## Access Control Design

_To be written by whoever does Part 4: how DAC, MAC and RBAC are applied, the composition
rule and the 2x2 table. The data files above are the input to that section._

## Authentication

- Passwords are hashed with scrypt (`n=16384, r=8, p=1`) and a random 16-byte salt per user.
- Hashes are compared with `hmac.compare_digest`.
- A username that does not exist still gets a full hash, so the response time does not reveal which names are real.
- 5 wrong passwords in a row lock that account for 60 seconds. A correct password resets the count.
- Passwords are never logged or stored in plain text.

## Audit log

Every login attempt (and, through `audit.log()`, every access decision from `policy.py`) is
appended to `server/audit.jsonl`. Fields: `timestamp` (UTC), `user`, `op`, `path`, `allowed`, `reason`.
Login lines have `"op": "login"` and no path. Sample, from a real run:

```
{"timestamp": "2026-11-19T18:17:01+00:00", "user": "alice", "op": "login", "path": null, "allowed": true, "reason": "ok"}
{"timestamp": "2026-11-19T18:17:01+00:00", "user": "mallory", "op": "login", "path": null, "allowed": false, "reason": "unknown user"}
{"timestamp": "2026-11-19T18:17:02+00:00", "user": "eve", "op": "login", "path": null, "allowed": false, "reason": "wrong password, account locked for 60s"}
{"timestamp": "2026-11-19T18:17:02+00:00", "user": "eve", "op": "login", "path": null, "allowed": false, "reason": "account locked"}
```

An access decision looks the same (this one is only an example of the format):

```
{"timestamp": "...", "user": "eve", "op": "read", "path": "/projects/confidential/x", "allowed": false, "reason": "..."}
```

## CTF

Plant the flag before starting the server:

```
python ctf/setup_flag.py --flag "FLAG{group07_sftp_wins}"
```

It writes `/projects/confidential/flag.txt` inside the jail and a hint in `/public/ctf_hint.txt`.
Only carol can read the flag. What stops the others:

| User  | DAC (carol, analyst, 660) | MAC (confidential) | RBAC | Result |
|-------|------|------|------|--------|
| eve   | other, denied | public, denied | guest has only /public, denied | denied |
| bob   | other, denied | internal, denied | admin, allowed | denied |
| alice | group, allowed | internal, denied | analyst, allowed | denied |
| carol | owner, allowed | confidential, allowed | analyst, allowed | allowed |

Path tricks (`..`, backslashes, case variants, 8.3 names, NTFS streams, NUL bytes) are stopped
before policy by `canonicalize()` and `safe_join()`. To try the attacks yourself:

```
python ctf/attack.py --username eve
```

It runs 24 attempts (traversal, aliasing, forged and reused handles, symlink, rename, write through a read handle)
and prints which ones were blocked. The full story is in `CTF_writeup.pdf`.

## Known limitations

- The lockout is per username and lives in memory. A restart clears it, and someone who knows a username can lock that user out for a minute.
- A locked account is refused without hashing, so it answers a little faster than a wrong password.
- Hashing takes about 35 ms and runs inside the event loop, so other connections wait briefly during a login.
- `audit.jsonl` is never rotated, and anyone who can write to the file can change it.
- Only password login is supported. The password is protected by the SSH connection, not by anything of ours.
- The client sends one request at a time (no pipelining), so big transfers are slower than with OpenSSH `sftp`.
- The client reads the password with `getpass`, so it cannot be scripted without a terminal.

## Use of generative AI

AI was used to generate the users.json file, and review/adjust loader.py and auth.py files.