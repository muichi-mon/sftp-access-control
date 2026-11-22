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
tests/           pytest tests (test_sftp.py, test_client.py)
ctf/             setup_flag.py (plants the flag), attack.py (attack script)
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
Modify: 2026-11-22 21:01:27
Access: 2026-11-22 21:01:27
sftp> put README.md /demo/README.md
README.md -> /demo/README.md (20856 bytes)
sftp> get /demo/README.md ./README.copy.md
/demo/README.md -> ./README.copy.md (20856 bytes)
sftp> ls -l /demo
-rw-rw-rw-    1 0        0           20856 Nov 22 21:01 README.md
sftp> ls /projects
error: Permission denied (PERMISSION_DENIED)
sftp> stat /nope
error: No such file (NO_SUCH_FILE)
sftp> mkdir demo
error: File already exists (FAILURE)
sftp> quit
```

`stat` and `ls -l` show the real mode bits of the file on disk (on Windows always `rw` for everyone).
They are not the DAC modes from `dac_owners.csv`; those are what the server enforces.

The client builds the SFTP v3 packets itself. asyncssh is only used for the SSH connection and
to open the `sftp` subsystem channel. It sends one request at a time and checks that every reply
has the request id it sent.

**OpenSSH interop.** Tested with OpenSSH_9.7p1 (the one that comes with Windows). This output is
from an earlier, separate run with a smaller `README.md`, so the file size differs from the session above:

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
| bob   | admin   | internal     | RBAC lets him do everything, and he owns `/`, `/public` and `/admin`. But he is not in the `analyst` group, so DAC keeps him out of `/projects`, MAC keeps him away from anything confidential, and MAC (no write down) means he can read `/public` but not write to it. |
| carol | analyst | confidential | Owns `/projects/confidential` and can read everything in `/projects`. MAC (no write down) stops her from writing into `/projects` or `/public`. |
| eve   | guest   | public       | Can only read `/public` (so she starts with `cd /public`; `ls /` is denied because the root is labelled internal and the guest role only covers `/public`). Everything else is denied. She is the attacker in the CTF. |

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

All access control goes through one function, `policy.authorize(user, op, path)`, which returns
`(allowed, reason)` and writes one audit line per decision. The rules come from the data files in
`server/data/` and are fixed while the server runs.

### Operations covered

| SFTP request | AuthZ operation | Notes |
|--------------|-----------------|-------|
| `REALPATH` | `realpath` | Always allowed for a logged-in user: it only cleans up the path and touches no file. Still audited. |
| `STAT`, `LSTAT` | `stat` | |
| `OPENDIR` | `list` | `READDIR` then reads from the handle. |
| `MKDIR` | `mkdir` | The mode sent by the client is ignored. |
| `OPEN` with only `READ` | `read` | |
| `OPEN` with `WRITE`, `APPEND`, `CREAT` or `TRUNC` | `write` | |
| `OPEN` with `READ` and a write flag | `read` **and** `write` | Both must be allowed, so write access can never be used to read a file. |
| `REMOVE` | `remove` | |
| `RMDIR` | `rmdir` | |
| `READ`, `WRITE`, `FSTAT`, `CLOSE` | none | They work on a handle that was authorized at `OPEN`/`OPENDIR`. Handles belong to one session, and a handle remembers whether it was opened for reading or writing. |
| `SETSTAT`, `RENAME`, `SYMLINK`, `READLINK`, anything else | none | Answered with `OP_UNSUPPORTED`. |

**Default deny.** A request is refused when:
- the operation is not in the table above,
- no rule matches the path in one of the three models,
- the user has no clearance or no roles,
- the policy data is not loaded, or
- `authorize()` raises an error.

### Enforcement point

Every request that names a path goes through the same steps in [server/server.py](server/server.py):

1. `canonicalize()` turns the client path into a clean POSIX path rooted at `/` (the jail).
   It refuses `..` above the root, backslashes, colons, control characters and NUL bytes.
2. `safe_join()` maps that path to the OS path inside `server/sftp_root/`. It refuses the path
   if `realpath()` gives back anything else, which blocks symlinks and, on Windows, case
   variants, 8.3 short names and device names.
3. `policy.authorize()` decides, using the canonical path from step 1.
4. Only then is the filesystem called.

A request stopped at step 1 or 2 never reaches the policy. The server audits it itself, with the
raw path and the reason (for example `path escapes the jail`).

### DAC (owner / group / other)

- **Ownership.** [dac_owners.csv](server/data/dac_owners.csv) gives each path prefix an owner,
  a group, a `dir_mode` and a `file_mode`, in octal like Unix. A path uses the entry with the
  **longest matching prefix**. A path with no matching entry is denied.
- **Groups.** A user is in a group when they have a role with the same name. For example, alice
  and carol have the `analyst` role, so they are in the `analyst` group.
- **Which bits apply.** If the user is the owner, the owner bits apply. Otherwise, if the user is
  in the group, the group bits apply. Otherwise the "other" bits apply.
- **Bits needed for each operation:**

  | Operation | Mode used | Bits needed |
  |-----------|-----------|-------------|
  | `read` | `file_mode` | r |
  | `write` | `file_mode` | w |
  | `stat` | `file_mode` (`dir_mode` when the path is itself a prefix in the CSV) | r |
  | `list` | `dir_mode` | r and x |
  | `mkdir`, `rmdir`, `remove` | `dir_mode` | w and x (they change the folder, as on Unix) |

  So on a folder, x is what allows listing it. Without x, `ls` is denied even if r is set.
  `stat` only needs r, so by design the x bit does **not** affect `stat`: with `dir_mode 744`,
  "other" can `stat` the folder but not `ls` it. The x bit of parent folders is not checked
  (no Unix-style path traversal check); each path is judged by its own closest DAC entry.
- **Inheritance.** New files and folders do not get their own entry. They inherit the owner,
  group and modes of the closest prefix above them. For example, a file that alice uploads to
  `/projects/demo/` follows the `/projects` entry. The mode a client sends with `MKDIR` or
  `OPEN` is ignored.

Examples with `/projects` (owner alice, group analyst, `dir 770`, `file 660`):

| User | Class | `read /projects/a.txt` | `write /projects/a.txt` | `list /projects` |
|------|-------|------------------------|-------------------------|------------------|
| alice | owner | allowed (rw-) | allowed | allowed (rwx) |
| carol | group (analyst) | allowed (rw-) | allowed | allowed (rwx) |
| bob | other | denied (---) | denied | denied |

On `/public` (`dir 755`, `file 644`), eve is "other": she can list the folder (r-x) and read
files (r--), but not write them.

### MAC (Bell-LaPadula)

- **Labels, lowest first:** `public` < `internal` < `confidential`.
- **Storage.** [mac_labels.json](server/data/mac_labels.json) holds the `levels`, the path labels
  (`labels`, longest prefix wins, so `/projects/confidential` overrides `/projects`) and each
  user's clearance (`users`).

  | Prefix | Label |
  |--------|-------|
  | `/` | internal |
  | `/public` | public |
  | `/projects` | internal |
  | `/projects/confidential` | confidential |
  | `/admin` | internal |

  | User | Clearance |
  |------|-----------|
  | alice | internal |
  | bob | internal |
  | carol | confidential |
  | eve | public |

- **Reading** (`read`, `stat`, `list`) needs clearance ≥ label: **no read up**.
- **Writing** (`write`, `mkdir`, `rmdir`, `remove`) needs clearance ≤ label: **no write down**.
- A user without a clearance, or a path without a label, is denied.

Examples:
- alice (internal) can read `/public` and `/projects`, but not `/projects/confidential` (read up).
- carol (confidential) can read everything, but cannot write into `/projects` or `/public` (write down).
- eve (public) cannot `ls /`, because the root is labelled internal.

### RBAC (roles)

- [user_roles.json](server/data/user_roles.json) gives each user a list of roles.
- [role_perms.csv](server/data/role_perms.csv) gives each role actions on path prefixes.
  A `y` grants the action.
- **Actions.** Each operation needs one action:
  - `read`: `read`, `stat`, `list`
  - `write`: `write`, `mkdir`
  - `delete`: `remove`, `rmdir`

  `realpath` needs no action: `authorize()` allows it before the models are checked (see
  [Operations covered](#operations-covered)).

| Role | Prefix | read | write | delete |
|------|--------|------|-------|--------|
| admin | `/` | y | y | y |
| analyst | `/projects` | y | y | |
| analyst | `/public` | y | | |
| guest | `/public` | y | | |

- **Scoping.** Inside one role, only the most specific (longest) matching prefix counts. So an
  analyst gets only `read` under `/public`, and nothing at all under `/admin`.
- **Several roles.** A user's permissions are the **union** of their roles' permissions. Giving
  alice the `admin` role as well would let her `mkdir` under `/admin` (as far as RBAC is concerned).
- **Per-user overrides.** `check_rbac()` also supports per-user `allow` and `deny` rules. A
  `deny` is checked first and **always overrides** any allow. The shipped data files do not
  define any overrides, so this is only used in the tests.

### Composition rule

```
allowed = DAC allows  AND  MAC allows  AND  RBAC allows
```

All three models are always evaluated. If any of them denies, the request is denied, and the
audit reason lists every model that said no. There is no other conflict rule: a deny from one
model cannot be outvoted by the others.

Example outcomes with the real data. RBAC allows all four requests below, so DAC and MAC
alone decide:

|  | **MAC allows** | **MAC denies** |
|--|----------------|----------------|
| **DAC allows** | alice reads `/projects/plan.txt` → **allowed** | alice reads `/projects/confidential/flag.txt` → **denied** (no read up) |
| **DAC denies** | bob reads `/projects/plan.txt` → **denied** (bob is "other" on 660) | bob reads `/projects/confidential/flag.txt` → **denied** (both) |

### Auditing

Every decision is appended as one JSON line to `server/audit.jsonl`. This covers policy
decisions, requests stopped by the jail, and logins. The fields are `timestamp` (UTC), `user`,
`op`, `path`, `allowed` and `reason`. Passwords are never logged. Sample:

```
{"timestamp": "2026-11-22T18:53:11+00:00", "user": "alice", "op": "read", "path": "/projects/confidential/flag.txt", "allowed": false, "reason": "denied: MAC: no read up (internal -> confidential)"}
{"timestamp": "2026-11-22T18:53:12+00:00", "user": "bob", "op": "write", "path": "/projects/confidential/flag.txt", "allowed": false, "reason": "denied: DAC: other lacks 0o2 on /projects/confidential (file mode 0o660)"}
{"timestamp": "2026-11-22T18:53:10+00:00", "user": "eve", "op": "read", "path": "/../../server/data/users.json", "allowed": false, "reason": "path escapes the jail"}
```

### Self-tests

The tests are in [tests/test_sftp.py](tests/test_sftp.py) and [tests/test_client.py](tests/test_client.py).
Each test has a one-line docstring with its objective and builds its own fixtures (temporary jail,
users, roles and labels). Run them with `python -m pytest -v`.

| Area | Tests |
|------|-------|
| DAC | `test_dac_owner_read_write_and_other_denied`, `test_dac_directory_execute_controls_listing` |
| MAC | `test_mac_no_read_up_and_no_write_down` |
| RBAC | `test_rbac_analyst_scope_role_union_and_deny_override` |
| Composite | `test_composite_dac_allows_mac_denies`, `test_composite_mac_allows_dac_denies`, `test_composite_all_allow` |
| Traversal | `test_traversal_denied_before_policy_and_audited`, `test_canonicalize_refuses_escapes`, `test_safe_join_refuses_symlink` |
| Audit | `test_eve_cannot_read_confidential`, `test_composite_all_allow`, `test_traversal_denied_before_policy_and_audited`, `test_sftp_end_to_end`, `test_sftp_end_to_end_real_policy` |
| End to end, several users | `test_sftp_end_to_end_real_policy`, `test_only_carol_reads_the_flag` |

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

Access decisions use the same fields. See the samples under [Auditing](#auditing) above.

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

It runs 18 attempts (traversal, aliasing, forged and reused handles, symlink, rename, write through a read handle)
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

AI tools were used to review code contributions from group members, and to create `users.json` and the
`README.md`. AI was also used to update and adjust the test files and the server files, with some updates to
`ctf/attack.py`. AI was used as a collaborative tool for better teamwork and project comprehension, and all
AI-assisted code and writeup was reviewed by the group.