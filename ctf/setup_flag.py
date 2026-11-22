import argparse
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_JAIL = ROOT / "server" / "sftp_root"
DEFAULT_FLAG = "FLAG{group07_sftp_wins}"
FLAG_PATH = "/projects/confidential/flag.txt"

HINT = """Welcome to the CTF.

The flag is in /projects/confidential/flag.txt.
Only someone with confidential clearance who is allowed there by DAC and RBAC can read it.
Every attempt is written to the audit log.
"""


def plant_flag(jail_dir=DEFAULT_JAIL, flag=DEFAULT_FLAG):
    jail = Path(jail_dir)
    target = jail.joinpath(*FLAG_PATH.strip("/").split("/"))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(flag + "\n", encoding="utf-8")
    try:
        os.chmod(target, 0o600)
    except OSError:
        pass
    hint = jail / "public" / "ctf_hint.txt"
    hint.parent.mkdir(parents=True, exist_ok=True)
    hint.write_text(HINT, encoding="utf-8")
    return target


def main():
    parser = argparse.ArgumentParser(description="plant the CTF flag")
    parser.add_argument("--flag", default=DEFAULT_FLAG)
    parser.add_argument("--jail", default=str(DEFAULT_JAIL))
    args = parser.parse_args()
    print(f"flag written to {plant_flag(args.jail, args.flag)}")


if __name__ == "__main__":
    main()
