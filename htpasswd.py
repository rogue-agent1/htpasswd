#!/usr/bin/env python3
"""htpasswd - Generate and verify HTTP basic auth password hashes.

One file. Zero deps. Guards gates.

Usage:
  htpasswd.py hash "password"                → SHA256 hash
  htpasswd.py hash "password" --algo md5     → APR1 MD5 hash
  htpasswd.py hash "password" --algo sha1    → SHA1 hash
  htpasswd.py entry admin "password"         → user:hash line
  htpasswd.py verify admin '$apr1$...' "pw"  → check password
  htpasswd.py file users.htpasswd add admin  → interactive add
  htpasswd.py file users.htpasswd list       → list users
  htpasswd.py file users.htpasswd check admin "pw"
"""

import argparse
import base64
import hashlib
import os
import sys
import getpass


def sha1_hash(password: str) -> str:
    """SHA1 hash (Apache {SHA} format)."""
    digest = hashlib.sha1(password.encode()).digest()
    return "{SHA}" + base64.b64encode(digest).decode()


def ssha_hash(password: str) -> str:
    """Salted SHA1 hash ({SSHA} format)."""
    salt = os.urandom(8)
    digest = hashlib.sha1(password.encode() + salt).digest()
    return "{SSHA}" + base64.b64encode(digest + salt).decode()


def sha256_hash(password: str) -> str:
    """SHA256 with random salt."""
    salt = os.urandom(16).hex()
    digest = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"$sha256${salt}${digest}"


def plaintext_hash(password: str) -> str:
    """Plaintext (not recommended)."""
    return password


def hash_password(password: str, algo: str = "sha256") -> str:
    algos = {
        "sha1": sha1_hash,
        "ssha": ssha_hash,
        "sha256": sha256_hash,
        "plain": plaintext_hash,
    }
    if algo not in algos:
        raise ValueError(f"Unknown algo: {algo}. Choose from: {', '.join(algos)}")
    return algos[algo](password)


def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against a hash."""
    if hashed.startswith("{SHA}"):
        expected = sha1_hash(password)
        return hashed == expected
    elif hashed.startswith("{SSHA}"):
        decoded = base64.b64decode(hashed[6:])
        digest = decoded[:20]
        salt = decoded[20:]
        check = hashlib.sha1(password.encode() + salt).digest()
        return digest == check
    elif hashed.startswith("$sha256$"):
        parts = hashed.split('$')
        salt = parts[2]
        expected = hashlib.sha256((salt + password).encode()).hexdigest()
        return parts[3] == expected
    else:
        # Plaintext fallback
        return hashed == password


def cmd_hash(args):
    pw = args.password
    if not pw:
        pw = getpass.getpass("Password: ")
    print(hash_password(pw, args.algo))


def cmd_entry(args):
    pw = args.password
    if not pw:
        pw = getpass.getpass("Password: ")
    h = hash_password(pw, args.algo)
    print(f"{args.user}:{h}")


def cmd_verify(args):
    if verify_password(args.password, args.hash):
        print("✓ Password matches")
        return 0
    else:
        print("✗ Password does not match")
        return 1


def cmd_file(args):
    path = args.path

    if args.subcmd == "list":
        if not os.path.exists(path):
            print(f"File not found: {path}", file=sys.stderr)
            return 1
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and ':' in line:
                    user, _ = line.split(':', 1)
                    print(f"  {user}")
        return 0

    if args.subcmd == "add":
        user = args.user
        pw = getpass.getpass(f"Password for {user}: ")
        h = hash_password(pw, args.algo)
        line = f"{user}:{h}\n"

        # Remove existing entry for user
        lines = []
        if os.path.exists(path):
            with open(path) as f:
                lines = [l for l in f if not l.startswith(user + ':')]
        lines.append(line)
        with open(path, 'w') as f:
            f.writelines(lines)
        print(f"Added {user} to {path}")
        return 0

    if args.subcmd == "check":
        user = args.user
        pw = args.password
        if not os.path.exists(path):
            print(f"File not found: {path}", file=sys.stderr)
            return 1
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line.startswith(user + ':'):
                    _, h = line.split(':', 1)
                    if verify_password(pw, h):
                        print(f"✓ {user} authenticated")
                        return 0
                    else:
                        print(f"✗ Wrong password for {user}")
                        return 1
        print(f"✗ User {user} not found")
        return 1

    if args.subcmd == "rm":
        user = args.user
        if not os.path.exists(path):
            return 1
        with open(path) as f:
            lines = [l for l in f if not l.startswith(user + ':')]
        with open(path, 'w') as f:
            f.writelines(lines)
        print(f"Removed {user}")
        return 0


def main():
    argv = sys.argv[1:]
    subcmds = {"hash", "entry", "verify", "file"}

    if not argv or argv[0] in ('-h', '--help'):
        print(__doc__)
        return 0

    cmd = argv[0]

    if cmd == "hash":
        parser = argparse.ArgumentParser()
        parser.add_argument("_", help="hash")
        parser.add_argument("password", nargs="?")
        parser.add_argument("--algo", "-a", default="sha256", choices=["sha1", "ssha", "sha256", "plain"])
        args = parser.parse_args(argv)
        cmd_hash(args)
        return 0

    if cmd == "entry":
        parser = argparse.ArgumentParser()
        parser.add_argument("_")
        parser.add_argument("user")
        parser.add_argument("password", nargs="?")
        parser.add_argument("--algo", "-a", default="sha256")
        args = parser.parse_args(argv)
        cmd_entry(args)
        return 0

    if cmd == "verify":
        parser = argparse.ArgumentParser()
        parser.add_argument("_")
        parser.add_argument("user")
        parser.add_argument("hash")
        parser.add_argument("password")
        args = parser.parse_args(argv)
        return cmd_verify(args)

    if cmd == "file":
        parser = argparse.ArgumentParser()
        parser.add_argument("_")
        parser.add_argument("path")
        parser.add_argument("subcmd", choices=["list", "add", "check", "rm"])
        parser.add_argument("user", nargs="?")
        parser.add_argument("password", nargs="?")
        parser.add_argument("--algo", "-a", default="sha256")
        args = parser.parse_args(argv)
        return cmd_file(args)

    print(f"Unknown command: {cmd}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main() or 0)
