# htpasswd

Generate and verify HTTP basic auth password hashes.

One file. Zero deps. Guards gates.

## Usage

```bash
# Hash a password
python3 htpasswd.py hash "password"
python3 htpasswd.py hash "password" --algo sha1

# Generate user:hash entry
python3 htpasswd.py entry admin "password"

# Verify password
python3 htpasswd.py verify admin '$sha256$...' "password"

# Manage htpasswd file
python3 htpasswd.py file users.htpasswd add admin
python3 htpasswd.py file users.htpasswd list
python3 htpasswd.py file users.htpasswd check admin "pw"
python3 htpasswd.py file users.htpasswd rm admin
```

Algorithms: sha256 (default), ssha, sha1, plain

## Requirements

Python 3.8+. No dependencies.

## License

MIT
