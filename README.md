# StorageGRID Avahi Fix

This repository contains `sg-avahi-fix.sh`, a utility to connect to StorageGRID VMs over SSH (port 8022 by default), enter their `storagegrid-<VM>` container, and ensure `avahi-daemon` is running in a robust, idempotent way.

## Features
- Connects as `admin` (default) and escalates with `sudo` to run inside the container as root.
- Supports key-based SSH or password-based SSH (uses `sshpass` for non-interactive runs).
- Prompts once for the admin password, stores it temporarily in a secure temp file during the run, and deletes it on exit.
- Avoids calling systemd wrappers inside containers that can fail (e.g. `detect-user-login.py` errors).
- Dry-run mode to preview actions without making changes.

## Usage

Basic:

```bash
./sg-avahi-fix.sh
```

Options:

- `--servers FILE`    Path to `servers.txt` (default: `./servers.txt`).
- `--port N`          SSH port (default: 8022).
- `--user NAME`       SSH username (default: `admin`).
- `--key PATH`        SSH private key to use (optional).
- `--dry-run`         Show actions but do not execute.
- `--no-keyring`      Do not use Linux keyring (secret-tool).
- `--gpg-file PATH`   Path to GPG-encrypted admin password file (default: `~/.netapp-sg/admin.pass.gpg`).
- `--store-pass`      Store/update admin password securely (keyring or GPG) and exit.
- `--parallel`        Process non-admin nodes in parallel (admins still first).
- `--log FILE`        Log file (default: `./sg-avahi-fix.log`).
- `-h, --help`        Show help.

Notes:
- Expects `servers.txt` with two columns: Name and IPAddress (headers allowed). Lines not matching `vm-sg-` nodes are ignored.
- If password-based SSH is required, `sshpass` must be installed for non-interactive runs.

## Password handling
- The script will attempt to obtain the admin password in this order:
  1. `ADMIN_PASS` environment variable (discouraged).
  2. Linux keyring (via `secret-tool`).
  3. GPG-encrypted file (`~/.netapp-sg/admin.pass.gpg`).
  4. Prompt once at runtime (no echo).
- When prompting, the password is stored temporarily in a secure file (`mktemp`) with `chmod 600` for the duration of the run and removed on exit. The password is not printed to stdout.
- You can store the password permanently using `--store-pass` which will save to keyring (preferred) or GPG.

## Troubleshooting
- If you see errors like `/sbin/detect-user-login.py failed: exit code 1`, the container image may not have a full systemd environment; the script avoids calling `systemctl` directly and prefers `/etc/init.d` or `runit` when available.
- If `gpg --pinentry-mode loopback` fails, add `allow-loopback-pinentry` to `~/.gnupg/gpg-agent.conf` and run `gpgconf --kill gpg-agent`.
- To run against a single host for testing, temporarily edit `servers.txt` to only contain that host, or run with `--dry-run` first.

## Safety
- The script attempts to securely wipe the temporary password file using `shred` if available, or truncates+deletes otherwise. If the script is killed with SIGKILL the cleanup trap won't run; consider running from a secure environment or using key-based auth.

## License
MIT
