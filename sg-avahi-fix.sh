#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------
# StorageGRID Avahi Discovery Fix
# - Connects to VMs on port 8022 as 'admin'
# - Escalates to root via sudo
# - Runs inside container 'storagegrid-<VM_NAME>'
#   * ln -s /etc/sv/avahi-daemon /var/local/service (idempotent)
#   * start avahi-daemon service
# ------------------------------------------------------------

# Defaults
SSH_USER="admin"
SSH_PORT=8022
SERVERS_FILE="./servers.txt"
LOG_FILE="./sg-avahi-fix.log"
CONTAINER_PREFIX="storagegrid-"
DRY_RUN=0
PARALLEL=0   # keep sequential to ensure admins first
KEY_FILE=""  # optional: SSH private key path

# Secure password storage options (checked in this order):
# 1) ENV var ADMIN_PASS (discouraged, but supported)
# 2) Linux keyring (secret-tool)
# 3) GPG encrypted file (~/.netapp-sg/admin.pass.gpg)
# 4) Prompt at runtime (no echo)
USE_KEYRING=1
GPG_FILE="${HOME}/.netapp-sg/admin.pass.gpg"

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  --servers FILE         Path to servers.txt (default: ${SERVERS_FILE})
  --port N               SSH port (default: ${SSH_PORT})
  --user NAME            SSH username (default: ${SSH_USER})
  --key PATH             SSH private key to use (optional)
  --dry-run              Show actions but do not execute
  --no-keyring           Do not use Linux keyring (secret-tool)
  --gpg-file PATH        Path to GPG-encrypted admin password file (default: ${GPG_FILE})
  --store-pass           Store/update admin password securely (keyring or GPG)
  --parallel             Process non-admin nodes in parallel (admins still first)
  --log FILE             Log file (default: ${LOG_FILE})
  -h, --help             Show this help

Notes:
- Expects 'servers.txt' with two columns: Name and IPAddress (headers allowed).
- Connects as 'admin' on port 8022. Needs sudo privileges on the VM.
- Requires 'ssh' on this machine. If password-only SSH is needed, requires 'sshpass'.
- Remote node must have docker or podman.
EOF
}

log() { printf "%s %s\n" "$(date +'%F %T')" "$*" | tee -a "$LOG_FILE" >&2; }

have_cmd() { command -v "$1" >/dev/null 2>&1; }

# Read password from sources (ENV -> keyring -> GPG -> prompt)
get_admin_password() {
  if [[ -n "${ADMIN_PASS:-}" ]]; then
    printf "%s" "${ADMIN_PASS}"
    return 0
  fi

  # If a temporary password file was created for one-shot runs, prefer it
  if [[ -n "${TEMP_PASS_FILE:-}" ]] && [[ -f "$TEMP_PASS_FILE" ]]; then
    # read without adding a trailing newline
    local pw
    pw=$(cat -- "$TEMP_PASS_FILE")
    printf "%s" "$pw"
    return 0
  fi

  if (( USE_KEYRING )) && have_cmd secret-tool; then
    # service=netapp-sg account=admin
    local pw
    if pw=$(secret-tool lookup service netapp-sg account admin 2>/dev/null); then
      if [[ -n "$pw" ]]; then
        printf "%s" "$pw"
        return 0
      fi
    fi
  fi

  if [[ -f "$GPG_FILE" ]] && have_cmd gpg; then
    local pw
    if pw=$(gpg --quiet --batch --decrypt "$GPG_FILE" 2>/dev/null); then
      if [[ -n "$pw" ]]; then
        printf "%s" "$pw"
        return 0
      fi
    fi
  fi

  # prompt
  >&2 printf "Admin password (won't echo): "
  stty -echo
  local pw
  IFS= read -r pw
  stty echo
  >&2 printf "\n"
  printf "%s" "$pw"
}

# Create a one-time in-memory-backed secure temporary password file and
# register cleanup. This prompts once (no-echo) if ADMIN_PASS/env not set.
ensure_admin_password_once() {
  # If ADMIN_PASS already provided in environment, materialize it to a temp file
  if [[ -n "${ADMIN_PASS:-}" ]]; then
    local pw="$ADMIN_PASS"
  else
    # Try keyring or existing persistent gpg file first
    if (( USE_KEYRING )) && have_cmd secret-tool; then
      if pw=$(secret-tool lookup service netapp-sg account admin 2>/dev/null); then
        if [[ -n "$pw" ]]; then
          : # have pw from keyring
        fi
      fi
    fi
    if [[ -z "${pw:-}" ]] && [[ -f "$GPG_FILE" ]] && have_cmd gpg; then
      if pw=$(gpg --quiet --batch --decrypt "$GPG_FILE" 2>/dev/null); then
        : # got pw from gpg
      fi
    fi
    if [[ -z "${pw:-}" ]]; then
      # prompt once
      >&2 printf "Admin password (won't echo): "
      stty -echo
      IFS= read -r pw
      stty echo
      >&2 printf "\n"
    fi
  fi

  # Ensure we have a password
  if [[ -z "${pw:-}" ]]; then
    echo "No admin password available." >&2
    return 1
  fi

  # Create a secure temp file containing the password for non-interactive use
  TEMP_PASS_FILE=$(mktemp --tmpdir netapp-sg-pass.XXXXXX)
  chmod 600 "$TEMP_PASS_FILE"
  # Avoid trailing newline issues: write exactly the password
  printf "%s" "$pw" > "$TEMP_PASS_FILE"

  # Ensure the stored password is removed on exit (best-effort wipe)
  cleanup_admin_password() {
    if [[ -n "${TEMP_PASS_FILE:-}" ]] && [[ -f "$TEMP_PASS_FILE" ]]; then
      # Overwrite then remove
      if command -v shred >/dev/null 2>&1; then
        shred -u "$TEMP_PASS_FILE" >/dev/null 2>&1 || rm -f "$TEMP_PASS_FILE" >/dev/null 2>&1 || true
      else
        # Truncate then remove
        : > "$TEMP_PASS_FILE" || true
        rm -f "$TEMP_PASS_FILE" >/dev/null 2>&1 || true
      fi
    fi
    # If a secret-tool entry was written by other flows, leave it alone (we only created temp file)
    unset TEMP_PASS_FILE
    unset pw
  }
  trap cleanup_admin_password EXIT
  return 0
}

store_admin_password() {
  # Prompt for password to store
  printf "Enter admin password to store (won't echo): "
  stty -echo
  local pw
  IFS= read -r pw
  stty echo
  printf "\n"

  if (( USE_KEYRING )) && have_cmd secret-tool; then
    printf "%s" "$pw" | secret-tool store --label="StorageGRID Admin" service netapp-sg account admin
    echo "Stored admin password in Linux keyring (secret-tool)."
    return 0
  fi

  mkdir -p "$(dirname "$GPG_FILE")"
  if have_cmd gpg; then
    # Try non-interactive loopback pinentry first (reads passphrase from stdin).
    # --passphrase-fd 0 consumes the passphrase we pipe in; stdin is also the data stream,
    # but for symmetric encryption gpg reads passphrase from the fd and the plaintext from stdin.
    printf "%s" "$pw" | gpg --quiet --batch --yes --symmetric --cipher-algo AES256 --pinentry-mode loopback --passphrase-fd 0 -o "$GPG_FILE"
    local rc=$?
    if [[ $rc -ne 0 ]] || [[ ! -f "$GPG_FILE" ]]; then
      # Fallback: try interactive symmetric encryption (will prompt for a passphrase)
      echo "Non-interactive GPG encryption failed (rc=$rc). Falling back to interactive gpg..."
      printf "%s" "$pw" | gpg --quiet --batch --yes --symmetric --cipher-algo AES256 -o "$GPG_FILE" 2>/dev/null || true
    fi

    if [[ ! -f "$GPG_FILE" ]]; then
      echo "Failed to create GPG-encrypted file: $GPG_FILE" >&2
      echo "If using gpg >=2.1 and loopback fails, add 'allow-loopback-pinentry' to ~/.gnupg/gpg-agent.conf and run 'gpgconf --kill gpg-agent', then retry."
      return 1
    fi

    chmod 600 "$GPG_FILE"
    echo "Stored admin password in GPG-encrypted file: $GPG_FILE"
    return 0
  fi

  echo "No secure storage available (secret-tool or gpg)."
  echo "Install one of them, or export ADMIN_PASS in the environment (less secure)."
  return 1
}

# Parse servers.txt into arrays, order: admins, gateways, storage
declare -a NAMES IPS
parse_servers() {
  if [[ ! -f "$SERVERS_FILE" ]]; then
    echo "servers.txt not found at: $SERVERS_FILE" >&2
    exit 1
  fi

  # Strip CRLF, ignore header lines, and blank lines
  local line name ip
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line//$'\r'/}"
    # Skip headers or separators
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^Name[[:space:]] ]] && continue
    [[ "$line" =~ ^-+ ]] && continue

    # Split on whitespace; first token is Name, last token is IP
    # This tolerates varying spacing
    name=$(awk '{print $1}' <<<"$line")
    ip=$(awk '{print $NF}' <<<"$line")

    # Basic sanity
    [[ "$name" =~ ^vm-sg- ]] || continue
    [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue

    NAMES+=("$name")
    IPS+=("$ip")
  done < "$SERVERS_FILE"

  if (( ${#NAMES[@]} == 0 )); then
    echo "No valid entries parsed from $SERVERS_FILE" >&2
    exit 1
  fi
}

# Create ordered index list: admin -> gateway -> storage -> other
declare -a ORDERED_IDX
order_nodes() {
  local i
  # Admin first
  for i in "${!NAMES[@]}"; do [[ "${NAMES[$i]}" == *"-adm-"* ]] && ORDERED_IDX+=("$i"); done
  # Gateways
  for i in "${!NAMES[@]}"; do [[ "${NAMES[$i]}" == *"-gw-"* ]] && ORDERED_IDX+=("$i"); done
  # Storage
  for i in "${!NAMES[@]}"; do [[ "${NAMES[$i]}" == *"-stg-"* ]] && ORDERED_IDX+=("$i"); done
  # Any others
  for i in "${!NAMES[@]}"; do
    if [[ "${NAMES[$i]}" != *"-adm-"* && "${NAMES[$i]}" != *"-gw-"* && "${NAMES[$i]}" != *"-stg-"* ]]; then
      ORDERED_IDX+=("$i")
    fi
  done
}

# Check whether we can SSH using key (no password)
can_ssh_with_key() {
  local host="$1"
  local opts=(-p "$SSH_PORT" -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=8)
  [[ -n "$KEY_FILE" ]] && opts+=(-i "$KEY_FILE")
  ssh "${opts[@]}" "${SSH_USER}@${host}" "echo ok" >/dev/null 2>&1
}

# Run remote commands with sudo, using either key or sshpass+password
remote_sudo_exec() {
  local host="$1"; shift
  local cmd="$*"

  # Default ssh options (do not allocate a tty by default to avoid echoing piped passwords)
  local ssh_opts_base=(-p "$SSH_PORT" -o StrictHostKeyChecking=no -o ConnectTimeout=15)
  local ssh_opts=("${ssh_opts_base[@]}")
  [[ -n "$KEY_FILE" ]] && ssh_opts+=(-i "$KEY_FILE")

  if can_ssh_with_key "$host"; then
    # Key-based SSH; still need sudo password unless NOPASSWD is configured
    # Provide sudo password on stdin from temp file (non-interactive)
    if [[ -n "${TEMP_PASS_FILE:-}" && -f "$TEMP_PASS_FILE" ]]; then
      ssh "${ssh_opts[@]}" "${SSH_USER}@${host}" "sudo -S -p '' bash -lc '$cmd'" < "$TEMP_PASS_FILE"
    else
      # Fallback to prompting (shouldn't happen if ensure_admin_password_once was called)
      local pw
      pw="$(get_admin_password)"
      # Interactive fallback: allocate a tty so sudo prompts work
      ssh_opts+=( -tt )
      ssh "${ssh_opts[@]}" "${SSH_USER}@${host}" "sudo -S -p '' bash -lc '$cmd'" <<<"$pw"
    fi
    return $?
  else
    # Password-based SSH requires sshpass. Use sshpass -f to read password from secure temp file.
    if ! have_cmd sshpass; then
      echo "sshpass is required for non-interactive password-based SSH. Install it and retry." >&2
      return 1
    fi
    if [[ -n "${TEMP_PASS_FILE:-}" && -f "$TEMP_PASS_FILE" ]]; then
      # Use sshpass to provide the SSH login password, and feed sudo the password via stdin
      SSH_ASKPASS_REQUIRE=never sshpass -f "$TEMP_PASS_FILE" ssh "${ssh_opts[@]}" "${SSH_USER}@${host}" "sudo -S -p '' bash -lc '$cmd'" < "$TEMP_PASS_FILE"
    else
      # Fallback to prompting
      local pw
      pw="$(get_admin_password)"
      # Interactive fallback: allocate a tty for manual password entry
      ssh_opts+=( -tt )
      SSH_ASKPASS_REQUIRE=never sshpass -p "$pw" ssh "${ssh_opts[@]}" "${SSH_USER}@${host}" "sudo -S -p '' bash -lc '$cmd'" <<<"$pw"
    fi
  fi
}

# Build the container-exec command payload
#
# NOTE: The inner container script was updated to avoid calling systemctl/service
# wrappers that may invoke Python helpers or expect a full systemd/D-Bus session
# (which often fail inside minimal containers and produce errors like
# '/sbin/detect-user-login.py failed: exit code 1'). The new logic prefers:
#  1) checking if avahi-daemon is already running;
#  2) using classic SysV init script (/etc/init.d) when present;
#  3) using runit/sv if available;
#  4) falling back to `systemctl --no-block start` as a last-resort best-effort.
#
# This provides a more robust, idempotent approach for varied container images.
container_fix_script() {
  local vm_name="$1"
  local cengine='$(
    if command -v docker >/dev/null 2>&1; then echo docker;
    elif command -v podman >/dev/null 2>&1; then echo podman;
    else echo none; fi
  )'

  # Inline script that runs on the remote host as root
  cat <<'EOS'
set -euo pipefail

# Determine container engine
if command -v docker >/dev/null 2>&1; then
  CENGINE="docker"
elif command -v podman >/dev/null 2>&1; then
  CENGINE="podman"
else
  echo "No container engine found (docker/podman)." >&2
  exit 2
fi
VM_NAME_PLACEHOLDER
CONTAINER_NAME="CONTAINER_PREFIX_PLACEHOLDER${VM_NAME}"

# Ensure container exists / running
if ! $CENGINE ps --format '{{.Names}}' | grep -xq "$CONTAINER_NAME"; then
  echo "Container '$CONTAINER_NAME' not found in '$CENGINE ps'." >&2
  echo "Containers present:" >&2
  $CENGINE ps --format '{{.Names}}' >&2 || true
  exit 3
fi
# Compose a robust inner command for the container (run as root -u 0)
INNER=$(cat <<'EOF_INNER'
set -euo pipefail

# Idempotent symlink
if [ ! -e /var/local/service/avahi-daemon ]; then
  ln -s /etc/sv/avahi-daemon /var/local/service || true
fi

# Check if avahi-daemon is already running
if pgrep -f avahi-daemon >/dev/null 2>&1; then
  echo "avahi-daemon already running"
  exit 0
fi

# Try classic SysV init script if present
if [ -x /etc/init.d/avahi-daemon ]; then
  echo "Starting avahi-daemon via /etc/init.d/avahi-daemon"
  /etc/init.d/avahi-daemon start || true
  sleep 1
  pgrep -f avahi-daemon >/dev/null 2>&1 && { echo "avahi-daemon started"; exit 0; } || true
fi

# Try runit/sv
if command -v sv >/dev/null 2>&1; then
  echo "Starting avahi-daemon via sv"
  sv up avahi-daemon || true
  sleep 1
  pgrep -f avahi-daemon >/dev/null 2>&1 && { echo "avahi-daemon started"; exit 0; } || true
fi

# As a last resort try systemctl but avoid wrappers that require a full systemd/D-Bus session.
if command -v systemctl >/dev/null 2>&1; then
  echo "Attempting systemctl start (best-effort, may fail inside container)"
  systemctl --no-block start avahi-daemon 2>/dev/null || systemctl start avahi-daemon 2>/dev/null || true
  sleep 1
  pgrep -f avahi-daemon >/dev/null 2>&1 && { echo "avahi-daemon started"; exit 0; } || true
fi

echo "Unable to start avahi-daemon via known init methods; attempted /etc/init.d, sv, and systemctl." >&2
# Show any available status output (best-effort)
({ /etc/init.d/avahi-daemon status 2>/dev/null || systemctl status avahi-daemon 2>/dev/null || sv status avahi-daemon 2>/dev/null || true; } ) | head -n 20
exit 3
EOF_INNER
)

# Execute inside container as root
$CENGINE exec -u 0 "$CONTAINER_NAME" bash -lc "$INNER"
EOS
}

# Run fix on a single node
process_node() {
  local name="$1" ip="$2"
  local container_name="${CONTAINER_PREFIX}${name}"

  log "==== Processing ${name} (${ip}) ===="

  if (( DRY_RUN )); then
    echo "[DRY-RUN] Would connect to ${ip} as ${SSH_USER} and fix container ${container_name}"
    return 0
  fi

  # Build remote script with placeholders replaced
  local remote_script
  remote_script="$(container_fix_script "$name")"
  remote_script="${remote_script//VM_NAME_PLACEHOLDER/VM_NAME=\"$name\"}"
  remote_script="${remote_script//CONTAINER_PREFIX_PLACEHOLDER/$CONTAINER_PREFIX}"

  # Escape for single-quoted remote payload
  # (We already single-quote the bash -lc payload in remote_sudo_exec.)
  remote_script=$(printf "%s" "$remote_script" | sed "s/'/'\\\\''/g")

  if remote_sudo_exec "$ip" "$remote_script"; then
    log "SUCCESS: ${name} (${ip}) fixed."
  else
    log "ERROR: ${name} (${ip}) failed."
    return 1
  fi
}

# -------------------- CLI parsing --------------------
STORE_PASS=0
while (( "$#" )); do
  case "$1" in
    --servers)        SERVERS_FILE="$2"; shift 2;;
    --port)           SSH_PORT="$2"; shift 2;;
    --user)           SSH_USER="$2"; shift 2;;
    --key)            KEY_FILE="$2"; shift 2;;
    --dry-run)        DRY_RUN=1; shift;;
    --no-keyring)     USE_KEYRING=0; shift;;
    --gpg-file)       GPG_FILE="$2"; shift 2;;
    --store-pass)     STORE_PASS=1; shift;;
    --parallel)       PARALLEL=1; shift;;
    --log)            LOG_FILE="$2"; shift 2;;
    -h|--help)        usage; exit 0;;
    *) echo "Unknown option: $1" >&2; usage; exit 1;;
  esac
done

# Optionally store/update password securely, then exit
if (( STORE_PASS )); then
  store_admin_password || exit 1
  exit 0
fi

# Preflight
: > "$LOG_FILE" || { echo "Cannot write log file: $LOG_FILE"; exit 1; }
have_cmd ssh || { echo "ssh not found"; exit 1; }

parse_servers
order_nodes

# Prepare one-shot admin password storage for non-dry runs. This prompts once
# and creates a secure temporary file used for sshpass and sudo stdin.
if (( DRY_RUN == 0 )); then
  ensure_admin_password_once || { echo "Failed to obtain admin password." >&2; exit 1; }
fi

# Process nodes: admins first (already ordered)
# Keep sequential by default; parallel only for non-admin segments if enabled.
errors=0

# Identify indexes for categories to allow optional parallelization later
declare -a ADM_IDX GW_IDX STG_IDX OTH_IDX
for i in "${ORDERED_IDX[@]}"; do
  case "${NAMES[$i]}" in
    *-adm-*) ADM_IDX+=("$i");;
    *-gw-*)  GW_IDX+=("$i");;
    *-stg-*) STG_IDX+=("$i");;
    *)       OTH_IDX+=("$i");;
  esac
done

# Always do admins sequentially, first
for i in "${ADM_IDX[@]}"; do
  name="${NAMES[$i]}"; ip="${IPS[$i]}"
  process_node "$name" "$ip" || ((errors++))
done
run_group() {
  local -n idxs=$1
  if (( PARALLEL )) && (( ${#idxs[@]} > 1 )); then
    pids=()
    for i in "${idxs[@]}"; do
      process_node "${NAMES[$i]}" "${IPS[$i]}" &
      pids+=($!)
    done
    for p in "${pids[@]}"; do wait "$p" || ((errors++)); done
  else
    for i in "${idxs[@]}"; do
      process_node "${NAMES[$i]}" "${IPS[$i]}" || ((errors++))
    done
  fi
}

# Then gateways, storage, others
run_group GW_IDX
run_group STG_IDX
run_group OTH_IDX

if (( errors > 0 )); then
  log "Completed with ${errors} error(s). Check ${LOG_FILE}."
  exit 1
else
  log "All nodes processed successfully."
fi