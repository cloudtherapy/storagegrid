#!/usr/bin/env bash
set -euo pipefail

# StorageGRID Avahi Fix - Indexed array loop (WSL-safe) + set -e safe counters
# v4.3
# - Reads servers.txt (PowerShell: Name, IPAddress)
# - SSH to nodes on port 8022 as 'admin'
# - Elevate to root (sudo -S; fallback su -)
# - In container: ln -s /etc/sv/avahi-daemon /var/local/service && start avahi-daemon
# - Order: admin -> gateway -> storage
# - Indexed array iteration (no stdin loops), 'ssh -n' to avoid stdin consumption
# - Counter increments use assignment arithmetic (ok=$((ok+1))) to be safe with set -e

VERSION="4.3"
ADMIN_USER="admin"
SSH_PORT=8022
SERVERS_FILE=""
DRY_RUN=0
DEBUG=0

info() { echo "INFO:  $*"; }
warn() { echo "WARN:  $*"; }
fail() { echo "ERROR: $*" >&2; exit 1; }

usage() {
  cat <<USAGE
StorageGRID Avahi Fix v${VERSION}

Usage:
  $(basename "$0") -s servers.txt [--dry-run] [--debug] [-u admin] [-p 8022]

Environment:
  SG_ADMIN_PASSWORD   Admin SSH password (if not set, you'll be prompted)
USAGE
}

prompt_password() { local pw; read -r -s -p "Enter admin SSH password: " pw; echo; printf "%s" "$pw"; }

# Parse servers.txt (tolerate CRLF); output "name ip"
parse_servers() {
  local file="$1"; [[ -f "$file" ]] || fail "servers file not found: $file"
  awk '
    NR<=2 { next }              # skip header lines
    NF<2 { next }               # skip blanks
    { sub(/\r$/,"") }           # strip CR (Windows)
    $1 ~ /^vm-sg-/ && $2 ~ /^[0-9.]+$/ { print $1, $2 }
  ' "$file"
}

# Order: -adm- first, then -gw-, then -stg-
order_nodes() {
  local list="$1"
  awk '
    {
      n=$1; ip=$2; w=99;
      if (n ~ /-adm-/) w=0; else if (n ~ /-gw-/) w=1; else if (n ~ /-stg-/) w=2;
      printf("%02d %s %s\n", w, n, ip);
    }
  ' <<< "$list" | sort -V | awk '{print $2, $3}'
}

# Build remote one-liner (no heredocs in loop path)
build_remote_cmd() {
  local cname="$1"
  # single-quoted heredoc used locally to build one string; LF-normalized environment required
  cat <<'EOS' | sed "s|__CNAME__|$(printf '%s' "$cname" | sed "s/[&/\]/\\&/g")|g"
CNAME='__CNAME__'; set -euo pipefail;
rt="$(command -v docker || true)"; [ -z "$rt" ] && rt="$(command -v podman || true)";
if [ -z "$rt" ]; then echo "[remote] No docker/podman found"; exit 1; fi
echo "[remote] Runtime: $rt"
cont="$("$rt" ps --format '{{.Names}}' | awk -v want="$CNAME" '
  $0==want { print; found=1; exit }
  /^storagegrid-/ { if (!cand) cand=$0 }
  END { if (!found) print cand }
')"
if [ -z "$cont" ]; then echo "[remote] No storagegrid container running"; "$rt" ps || true; exit 1; fi
echo "[remote] Using container: $cont"
"$rt" exec -u 0 "$cont" sh -lc '
  set -e
  [ -e /var/local/service/avahi-daemon ] || ln -s /etc/sv/avahi-daemon /var/local/service || true
  if command -v service >/dev/null 2>&1; then
    service avahi-daemon start || true
  elif command -v systemctl >/dev/null 2>&1; then
    systemctl start avahi-daemon || true
  elif command -v sv >/dev/null 2>&1; then
    sv start avahi-daemon || true
  else
    echo "[remote] No known service manager (service/systemctl/sv)"; exit 1
  fi
  command -v pgrep >/dev/null 2>&1 && pgrep -x avahi-daemon >/dev/null 2>&1 || echo "[remote] avahi-daemon not yet visible (may still be starting)"
'
echo "[remote] Fix applied."
EOS
}

process_host() {
  local name="$1" ip="$2" pw="$3"
  local cname="storagegrid-${name}"
  info "---- ${name} (${ip}) -> ${cname}"

  if (( DRY_RUN )); then
    info "[dry-run] Would SSH ${ADMIN_USER}@${ip}:${SSH_PORT}, elevate, and patch ${cname}"
    return 0
  fi

  local REMOTE_CMD; REMOTE_CMD="$(build_remote_cmd "$cname")"

  # Try sudo path first; '-n' ensures ssh does not read from parent stdin
  set +e
  sshpass -p "$pw" ssh -n -p "$SSH_PORT" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o RequestTTY=no -o ConnectTimeout=10 \
    "${ADMIN_USER}@${ip}" \
    "printf '%s\n' '${pw}' | sudo -S -p '' bash -lc $(printf %q "$REMOTE_CMD")"
  local rc=$?
  set -e

  if (( rc != 0 )); then
    warn "sudo path failed on ${name}; trying su - (requires TTY)"
    set +e
    sshpass -p "$pw" ssh -tt -p "$SSH_PORT" \
      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 \
      "${ADMIN_USER}@${ip}" \
      "su - -c $(printf %q "bash -lc \"$REMOTE_CMD\"")" < /dev/null
    rc=$?
    set -e
  fi

  if (( rc == 0 )); then
    info "SUCCESS: ${name}"
  else
    warn "FAILED: ${name} (rc=$rc)"
    return 1
  fi
}

main() {
  # Args
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -s|--servers) SERVERS_FILE="$2"; shift 2;;
      -u|--user) ADMIN_USER="$2"; shift 2;;
      -p|--port) SSH_PORT="$2"; shift 2;;
      --dry-run) DRY_RUN=1; shift;;
      --debug) DEBUG=1; set -x; shift;;
      -h|--help) usage; exit 0;;
      *) usage; exit 1;;
    esac
  done
  [[ -n "$SERVERS_FILE" ]] || { usage; exit 1; }

  echo "StorageGRID Avahi Fix v${VERSION}"
  echo "Servers file: $SERVERS_FILE"
  echo "SSH: ${ADMIN_USER}@<ip>:${SSH_PORT}"
  echo "Dry-run: $DRY_RUN  Debug: $DEBUG"

  for c in awk ssh sshpass; do command -v "$c" >/dev/null 2>&1 || fail "Missing dependency: $c"; done

  # Parse/order and load into an array (no stdin loops)
  local parsed ordered
  parsed="$(parse_servers "$SERVERS_FILE")"
  [[ -n "$parsed" ]] || fail "No valid Name/IP pairs parsed from $SERVERS_FILE"
  echo "Parsed nodes:"; echo "$parsed" | sed 's/^/  /'
  ordered="$(order_nodes "$parsed")"
  echo "Execution order:"; echo "$ordered" | sed 's/^/  /'

  # Map into array, robust to WSL; fallback if mapfile missing
  declare -a NODES=()
  if command -v mapfile >/dev/null 2>&1; then
    mapfile -t NODES <<< "$ordered"
  else
    IFS=$'\n' read -r -d '' -a NODES < <(printf '%s\0' "$ordered")
  fi
  echo "Total nodes: ${#NODES[@]}"

  local ADMIN_PW="${SG_ADMIN_PASSWORD:-}"
  [[ -n "$ADMIN_PW" ]] || ADMIN_PW="$(prompt_password)"

  local ok=0 bad=0
  local i entry name ip
  for i in "${!NODES[@]}"; do
    entry="${NODES[$i]}"
    name="${entry%% *}"
    ip="${entry##* }"
    echo "INFO:  Index $i -> entry='$entry'  name='$name'  ip='$ip'"
    if [[ -z "$name" || -z "$ip" || "$name" == "$ip" ]]; then
      warn "Skipping malformed entry at index $i: '$entry'"
      continue
    fi
    if process_host "$name" "$ip" "$ADMIN_PW"; then
      ok=$((ok+1))     # SAFE with set -e
    else
      bad=$((bad+1))   # SAFE with set -e
    fi
  done

  echo "======================================="
  echo "Completed: success=$ok, failed=$bad"
  if [[ $bad -eq 0 ]]; then exit 0; else exit 1; fi
}

main "$@"