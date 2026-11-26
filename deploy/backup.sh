#!/usr/bin/env bash
set -euo pipefail
umask 077

# Verified atomic tarball backup of persistent fatext-server state.
# Usage: bash deploy/backup.sh [DATA_DIR] [BACKUP_DIR]

DATA_DIR="${1:-/var/lib/fatext}"
BACKUP_DIR="${2:-/var/backups/fatext}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)-$$"
OUT="${BACKUP_DIR}/fatext-${STAMP}.tar.gz"
TMP="${OUT}.tmp"

if [[ ! -d "$DATA_DIR" ]]; then
  echo "Error: DATA_DIR does not exist: $DATA_DIR" >&2
  exit 1
fi

mkdir -p "$BACKUP_DIR"
if [[ $EUID -eq 0 || -O "$BACKUP_DIR" ]]; then
  chmod 0700 "$BACKUP_DIR"
fi
trap 'rm -f "$TMP"' EXIT

ITEMS=()
for name in keys friends mail docs rooms blacklist public registration-work; do
  if [[ -e "${DATA_DIR}/${name}" ]]; then
    ITEMS+=("$name")
  fi
done
if [[ "${FATEXT_BACKUP_SKIP_ACME:-0}" != 1 && -d "${DATA_DIR}/acme" ]]; then
  ITEMS+=("acme")
fi

if [[ ${#ITEMS[@]} -eq 0 ]]; then
  echo "Error: no persistent fatext state entries found in ${DATA_DIR}" >&2
  exit 1
fi

for name in hidden.json posting.json recovery-required; do
  if [[ -f "${DATA_DIR}/moderation/$name" ]]; then
    ITEMS+=("moderation/$name")
  fi
done

TAR_RC=0
for attempt in 1 2 3; do
  set +e
  tar --exclude='*.tmp.*' --exclude='*.tmp' -C "$DATA_DIR" -czf "$TMP" "${ITEMS[@]}"
  TAR_RC=$?
  set -e
  if [[ $TAR_RC -eq 0 ]]; then
    break
  elif [[ $TAR_RC -eq 1 && $attempt -lt 3 ]]; then
    rm -f "$TMP"
    sleep 1
  else
    exit $TAR_RC
  fi
done
tar -tzf "$TMP" >/dev/null
chmod 0600 "$TMP"
mv -f "$TMP" "$OUT"
trap - EXIT
echo "Backup written: $OUT"

# Keep last 14 snapshots (portable across GNU and BSD/macOS xargs)
OLD="$(ls -1t "${BACKUP_DIR}"/fatext-*.tar.gz 2>/dev/null | tail -n +15 || true)"
if [[ -n "$OLD" ]]; then
  while IFS= read -r f; do
    [[ -n "$f" ]] && rm -f "$f"
  done <<< "$OLD"
fi
