#!/usr/bin/env bash
set -euo pipefail

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
chmod 0700 "$BACKUP_DIR"
trap 'rm -f "$TMP"' EXIT

ITEMS=()
for name in keys friends mail docs rooms blacklist public; do
  if [[ -e "${DATA_DIR}/${name}" ]]; then
    ITEMS+=("$name")
  fi
done

if [[ ${#ITEMS[@]} -eq 0 ]]; then
  echo "Error: no persistent fatext state entries found in ${DATA_DIR}" >&2
  exit 1
fi

tar -C "$DATA_DIR" -czf "$TMP" "${ITEMS[@]}"
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
