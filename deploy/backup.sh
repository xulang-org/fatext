#!/usr/bin/env bash
set -euo pipefail

# Encrypted/tarball backup of persistent fatext-server state.
# Usage: bash deploy/backup.sh [DATA_DIR] [BACKUP_DIR]

DATA_DIR="${1:-/var/lib/fatext}"
BACKUP_DIR="${2:-/var/backups/fatext}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${BACKUP_DIR}/fatext-${STAMP}.tar.gz"

mkdir -p "$BACKUP_DIR"
chmod 0700 "$BACKUP_DIR"

tar -C "$DATA_DIR" -czf "$OUT" \
  keys \
  friends \
  mail \
  channels \
  threads \
  daily \
  channels.json \
  pins.json \
  banned_emails.txt 2>/dev/null || tar -C "$DATA_DIR" -czf "$OUT" .

chmod 0600 "$OUT"
echo "Backup written: $OUT"

# Keep last 14 snapshots
ls -1t "${BACKUP_DIR}"/fatext-*.tar.gz 2>/dev/null | tail -n +15 | xargs -r rm -f
