#!/usr/bin/env bash
set -euo pipefail

# Verified atomic restore of fatext-server persistent state from deploy/backup.sh archives.
# Usage:
#   bash deploy/restore.sh <BACKUP_TAR_GZ> [DATA_DIR] [--dry-run]

ARCHIVE="${1:-}"
DATA_DIR="${2:-/var/lib/fatext}"
MODE="${3:-}"

if [[ "$DATA_DIR" == "--dry-run" ]]; then
  MODE="--dry-run"
  DATA_DIR="/var/lib/fatext"
fi

if [[ -z "$ARCHIVE" || ! -f "$ARCHIVE" ]]; then
  echo "Usage: bash deploy/restore.sh <BACKUP_TAR_GZ> [DATA_DIR] [--dry-run]" >&2
  exit 1
fi

if [[ -n "$MODE" && "$MODE" != "--dry-run" ]]; then
  echo "Unknown flag: $MODE" >&2
  exit 1
fi

# Verify tarball readability & reject unsafe paths (absolute paths, '..', symlinks, hardlinks, devices)
MANIFEST="$(tar -tzf "$ARCHIVE")"
while IFS= read -r entry; do
  [[ -z "$entry" ]] && continue
  if [[ "$entry" == /* || "$entry" == ../* || "$entry" == */../* || "$entry" == */.. || "$entry" == ".." ]]; then
    echo "Error: unsafe path in backup archive: $entry" >&2
    exit 1
  fi
done <<< "$MANIFEST"

VERBOSE_MANIFEST="$(tar -tvzf "$ARCHIVE")"
while IFS= read -r vline; do
  [[ -z "$vline" ]] && continue
  ftype="${vline:0:1}"
  if [[ "$ftype" == "l" || "$ftype" == "h" || "$ftype" == "b" || "$ftype" == "c" || "$ftype" == "p" ]]; then
    echo "Error: unsafe entry type (${ftype}) in backup archive: $vline" >&2
    exit 1
  fi
done <<< "$VERBOSE_MANIFEST"

if [[ "$MODE" == "--dry-run" ]]; then
  echo "Dry-run verified archive (${ARCHIVE}):"
  printf '%s\n' "$MANIFEST"
  exit 0
fi

mkdir -p "$DATA_DIR"
PARENT_DIR="$(cd "$(dirname "$DATA_DIR")" && pwd)"
STAGE="$(mktemp -d "${PARENT_DIR}/.fatext-restore.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT

tar -xzf "$ARCHIVE" -C "$STAGE"

# A data snapshot can predate a visibility decision. Preserve local decisions.
# A fresh destination stays dark until the operator reconciles the latest ledger.
if [[ -L "${DATA_DIR}/moderation" ]]; then
  echo "Error: moderation directory must not be a symbolic link" >&2
  exit 1
fi
install -d -m 0750 "${DATA_DIR}/moderation"
if [[ ! -f "${DATA_DIR}/moderation/hidden.json" ]]; then
  touch "${DATA_DIR}/moderation/recovery-required"
  chmod 0640 "${DATA_DIR}/moderation/recovery-required"
  for name in hidden.json posting.json; do
    if [[ -f "${STAGE}/moderation/$name" ]]; then
      install -m 0640 "${STAGE}/moderation/$name" "${DATA_DIR}/moderation/$name"
    fi
  done
fi

RESTORED=0
for name in keys friends mail docs rooms blacklist public registration-work acme; do
  if [[ -e "${STAGE}/${name}" ]]; then
    rm -rf "${DATA_DIR}/${name}.bak" 2>/dev/null || true
    if [[ -e "${DATA_DIR}/${name}" ]]; then
      mv "${DATA_DIR}/${name}" "${DATA_DIR}/${name}.bak"
    fi
    mv "${STAGE}/${name}" "${DATA_DIR}/${name}"
    rm -rf "${DATA_DIR}/${name}.bak"
    RESTORED=$((RESTORED + 1))
  fi
done

mkdir -p "${DATA_DIR}/logs" "${DATA_DIR}/dl"
chmod 0755 "$DATA_DIR"
for name in keys friends mail docs rooms blacklist public registration-work logs dl; do
  [[ -d "${DATA_DIR}/${name}" ]] && chmod 0755 "${DATA_DIR}/${name}"
done
if [[ -d "${DATA_DIR}/acme" ]]; then
  chmod 0700 "${DATA_DIR}/acme"
  for pf in "${DATA_DIR}/acme"/*.pem; do
    [[ -f "$pf" ]] && chmod 0600 "$pf"
  done
fi

if [[ $EUID -eq 0 ]] && id -u fatext >/dev/null 2>&1; then
  chown -R fatext:fatext "$DATA_DIR"
fi

echo "Restore complete (${RESTORED} state roots) into ${DATA_DIR}"
