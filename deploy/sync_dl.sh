#!/usr/bin/env bash
set -euo pipefail

# Sync fatext-cli release assets from private GitHub Release into FATEXT_DL_DIR.
# Verifies SHA256SUMS and optional RSA-PSS signature (SHA256SUMS.sig) before publishing.
#
# Usage:
#   bash deploy/sync_dl.sh [TAG] [DL_DIR] [OFFICIAL_PEM]
# Example:
#   sudo bash deploy/sync_dl.sh latest /var/lib/fatext/dl https://fatext.com/k/ftx_fatextoffice.pem

TAG="${1:-latest}"
DL_DIR="${2:-/var/lib/fatext/dl}"
OFFICIAL_PEM="${3:-}"
REPO="${FATEXT_CLI_REPO:-xulang-org/fatext-cli}"

if [[ -n "$OFFICIAL_PEM" && "$OFFICIAL_PEM" == http://* ]]; then
  echo "Error: refusing insecure http:// OFFICIAL_PEM URL (use https:// or a local file path)" >&2
  exit 1
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "Error: gh CLI is required to download from ${REPO}" >&2
  exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "Downloading release '${TAG}' from ${REPO}..."
if [[ "$TAG" == "latest" ]]; then
  gh release download --repo "$REPO" --dir "$TMP"
else
  gh release download "$TAG" --repo "$REPO" --dir "$TMP"
fi

if [[ ! -f "${TMP}/SHA256SUMS" ]]; then
  echo "Error: SHA256SUMS missing from release assets" >&2
  exit 1
fi

echo "Verifying SHA256SUMS against downloaded archives..."
(
  cd "$TMP"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c SHA256SUMS --ignore-missing
  else
    shasum -a 256 -c SHA256SUMS --ignore-missing
  fi
)

if [[ -n "$OFFICIAL_PEM" ]]; then
  if [[ "$OFFICIAL_PEM" == http://* ]]; then
    echo "Error: refusing insecure http:// OFFICIAL_PEM URL (use https:// or a local file path)" >&2
    exit 1
  fi
  if [[ ! -f "${TMP}/SHA256SUMS.sig" ]]; then
    echo "Error: OFFICIAL_PEM given, but SHA256SUMS.sig is missing" >&2
    exit 1
  fi
  PEM_PATH="${TMP}/official.pem"
  if [[ "$OFFICIAL_PEM" == https://* ]]; then
    curl -fsSL "$OFFICIAL_PEM" -o "$PEM_PATH"
  else
    cp "$OFFICIAL_PEM" "$PEM_PATH"
  fi
  openssl base64 -d -A -in "${TMP}/SHA256SUMS.sig" -out "${TMP}/SHA256SUMS.sig.bin" 2>/dev/null \
    || cp "${TMP}/SHA256SUMS.sig" "${TMP}/SHA256SUMS.sig.bin"
  openssl dgst -sha256 -verify "$PEM_PATH" \
    -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -sigopt rsa_mgf1_md:sha256 \
    -signature "${TMP}/SHA256SUMS.sig.bin" "${TMP}/SHA256SUMS"
  rm -f "${TMP}/SHA256SUMS.sig.bin" "$PEM_PATH"
  echo "Verified SHA256SUMS.sig against official public key."
fi

VERIFIED_FILES=()
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  fname="${line#* }"
  fname="${fname# }"
  fname="${fname#\*}"
  if [[ "$fname" == */* ]]; then
    echo "Error: unsafe path in SHA256SUMS: ${fname}" >&2
    exit 1
  fi
  if [[ -f "${TMP}/${fname}" ]]; then
    if [[ ! "$fname" =~ ^(fatext-[A-Za-z0-9._-]+\.(tar\.gz|zip)|install\.sh)$ ]]; then
      echo "Error: unsupported artifact name in SHA256SUMS: ${fname}" >&2
      exit 1
    fi
    VERIFIED_FILES+=("${TMP}/${fname}")
  fi
done < "${TMP}/SHA256SUMS"

if [[ ${#VERIFIED_FILES[@]} -eq 0 ]]; then
  echo "Error: no verified artifacts from SHA256SUMS found in release" >&2
  exit 1
fi

install -d -m 0755 "$DL_DIR"
for f in "${VERIFIED_FILES[@]}" "${TMP}/SHA256SUMS" "${TMP}/SHA256SUMS.sig"; do
  if [[ -f "$f" ]]; then
    base="$(basename "$f")"
    install -m 0644 "$f" "${DL_DIR}/${base}.tmp"
    mv -f "${DL_DIR}/${base}.tmp" "${DL_DIR}/${base}"
  fi
done

if [[ $EUID -eq 0 ]] && id -u fatext >/dev/null 2>&1; then
  chown -R fatext:fatext "$DL_DIR"
fi

# Resolve synced SemVer and update latest.json so /.well-known/fatext.json stays dynamic
SYNC_VER=""
if [[ "$TAG" != "latest" && "$TAG" =~ ^v([0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?)$ ]]; then
  SYNC_VER="${BASH_REMATCH[1]}"
fi
if [[ -z "$SYNC_VER" ]]; then
  SYNC_VER="$(ls -1 "${DL_DIR}"/fatext-v*.tar.gz "${DL_DIR}"/fatext-v*.zip 2>/dev/null \
    | sed -nE 's|.*/fatext-v([0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?)-(macos|linux|windows)-.*|\1|p' \
    | sort -V | tail -n 1 || true)"
fi
if [[ -n "$SYNC_VER" ]]; then
  NOW_UTC="$(date -u +%s)"
  printf '{"latest_version":"%s","updated_at":%s}\n' "$SYNC_VER" "$NOW_UTC" > "${DL_DIR}/latest.json.tmp"
  chmod 0644 "${DL_DIR}/latest.json.tmp"
  if [[ $EUID -eq 0 ]] && id -u fatext >/dev/null 2>&1; then
    chown fatext:fatext "${DL_DIR}/latest.json.tmp"
  fi
  mv -f "${DL_DIR}/latest.json.tmp" "${DL_DIR}/latest.json"
  echo "Updated ${DL_DIR}/latest.json -> ${SYNC_VER}"
fi

echo "Published CLI artifacts to ${DL_DIR}:"
ls -lh "$DL_DIR"
