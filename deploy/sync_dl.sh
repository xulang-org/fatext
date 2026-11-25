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
  if [[ ! -f "${TMP}/SHA256SUMS.sig" ]]; then
    echo "Error: OFFICIAL_PEM given, but SHA256SUMS.sig is missing" >&2
    exit 1
  fi
  PEM_PATH="${TMP}/official.pem"
  if [[ "$OFFICIAL_PEM" == http://* || "$OFFICIAL_PEM" == https://* ]]; then
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

install -d -m 0755 "$DL_DIR"
for f in "${TMP}"/fatext-*.tar.gz "${TMP}"/fatext-*.zip "${TMP}/SHA256SUMS" "${TMP}/SHA256SUMS.sig" "${TMP}/install.sh"; do
  if [[ -f "$f" ]]; then
    base="$(basename "$f")"
    install -m 0644 "$f" "${DL_DIR}/${base}.tmp"
    mv -f "${DL_DIR}/${base}.tmp" "${DL_DIR}/${base}"
  fi
done

if [[ $EUID -eq 0 ]] && id -u fatext >/dev/null 2>&1; then
  chown -R fatext:fatext "$DL_DIR"
fi

echo "Published CLI artifacts to ${DL_DIR}:"
ls -lh "$DL_DIR"
