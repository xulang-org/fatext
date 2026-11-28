#!/usr/bin/env bash
set -euo pipefail

# Sync fatext-cli release assets from GitHub Releases into FATEXT_DL_DIR.
# Verifies RSA-PSS signature (SHA256SUMS.sig) before downloading binary archives
# and verifies SHA256SUMS digests before publishing atomically.
#
# Usage:
#   bash deploy/sync_dl.sh [--force] [TAG] [DL_DIR] [OFFICIAL_PEM]
# Example:
#   sudo bash deploy/sync_dl.sh latest /var/lib/fatext/dl https://fatext.com/k/ftx_fatextoffice.pem

FORCE="${FATEXT_SYNC_FORCE:-0}"
if [[ "${1:-}" == "--force" ]]; then
  FORCE=1
  shift
fi

TAG="${1:-latest}"
DL_DIR="${2:-/var/lib/fatext/dl}"
OFFICIAL_PEM="${3:-}"
REPO="${FATEXT_CLI_REPO:-xulang-org/fatext-cli}"
SEMVER_TAG_RE='^v[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$'

if [[ -n "$OFFICIAL_PEM" && "$OFFICIAL_PEM" == http://* ]]; then
  echo "Error: refusing insecure http:// OFFICIAL_PEM URL (use https:// or a local file path)" >&2
  exit 1
fi

if [[ "$TAG" != "latest" ]] && [[ ! "$TAG" =~ $SEMVER_TAG_RE ]]; then
  echo "Error: invalid release tag '${TAG}'" >&2
  exit 1
fi

resolve_latest_tag() {
  local api_url="https://api.github.com/repos/${REPO}/releases/latest"
  local token="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
  local json_out=""
  local resolved=""

  if command -v curl >/dev/null 2>&1; then
    if [[ -n "$token" ]]; then
      json_out="$(curl -fsSL -H "Accept: application/vnd.github+json" -H "Authorization: Bearer ${token}" "$api_url" 2>/dev/null || true)"
    else
      json_out="$(curl -fsSL -H "Accept: application/vnd.github+json" "$api_url" 2>/dev/null || true)"
    fi
    if [[ -n "$json_out" ]]; then
      if command -v python3 >/dev/null 2>&1; then
        resolved="$(printf '%s' "$json_out" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("tag_name",""))' 2>/dev/null || true)"
      else
        resolved="$(printf '%s' "$json_out" | sed -nE 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' | head -n 1)"
      fi
    fi
  fi

  if [[ -z "$resolved" ]] && command -v gh >/dev/null 2>&1; then
    resolved="$(gh release view --repo "$REPO" --json tagName --jq .tagName 2>/dev/null || true)"
  fi

  if [[ -z "$resolved" ]] || [[ ! "$resolved" =~ $SEMVER_TAG_RE ]]; then
    echo "Error: failed to resolve valid latest release tag from ${REPO}" >&2
    exit 1
  fi
  printf '%s' "$resolved"
}

if [[ "$TAG" == "latest" ]]; then
  RESOLVED_TAG="$(resolve_latest_tag)"
else
  RESOLVED_TAG="$TAG"
fi
RESOLVED_VER="${RESOLVED_TAG#v}"

if [[ "$FORCE" != "1" && -f "${DL_DIR}/latest.json" && -f "${DL_DIR}/SHA256SUMS" ]]; then
  CUR_VER="$(sed -nE 's/.*"latest_version"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' "${DL_DIR}/latest.json" | head -n 1)"
  if [[ "$CUR_VER" == "$RESOLVED_VER" ]]; then
    echo "Already up to date: ${RESOLVED_TAG} (${DL_DIR})"
    exit 0
  fi
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

verify_sums_sig() {
  [[ -n "$OFFICIAL_PEM" ]] || return 0
  if [[ ! -f "${TMP}/SHA256SUMS.sig" ]]; then
    echo "Error: OFFICIAL_PEM given, but SHA256SUMS.sig is missing" >&2
    exit 1
  fi
  local pem_path="${TMP}/official.pem"
  if [[ "$OFFICIAL_PEM" == https://* ]]; then
    curl -fsSL "$OFFICIAL_PEM" -o "$pem_path"
  else
    cp "$OFFICIAL_PEM" "$pem_path"
  fi
  openssl base64 -d -A -in "${TMP}/SHA256SUMS.sig" -out "${TMP}/SHA256SUMS.sig.bin" 2>/dev/null \
    || cp "${TMP}/SHA256SUMS.sig" "${TMP}/SHA256SUMS.sig.bin"
  openssl dgst -sha256 -verify "$pem_path" \
    -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -sigopt rsa_mgf1_md:sha256 \
    -signature "${TMP}/SHA256SUMS.sig.bin" "${TMP}/SHA256SUMS"
  rm -f "${TMP}/SHA256SUMS.sig.bin" "$pem_path"
  echo "Verified SHA256SUMS.sig against official public key."
}

parse_manifest_names() {
  local line=""
  local fname=""
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    fname="${line#* }"
    fname="${fname# }"
    fname="${fname#\*}"
    if [[ "$fname" == */* || "$fname" == *..* ]]; then
      echo "Error: unsafe path in SHA256SUMS: ${fname}" >&2
      exit 1
    fi
    if [[ ! "$fname" =~ ^(fatext-[A-Za-z0-9._-]+\.(tar\.gz|zip)|install\.sh)$ ]]; then
      echo "Error: unsupported artifact name in SHA256SUMS: ${fname}" >&2
      exit 1
    fi
    printf '%s\n' "$fname"
  done < "${TMP}/SHA256SUMS"
}

USED_CURL=0
RELEASE_BASE="https://github.com/${REPO}/releases/download/${RESOLVED_TAG}"
echo "Downloading release '${RESOLVED_TAG}' from ${REPO}..."
if command -v curl >/dev/null 2>&1 && curl -fsSL "${RELEASE_BASE}/SHA256SUMS" -o "${TMP}/SHA256SUMS" 2>/dev/null; then
  if [[ -n "$OFFICIAL_PEM" ]]; then
    if ! curl -fsSL "${RELEASE_BASE}/SHA256SUMS.sig" -o "${TMP}/SHA256SUMS.sig" 2>/dev/null; then
      echo "Error: OFFICIAL_PEM given, but failed to download SHA256SUMS.sig" >&2
      exit 1
    fi
  else
    curl -fsSL "${RELEASE_BASE}/SHA256SUMS.sig" -o "${TMP}/SHA256SUMS.sig" 2>/dev/null || rm -f "${TMP}/SHA256SUMS.sig"
  fi
  verify_sums_sig
  while IFS= read -r fname; do
    [[ -n "$fname" ]] || continue
    curl -fsSL "${RELEASE_BASE}/${fname}" -o "${TMP}/${fname}"
  done < <(parse_manifest_names)
  USED_CURL=1
fi

if [[ "$USED_CURL" -eq 0 ]]; then
  rm -f "${TMP}/SHA256SUMS" "${TMP}/SHA256SUMS.sig"
  if ! command -v gh >/dev/null 2>&1; then
    echo "Error: failed to fetch release '${RESOLVED_TAG}' via curl and gh CLI is not installed" >&2
    exit 1
  fi
  gh release download "$RESOLVED_TAG" --repo "$REPO" --dir "$TMP"
  if [[ ! -f "${TMP}/SHA256SUMS" ]]; then
    echo "Error: SHA256SUMS missing from release assets" >&2
    exit 1
  fi
  verify_sums_sig
fi

VERIFIED_FILES=()
while IFS= read -r fname; do
  [[ -n "$fname" ]] || continue
  if [[ ! -f "${TMP}/${fname}" ]]; then
    echo "Error: manifest entry missing from downloaded files: ${fname}" >&2
    exit 1
  fi
  VERIFIED_FILES+=("${TMP}/${fname}")
done < <(parse_manifest_names)

if [[ ${#VERIFIED_FILES[@]} -eq 0 ]]; then
  echo "Error: no verified artifacts from SHA256SUMS found in release" >&2
  exit 1
fi

echo "Verifying SHA256SUMS against downloaded archives..."
(
  cd "$TMP"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c SHA256SUMS
  else
    shasum -a 256 -c SHA256SUMS
  fi
)

install -d -m 0755 "$DL_DIR"
KEEP_LIST=" "
for f in "${VERIFIED_FILES[@]}" "${TMP}/SHA256SUMS" "${TMP}/SHA256SUMS.sig"; do
  if [[ -f "$f" ]]; then
    base="$(basename "$f")"
    KEEP_LIST="${KEEP_LIST}${base} "
    install -m 0644 "$f" "${DL_DIR}/${base}.tmp"
    mv -f "${DL_DIR}/${base}.tmp" "${DL_DIR}/${base}"
  fi
done

# Remove superseded versioned archives so every artifact in /dl/ stays covered by SHA256SUMS
for existing in "${DL_DIR}"/fatext-v*.tar.gz "${DL_DIR}"/fatext-v*.zip; do
  [[ -e "$existing" ]] || continue
  ebase="$(basename "$existing")"
  if [[ "$KEEP_LIST" != *" ${ebase} "* ]]; then
    rm -f "$existing"
  fi
done

if [[ $EUID -eq 0 ]] && id -u fatext >/dev/null 2>&1; then
  chown -R fatext:fatext "$DL_DIR"
fi

# Update latest.json so /.well-known/fatext.json dynamically tracks the synced version
NOW_UTC="$(date -u +%s)"
printf '{"latest_version":"%s","updated_at":%s}\n' "$RESOLVED_VER" "$NOW_UTC" > "${DL_DIR}/latest.json.tmp"
chmod 0644 "${DL_DIR}/latest.json.tmp"
if [[ $EUID -eq 0 ]] && id -u fatext >/dev/null 2>&1; then
  chown fatext:fatext "${DL_DIR}/latest.json.tmp"
fi
mv -f "${DL_DIR}/latest.json.tmp" "${DL_DIR}/latest.json"
echo "Updated ${DL_DIR}/latest.json -> ${RESOLVED_VER}"

echo "Published CLI artifacts to ${DL_DIR}:"
ls -lh "$DL_DIR"
