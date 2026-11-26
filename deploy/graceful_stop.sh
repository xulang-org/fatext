#!/usr/bin/env bash
set -euo pipefail

# Graceful drain hook for systemd ExecStop: signals /internal/shutdown so fatext-server
# drains active SSE listeners (emitting {"kind":"shutdown"}) and flushes logs/metrics cleanly.

if [[ -z "${FATEXT_SHUTDOWN_SECRET:-}" || -z "${FATEXT_ADDR:-}" ]]; then
  if [[ -r /etc/fatext/fatext.env ]]; then
    set -a
    # shellcheck disable=SC1091
    source /etc/fatext/fatext.env
    set +a
  fi
fi

SECRET="${FATEXT_SHUTDOWN_SECRET:-}"
if [[ -z "$SECRET" ]]; then
  exit 0
fi

ADDR="${FATEXT_ADDR:-127.0.0.1:8080}"
PORT="${ADDR##*:}"
if [[ -z "$PORT" || ! "$PORT" =~ ^[0-9]+$ ]]; then
  PORT="8080"
fi
BIND_HOST="${ADDR%:*}"
BIND_HOST="${BIND_HOST#[}"
BIND_HOST="${BIND_HOST%]}"
CONNECT_HOST="127.0.0.1"
if [[ -n "$BIND_HOST" && "$BIND_HOST" != "0.0.0.0" && "$BIND_HOST" != "::" && "$BIND_HOST" != "$ADDR" ]]; then
  CONNECT_HOST="$BIND_HOST"
fi
URL_HOST="$CONNECT_HOST"
if [[ "$URL_HOST" == *:* ]]; then
  URL_HOST="[${URL_HOST}]"
fi

URL="http://${URL_HOST}:${PORT}/internal/shutdown"
CURL_ARGS=(--noproxy '*')
if [[ ( -n "${FATEXT_TLS_CERT:-}" && -n "${FATEXT_TLS_KEY:-}" ) || -n "${FATEXT_ACME_DOMAINS:-}" ]]; then
  DOMAINS="${FATEXT_ACME_DOMAINS:-}"
  TLS_HOST="${FATEXT_PUBLIC_HOST:-${DOMAINS%%,*}}"
  TLS_HOST="${TLS_HOST:-fatext.com}"
  TLS_HOST="${TLS_HOST//[[:space:]]/}"
  URL="https://${TLS_HOST}:${PORT}/internal/shutdown"
  CURL_ARGS+=(--resolve "${TLS_HOST}:${PORT}:${CONNECT_HOST}")
  if [[ -n "${SSL_CERT_FILE:-}" ]]; then
    CURL_ARGS+=(--cacert "$SSL_CERT_FILE")
  fi
fi

curl -q -fsS "${CURL_ARGS[@]}" -X POST -K - \
  --max-time 5 \
  "$URL" >/dev/null 2>&1 <<EOF || exit 0
header = "X-Fatext-Shutdown-Secret: ${SECRET}"
EOF

if [[ -n "${MAINPID:-}" && "${MAINPID}" =~ ^[0-9]+$ ]]; then
  for _ in $(seq 1 50); do
    if ! kill -0 "$MAINPID" 2>/dev/null; then
      exit 0
    fi
    sleep 0.1
  done
fi
exit 0
