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

SCHEME="http"
if [[ ( -n "${FATEXT_TLS_CERT:-}" && -n "${FATEXT_TLS_KEY:-}" ) || -n "${FATEXT_ACME_DOMAINS:-}" ]]; then
  SCHEME="https"
fi

curl -fsSk -X POST -K - \
  --max-time 5 \
  "${SCHEME}://127.0.0.1:${PORT}/internal/shutdown" >/dev/null 2>&1 <<EOF || true
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
