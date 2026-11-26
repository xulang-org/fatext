#!/usr/bin/env bash
set -euo pipefail

# Bootstrap fatext-server on Linux with built-in ACME Auto-TLS (no Caddy or certbot required).
# Usage (as root):
#   sudo bash deploy/setup.sh [DOMAIN] [ACME_EMAIL]

DOMAIN="${1:-fatext.com}"
ACME_EMAIL="${2:-}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [[ "$DOMAIN" != *.*.* && "$DOMAIN" != www.* ]]; then
  ACME_DOMAINS="${DOMAIN},www.${DOMAIN}"
else
  ACME_DOMAINS="${DOMAIN}"
fi

if [[ $EUID -ne 0 ]]; then
  echo "Run as root (e.g. sudo bash deploy/setup.sh $DOMAIN $ACME_EMAIL)" >&2
  exit 1
fi

id -u fatext >/dev/null 2>&1 || useradd --system --home /var/lib/fatext --shell /usr/sbin/nologin fatext

install -d -m 0755 /opt/fatext /opt/fatext/deploy /opt/fatext/scripts /etc/fatext /var/lib/fatext /var/lib/fatext/dl /var/lib/fatext/public
install -d -m 0700 -o fatext -g fatext /var/lib/fatext/acme
cp -r "$REPO_ROOT/www" /opt/fatext/
cp -r "$REPO_ROOT/templates" /opt/fatext/
cp -r "$REPO_ROOT/config" /opt/fatext/
install -m 0755 "$REPO_ROOT/deploy/backup.sh" /opt/fatext/deploy/backup.sh
install -m 0755 "$REPO_ROOT/deploy/restore.sh" /opt/fatext/deploy/restore.sh
install -m 0755 "$REPO_ROOT/deploy/graceful_stop.sh" /opt/fatext/deploy/graceful_stop.sh
install -m 0755 "$REPO_ROOT/deploy/sync_dl.sh" /opt/fatext/deploy/sync_dl.sh
install -m 0644 "$REPO_ROOT/scripts/analyze_logs.py" /opt/fatext/scripts/analyze_logs.py

if [[ -x "$REPO_ROOT/build/fatext-server" ]]; then
  install -m 0755 "$REPO_ROOT/build/fatext-server" /usr/local/bin/fatext-server
else
  echo "Warning: $REPO_ROOT/build/fatext-server not found; copy your built binary to /usr/local/bin/fatext-server" >&2
fi

if [[ ! -f /etc/fatext/fatext.env ]]; then
  SECRET="$(openssl rand -hex 32)"
  SHUTDOWN_SECRET="$(openssl rand -hex 32)"
  ADMIN_SECRET="$(openssl rand -hex 32)"
  cat >/etc/fatext/fatext.env <<EOF
FATEXT_ADDR=0.0.0.0:443
FATEXT_HTTP_REDIRECT_ADDR=0.0.0.0:80
FATEXT_PUBLIC_HOST=${DOMAIN}
FATEXT_ACME_DOMAINS=${ACME_DOMAINS}
FATEXT_ACME_EMAIL=${ACME_EMAIL}
FATEXT_ACME_DIR=/var/lib/fatext/acme
FATEXT_ACME_STAGING=0
FATEXT_ACME_RENEW_DAYS=30
# Static cert fallback (mutually exclusive with FATEXT_ACME_DOMAINS; hot-reloadable via POST /internal/admin/reload):
# FATEXT_TLS_CERT=/etc/letsencrypt/live/${DOMAIN}/fullchain.pem
# FATEXT_TLS_KEY=/etc/letsencrypt/live/${DOMAIN}/privkey.pem
FATEXT_DATA_DIR=/var/lib/fatext
FATEXT_WWW_DIR=/opt/fatext/www
FATEXT_TEMPLATES_DIR=/opt/fatext/templates
FATEXT_DL_DIR=/var/lib/fatext/dl
FATEXT_POW_BITS=20
FATEXT_IP_RPM=600
FATEXT_MAX_CONNS=4096
FATEXT_MAX_CONNS_PER_IP=64
FATEXT_MAX_SSE=2048
FATEXT_MAX_SSE_PER_AGENT=8
FATEXT_DRAIN_MS=300
FATEXT_TLS_HANDSHAKE_MS=5000
FATEXT_LOG_DIR=/var/lib/fatext/logs
FATEXT_LOG_RETENTION_DAYS=30
FATEXT_SLOW_MS=200
FATEXT_METRICS_INTERVAL_SEC=60
FATEXT_LOG_STDOUT=1
FATEXT_TRUST_PROXY=0
FATEXT_MAIL_INTERNAL_SECRET=${SECRET}
FATEXT_SHUTDOWN_SECRET=${SHUTDOWN_SECRET}
FATEXT_ADMIN_SECRET=${ADMIN_SECRET}
EOF
  chmod 0600 /etc/fatext/fatext.env
  echo "Created /etc/fatext/fatext.env (generated mail, shutdown & admin secrets)."
fi

cp /opt/fatext/config/channels.json /var/lib/fatext/public/channels.json
cp /opt/fatext/config/pins.json /var/lib/fatext/public/pins.json
chown -R fatext:fatext /opt/fatext /var/lib/fatext

install -m 0644 "$REPO_ROOT/deploy/fatext.service" /etc/systemd/system/fatext.service
install -m 0644 "$REPO_ROOT/deploy/fatext-backup.service" /etc/systemd/system/fatext-backup.service
install -m 0644 "$REPO_ROOT/deploy/fatext-backup.timer" /etc/systemd/system/fatext-backup.timer
install -m 0644 "$REPO_ROOT/deploy/fatext-log-report.service" /etc/systemd/system/fatext-log-report.service
install -m 0644 "$REPO_ROOT/deploy/fatext-log-report.timer" /etc/systemd/system/fatext-log-report.timer
systemctl daemon-reload
systemctl enable fatext.service fatext-backup.timer fatext-log-report.timer

chmod 0700 /var/lib/fatext/acme

echo "Setup complete (built-in ACME Auto-TLS enabled for ${ACME_DOMAINS})."
echo "Ensure DNS A/AAAA records for ${ACME_DOMAINS} point to this host and ports 80/443 are open."
echo "Next:"
echo "  1. Run: python3 $REPO_ROOT/scripts/init_official.py --data-dir /var/lib/fatext --out-dir /etc/fatext"
echo "  2. Start service (automatically issues & renews TLS cert with zero downtime): systemctl start fatext fatext-backup.timer fatext-log-report.timer && systemctl status fatext"
echo "  3. Publish signed CLI binaries: bash /opt/fatext/deploy/sync_dl.sh latest /var/lib/fatext/dl https://${DOMAIN}/k/ftx_fatextoffice.pem"
