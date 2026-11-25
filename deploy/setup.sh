#!/usr/bin/env bash
set -euo pipefail

# Bootstrap fatext-server on Linux with native built-in TLS (no Caddy required).
# Usage (as root):
#   sudo bash deploy/setup.sh [DOMAIN]

DOMAIN="${1:-fatext.com}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [[ $EUID -ne 0 ]]; then
  echo "Run as root (e.g. sudo bash deploy/setup.sh $DOMAIN)" >&2
  exit 1
fi

id -u fatext >/dev/null 2>&1 || useradd --system --home /var/lib/fatext --shell /usr/sbin/nologin fatext

install -d -m 0755 /opt/fatext /opt/fatext/deploy /opt/fatext/scripts /etc/fatext /var/lib/fatext /var/lib/fatext/dl
cp -r "$REPO_ROOT/www" /opt/fatext/
cp -r "$REPO_ROOT/templates" /opt/fatext/
cp -r "$REPO_ROOT/config" /opt/fatext/
install -m 0755 "$REPO_ROOT/deploy/backup.sh" /opt/fatext/deploy/backup.sh
install -m 0755 "$REPO_ROOT/deploy/sync_dl.sh" /opt/fatext/deploy/sync_dl.sh
install -m 0644 "$REPO_ROOT/scripts/analyze_logs.py" /opt/fatext/scripts/analyze_logs.py

if [[ -x "$REPO_ROOT/build/fatext-server" ]]; then
  install -m 0755 "$REPO_ROOT/build/fatext-server" /usr/local/bin/fatext-server
else
  echo "Warning: $REPO_ROOT/build/fatext-server not found; copy your built binary to /usr/local/bin/fatext-server" >&2
fi

if [[ ! -f /etc/fatext/fatext.env ]]; then
  SECRET="$(openssl rand -hex 32)"
  cat >/etc/fatext/fatext.env <<EOF
FATEXT_ADDR=0.0.0.0:443
FATEXT_HTTP_REDIRECT_ADDR=0.0.0.0:80
FATEXT_TLS_CERT=/etc/letsencrypt/live/${DOMAIN}/fullchain.pem
FATEXT_TLS_KEY=/etc/letsencrypt/live/${DOMAIN}/privkey.pem
FATEXT_DATA_DIR=/var/lib/fatext
FATEXT_WWW_DIR=/opt/fatext/www
FATEXT_TEMPLATES_DIR=/opt/fatext/templates
FATEXT_DL_DIR=/var/lib/fatext/dl
FATEXT_POW_BITS=20
FATEXT_IP_RPM=600
FATEXT_LOG_DIR=/var/lib/fatext/logs
FATEXT_LOG_RETENTION_DAYS=30
FATEXT_SLOW_MS=200
FATEXT_METRICS_INTERVAL_SEC=60
FATEXT_LOG_STDOUT=1
FATEXT_TRUST_PROXY=0
FATEXT_MAIL_INTERNAL_SECRET=${SECRET}
EOF
  chmod 0600 /etc/fatext/fatext.env
  echo "Created /etc/fatext/fatext.env (generated FATEXT_MAIL_INTERNAL_SECRET)."
fi

cp /opt/fatext/config/channels.json /var/lib/fatext/channels.json
cp /opt/fatext/config/pins.json /var/lib/fatext/pins.json
chown -R fatext:fatext /opt/fatext /var/lib/fatext

install -m 0644 "$REPO_ROOT/deploy/fatext.service" /etc/systemd/system/fatext.service
install -m 0644 "$REPO_ROOT/deploy/fatext-backup.service" /etc/systemd/system/fatext-backup.service
install -m 0644 "$REPO_ROOT/deploy/fatext-backup.timer" /etc/systemd/system/fatext-backup.timer
install -m 0644 "$REPO_ROOT/deploy/fatext-log-report.service" /etc/systemd/system/fatext-log-report.service
install -m 0644 "$REPO_ROOT/deploy/fatext-log-report.timer" /etc/systemd/system/fatext-log-report.timer
systemctl daemon-reload
systemctl enable fatext.service fatext-backup.timer fatext-log-report.timer

echo "Setup complete."
echo "Next:"
echo "  1. Issue TLS cert if not present (e.g. certbot certonly --standalone -d ${DOMAIN} -d www.${DOMAIN})"
echo "     Add a certbot deploy-hook (e.g. /etc/letsencrypt/renewal-hooks/deploy/fatext.sh):"
echo "       setfacl -m u:fatext:rx /etc/letsencrypt/live /etc/letsencrypt/archive && setfacl -R -m u:fatext:rX /etc/letsencrypt/live/${DOMAIN} /etc/letsencrypt/archive/${DOMAIN} && systemctl restart fatext"
echo "  2. Run: python3 $REPO_ROOT/scripts/init_official.py --data-dir /var/lib/fatext --out-dir /etc/fatext"
echo "  3. Publish signed CLI binaries: bash /opt/fatext/deploy/sync_dl.sh latest /var/lib/fatext/dl https://${DOMAIN}/k/ftx_fatextoffice.pem"
echo "  4. Start service: systemctl start fatext fatext-backup.timer fatext-log-report.timer && systemctl status fatext"
