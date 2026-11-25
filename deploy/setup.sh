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

install -d -m 0755 /opt/fatext /etc/fatext /var/lib/fatext /var/lib/fatext/dl
cp -r "$REPO_ROOT/www" /opt/fatext/
cp -r "$REPO_ROOT/templates" /opt/fatext/
cp -r "$REPO_ROOT/config" /opt/fatext/

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
FATEXT_MAIL_INTERNAL_SECRET=${SECRET}
EOF
  chmod 0600 /etc/fatext/fatext.env
  echo "Created /etc/fatext/fatext.env (generated FATEXT_MAIL_INTERNAL_SECRET)."
fi

cp /opt/fatext/config/channels.json /var/lib/fatext/channels.json
cp /opt/fatext/config/pins.json /var/lib/fatext/pins.json
chown -R fatext:fatext /opt/fatext /var/lib/fatext

install -m 0644 "$REPO_ROOT/deploy/fatext.service" /etc/systemd/system/fatext.service
systemctl daemon-reload
systemctl enable fatext.service

echo "Setup complete."
echo "Next:"
echo "  1. Issue TLS cert if not present (e.g. certbot certonly --standalone -d ${DOMAIN} -d www.${DOMAIN})"
echo "     Ensure user 'fatext' can read FATEXT_TLS_CERT and FATEXT_TLS_KEY (or grant ACL / copy on deploy hook)."
echo "  2. Run: python3 $REPO_ROOT/scripts/init_official.py --data-dir /var/lib/fatext --out-dir /etc/fatext"
echo "  3. Start service: systemctl start fatext && systemctl status fatext"
