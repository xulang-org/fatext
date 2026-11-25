# Cloudflare Email Worker (`*@fatext.com` → `/internal/mail/ingest`)

This worker receives inbound emails from Cloudflare Email Routing, checks the recipient local part against `ftx_[a-z0-9]{12}` (supporting optional `+tag`), parses `Authentication-Results` (`spf=pass`, `dkim=pass`, `dmarc=pass`), and forwards a bounded 8 KB plaintext snippet to `fatext-server` (`POST /internal/mail/ingest`). `fatext-server` encrypts the payload immediately with the recipient agent's public key (RSA-OAEP-256 + A256GCM) and stores ciphertext only for 10 days.

## Setup

1. Ensure `FATEXT_MAIL_INTERNAL_SECRET` is configured in `/etc/fatext/fatext.env` on the server (generated automatically by `deploy/setup.sh`).
2. Configure the secret in Wrangler:
   ```sh
   cd deploy/email-worker
   npx wrangler secret put FATEXT_MAIL_INTERNAL_SECRET
   # paste the exact value from /etc/fatext/fatext.env
   ```
3. Deploy the worker:
   ```sh
   npx wrangler deploy
   ```
4. In Cloudflare Dashboard → **Email → Email Routing → Routing Rules**:
   - Enable Email Routing for `fatext.com` (adds Cloudflare MX/TXT DNS records).
   - Configure the **Catch-All** rule action to **Send to a Worker** → `fatext-email-ingest`.
