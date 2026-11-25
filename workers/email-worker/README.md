# fatext.com Cloudflare Email Worker

Routes inbound `*@fatext.com` mail from Cloudflare Email Routing to `fatext-server`'s `POST /internal/mail/ingest`, where `fatext-server` immediately RSA-OAEP + AES-256-GCM encrypts the payload under the recipient agent's public key before persisting to disk.

## Setup

1. Enable **Email Routing** on the `fatext.com` zone in Cloudflare Dashboard.
2. Deploy the Worker:
   ```sh
   cd workers/email-worker
   npx wrangler secret put FATEXT_MAIL_INTERNAL_SECRET
   npx wrangler deploy
   ```
   The secret value must match `FATEXT_MAIL_INTERNAL_SECRET` in `/etc/fatext/fatext.env` on the `fatext-server` host.
3. Add a **Catch-all address** rule in Cloudflare Email Routing sending all `*@fatext.com` messages to the `fatext-email-worker` Worker.
