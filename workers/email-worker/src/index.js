/**
 * Cloudflare Email Worker for *@fatext.com
 *
 * Parses recipient local-part -> ftx_<id>, extracts From / Subject / Authentication-Results
 * (SPF/DKIM/DMARC) + bounded plain text snippet, and forwards to fatext-server
 * POST /internal/mail/ingest authenticated by X-Internal-Secret.
 */

const AGENT_ID_RE = /^ftx_[a-z0-9]{12}$/;
const MAX_SUBJECT_LEN = 256;
const MAX_SNIPPET_LEN = 8192;

function extractLocalPart(address) {
  if (!address || typeof address !== "string") return "";
  const cleaned = address.trim().replace(/^.*</, "").replace(/>.*$/, "");
  const at = cleaned.indexOf("@");
  if (at <= 0) return "";
  return cleaned.slice(0, at).toLowerCase();
}

function extractTrustedAuthResults(headerVal) {
  if (!headerVal) return "";
  const parts = String(headerVal).split(/,\s*(?=[a-z0-9.-]+\s*;)/i);
  for (const part of parts) {
    const semi = part.indexOf(";");
    const authserv = (semi >= 0 ? part.slice(0, semi) : part).trim().toLowerCase();
    if (/^[a-z0-9.-]*cloudflare\.[a-z]+$/.test(authserv)) {
      return part;
    }
  }
  return "";
}

function parseAuthResult(headerVal, mechanism) {
  const trusted = extractTrustedAuthResults(headerVal);
  if (!trusted) return false;
  const re = new RegExp(`\\b${mechanism}=([a-z0-9_-]+)`, "i");
  const m = trusted.match(re);
  return !!(m && m[1] && m[1].toLowerCase() === "pass");
}

function extractBodySnippet(rawText) {
  if (!rawText) return "";
  const sep = rawText.indexOf("\r\n\r\n");
  const sepLf = rawText.indexOf("\n\n");
  let body = rawText;
  if (sep >= 0 && (sepLf < 0 || sep < sepLf)) {
    body = rawText.slice(sep + 4);
  } else if (sepLf >= 0) {
    body = rawText.slice(sepLf + 2);
  }
  const normalized = body.replace(/\r\n/g, "\n").trim();
  return normalized.slice(0, MAX_SNIPPET_LEN);
}

export default {
  async email(message, env, ctx) {
    const recipientId = extractLocalPart(message.to);
    if (!AGENT_ID_RE.test(recipientId)) {
      message.setReject(`Unknown agent mailbox: ${message.to}`);
      return;
    }

    if (!env.FATEXT_MAIL_INTERNAL_SECRET || !env.FATEXT_INGEST_URL) {
      message.setReject("Mail ingest gateway misconfigured");
      return;
    }

    const authResults = message.headers.get("authentication-results") || "";
    const subject = (message.headers.get("subject") || "").slice(0, MAX_SUBJECT_LEN);
    const spfPass = parseAuthResult(authResults, "spf");
    const dkimPass = parseAuthResult(authResults, "dkim");
    const dmarcPass = parseAuthResult(authResults, "dmarc");

    let rawText = "";
    try {
      const buf = await new Response(message.raw).arrayBuffer();
      const limited = new Uint8Array(buf, 0, Math.min(buf.byteLength, 32768));
      rawText = new TextDecoder("utf-8", { fatal: false }).decode(limited);
    } catch {
      rawText = "";
    }

    const payload = {
      to_agent_id: recipientId,
      from: (message.from || "").slice(0, 320),
      subject,
      raw_snippet: extractBodySnippet(rawText),
      spf_pass: spfPass,
      dkim_pass: dkimPass,
      dmarc_pass: dmarcPass,
      received_at: Math.floor(Date.now() / 1000),
    };

    const resp = await fetch(env.FATEXT_INGEST_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Internal-Secret": env.FATEXT_MAIL_INTERNAL_SECRET,
      },
      body: JSON.stringify(payload),
    });

    if (resp.status === 403 || resp.status === 404) {
      message.setReject(`Rejected by recipient (${resp.status})`);
      return;
    }
    if (!resp.ok) {
      throw new Error(`fatext ingest failed with HTTP ${resp.status}`);
    }
  },
};
