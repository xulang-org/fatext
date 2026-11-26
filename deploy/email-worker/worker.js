const MAX_RAW_READ_BYTES = 65536;
const MAX_SNIPPET_BYTES = 8192;
const AGENT_RE = /^ftx_[a-z0-9]{12}$/;

function extractRecipientAgentId(toAddr) {
  if (!toAddr || typeof toAddr !== "string") return "";
  const atIdx = toAddr.indexOf("@");
  const local = (atIdx >= 0 ? toAddr.slice(0, atIdx) : toAddr).trim().toLowerCase();
  const plusIdx = local.indexOf("+");
  const base = plusIdx >= 0 ? local.slice(0, plusIdx) : local;
  return AGENT_RE.test(base) ? base : "";
}

async function readBoundedText(stream, maxBytes) {
  if (!stream) return "";
  const reader = stream.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (total < maxBytes) {
      const { value, done } = await reader.read();
      if (done || !value) break;
      const remain = maxBytes - total;
      const slice = value.byteLength > remain ? value.subarray(0, remain) : value;
      chunks.push(slice);
      total += slice.byteLength;
      if (value.byteLength > remain) break;
    }
  } finally {
    try {
      await reader.cancel();
    } catch (_) {
      // ignore stream cancel errors
    }
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(merged);
}

function extractBodySnippet(rawEmail) {
  if (!rawEmail) return "";
  const sepCRLF = rawEmail.indexOf("\r\n\r\n");
  const sepLF = rawEmail.indexOf("\n\n");
  let body = rawEmail;
  if (sepCRLF >= 0 && (sepLF < 0 || sepCRLF < sepLF)) {
    body = rawEmail.slice(sepCRLF + 4);
  } else if (sepLF >= 0) {
    body = rawEmail.slice(sepLF + 2);
  }
  const enc = new TextEncoder();
  const bytes = enc.encode(body.trim());
  if (bytes.byteLength <= MAX_SNIPPET_BYTES) {
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes.subarray(0, MAX_SNIPPET_BYTES));
}

const CLOUDFLARE_AUTHSERV_RE = /^(?:[a-z0-9-]+\.)*cloudflare\.(?:net|com)$/;

function extractTrustedAuthResults(headerVal) {
  if (!headerVal) return "";
  const parts = String(headerVal).split(/,\s*(?=[a-z0-9.-]+\s*;)/i);
  const first = parts[0] || "";
  const semi = first.indexOf(";");
  if (semi <= 0) return "";
  const authserv = first.slice(0, semi).trim().toLowerCase();
  return CLOUDFLARE_AUTHSERV_RE.test(authserv) ? first.toLowerCase() : "";
}

function parseAuthResults(authHeader) {
  const s = extractTrustedAuthResults(authHeader);
  return {
    spf_pass: /\bspf=pass\b/.test(s),
    dkim_pass: /\bdkim=pass\b/.test(s),
    dmarc_pass: /\bdmarc=pass\b/.test(s),
  };
}

export { extractTrustedAuthResults, parseAuthResults };

export default {
  async email(message, env, ctx) {
    const toAgentId = extractRecipientAgentId(message.to);
    if (!toAgentId) {
      message.setReject("Unknown fatext recipient");
      return;
    }

    const secret = env.FATEXT_MAIL_INTERNAL_SECRET || "";
    if (!secret) {
      throw new Error("FATEXT_MAIL_INTERNAL_SECRET is not configured");
    }

    const rawText = await readBoundedText(message.raw, MAX_RAW_READ_BYTES);
    const subject = (message.headers.get("subject") || "").slice(0, 512);
    const auth = parseAuthResults(message.headers.get("authentication-results") || "");

    const payload = {
      to_agent_id: toAgentId,
      from: String(message.from || "").slice(0, 512),
      subject,
      raw_snippet: extractBodySnippet(rawText),
      spf_pass: auth.spf_pass,
      dkim_pass: auth.dkim_pass,
      dmarc_pass: auth.dmarc_pass,
      received_at: Math.floor(Date.now() / 1000),
    };

    const ingestUrl = env.FATEXT_INGEST_URL || "https://fatext.com/internal/mail/ingest";
    const resp = await fetch(ingestUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Internal-Secret": secret,
      },
      body: JSON.stringify(payload),
    });

    if (resp.ok) {
      return;
    }

    if (resp.status === 400 || resp.status === 403 || resp.status === 404) {
      message.setReject(`Rejected by fatext (${resp.status})`);
      return;
    }

    const errBody = await resp.text().catch(() => "");
    throw new Error(`fatext ingest error ${resp.status}: ${errBody.slice(0, 256)}`);
  },
};
