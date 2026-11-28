#!/usr/bin/env python3
"""End-to-end Phase 1 test for fatext-server using real OpenSSL RSASSA-PSS-SHA256 signatures."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import http.client
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = Path(os.environ.get("FATEXT_SERVER_BIN", str(ROOT / "build" / "fatext-server")))
WWW_DIR = ROOT / "www"
TPL_DIR = ROOT / "templates"
HOST = "127.0.0.1"
POW_BITS = 12


def pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, 0))
        return int(s.getsockname()[1])


PORT = pick_free_port()


class ZeroJSParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.has_refresh = False
        self.in_ext_script = False
        self.errors: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        t = tag.lower()
        amap = {k.lower(): (v or "") for k, v in attrs}
        if t == "script":
            stype = amap.get("type", "").lower()
            src = amap.get("src", "")
            if stype == "application/ld+json":
                if src:
                    self.errors.append(f"json-ld <script> with src={src!r}")
            elif src.startswith("/static/fatext.js"):
                if "defer" not in amap:
                    self.errors.append(f"first-party script missing defer: {amap!r}")
                self.in_ext_script = True
            else:
                self.errors.append(f"disallowed <script> found: {amap!r}")
        if t == "meta" and amap.get("http-equiv", "").lower() == "refresh":
            self.has_refresh = True
        for k, v in attrs:
            if k.lower().startswith("on"):
                self.errors.append(f"inline event handler {k!r}")
            if k.lower() in ("href", "src", "action") and v and v.strip().lower().startswith("javascript:"):
                self.errors.append(f"javascript: URL in {k!r}")

    def handle_data(self, data: str) -> None:
        if self.in_ext_script and data.strip():
            self.errors.append(f"non-empty body inside external <script>: {data!r}")

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script":
            self.in_ext_script = False


def assert_zero_js(html_text: str, *, expect_refresh: bool, label: str) -> None:
    p = ZeroJSParser()
    p.feed(html_text)
    p.close()
    assert not p.errors, f"{label}: JS violation: {p.errors}"
    assert p.has_refresh == expect_refresh, (
        f"{label}: expected refresh={expect_refresh}, got {p.has_refresh}"
    )
    leftover = re.findall(r"\$[a-z][a-z0-9_]*", html_text)
    assert not leftover, f"{label}: leftover template placeholders {leftover}"


def gen_rsa_keypair(workdir: Path, name: str) -> tuple[Path, str]:
    priv = workdir / f"{name}.priv.pem"
    pub = workdir / f"{name}.pub.pem"
    subprocess.run(
        ["/usr/bin/openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(priv)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["/usr/bin/openssl", "pkey", "-in", str(priv), "-pubout", "-out", str(pub)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return priv, pub.read_text(encoding="utf-8")


def sign_request(priv_path: Path, method: str, path_and_query: str, ts: str, body: bytes) -> str:
    body_hex = hashlib.sha256(body).hexdigest()
    sts = f"{method}\n{path_and_query}\n{ts}\n{body_hex}".encode("utf-8")
    res = subprocess.run(
        [
            "/usr/bin/openssl",
            "dgst",
            "-sha256",
            "-sigopt",
            "rsa_padding_mode:pss",
            "-sigopt",
            "rsa_pss_saltlen:32",
            "-sigopt",
            "rsa_mgf1_md:sha256",
            "-sign",
            str(priv_path),
        ],
        input=sts,
        capture_output=True,
        check=True,
    )
    return base64.b64encode(res.stdout).decode("ascii")


def leading_zero_bits(digest: bytes) -> int:
    bits = 0
    for b in digest:
        if b == 0:
            bits += 8
            continue
        mask = 128
        while mask:
            if b & mask:
                return bits
            bits += 1
            mask >>= 1
    return bits


def solve_pow_register(pub_pem: str, ts: str, bits: int) -> str:
    pem_hex = hashlib.sha256(pub_pem.encode("utf-8")).hexdigest()
    n = 0
    while True:
        d = hashlib.sha256(f"{pem_hex}:{ts}:{n}".encode("utf-8")).digest()
        if leading_zero_bits(d) >= bits:
            return str(n)
        n += 1


def solve_pow_post(agent_id: str, ts: str, bits: int) -> str:
    n = 0
    while True:
        d = hashlib.sha256(f"{agent_id}:{ts}:{n}".encode("utf-8")).digest()
        if leading_zero_bits(d) >= bits:
            return str(n)
        n += 1


def request(method: str, path: str, body: bytes = b"", headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], bytes]:
    conn = http.client.HTTPConnection(HOST, PORT, timeout=10)
    try:
        hdrs = dict(headers or {})
        if body and "Content-Type" not in hdrs:
            hdrs["Content-Type"] = "application/json"
        conn.request(method, path, body=body, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read()
        resp_hdrs = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, resp_hdrs, data
    finally:
        conn.close()


def start_server(data_dir: Path, log_path: Path) -> subprocess.Popen[bytes]:
    env = os.environ.copy()
    env["FATEXT_ADDR"] = f"{HOST}:{PORT}"
    env["FATEXT_DATA_DIR"] = str(data_dir)
    env["FATEXT_WWW_DIR"] = str(WWW_DIR)
    env["FATEXT_TEMPLATES_DIR"] = str(TPL_DIR)
    env["FATEXT_POW_BITS"] = str(POW_BITS)
    logf = log_path.open("ab")
    proc = subprocess.Popen([str(BIN)], env=env, stdout=logf, stderr=subprocess.STDOUT)
    for _ in range(50):
        if proc.poll() is not None:
            raise RuntimeError(f"fatext-server exited early ({proc.returncode}):\n{log_path.read_text()}")
        try:
            st, _, body = request("GET", "/health")
            if st == 200 and body == b"ok\n" and proc.poll() is None:
                return proc
        except OSError:
            pass
        time.sleep(0.1)
    raise RuntimeError("fatext-server failed healthcheck in time")


def stop_server(proc: subprocess.Popen[bytes] | None) -> None:
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def main() -> int:
    assert BIN.exists(), f"Missing binary: {BIN}"
    with tempfile.TemporaryDirectory(prefix="fatext_phase1_") as tmp:
        tmp_path = Path(tmp)
        data_dir = tmp_path / "data"
        log_path = tmp_path / "server.log"
        proc: subprocess.Popen[bytes] | None = None
        try:
            proc = start_server(data_dir, log_path)
            today_utc = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")

            # 1. Health, discovery, static assets
            for p in (
                "/health",
                "/llms.txt",
                "/llms-full.txt",
                "/.well-known/fatext.json",
                "/.well-known/security.txt",
                "/SKILL.md",
                "/docs/identity.md",
                "/docs/messaging.md",
                "/docs/p2p.md",
                "/protocol.md",
                "/static/fatext.css",
                "/static/fatext.js",
            ):
                st, hdrs, body = request("GET", p)
                assert st == 200 and len(body) > 0, f"GET {p} -> {st}"
                if p == "/static/fatext.js":
                    assert "application/javascript" in hdrs.get("content-type", ""), hdrs
                    js_s = body.decode("utf-8")
                    assert "crypto.subtle.verify" in js_s and "navigator.clipboard" in js_s
                if p == "/SKILL.md":
                    assert len(body) <= 6500, f"/SKILL.md too large: {len(body)}"
                    sk_s = body.decode("utf-8")
                    assert "/docs/identity.md" in sk_s and "/docs/messaging.md" in sk_s and "/docs/p2p.md" in sk_s
                if p == "/.well-known/security.txt":
                    sec_s = body.decode("utf-8")
                    assert "advisories/new" in sec_s and "ftx_fatextoffice.pem" in sec_s
                if p == "/protocol.md":
                    pr_s = body.decode("utf-8")
                    assert "/internal/mail/ingest" in pr_s and "/internal/email" not in pr_s
            print("[1/12] health, discovery & static assets OK")

            # 2. Register Agent 1 (bad PoW, bad sig, then valid)
            priv1, pub1 = gen_rsa_keypair(tmp_path, "agent1")
            ts1 = str(int(time.time()))
            reg_body = json.dumps({"public_key_pem": pub1}).encode("utf-8")
            sig1 = sign_request(priv1, "POST", "/v1/agents/register", ts1, reg_body)

            bad_nonce = 0
            while leading_zero_bits(hashlib.sha256(
                f"{hashlib.sha256(pub1.encode()).hexdigest()}:{ts1}:{bad_nonce}".encode()
            ).digest()) >= POW_BITS:
                bad_nonce += 1
            st, _, b = request("POST", "/v1/agents/register", reg_body, {
                "X-Timestamp": ts1, "X-Signature": sig1, "X-PoW-Nonce": str(bad_nonce),
            })
            assert st == 400 and json.loads(b)["error"]["code"] == "ERR_POW_INSUFFICIENT"
            assert json.loads(b)["error"]["required_bits"] == POW_BITS

            valid_nonce = solve_pow_register(pub1, ts1, POW_BITS)
            st, _, b = request("POST", "/v1/agents/register", reg_body, {"X-Timestamp": ts1, "X-Signature": "AAAA", "X-PoW-Nonce": valid_nonce})
            assert st == 401 and json.loads(b)["error"]["code"] == "ERR_BAD_SIGNATURE", f"bad sig -> {st} {b}"

            ts1b = str(int(time.time()))
            valid_nonce_b = solve_pow_register(pub1, ts1b, POW_BITS)
            sig1b = sign_request(priv1, "POST", "/v1/agents/register", ts1b, reg_body)
            st, _, b = request("POST", "/v1/agents/register", reg_body, {"X-Timestamp": ts1b, "X-Signature": sig1b, "X-PoW-Nonce": valid_nonce_b})
            assert st == 201, f"register -> {st} {b}"
            reg1 = json.loads(b)
            aid1 = reg1["agent_id"]
            assert re.fullmatch(r"ftx_[a-z0-9]{12}", aid1), aid1
            assert isinstance(reg1["created_at"], int) and reg1["created_at"] > 0

            st, _, kj = request("GET", f"/k/{aid1}.json")
            assert st == 200 and json.loads(kj)["agent_id"] == aid1
            st, _, kp = request("GET", f"/k/{aid1}.pem")
            assert st == 200 and "BEGIN PUBLIC KEY" in kp.decode("utf-8")
            print(f"[2/12] register + /k/{{id}}.json/.pem OK ({aid1})")

            # 3. Replay protection
            st, _, b = request("POST", "/v1/agents/register", reg_body, {"X-Timestamp": ts1b, "X-Signature": sig1b, "X-PoW-Nonce": valid_nonce_b})
            assert st == 401 and json.loads(b)["error"]["code"] == "ERR_REPLAY", f"replay -> {st} {b}"
            stop_server(proc)
            proc = start_server(data_dir, log_path)
            fresh_sig = sign_request(priv1, "POST", "/v1/agents/register", ts1b, reg_body)
            st, _, b = request("POST", "/v1/agents/register", reg_body, {
                "X-Timestamp": ts1b, "X-Signature": fresh_sig, "X-PoW-Nonce": valid_nonce_b,
            })
            assert st == 409 and json.loads(b)["error"]["code"] == "ERR_REPLAY", (st, b)
            assert len((data_dir / "keys" / "registry.jsonl").read_text().splitlines()) == 1
            print("[3/12] signature replay and persistent registration proof checks OK")

            # 4. Profile update: unknown ext field, bad revision, valid with <script> escaping + SSR
            def signed_req(priv: Path, aid: str, method: str, path: str, payload: dict, pow_scope_post: bool = False):
                ts = str(int(time.time()))
                body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
                sig = sign_request(priv, method, path, ts, body)
                hdrs = {"X-Agent-Id": aid, "X-Timestamp": ts, "X-Signature": sig}
                if pow_scope_post:
                    hdrs["X-PoW-Nonce"] = solve_pow_post(aid, ts, POW_BITS)
                return request(method, path, body, hdrs)

            st, _, b = signed_req(priv1, aid1, "PUT", "/v1/agents/profile", {
                "revision": 1,
                "profile": {"name": "xu-coder-01", "bio": "ok"},
                "extensions": {"evil_unknown": 123},
            })
            assert st == 400 and json.loads(b)["error"]["code"] == "ERR_UNKNOWN_EXT_FIELD", f"ext -> {st} {b}"

            st, _, b = signed_req(priv1, aid1, "PUT", "/v1/agents/profile", {
                "revision": 99,
                "profile": {"name": "xu-coder-01", "bio": "ok"},
            })
            assert st == 400 and json.loads(b)["error"]["code"] == "ERR_REVISION_NOT_MONOTONIC", f"rev -> {st} {b}"

            st, _, b = signed_req(priv1, aid1, "PUT", "/v1/agents/profile", {
                "revision": 1,
                "profile": {"name": "xu-coder-01", "bio": "Builds zero-DB tools <script>alert(1)</script>"},
                "extensions": {
                    "owner_name": "Alice",
                    "owner_bio": "Systems engineer",
                    "model": "claude-4.5-sonnet",
                    "runtime": "xu-native",
                    "tags": ["systems", "xu"],
                    "homepage": "https://xulang.org",
                    "dm_policy": "friends",
                    "accept_email": True,
                    "lang": ["zh", "en"],
                },
            })
            assert st == 200, f"profile update -> {st} {b}"

            st, _, agent_html = request("GET", f"/a/{aid1}")
            assert st == 200
            ah = agent_html.decode("utf-8")
            assert_zero_js(ah, expect_refresh=False, label=f"/a/{aid1}")
            assert "&lt;script&gt;alert(1)&lt;/script&gt;" in ah
            assert "Alice" in ah and "xu-coder-01" in ah
            assert f"{aid1}@fatext.com" in ah
            print("[4/12] profile update, ext whitelist & escaped agent SSR OK")

            # 5. Unknown channel rejected
            st, _, b = signed_req(priv1, aid1, "POST", "/v1/channels/badchan/posts", {"text": "hi"}, pow_scope_post=True)
            assert st == 400 and json.loads(b)["error"]["code"] == "ERR_UNKNOWN_CHANNEL", f"badchan -> {st} {b}"
            print("[5/12] channel whitelist enforcement OK")

            # 6. Create post in #general + daily 1-post limit
            st, _, b = signed_req(priv1, aid1, "POST", "/v1/channels/general/posts", {
                "text": "Hello fatext v3.0! Testing <script>xss</script> & 中文 UTF-8."
            }, pow_scope_post=True)
            assert st == 201, f"post -> {st} {b}"
            post_res = json.loads(b)
            msg_id = post_res["msg_id"]
            assert re.fullmatch(r"msg_[0-9A-HJKMNP-TV-Z]{26}", msg_id), msg_id

            st, hdrs, b = signed_req(priv1, aid1, "POST", "/v1/channels/dev/posts", {"text": "2nd post today"}, pow_scope_post=True)
            assert st == 429 and json.loads(b)["error"]["code"] == "ERR_DAILY_POST_LIMIT", f"daily limit -> {st} {b}"
            assert int(hdrs["retry-after"]) > 0
            print(f"[6/12] post + daily 1-post limit OK ({msg_id})")

            # 7. Raw .jsonl, .sha256, and archive HTML
            st, _, day_jsonl = request("GET", f"/c/general/{today_utc}.jsonl")
            assert st == 200 and msg_id in day_jsonl.decode("utf-8")
            st, _, day_sha = request("GET", f"/c/general/{today_utc}.sha256")
            expected_sha = hashlib.sha256(day_jsonl).hexdigest()
            assert st == 200 and day_sha.decode("utf-8").startswith(expected_sha), f"sha mismatch: {day_sha}"

            st, _, arch_html = request("GET", f"/c/general/{today_utc}")
            assert st == 200
            assert_zero_js(arch_html.decode("utf-8"), expect_refresh=False, label="channel archive")
            assert expected_sha in arch_html.decode("utf-8")
            print("[7/12] channel .jsonl, .sha256 & archive SSR OK")

            # 8. Thread reply + 120s cooldown
            st, _, b = signed_req(priv1, aid1, "POST", f"/v1/threads/{msg_id}/replies", {"text": "First reply from author."})
            assert st == 201, f"reply1 -> {st} {b}"
            reply1_id = json.loads(b)["msg_id"]

            st, hdrs, b = signed_req(priv1, aid1, "POST", f"/v1/threads/{msg_id}/replies", {"text": "Immediate 2nd reply"})
            assert st == 429 and json.loads(b)["error"]["code"] == "ERR_THREAD_COOLDOWN", f"cooldown -> {st} {b}"
            assert 0 < int(hdrs["retry-after"]) <= 120
            print("[8/12] thread reply + 120s cooldown OK")

            # 9. Register 2nd agent -> closed reply -> thread .jsonl & SSR
            priv2, pub2 = gen_rsa_keypair(tmp_path, "agent2")
            ts2 = str(int(time.time()))
            reg2_body = json.dumps({"public_key_pem": pub2}).encode("utf-8")
            n2 = solve_pow_register(pub2, ts2, POW_BITS)
            s2 = sign_request(priv2, "POST", "/v1/agents/register", ts2, reg2_body)
            st, _, b = request("POST", "/v1/agents/register", reg2_body, {"X-Timestamp": ts2, "X-Signature": s2, "X-PoW-Nonce": n2})
            assert st == 201
            aid2 = json.loads(b)["agent_id"]

            st, _, b = signed_req(priv2, aid2, "POST", f"/v1/threads/{msg_id}/replies", {
                "text": "Got it, closing thread.",
                "reply_to": reply1_id,
                "conversation_state": "closed",
            })
            assert st == 201, f"reply2 -> {st} {b}"

            st, _, t_jsonl = request("GET", f"/t/{msg_id}.jsonl")
            assert st == 200
            t_lines = [ln for ln in t_jsonl.decode("utf-8").splitlines() if ln.strip()]
            assert len(t_lines) == 3, len(t_lines)

            st, _, t_html = request("GET", f"/t/{msg_id}")
            assert st == 200
            th = t_html.decode("utf-8")
            assert_zero_js(th, expect_refresh=False, label="thread SSR")
            assert "[✓ RSA]" in th and "reply-closed" in th and "&lt;script&gt;xss&lt;/script&gt;" in th
            print("[9/12] 2nd agent closed reply + thread SSR OK")

            # 10. Hot-reload pins.json
            pins_file = data_dir / "public" / "pins.json"
            pins_file.write_text(json.dumps({
                "pins": [{
                    "msg_id": msg_id,
                    "channels": ["*"],
                    "pin_type": "sponsored",
                    "label": "SPONSORED",
                    "priority": 100,
                    "created_at": int(time.time()),
                    "expires_at": None,
                    "audit_by": "manual",
                    "payment_ref": "internal_secret_ref",
                }]
            }), encoding="utf-8")
            time.sleep(1.1)

            st, _, pins_api = request("GET", "/v1/channels/general/pins")
            assert st == 200
            pins_obj = json.loads(pins_api)
            assert len(pins_obj["pins"]) == 1 and pins_obj["pins"][0]["post"]["msg_id"] == msg_id
            assert "audit_by" not in pins_api.decode("utf-8") and "payment_ref" not in pins_api.decode("utf-8")

            st, hh_hdrs, home_html = request("GET", "/")
            assert st == 200
            csp = hh_hdrs.get("content-security-policy", "")
            assert "default-src 'none'" in csp and "script-src 'self'" in csp and "connect-src 'self'" in csp, csp
            assert "unsafe-inline" not in csp and "unsafe-eval" not in csp, csp
            hh = home_html.decode("utf-8")
            assert_zero_js(hh, expect_refresh=False, label="home SSR default")
            assert '/static/fatext.js?v=' in hh
            assert "/?live=1" in hh
            assert "[PIN · SPONSORED]" in hh
            assert "SEND THIS TO YOUR AI AGENT" in hh and "Read https://fatext.com/SKILL.md" in hh
            assert 'href="/dl/"' in hh and 'href="/help#architecture"' in hh
            assert 'href="/help"' in hh and 'href="/about"' in hh and 'href="/privacy"' in hh and 'href="/terms"' in hh

            st_hl, _, home_live = request("GET", "/?live=1")
            assert st_hl == 200
            assert_zero_js(home_live.decode("utf-8"), expect_refresh=True, label="home SSR ?live=1")

            st_ch, _, ch_html = request("GET", "/c/general")
            assert st_ch == 200
            ch_s = ch_html.decode("utf-8")
            assert_zero_js(ch_s, expect_refresh=False, label="channel general SSR default")
            assert "/c/general?live=1" in ch_s

            st_chl, _, ch_live = request("GET", "/c/general?live=1")
            assert st_chl == 200
            assert_zero_js(ch_live.decode("utf-8"), expect_refresh=True, label="channel general SSR ?live=1")

            st_dl, _, dl_html = request("GET", "/dl/")
            assert st_dl == 200, f"GET /dl/ -> {st_dl}"
            dl_s = dl_html.decode("utf-8")
            assert_zero_js(dl_s, expect_refresh=False, label="download SSR")
            assert "Download fatext CLI" in dl_s and "SHA256SUMS.sig" in dl_s

            for p_path, p_marker in [("/help", "Usage Help"), ("/about", "About fatext"), ("/privacy", "Privacy &amp; Security Policy"), ("/terms", "Terms of Use"), ("/report", "Report public content"), ("/report/status", "Report status")]:
                st_p, _, p_html = request("GET", p_path)
                assert st_p == 200, f"GET {p_path} -> {st_p}"
                p_s = p_html.decode("utf-8")
                assert_zero_js(p_s, expect_refresh=False, label=f"{p_path} SSR")
                assert p_marker in p_s, f"GET {p_path} missing {p_marker}"
                if p_path == "/privacy":
                    assert "/internal/mail/ingest" in p_s and "forward secrecy" in p_s.lower()
                if p_path == "/report":
                    assert '<option value="spam">' in p_s and 'fatext</a> / report' in p_s
                if p_path == "/report/status":
                    assert 'fatext</a> / <a href="/report">report</a> / status' in p_s
            print("[10/12] hot-reload pins.json + home/channel/policy SSR OK")

            # 11. Zero-DB restart recovery of daily post limit
            stop_server(proc)
            proc = start_server(data_dir, log_path)
            st, _, b = signed_req(priv1, aid1, "POST", "/v1/channels/crypto/posts", {"text": "post after restart"}, pow_scope_post=True)
            assert st == 429 and json.loads(b)["error"]["code"] == "ERR_DAILY_POST_LIMIT", f"restart recovery -> {st} {b}"
            print("[11/12] zero-DB restart recovery OK")

            # 12. Revocation -> 403 ERR_REVOKED + revoked SSR page
            st, _, b = signed_req(priv1, aid1, "POST", "/v1/agents/revoke", {"successor_id": aid2})
            assert st == 200 and json.loads(b)["status"] == "revoked", f"revoke -> {st} {b}"

            st, _, b = signed_req(priv1, aid1, "POST", "/v1/threads/{msg_id}/replies".format(msg_id=msg_id), {"text": "after revoke"})
            assert st == 403 and json.loads(b)["error"]["code"] == "ERR_REVOKED", f"post-revoke -> {st} {b}"

            st, _, rev_html = request("GET", f"/a/{aid1}")
            assert st == 200
            rh = rev_html.decode("utf-8")
            assert_zero_js(rh, expect_refresh=False, label="revoked agent SSR")
            assert "REVOKED" in rh and aid2 in rh
            print("[12/12] revocation + ERR_REVOKED + revoked SSR OK")

            print("ALL 12 PHASE 1 CHECKS PASSED.")
            return 0
        finally:
            stop_server(proc)
            if log_path.exists():
                print("--- server.log ---")
                print(log_path.read_text(encoding="utf-8", errors="replace"))


if __name__ == "__main__":
    raise SystemExit(main())
