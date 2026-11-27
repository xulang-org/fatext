#!/usr/bin/env python3
"""Integration tests for Statistics & Backend Admin Control Plane endpoints:
  1. Disabled-by-default security (FATEXT_ADMIN_SECRET unset -> 404 ERR_NOT_FOUND).
  2. Auth boundary (missing/wrong secret -> 403, X-Fatext-Admin-Secret & Bearer -> 200,
     authenticated admin bypasses FATEXT_IP_RPM while anon hits 429).
  3. Public GET /v1/stats (Cache-Control: public, max-age=30, counts, zero secrets).
  4. Prometheus GET /internal/metrics + JSON GET /internal/admin/stats +
     GET /internal/admin/stats/history?days=7 with monotonic post-flush cumulative totals.
  5. Agent directory/detail + Ban/Unban + SSE force-disconnect (`disconnect`, `ban`).
  6. Governance hot-mutations: channels create/delete, pins upsert/delete, banned-emails add/remove.
  7. Live SSE/Rooms metadata, GET/PATCH runtime config, POST reload, GET events?kind=admin_action,
     plus strict zero-secret / zero-plaintext privacy audit.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
SERVER_BIN = Path(os.environ.get("FATEXT_SERVER_BIN", str(ROOT / "build" / "fatext-server")))
WWW_DIR = ROOT / "www"
TPL_DIR = ROOT / "templates"
HOST = "127.0.0.1"
ADMIN_SECRET = "adm_test_secret_89f0c1d2e3a4b5c6"
POW_BITS = 8


def assert_eq(a, b, msg: str = "") -> None:
    if a != b:
        raise AssertionError(f"{msg}: expected {b!r}, got {a!r}")


def assert_true(cond: bool, msg: str = "") -> None:
    if not cond:
        raise AssertionError(f"Assertion failed: {msg}")


def free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, 0))
        return int(s.getsockname()[1])


def start_server(port: int, data_dir: Path, extra_env: dict[str, str] | None = None) -> subprocess.Popen:
    env = os.environ.copy()
    env.update(
        {
            "FATEXT_ADDR": f"{HOST}:{port}",
            "FATEXT_DATA_DIR": str(data_dir),
            "FATEXT_WWW_DIR": str(WWW_DIR),
            "FATEXT_TEMPLATES_DIR": str(TPL_DIR),
            "FATEXT_POW_BITS": str(POW_BITS),
            "FATEXT_IP_RPM": "5000",
            "FATEXT_METRICS_INTERVAL_SEC": "1",
        }
    )
    if extra_env:
        env.update(extra_env)
    proc = subprocess.Popen([str(SERVER_BIN)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    deadline = time.time() + 10.0
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"http://{HOST}:{port}/health", timeout=1.0) as r:
                if r.status == 200:
                    return proc
        except Exception:
            time.sleep(0.05)
    raise RuntimeError("fatext-server failed health check")


def http_req(port: int, method: str, path: str, body: bytes | None = None, headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], bytes]:
    conn = http.client.HTTPConnection(HOST, port, timeout=10.0)
    hdrs = dict(headers or {})
    if body is not None and "Content-Type" not in hdrs:
        hdrs["Content-Type"] = "application/json"
    conn.request(method, path, body=body, headers=hdrs)
    resp = conn.getresponse()
    raw = resp.read()
    resp_hdrs = {k.lower(): v for k, v in resp.getheaders()}
    st = resp.status
    conn.close()
    return st, resp_hdrs, raw


def gen_rsa_keypair(tmp_dir: Path, name: str) -> tuple[Path, str]:
    priv = tmp_dir / f"{name}.priv.pem"
    pub = tmp_dir / f"{name}.pub.pem"
    subprocess.run(
        ["/usr/bin/openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(priv)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["/usr/bin/openssl", "rsa", "-in", str(priv), "-pubout", "-out", str(pub)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return priv, pub.read_text(encoding="utf-8")


def openssl_sign_pss(priv_pem: Path, msg: str) -> str:
    with tempfile.NamedTemporaryFile("wb", delete=False) as mf:
        mf.write(msg.encode("utf-8"))
        mpath = Path(mf.name)
    spath = Path(str(mpath) + ".sig")
    try:
        subprocess.run(
            [
                "/usr/bin/openssl", "dgst", "-sha256",
                "-sigopt", "rsa_padding_mode:pss",
                "-sigopt", "rsa_pss_saltlen:32",
                "-sigopt", "rsa_mgf1_md:sha256",
                "-sign", str(priv_pem),
                "-out", str(spath),
                str(mpath),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return base64.b64encode(spath.read_bytes()).decode("ascii")
    finally:
        mpath.unlink(missing_ok=True)
        spath.unlink(missing_ok=True)


def leading_zero_bits(digest: bytes) -> int:
    n = 0
    for b in digest:
        if b == 0:
            n += 8
        else:
            for bit in range(7, -1, -1):
                if (b & (1 << bit)) == 0:
                    n += 1
                else:
                    return n
    return n


def solve_pow(seed_prefix: str, bits: int = POW_BITS) -> str:
    nonce = 0
    while True:
        cand = str(nonce)
        if leading_zero_bits(hashlib.sha256((seed_prefix + cand).encode("utf-8")).digest()) >= bits:
            return cand
        nonce += 1


def solve_pow_register(pub_pem: str, ts: str, bits: int = POW_BITS) -> str:
    pub_sha = hashlib.sha256(pub_pem.encode("utf-8")).hexdigest()
    return solve_pow(f"{pub_sha}:{ts}:", bits)


def solve_pow_post(aid: str, ts: str, bits: int = POW_BITS) -> str:
    return solve_pow(f"{aid}:{ts}:", bits)


def sign_headers(priv: Path, aid: str | None, method: str, path: str, body: bytes, pow_nonce: str | None = None, ts_override: str | None = None) -> dict[str, str]:
    ts = ts_override or str(int(time.time()))
    bhash = hashlib.sha256(body).hexdigest()
    sig = openssl_sign_pss(priv, f"{method}\n{path}\n{ts}\n{bhash}")
    h = {"Content-Type": "application/json", "X-Timestamp": ts, "X-Signature": sig}
    if aid:
        h["X-Agent-Id"] = aid
    if pow_nonce:
        h["X-PoW-Nonce"] = pow_nonce
    return h


def register_agent(port: int, priv: Path, pub_pem: str, name: str, email: str = "") -> str:
    ts = str(int(time.time()))
    payload: dict = {"public_key_pem": pub_pem, "name": name, "bio": f"{name} bio"}
    if email:
        payload["email"] = email
    body = json.dumps(payload).encode("utf-8")
    nonce = solve_pow_register(pub_pem, ts)
    hdrs = sign_headers(priv, None, "POST", "/v1/agents/register", body, pow_nonce=nonce, ts_override=ts)
    st, _, raw = http_req(port, "POST", "/v1/agents/register", body, hdrs)
    assert_eq(st, 201, f"register {name} failed: {raw.decode('utf-8', 'replace')}")
    return json.loads(raw.decode("utf-8"))["agent_id"]


def main() -> int:
    if not SERVER_BIN.is_file():
        print(f"Missing {SERVER_BIN}; build fatext-server first.", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory(prefix="fatext-admin-test-") as td:
        tmp = Path(td)
        keys_dir = tmp / "keys"
        keys_dir.mkdir()
        a_priv, a_pub = gen_rsa_keypair(keys_dir, "alice")
        b_priv, b_pub = gen_rsa_keypair(keys_dir, "bob")

        # -----------------------------------------------------------------
        # 1. Disabled-by-default security (FATEXT_ADMIN_SECRET unset)
        # -----------------------------------------------------------------
        print("[1/7] Testing disabled-by-default security (404 when FATEXT_ADMIN_SECRET unset)...")
        port_off = free_tcp_port()
        data_off = tmp / "data_off"
        data_off.mkdir()
        srv_off = start_server(port_off, data_off)
        try:
            for ep in ("/internal/metrics", "/internal/admin/stats", "/internal/admin/agents"):
                st, _, raw = http_req(port_off, "GET", ep, headers={"X-Fatext-Admin-Secret": ADMIN_SECRET})
                assert_eq(st, 404, f"{ep} should return 404 when admin disabled: {raw!r}")
        finally:
            srv_off.terminate()
            srv_off.wait(timeout=5)

        # -----------------------------------------------------------------
        # 2. Auth boundary + Rate-limit bypass
        # -----------------------------------------------------------------
        print("[2/7] Testing admin auth boundary (403/200) and IP rate-limit bypass...")
        port = free_tcp_port()
        data_dir = tmp / "data"
        data_dir.mkdir()
        srv = start_server(
            port,
            data_dir,
            extra_env={"FATEXT_ADMIN_SECRET": ADMIN_SECRET, "FATEXT_IP_RPM": "6"},
        )
        sse_conn = None
        try:
            # Missing / wrong secret -> 403
            st_no, _, _ = http_req(port, "GET", "/internal/admin/stats")
            assert_eq(st_no, 403, "missing secret returns 403")
            st_bad, _, _ = http_req(port, "GET", "/internal/metrics", headers={"X-Fatext-Admin-Secret": "wrong-secret"})
            assert_eq(st_bad, 403, "wrong secret returns 403")

            # Valid X-Fatext-Admin-Secret & Bearer -> 200
            st_ok1, _, _ = http_req(port, "GET", "/internal/admin/stats", headers={"X-Fatext-Admin-Secret": ADMIN_SECRET})
            assert_eq(st_ok1, 200, "X-Fatext-Admin-Secret works")
            st_ok2, _, _ = http_req(port, "GET", "/internal/admin/config", headers={"Authorization": f"Bearer {ADMIN_SECRET}"})
            assert_eq(st_ok2, 200, "Authorization Bearer works")

            # Exhaust anon IP rate limit (rpm=6) and verify authenticated admin STILL returns 200!
            saw_429 = False
            for _ in range(10):
                s_h, _, _ = http_req(port, "GET", "/health")
                if s_h == 429:
                    saw_429 = True
                    break
            assert_true(saw_429, "anon requests hit rpm=6 429")
            st_bypass, _, _ = http_req(port, "GET", "/internal/metrics", headers={"X-Fatext-Admin-Secret": ADMIN_SECRET})
            assert_eq(st_bypass, 200, "authenticated admin bypasses IP rate limit")

            # Raise ip_rpm via PATCH /internal/admin/config immediately (including static_loop sync)!
            cfg_low = json.dumps({"ip_rpm": 3}).encode("utf-8")
            st_cfg_low, _, _ = http_req(
                port, "PATCH", "/internal/admin/config", body=cfg_low, headers={"X-Fatext-Admin-Secret": ADMIN_SECRET}
            )
            assert_eq(st_cfg_low, 200, "PATCH config ip_rpm=3 failed")
            saw_static_429 = False
            for _ in range(8):
                s_st, _, _ = http_req(port, "GET", "/llms.txt")
                if s_st == 429:
                    saw_static_429 = True
                    break
            assert_true(saw_static_429, "static_loop did not sync live ip_rpm=3 from PATCH /internal/admin/config")

            cfg_body = json.dumps({"ip_rpm": 5000}).encode("utf-8")
            st_cfg, _, cfg_raw = http_req(
                port, "PATCH", "/internal/admin/config", body=cfg_body, headers={"X-Fatext-Admin-Secret": ADMIN_SECRET}
            )
            assert_eq(st_cfg, 200, f"PATCH config failed: {cfg_raw!r}")
            assert_eq(json.loads(cfg_raw.decode("utf-8"))["ip_rpm"], 5000, "ip_rpm updated live")
            for _ in range(5):
                s_st2, _, _ = http_req(port, "GET", "/llms.txt")
                assert_eq(s_st2, 200, "static_loop should recover after PATCH ip_rpm=5000")

            # -----------------------------------------------------------------
            # 3. Register agents, create post & room, check /v1/stats
            # -----------------------------------------------------------------
            print("[3/7] Testing public GET /v1/stats and entity creation...")
            aid = register_agent(port, a_priv, a_pub, "AdminTestAlice")
            bid = register_agent(port, b_priv, b_pub, "AdminTestBob")

            post_txt = "PUBLIC_STATS_POST_MARKER"
            pbody = json.dumps({"text": post_txt}).encode("utf-8")
            pts = str(int(time.time()))
            pnonce = solve_pow_post(aid, pts)
            st_p, _, p_raw = http_req(port, "POST", "/v1/channels/general/posts", pbody, sign_headers(a_priv, aid, "POST", "/v1/channels/general/posts", pbody, pnonce, pts))
            assert_eq(st_p, 201, f"create post failed: {p_raw!r}")
            msg_id = json.loads(p_raw.decode("utf-8"))["msg_id"]

            # Create an encrypted room (with a secret marker that must NEVER appear in admin responses)
            secret_room_name = "Ops Audit Room"
            rm_body = json.dumps({"room_id": "room_aaaaaaaaaaaaaaaaaaaaaaaaaa", "name": secret_room_name, "max_members": 16}).encode("utf-8")
            st_rm, _, rm_raw = http_req(port, "POST", "/v1/rooms", rm_body, sign_headers(a_priv, aid, "POST", "/v1/rooms", rm_body))
            assert_eq(st_rm, 201, f"create room failed: {rm_raw!r}")

            st_vs, hdr_vs, vs_raw = http_req(port, "GET", "/v1/stats")
            assert_eq(st_vs, 200, "/v1/stats 200")
            assert_true("max-age=30" in hdr_vs.get("cache-control", ""), f"missing Cache-Control on /v1/stats: {hdr_vs}")
            vs_j = json.loads(vs_raw.decode("utf-8"))
            assert_eq(vs_j["agents_total"], 2, "public stats agents_total")
            assert_eq(vs_j["channels_total"], 5, "public stats channels_total")
            assert_eq(vs_j["posts_today"], 1, "public stats posts_today")

            # -----------------------------------------------------------------
            # 4. Prometheus metrics + JSON dashboard + monotonic flush + history
            # -----------------------------------------------------------------
            print("[4/7] Testing /internal/metrics (Prometheus), /internal/admin/stats, and stats/history...")
            time.sleep(1.3)  # Allow FATEXT_METRICS_INTERVAL_SEC=1 to flush >= 1 snapshot
            st_m, hdr_m, m_raw = http_req(port, "GET", "/internal/metrics", headers={"X-Fatext-Admin-Secret": ADMIN_SECRET})
            assert_eq(st_m, 200, "/internal/metrics 200")
            assert_true("text/plain" in hdr_m.get("content-type", ""), "prometheus content-type")
            m_txt = m_raw.decode("utf-8")
            assert_true("fatext_agents_total 2" in m_txt, f"missing fatext_agents_total 2:\n{m_txt}")
            assert_true("fatext_rooms_total 1" in m_txt, "missing fatext_rooms_total 1")
            assert_true("fatext_posts_today_total 1" in m_txt, "missing fatext_posts_today_total 1")
            assert_true('fatext_http_request_duration_seconds_bucket{le="+Inf"}' in m_txt, "missing histogram +Inf")

            st_ds, _, ds_raw = http_req(port, "GET", "/internal/admin/stats?refresh=1", headers={"X-Fatext-Admin-Secret": ADMIN_SECRET})
            assert_eq(st_ds, 200, "/internal/admin/stats 200")
            ds = json.loads(ds_raw.decode("utf-8"))
            assert_eq(ds["entities"]["agents_total"], 2, "admin stats agents_total")
            assert_eq(ds["entities"]["rooms_total"], 1, "admin stats rooms_total")
            assert_eq(ds["per_channel_today"]["general"], 1, "per_channel_today general=1")
            assert_true(ds["cumulative"]["req_total"] >= ds["window"]["req_total"], "cumulative monotonic across metric flush")

            st_hist, _, hist_raw = http_req(port, "GET", "/internal/admin/stats/history?days=3", headers={"X-Fatext-Admin-Secret": ADMIN_SECRET})
            assert_eq(st_hist, 200, "/internal/admin/stats/history 200")
            hj = json.loads(hist_raw.decode("utf-8"))
            assert_eq(hj["days"], 3, "history days=3")
            assert_true(hj["history"][0]["snapshots"] >= 1 and hj["history"][0]["req_total"] >= 1, f"today snapshot missing: {hj}")

            # -----------------------------------------------------------------
            # 5. Agent directory/detail, Ban/Unban & Live SSE force-disconnect
            # -----------------------------------------------------------------
            print("[5/7] Testing agent listing/detail, ban/unban, and live SSE disconnect...")
            sse_hdrs = sign_headers(b_priv, bid, "GET", "/v1/stream", b"")
            sse_conn = http.client.HTTPConnection(HOST, port, timeout=10.0)
            sse_conn.request("GET", "/v1/stream", headers=sse_hdrs)
            sse_resp = sse_conn.getresponse()
            assert_eq(sse_resp.status, 200, "Bob SSE connected")
            _ = sse_resp.fp.readline()  # :ok

            # Verify /internal/admin/sse lists Bob
            st_sse, _, sse_raw = http_req(port, "GET", "/internal/admin/sse", headers={"X-Fatext-Admin-Secret": ADMIN_SECRET})
            assert_eq(st_sse, 200, "/internal/admin/sse 200")
            sse_j = json.loads(sse_raw.decode("utf-8"))
            assert_eq(sse_j["total"], 1, "1 active SSE stream")
            assert_eq(sse_j["connections"][0]["agent_id"], bid, "Bob listed in active SSE")

            # List & search agents
            st_al, _, al_raw = http_req(port, "GET", "/internal/admin/agents?q=alice&limit=10", headers={"X-Fatext-Admin-Secret": ADMIN_SECRET})
            assert_eq(st_al, 200, "agents search 200")
            al_j = json.loads(al_raw.decode("utf-8"))
            assert_eq(al_j["total"], 1, "search 'alice' matched 1 agent")
            assert_eq(al_j["agents"][0]["agent_id"], aid, "matched Alice id")

            st_ad, _, ad_raw = http_req(port, "GET", f"/internal/admin/agents/{aid}", headers={"X-Fatext-Admin-Secret": ADMIN_SECRET})
            assert_eq(st_ad, 200, "agent detail 200")
            ad_j = json.loads(ad_raw.decode("utf-8"))
            assert_eq(ad_j["room_count"], 1, "Alice room_count=1")

            # Ban Bob -> kicks SSE immediately and rejects Bob API requests
            st_ban, _, ban_raw = http_req(
                port, "POST", f"/internal/admin/agents/{bid}/ban",
                body=json.dumps({"reason": "abuse_test"}).encode("utf-8"),
                headers={"X-Fatext-Admin-Secret": ADMIN_SECRET},
            )
            assert_eq(st_ban, 200, f"ban Bob failed: {ban_raw!r}")
            ban_j = json.loads(ban_raw.decode("utf-8"))
            assert_eq(ban_j["banned"], True, "Bob marked banned")
            assert_eq(ban_j["disconnected_sse"], 1, "Bob SSE kicked count=1")
            sse_tail = sse_resp.read().decode("utf-8", errors="replace")
            assert_true('"kind":"disconnected"' in sse_tail, f"Bob SSE missing disconnected frame: {sse_tail!r}")
            sse_conn.close()
            sse_conn = None

            # Banned Bob gets 403 on authenticated API
            st_bfr, _, _ = http_req(port, "GET", "/v1/friends", headers=sign_headers(b_priv, bid, "GET", "/v1/friends", b""))
            assert_eq(st_bfr, 403, "banned Bob rejected with 403")

            # Unban Bob -> access restored
            st_unban, _, unban_raw = http_req(port, "DELETE", f"/internal/admin/agents/{bid}/ban", headers={"X-Fatext-Admin-Secret": ADMIN_SECRET})
            assert_eq(st_unban, 200, f"unban Bob failed: {unban_raw!r}")
            assert_eq(json.loads(unban_raw.decode("utf-8"))["banned"], False, "Bob unbanned")
            st_bfr2, _, _ = http_req(port, "GET", "/v1/friends", headers=sign_headers(b_priv, bid, "GET", "/v1/friends", b""))
            assert_eq(st_bfr2, 200, "unbanned Bob access restored")

            # Test standalone /disconnect endpoint
            sse_conn = http.client.HTTPConnection(HOST, port, timeout=10.0)
            sse_conn.request("GET", "/v1/stream", headers=sign_headers(b_priv, bid, "GET", "/v1/stream", b""))
            sse_resp2 = sse_conn.getresponse()
            assert_eq(sse_resp2.status, 200, "Bob SSE #2 connected")
            _ = sse_resp2.fp.readline()
            st_dc, _, dc_raw = http_req(port, "POST", f"/internal/admin/agents/{bid}/disconnect", headers={"X-Fatext-Admin-Secret": ADMIN_SECRET})
            assert_eq(st_dc, 200, "disconnect 200")
            assert_eq(json.loads(dc_raw.decode("utf-8"))["disconnected_sse"], 1, "disconnected_sse=1")
            _ = sse_resp2.read()
            sse_conn.close()
            sse_conn = None

            # -----------------------------------------------------------------
            # 6. Governance: Channels, Pins & Banned Emails
            # -----------------------------------------------------------------
            print("[6/7] Testing channels, pins, and banned-emails hot management...")
            st_cc, _, _ = http_req(
                port, "POST", "/internal/admin/channels",
                body=json.dumps({"name": "ops-live", "description": "Live ops channel"}).encode("utf-8"),
                headers={"X-Fatext-Admin-Secret": ADMIN_SECRET},
            )
            assert_eq(st_cc, 201, "create channel ops-live 201")

            # Bob posts into newly created channel immediately
            ops_b = json.dumps({"text": "Hello ops-live!"}).encode("utf-8")
            ots = str(int(time.time()))
            st_op, _, _ = http_req(
                port, "POST", "/v1/channels/ops-live/posts", ops_b,
                sign_headers(b_priv, bid, "POST", "/v1/channels/ops-live/posts", ops_b, solve_pow_post(bid, ots), ots),
            )
            assert_eq(st_op, 201, "post to dynamically created channel ops-live")

            st_cd, _, _ = http_req(port, "DELETE", "/internal/admin/channels/ops-live", headers={"X-Fatext-Admin-Secret": ADMIN_SECRET})
            assert_eq(st_cd, 200, "delete channel ops-live 200")
            st_cl, _, cl_raw = http_req(port, "GET", "/internal/admin/channels", headers={"X-Fatext-Admin-Secret": ADMIN_SECRET})
            assert_eq(st_cl, 200, "list channels 200")
            assert_true(all(c["name"] != "ops-live" for c in json.loads(cl_raw.decode("utf-8"))["channels"]), "ops-live removed")

            # Pins upsert + GET /v1/channels/general/pins + delete
            st_pin, _, _ = http_req(
                port, "POST", "/internal/admin/pins",
                body=json.dumps({"msg_id": msg_id, "channels": ["general"], "pin_type": "sponsored", "label": "Pinned!", "priority": 99}).encode("utf-8"),
                headers={"X-Fatext-Admin-Secret": ADMIN_SECRET},
            )
            assert_eq(st_pin, 200, "upsert pin 200")
            st_gp, _, gp_raw = http_req(port, "GET", "/v1/channels/general/pins")
            assert_eq(st_gp, 200, "public general pins 200")
            assert_true(msg_id in gp_raw.decode("utf-8"), "pin visible in /v1/channels/general/pins")
            st_pd, _, _ = http_req(port, "DELETE", f"/internal/admin/pins/{msg_id}", headers={"X-Fatext-Admin-Secret": ADMIN_SECRET})
            assert_eq(st_pd, 200, "delete pin 200")

            # Banned emails add + duplicate blocked on register + delete
            st_be, _, _ = http_req(
                port, "POST", "/internal/admin/banned-emails",
                body=json.dumps({"pattern": "*@evil.example"}).encode("utf-8"),
                headers={"X-Fatext-Admin-Secret": ADMIN_SECRET},
            )
            assert_eq(st_be, 200, "add banned email 200")
            st_bed, _, _ = http_req(
                port, "DELETE", "/internal/admin/banned-emails",
                body=json.dumps({"pattern": "*@evil.example"}).encode("utf-8"),
                headers={"X-Fatext-Admin-Secret": ADMIN_SECRET},
            )
            assert_eq(st_bed, 200, "delete banned email 200")

            # -----------------------------------------------------------------
            # 7. Rooms metadata, Reload, Events audit trail & Privacy audit
            # -----------------------------------------------------------------
            print("[7/7] Testing rooms metadata, reload, admin_action audit logs, and zero-secret check...")
            st_rls, _, rls_raw = http_req(port, "GET", "/internal/admin/rooms", headers={"X-Fatext-Admin-Secret": ADMIN_SECRET})
            assert_eq(st_rls, 200, "/internal/admin/rooms 200")
            rls_j = json.loads(rls_raw.decode("utf-8"))
            assert_eq(rls_j["total"], 1, "1 room in metadata listing")
            assert_eq(rls_j["rooms"][0]["name"], secret_room_name, "room metadata name matches")
            assert_true("BEGIN" not in rls_raw.decode("utf-8") and "frame" not in rls_raw.decode("utf-8"), "no keys/frames in admin rooms")

            st_rl, _, _ = http_req(port, "POST", "/internal/admin/reload", headers={"X-Fatext-Admin-Secret": ADMIN_SECRET})
            assert_eq(st_rl, 200, "/internal/admin/reload 200")

            st_ev, _, ev_raw = http_req(port, "GET", "/internal/admin/events?kind=admin_action&limit=50", headers={"X-Fatext-Admin-Secret": ADMIN_SECRET})
            assert_eq(st_ev, 200, "/internal/admin/events 200")
            ev_j = json.loads(ev_raw.decode("utf-8"))
            actions = {e.get("action") for e in ev_j["events"]}
            for need in ("update_config", "ban_agent", "unban_agent", "disconnect_sse", "create_channel", "delete_channel", "upsert_pin", "delete_pin", "add_banned_email", "remove_banned_email", "reload_configs"):
                assert_true(need in actions, f"missing admin_action {need!r} in {actions}")

            # Verify ADMIN_SECRET is NEVER leaked in any log file or config/stats response!
            for resp_bytes in (ds_raw, cfg_raw, ev_raw):
                assert_true(ADMIN_SECRET.encode("utf-8") not in resp_bytes, "ADMIN_SECRET leaked in response")
            for p in (data_dir / "logs").glob("*.jsonl"):
                assert_true(ADMIN_SECRET not in p.read_text(encoding="utf-8", errors="ignore"), f"ADMIN_SECRET leaked in {p.name}")

            print("ALL 7 ADMIN & STATISTICS TESTS PASSED!")
            return 0
        finally:
            if sse_conn is not None:
                try:
                    sse_conn.close()
                except Exception:
                    pass
            if srv.poll() is None:
                srv.terminate()
                srv.wait(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
