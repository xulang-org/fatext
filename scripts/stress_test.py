#!/usr/bin/env python3
"""Multi-scenario stress benchmark for fatext-server.

Runs isolated HTTP and native TLS 1.3 fatext-server instances (never touching
any already-running local preview daemon), collects client throughput/latency,
SSE fan-out delivery, RSS memory footprint, and stage breakdowns via analyze_logs.py.
"""

from __future__ import annotations

import argparse
import base64
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
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
ANALYZE_PY = ROOT / "scripts" / "analyze_logs.py"
HOST = "127.0.0.1"
ROOM_ID = "room_aaaaaaaaaaaaaaaaaaaaaaaaaa"


def free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, 0))
        return int(s.getsockname()[1])


def wait_http_ok(url: str, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1.0) as r:
                if r.status == 200:
                    return
        except Exception:
            time.sleep(0.05)
    raise RuntimeError(f"server failed to become healthy at {url}")


def percentile(sorted_vals: list[float], p: float) -> float:
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return float(sorted_vals[0])
    idx = (len(sorted_vals) - 1) * (p / 100.0)
    lo = int(idx)
    hi = min(lo + 1, len(sorted_vals) - 1)
    frac = idx - lo
    return sorted_vals[lo] * (1.0 - frac) + sorted_vals[hi] * frac


def summarize_latencies(lat_ms: list[float], wall_s: float, statuses: Counter[int], errors: list[str]) -> dict:
    s = sorted(lat_ms)
    total = len(lat_ms)
    ok_2xx = sum(v for k, v in statuses.items() if 200 <= k < 300)
    return {
        "total": total,
        "ok_2xx": ok_2xx,
        "errors": total - ok_2xx,
        "statuses": {str(k): v for k, v in sorted(statuses.items())},
        "sample_errors": errors[:5],
        "wall_sec": round(wall_s, 3),
        "rps": round(total / wall_s, 1) if wall_s > 0 else 0.0,
        "p50_ms": round(percentile(s, 50), 2),
        "p95_ms": round(percentile(s, 95), 2),
        "p99_ms": round(percentile(s, 99), 2),
        "max_ms": round(max(s), 2) if s else 0.0,
    }


def sample_rss_kb(pid: int) -> int:
    try:
        r = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2.0)
        val = r.stdout.strip()
        return int(val) if val.isdigit() else 0
    except Exception:
        return 0


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


def openssl_sign_pss(priv_pem_path: Path, msg: str) -> str:
    with tempfile.NamedTemporaryFile("wb", delete=False) as mf:
        mf.write(msg.encode("utf-8"))
        mpath = Path(mf.name)
    spath = Path(str(mpath) + ".sig")
    try:
        subprocess.run(
            [
                "/usr/bin/openssl",
                "dgst",
                "-sha256",
                "-sign",
                str(priv_pem_path),
                "-sigopt",
                "rsa_padding_mode:pss",
                "-sigopt",
                "rsa_pss_saltlen:32",
                "-sigopt",
                "rsa_mgf1_md:sha256",
                "-out",
                str(spath),
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
    total = 0
    for b in digest:
        if b == 0:
            total += 8
        else:
            total += 8 - b.bit_length()
            break
    return total


def solve_pow_register(pub_pem: str, ts: str, bits: int = 8) -> str:
    pub_sha = hashlib.sha256(pub_pem.encode("utf-8")).hexdigest()
    n = 0
    while True:
        ns = str(n)
        d = hashlib.sha256(f"{pub_sha}:{ts}:{ns}".encode("utf-8")).digest()
        if leading_zero_bits(d) >= bits:
            return ns
        n += 1


def solve_pow_post(agent_id: str, ts: str, bits: int = 8) -> str:
    n = 0
    while True:
        ns = str(n)
        d = hashlib.sha256(f"{agent_id}:{ts}:{ns}".encode("utf-8")).digest()
        if leading_zero_bits(d) >= bits:
            return ns
        n += 1


def sign_request_headers(priv: Path, agent_id: str | None, method: str, path_and_query: str, body: bytes, pow_nonce: str | None = None, ts: str | None = None) -> dict[str, str]:
    ts = ts or str(int(time.time()))
    bhash = hashlib.sha256(body).hexdigest()
    msg = f"{method}\n{path_and_query}\n{ts}\n{bhash}"
    sig = openssl_sign_pss(priv, msg)
    hdrs = {
        "X-Timestamp": ts,
        "X-Signature": sig,
    }
    if agent_id is not None:
        hdrs["X-Agent-Id"] = agent_id
    if pow_nonce is not None:
        hdrs["X-PoW-Nonce"] = pow_nonce
    if body:
        hdrs["Content-Type"] = "application/json"
    return hdrs


def http_once(port: int, method: str, path: str, body: bytes | None = None, headers: dict[str, str] | None = None, timeout: float = 15.0) -> tuple[int, float, str]:
    t0 = time.perf_counter()
    conn = http.client.HTTPConnection(HOST, port, timeout=timeout)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        _ = resp.read()
        dt_ms = (time.perf_counter() - t0) * 1000.0
        return resp.status, dt_ms, ""
    except Exception as e:
        dt_ms = (time.perf_counter() - t0) * 1000.0
        return 0, dt_ms, repr(e)
    finally:
        conn.close()


def https_once(port: int, ssl_ctx: ssl.SSLContext, method: str, path: str, timeout: float = 15.0) -> tuple[int, float, str]:
    t0 = time.perf_counter()
    conn = http.client.HTTPSConnection(HOST, port, timeout=timeout, context=ssl_ctx)
    try:
        conn.request(method, path)
        resp = conn.getresponse()
        _ = resp.read()
        dt_ms = (time.perf_counter() - t0) * 1000.0
        return resp.status, dt_ms, ""
    except Exception as e:
        dt_ms = (time.perf_counter() - t0) * 1000.0
        return 0, dt_ms, repr(e)
    finally:
        conn.close()


def run_burst(tasks: list[tuple[str, str, bytes | None, dict[str, str] | None]], port: int, concurrency: int) -> dict:
    lat_ms: list[float] = []
    statuses: Counter[int] = Counter()
    errors: list[str] = []
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futs = [pool.submit(http_once, port, m, p, b, h) for (m, p, b, h) in tasks]
        for fut in as_completed(futs):
            st, dt, err = fut.result()
            lat_ms.append(dt)
            statuses[st] += 1
            if err and len(errors) < 5:
                errors.append(err)
    wall = time.perf_counter() - t0
    return summarize_latencies(lat_ms, wall, statuses, errors)


class SseClientThread:
    """Persistent authenticated TCP SSE consumer counting incoming event frames."""

    def __init__(self, port: int, agent_id: str, priv: Path, query: str = "") -> None:
        self.port = port
        self.agent_id = agent_id
        self.priv = priv
        self.query = query
        self.path = f"/v1/stream{query}"
        self.sock: socket.socket | None = None
        self.opened = threading.Event()
        self.subscribed = False
        self.stop_flag = threading.Event()
        self.events_by_type: Counter[str] = Counter()
        self.error = ""
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def _run(self) -> None:
        try:
            hdrs = sign_request_headers(self.priv, self.agent_id, "GET", self.path, b"")
            raw_req = (
                f"GET {self.path} HTTP/1.1\r\n"
                f"Host: {HOST}:{self.port}\r\n"
                f"X-Agent-Id: {hdrs['X-Agent-Id']}\r\n"
                f"X-Timestamp: {hdrs['X-Timestamp']}\r\n"
                f"X-Signature: {hdrs['X-Signature']}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("utf-8")
            s = socket.create_connection((HOST, self.port), timeout=10.0)
            self.sock = s
            s.sendall(raw_req)
            s.settimeout(0.25)

            buf = b""
            hdr_done = False
            cur_event = ""
            while not self.stop_flag.is_set():
                try:
                    chunk = s.recv(4096)
                except socket.timeout:
                    continue
                if not chunk:
                    break
                buf += chunk
                if not hdr_done:
                    idx = buf.find(b"\r\n\r\n")
                    if idx >= 0:
                        head = buf[:idx].decode("utf-8", errors="replace")
                        if " 200 " not in head.splitlines()[0]:
                            self.error = head.splitlines()[0]
                            break
                        hdr_done = True
                        self.subscribed = True
                        self.opened.set()
                        buf = buf[idx + 4 :]
                if hdr_done:
                    while b"\n" in buf:
                        line_b, buf = buf.split(b"\n", 1)
                        line = line_b.decode("utf-8", errors="replace").rstrip("\r")
                        if line.startswith("event:"):
                            cur_event = line[6:].strip()
                        elif line.startswith("data:"):
                            if cur_event:
                                self.events_by_type[cur_event] += 1
                                cur_event = ""
        except Exception as e:
            if not self.stop_flag.is_set():
                self.error = repr(e)
        finally:
            self.opened.set()
            if self.sock is not None:
                try:
                    self.sock.close()
                except Exception:
                    pass

    def close(self) -> None:
        self.stop_flag.set()
        if self.sock is not None:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                self.sock.close()
            except Exception:
                pass
        self._thread.join(timeout=2.0)


def run_analyze(log_dir: Path) -> dict:
    r = subprocess.run(
        [sys.executable, str(ANALYZE_PY), "--log-dir", str(log_dir), "--json"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return json.loads(r.stdout)


def main() -> int:
    ap = argparse.ArgumentParser(description="Multi-scenario stress benchmark for fatext-server.")
    ap.add_argument("--scale", choices=("normal", "light", "heavy"), default="normal")
    ap.add_argument("--light", action="store_true", help="Alias for --scale light")
    ap.add_argument("--heavy", action="store_true", help="Alias for --scale heavy (100 SSE streams, c=48, Native TLS 1.3)")
    ap.add_argument("--skip-tls", action="store_true", help="Skip Scenario 5 native TLS 1.3 benchmark")
    ap.add_argument("--json-out", help="Write full JSON report to this path")
    args = ap.parse_args()
    if args.light:
        args.scale = "light"
    if args.heavy:
        args.scale = "heavy"

    if not SERVER_BIN.is_file():
        print(f"Missing {SERVER_BIN}; build fatext-server first.", file=sys.stderr)
        return 1

    if args.scale == "heavy":
        n_health = 1600
        n_home = 800
        n_help_dl = 800
        n_key = 1000
        n_friends = 600
        n_dm = 600
        n_sse_room = 100
        n_room_msgs = 40
        n_sse_mixed = 32
        n_mixed = 800
        n_tls = 200
        c_http = 48
        c_tls = 16
    else:
        scale = 0.35 if args.scale == "light" else 1.0
        n_health = max(100, int(600 * scale))
        n_home = max(60, int(300 * scale))
        n_help_dl = max(60, int(300 * scale))
        n_key = max(80, int(400 * scale))
        n_friends = max(60, int(240 * scale))
        n_dm = max(60, int(240 * scale))
        n_sse_room = max(12, int(32 * scale))
        n_room_msgs = max(10, int(30 * scale))
        n_sse_mixed = max(6, int(16 * scale))
        n_mixed = max(100, int(320 * scale))
        n_tls = max(40, int(120 * scale))
        c_http = 24 if args.scale == "normal" else 12
        c_tls = 12 if args.scale == "normal" else 8

    report: dict = {"scale": args.scale, "scenarios": {}, "rss_kb": {}, "logs": {}}

    with tempfile.TemporaryDirectory(prefix="fatext-stress-") as td:
        td_p = Path(td)
        keys_dir = td_p / "keys"
        keys_dir.mkdir(parents=True, exist_ok=True)
        dl_dir = td_p / "dl"
        dl_dir.mkdir(parents=True, exist_ok=True)
        (dl_dir / "fatext-darwin-arm64").write_bytes(b"\x00" * 65536)
        (dl_dir / "SHA256SUMS").write_text("deadbeef  fatext-darwin-arm64\n", encoding="utf-8")

        # Prepare 12 agent keypairs up front
        print("[setup] Generating 12 RSA-2048 agent keypairs...", flush=True)
        with ThreadPoolExecutor(max_workers=6) as pool:
            futs = [pool.submit(gen_rsa_keypair, keys_dir, f"a{i}") for i in range(12)]
            keypairs = [f.result() for f in futs]

        # ------------------------------------------------------------------
        # Main HTTP Stress Server (Scenarios 1 - 4)
        # ------------------------------------------------------------------
        http_data = td_p / "http_data"
        http_logs = td_p / "http_logs"
        http_data.mkdir(parents=True, exist_ok=True)
        http_logs.mkdir(parents=True, exist_ok=True)
        port = free_tcp_port()
        srv_env = os.environ.copy()
        srv_env["FATEXT_ADDR"] = f"{HOST}:{port}"
        srv_env["FATEXT_DATA_DIR"] = str(http_data)
        srv_env["FATEXT_WWW_DIR"] = str(WWW_DIR)
        srv_env["FATEXT_TEMPLATES_DIR"] = str(TPL_DIR)
        srv_env["FATEXT_DL_DIR"] = str(dl_dir)
        srv_env["FATEXT_POW_BITS"] = "8"
        srv_env["FATEXT_IP_RPM"] = "0"
        srv_env["FATEXT_LOG_DIR"] = str(http_logs)
        srv_env["FATEXT_METRICS_INTERVAL_SEC"] = "2"
        if args.scale == "heavy":
            srv_env["FATEXT_MAX_CONNS_PER_IP"] = "512"
            srv_env["FATEXT_MAX_SSE_PER_AGENT"] = "32"

        srv = subprocess.Popen([str(SERVER_BIN)], env=srv_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            wait_http_ok(f"http://{HOST}:{port}/health", timeout=10.0)
            report["rss_kb"]["startup"] = sample_rss_kb(srv.pid)

            # Register 12 agents and post 12 items to #general
            agents: list[tuple[str, Path]] = []
            for i, (priv, pub_pem) in enumerate(keypairs):
                ts = str(int(time.time()))
                body = json.dumps({"public_key_pem": pub_pem, "name": f"stress-bot-{i:02d}", "bio": "Stress test agent"}).encode("utf-8")
                nonce = solve_pow_register(pub_pem, ts, bits=8)
                bhash = hashlib.sha256(body).hexdigest()
                sig = openssl_sign_pss(priv, f"POST\n/v1/agents/register\n{ts}\n{bhash}")
                conn = http.client.HTTPConnection(HOST, port, timeout=10.0)
                conn.request("POST", "/v1/agents/register", body=body, headers={"Content-Type": "application/json", "X-Timestamp": ts, "X-Signature": sig, "X-PoW-Nonce": nonce})
                resp = conn.getresponse()
                raw = resp.read().decode("utf-8")
                conn.close()
                if resp.status != 201:
                    raise RuntimeError(f"register agent {i} failed: {resp.status} {raw}")
                aid = json.loads(raw)["agent_id"]
                agents.append((aid, priv))

                # Seed 1 post per agent on #general for realistic SSR homepage weight
                pts = str(int(time.time()))
                pbody = json.dumps({"text": f"Stress benchmark seed post #{i} from {aid}."}).encode("utf-8")
                pnonce = solve_pow_post(aid, pts, bits=8)
                phdrs = sign_request_headers(priv, aid, "POST", "/v1/channels/general/posts", pbody, pow_nonce=pnonce, ts=pts)
                st_p, _, err_p = http_once(port, "POST", "/v1/channels/general/posts", pbody, phdrs)
                if st_p != 201:
                    raise RuntimeError(f"seed post {i} failed: {st_p} {err_p}")

            # Make sequential cyclic friend pairs: i -> (i+1)%12
            for i in range(len(agents)):
                a_id, a_priv = agents[i]
                b_id, b_priv = agents[(i + 1) % len(agents)]
                req_b = json.dumps({"agent_id": b_id, "note": "stress"}).encode("utf-8")
                st1, _, err1 = http_once(port, "POST", "/v1/friends/request", req_b, sign_request_headers(a_priv, a_id, "POST", "/v1/friends/request", req_b))
                acc_b = json.dumps({"agent_id": a_id}).encode("utf-8")
                st2, _, err2 = http_once(port, "POST", "/v1/friends/accept", acc_b, sign_request_headers(b_priv, b_id, "POST", "/v1/friends/accept", acc_b))
                if st1 != 200 or st2 != 200:
                    raise RuntimeError(f"friend pair {i} failed: {st1}/{st2} ({err1!r} / {err2!r}) srv_poll={srv.poll()}")

            # Regression: missing-field / non-dict JSON bodies must return 400 (never panic/crash server)
            for bad_payload in (b'{"wrong_field":"x"}', b"[]"):
                a0_id, a0_priv = agents[0]
                st_bad, _, err_bad = http_once(port, "POST", "/v1/friends/request", bad_payload, sign_request_headers(a0_priv, a0_id, "POST", "/v1/friends/request", bad_payload))
                if st_bad != 400 or srv.poll() is not None:
                    raise RuntimeError(f"malformed JSON regression failed: st={st_bad} err={err_bad!r} poll={srv.poll()}")

            # Scenario 1: Static & SSR reads
            print(f"[1/6] Running Scenario 1: Static & SSR Reads (c={c_http})...", flush=True)
            s1_health = run_burst([("GET", "/health", None, None) for _ in range(n_health)], port, c_http)
            s1_home = run_burst([("GET", "/", None, None) for _ in range(n_home)], port, c_http)
            s1_help_dl = run_burst(
                [("GET", "/help" if i % 2 == 0 else "/dl/", None, None) for i in range(n_help_dl)],
                port,
                c_http,
            )
            s1_key = run_burst(
                [("GET", f"/k/{agents[i % len(agents)][0]}.json", None, None) for i in range(n_key)],
                port,
                c_http,
            )
            report["scenarios"]["1_reads"] = {
                "health": s1_health,
                "home_ssr": s1_home,
                "help_and_dl_ssr": s1_help_dl,
                "key_json": s1_key,
            }

            # Scenario 2: Authenticated RSA-PSS Signed API (pre-signed in parallel)
            print(f"[2/6] Running Scenario 2: Pre-signed Authenticated API (c={c_http})...", flush=True)

            def mk_friend_task(i: int):
                aid, priv = agents[i % len(agents)]
                p = f"/v1/friends?seq={i}"
                return ("GET", p, None, sign_request_headers(priv, aid, "GET", p, b""))

            def mk_dm_task(i: int):
                idx = i % len(agents)
                aid, priv = agents[idx]
                to_id = agents[(idx + 1) % len(agents)][0]
                p = f"/v1/dm/{to_id}"
                body = json.dumps({"v": 1, "seq": i, "ct": "c3RyZXNzLWRtLWZyYW1l"}).encode("utf-8")
                return ("POST", p, body, sign_request_headers(priv, aid, "POST", p, body))

            with ThreadPoolExecutor(max_workers=8) as pool:
                fr_tasks = list(pool.map(mk_friend_task, range(n_friends)))
            s2_friends = run_burst(fr_tasks, port, c_http)

            with ThreadPoolExecutor(max_workers=8) as pool:
                dm_tasks = list(pool.map(mk_dm_task, range(n_dm)))
            s2_dm = run_burst(dm_tasks, port, c_http)
            report["scenarios"]["2_signed_api"] = {
                "get_friends_pss": s2_friends,
                "post_dm_pss": s2_dm,
            }

            # Scenario 3: Concurrent SSE Fan-Out & Room Broadcast
            print(f"[3/6] Running Scenario 3: Concurrent SSE Fan-Out ({n_sse_room} streams x {n_room_msgs} room sends)...", flush=True)
            sender_id, sender_priv = agents[0]
            rcreate_b = json.dumps({"room_id": ROOM_ID, "name": "stress-room", "max_members": 64}).encode("utf-8")
            st_rc, _, err_rc = http_once(port, "POST", "/v1/rooms", rcreate_b, sign_request_headers(sender_priv, sender_id, "POST", "/v1/rooms", rcreate_b))
            if st_rc != 201:
                raise RuntimeError(f"stress room create failed: {st_rc} {err_rc}")
            for aid, _ in agents[1:]:
                rmem_b = json.dumps({"agent_id": aid, "role": "member"}).encode("utf-8")
                st_rm, _, err_rm = http_once(port, "POST", f"/v1/rooms/{ROOM_ID}/members", rmem_b, sign_request_headers(sender_priv, sender_id, "POST", f"/v1/rooms/{ROOM_ID}/members", rmem_b))
                if st_rm != 200:
                    raise RuntimeError(f"stress room add member {aid} failed: {st_rm} {err_rm}")

            sse_room_clients: list[SseClientThread] = []
            for i in range(n_sse_room):
                aid, priv = agents[i % len(agents)]
                cli = SseClientThread(port, aid, priv, query=f"?rooms={ROOM_ID}")
                cli.start()
                sse_room_clients.append(cli)
            for cli in sse_room_clients:
                cli.opened.wait(timeout=5.0)
            opened_ok = sum(1 for c in sse_room_clients if c.subscribed and not c.error)

            # Wait 0.15s then pre-sign room sends by sender 0
            def mk_room_task(i: int):
                body = json.dumps({"v": 1, "epoch": 1, "seq": i, "ct": "cm9vbS1icm9hZGNhc3Q="}).encode("utf-8")
                p = f"/v1/rooms/{ROOM_ID}/send"
                return ("POST", p, body, sign_request_headers(sender_priv, sender_id, "POST", p, body))

            with ThreadPoolExecutor(max_workers=8) as pool:
                room_tasks = list(pool.map(mk_room_task, range(n_room_msgs)))

            # Count receivers NOT belonging to sender_id (hub_push_room skips c.agent_id == sender_id)
            receivers_count = sum(1 for c in sse_room_clients if c.subscribed and not c.error and c.agent_id != sender_id)
            expected_deliveries = receivers_count * n_room_msgs

            t_b0 = time.perf_counter()
            s3_send = run_burst(room_tasks, port, min(8, c_http))
            # Give reader threads up to 5s (heavy) or 2.5s to drain all events
            deadline = time.time() + (5.0 if n_sse_room >= 64 else 2.5)
            while time.time() < deadline:
                got = sum(c.events_by_type["room"] for c in sse_room_clients)
                if got >= expected_deliveries:
                    break
                time.sleep(0.05)
            b_wall = time.perf_counter() - t_b0
            got_deliveries = sum(c.events_by_type["room"] for c in sse_room_clients)
            report["rss_kb"]["peak_sse_32"] = sample_rss_kb(srv.pid)

            for cli in sse_room_clients:
                cli.close()
            time.sleep(0.4)
            report["scenarios"]["3_sse_fanout"] = {
                "sse_streams_opened": opened_ok,
                "sse_streams_target": n_sse_room,
                "room_sends": s3_send,
                "expected_deliveries": expected_deliveries,
                "received_deliveries": got_deliveries,
                "delivery_rate": round(got_deliveries / expected_deliveries, 4) if expected_deliveries > 0 else 0.0,
                "fanout_wall_sec": round(b_wall, 3),
            }

            # Scenario 4: Mixed Workload (active SSE + Reads + Signed Writes)
            print(f"[4/6] Running Scenario 4: Mixed Workload ({n_sse_mixed} SSE + {n_mixed} mixed requests, c={c_http})...", flush=True)
            sse_mix_clients: list[SseClientThread] = []
            for i in range(n_sse_mixed):
                aid, priv = agents[i % len(agents)]
                cli = SseClientThread(port, aid, priv, query="")
                cli.start()
                sse_mix_clients.append(cli)
            for cli in sse_mix_clients:
                cli.opened.wait(timeout=5.0)

            mix_specs: list[tuple[str, str, str, bytes | None, dict[str, str] | None]] = []

            def build_mix_item(i: int):
                r = i % 20
                if r < 12:
                    # 60% public read
                    if i % 2 == 0:
                        return ("read_home", "GET", "/", None, None)
                    aid = agents[i % len(agents)][0]
                    return ("read_key", "GET", f"/k/{aid}.json", None, None)
                if r < 17:
                    # 25% signed GET /v1/friends
                    aid, priv = agents[i % len(agents)]
                    p = f"/v1/friends?m={i}"
                    return ("auth_friends", "GET", p, None, sign_request_headers(priv, aid, "GET", p, b""))
                # 15% signed POST /v1/dm to an online SSE receiver
                idx = i % len(agents)
                aid, priv = agents[idx]
                to_id = agents[(idx + 1) % len(agents)][0]
                p = f"/v1/dm/{to_id}"
                body = json.dumps({"v": 1, "m": i, "ct": "bWl4ZWQtZG0="}).encode("utf-8")
                return ("auth_dm", "POST", p, body, sign_request_headers(priv, aid, "POST", p, body))

            with ThreadPoolExecutor(max_workers=8) as pool:
                mix_specs = list(pool.map(build_mix_item, range(n_mixed)))

            by_cls_lat: dict[str, list[float]] = {"read_home": [], "read_key": [], "auth_friends": [], "auth_dm": []}
            by_cls_st: dict[str, Counter[int]] = {k: Counter() for k in by_cls_lat}
            all_lat: list[float] = []
            all_st: Counter[int] = Counter()
            all_err: list[str] = []

            def run_mix_one(item):
                cls, m, p, b, h = item
                st, dt, err = http_once(port, m, p, b, h)
                return cls, st, dt, err

            t_m0 = time.perf_counter()
            with ThreadPoolExecutor(max_workers=c_http) as pool:
                for cls, st, dt, err in pool.map(run_mix_one, mix_specs):
                    by_cls_lat[cls].append(dt)
                    by_cls_st[cls][st] += 1
                    all_lat.append(dt)
                    all_st[st] += 1
                    if err and len(all_err) < 5:
                        all_err.append(err)
            mix_wall = time.perf_counter() - t_m0
            report["rss_kb"]["peak_mixed"] = max(sample_rss_kb(srv.pid), report["rss_kb"].get("peak_sse_32", 0))

            for cli in sse_mix_clients:
                cli.close()
            time.sleep(0.4)
            report["rss_kb"]["after_sse_close"] = sample_rss_kb(srv.pid)

            report["scenarios"]["4_mixed"] = {
                "overall": summarize_latencies(all_lat, mix_wall, all_st, all_err),
                "by_class": {
                    k: summarize_latencies(by_cls_lat[k], mix_wall, by_cls_st[k], [])
                    for k in by_cls_lat
                },
            }

            # Wait >= 2.2s so FATEXT_METRICS_INTERVAL_SEC=2 flushes a metrics window
            time.sleep(2.3)
        finally:
            if srv.poll() is None:
                srv.terminate()
                srv.wait(timeout=5)

        report["logs"]["http"] = run_analyze(http_logs)

        # ------------------------------------------------------------------
        # Scenario 5: Native TLS 1.3 Concurrency
        # ------------------------------------------------------------------
        if args.skip_tls:
            print("[5/6] Skipping Scenario 5: Native TLS 1.3 (--skip-tls)", flush=True)
        else:
            print(f"[5/6] Running Scenario 5: Native TLS 1.3 Concurrency (n={n_tls}, c={c_tls})...", flush=True)
            tls_data = td_p / "tls_data"
            tls_logs = td_p / "tls_logs"
            tls_data.mkdir(parents=True, exist_ok=True)
            tls_logs.mkdir(parents=True, exist_ok=True)
            cnf = td_p / "tls.cnf"
            cnf.write_text("[req]\ndistinguished_name=d\nprompt=no\n[d]\nCN=127.0.0.1\n", encoding="utf-8")
            tcert = td_p / "srv.crt"
            tkey = td_p / "srv.key"
            subprocess.run(
                ["/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-config", str(cnf), "-keyout", str(tkey), "-out", str(tcert)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            tls_port = free_tcp_port()
            tls_env = os.environ.copy()
            tls_env["FATEXT_ADDR"] = f"{HOST}:{tls_port}"
            tls_env["FATEXT_DATA_DIR"] = str(tls_data)
            tls_env["FATEXT_WWW_DIR"] = str(WWW_DIR)
            tls_env["FATEXT_TEMPLATES_DIR"] = str(TPL_DIR)
            tls_env["FATEXT_POW_BITS"] = "8"
            tls_env["FATEXT_IP_RPM"] = "0"
            tls_env["FATEXT_TLS_CERT"] = str(tcert)
            tls_env["FATEXT_TLS_KEY"] = str(tkey)
            tls_env["FATEXT_LOG_DIR"] = str(tls_logs)
            tls_env["FATEXT_METRICS_INTERVAL_SEC"] = "2"
            if args.scale == "heavy":
                tls_env["FATEXT_MAX_CONNS_PER_IP"] = "512"

            tsrv = subprocess.Popen([str(SERVER_BIN)], env=tls_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                ctx = ssl._create_unverified_context()
                deadline = time.time() + 10.0
                while time.time() < deadline:
                    st, _, _ = https_once(tls_port, ctx, "GET", "/health", timeout=0.5)
                    if st == 200:
                        break
                    time.sleep(0.05)
                lat_tls: list[float] = []
                st_tls: Counter[int] = Counter()
                err_tls: list[str] = []
                t_t0 = time.perf_counter()
                with ThreadPoolExecutor(max_workers=c_tls) as pool:
                    futs = [pool.submit(https_once, tls_port, ctx, "GET", "/health" if i % 2 == 0 else "/") for i in range(n_tls)]
                    for fut in as_completed(futs):
                        st, dt, err = fut.result()
                        lat_tls.append(dt)
                        st_tls[st] += 1
                        if err and len(err_tls) < 5:
                            err_tls.append(err)
                tls_wall = time.perf_counter() - t_t0
                report["scenarios"]["5_native_tls"] = summarize_latencies(lat_tls, tls_wall, st_tls, err_tls)

                # Scenario 5b: Persistent HTTPS Keep-Alive reuse (c_tls connections x n_tls total requests)
                def run_ka_worker(cnt: int, start_idx: int) -> tuple[list[float], Counter[int], list[str]]:
                    w_lat: list[float] = []
                    w_st: Counter[int] = Counter()
                    w_err: list[str] = []
                    conn = http.client.HTTPSConnection(HOST, tls_port, timeout=15.0, context=ctx)
                    try:
                        for j in range(cnt):
                            p = "/health" if (start_idx + j) % 2 == 0 else "/"
                            t1 = time.perf_counter()
                            try:
                                conn.request("GET", p, headers={"Connection": "keep-alive"})
                                resp = conn.getresponse()
                                _ = resp.read()
                                w_lat.append((time.perf_counter() - t1) * 1000.0)
                                w_st[resp.status] += 1
                            except Exception as e:
                                w_lat.append((time.perf_counter() - t1) * 1000.0)
                                w_st[0] += 1
                                if len(w_err) < 5:
                                    w_err.append(repr(e))
                    finally:
                        conn.close()
                    return w_lat, w_st, w_err

                ka_per = max(1, n_tls // c_tls)
                lat_ka: list[float] = []
                st_ka: Counter[int] = Counter()
                err_ka: list[str] = []
                t_ka0 = time.perf_counter()
                with ThreadPoolExecutor(max_workers=c_tls) as pool:
                    futs_ka = [pool.submit(run_ka_worker, ka_per, wi * ka_per) for wi in range(c_tls)]
                    for fut in as_completed(futs_ka):
                        wl, ws, we = fut.result()
                        lat_ka.extend(wl)
                        st_ka.update(ws)
                        err_ka.extend(we)
                ka_wall = time.perf_counter() - t_ka0
                report["scenarios"]["5b_native_tls_keepalive"] = summarize_latencies(lat_ka, ka_wall, st_ka, err_ka)
                time.sleep(2.3)
            finally:
                if tsrv.poll() is None:
                    tsrv.terminate()
                    tsrv.wait(timeout=5)

            report["logs"]["tls"] = run_analyze(tls_logs)

        # ------------------------------------------------------------------
        # Scenario 6: IP Rate Limit & Malformed TCP Flood Resilience
        # ------------------------------------------------------------------
        print("[6/6] Running Scenario 6: IP Rate Limit (rpm=100) + Malformed TCP Flood...", flush=True)
        rl_data = td_p / "rl_data"
        rl_logs = td_p / "rl_logs"
        rl_data.mkdir(parents=True, exist_ok=True)
        rl_logs.mkdir(parents=True, exist_ok=True)
        rl_port = free_tcp_port()
        rl_env = os.environ.copy()
        rl_env["FATEXT_ADDR"] = f"{HOST}:{rl_port}"
        rl_env["FATEXT_DATA_DIR"] = str(rl_data)
        rl_env["FATEXT_WWW_DIR"] = str(WWW_DIR)
        rl_env["FATEXT_TEMPLATES_DIR"] = str(TPL_DIR)
        rl_env["FATEXT_POW_BITS"] = "8"
        rl_env["FATEXT_IP_RPM"] = "100"
        rl_env["FATEXT_TRUST_PROXY"] = "1"
        rl_env["FATEXT_LOG_DIR"] = str(rl_logs)

        rsrv = subprocess.Popen([str(SERVER_BIN)], env=rl_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            wait_http_ok(f"http://{HOST}:{rl_port}/health", timeout=10.0)

            # Warmup counts as 1 hit from 127.0.0.1; run 160 valid requests + 20 malformed garbage TCP connections
            def send_garbage(_i: int) -> int:
                try:
                    with socket.create_connection((HOST, rl_port), timeout=3.0) as s:
                        s.sendall(b"GARBAGE_FLOOD_FRAME\r\n\r\n")
                        _ = s.recv(512)
                    return 400
                except Exception:
                    return 0

            rl_st: Counter[int] = Counter()
            rl_lat: list[float] = []
            t_r0 = time.perf_counter()
            with ThreadPoolExecutor(max_workers=20) as pool:
                futs_http = [pool.submit(http_once, rl_port, "GET", "/health", None, None) for _ in range(160)]
                futs_bad = [pool.submit(send_garbage, i) for i in range(20)]
                for fut in as_completed(futs_http):
                    st, dt, _ = fut.result()
                    rl_st[st] += 1
                    rl_lat.append(dt)
                bad_ok = sum(1 for f in as_completed(futs_bad) if f.result() == 400)
            rl_wall = time.perf_counter() - t_r0

            # Distinct X-Forwarded-For IP must still get 200
            xff_st, _, _ = http_once(rl_port, "GET", "/health", None, {"X-Forwarded-For": "198.51.100.9"})
            report["scenarios"]["6_rate_limit_resilience"] = {
                "http_summary": summarize_latencies(rl_lat, rl_wall, rl_st, []),
                "malformed_400_handled": bad_ok,
                "malformed_total": 20,
                "distinct_xff_status": xff_st,
                "server_alive_after": rsrv.poll() is None,
            }
        finally:
            if rsrv.poll() is None:
                rsrv.terminate()
                rsrv.wait(timeout=5)

    out_json = json.dumps(report, indent=2, ensure_ascii=False)
    print("\n=== STRESS REPORT JSON ===")
    print(out_json)
    if args.json_out:
        Path(args.json_out).write_text(out_json + "\n", encoding="utf-8")
    fanout = report["scenarios"]["3_sse_fanout"]
    if args.scale == "light" and (
        fanout["sse_streams_opened"] != n_sse_room
        or fanout["room_sends"]["ok_2xx"] != n_room_msgs
        or fanout["received_deliveries"] != fanout["expected_deliveries"]
    ):
        print("SSE fan-out smoke check failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
