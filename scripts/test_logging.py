#!/usr/bin/env python3
"""End-to-end verification for fatext-server structured logging, metrics, retention, privacy, and analyzer."""

from __future__ import annotations

import datetime as dt
import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVER_BIN = ROOT / "build" / "fatext-server"
CLI_BIN = ROOT.parent / "fatext-cli" / "build" / "fatext"
ANALYZE_PY = ROOT / "scripts" / "analyze_logs.py"
WWW_DIR = ROOT / "www"
TPL_DIR = ROOT / "templates"
HOST = "127.0.0.1"


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
    raise TimeoutError(f"{url} did not become ready")


def assert_eq(a, b, msg: str = "") -> None:
    if a != b:
        raise AssertionError(f"{msg}: {a!r} != {b!r}")


def assert_true(cond: bool, msg: str = "") -> None:
    if not cond:
        raise AssertionError(f"assertion failed: {msg}")


def run_cli(
    args: list[str],
    *,
    agent_home: str | None = None,
    human_home: str | None = None,
    api_url: str,
) -> tuple[int, str, str]:
    env = os.environ.copy()
    if agent_home is not None:
        env["FATEXT_HOME"] = agent_home
    if human_home is not None:
        env["FATEXT_HUMAN_HOME"] = human_home
    res = subprocess.run(
        [str(CLI_BIN), "--api", api_url] + args,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30.0,
    )
    return res.returncode, res.stdout, res.stderr


def load_jsonl_glob(log_dir: Path, pattern: str) -> list[dict]:
    out = []
    for p in sorted(log_dir.glob(pattern)):
        for ln in p.read_text(encoding="utf-8").splitlines():
            ln = ln.strip()
            if ln:
                out.append(json.loads(ln))
    return out


def main() -> int:
    if not SERVER_BIN.is_file() or not CLI_BIN.is_file():
        print("Missing built binaries", file=sys.stderr)
        return 1

    today_s = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
    mail_secret = "log-test-secret-do-not-leak-8821"
    dm_secret = "PRIVATE_DM_PLAINTEXT_NEVER_LOG_7731"
    mail_subj = "PRIVATE_MAIL_SUBJECT_NEVER_LOG_4412"
    mail_snip = "PRIVATE_MAIL_BODY_NEVER_LOG_9923"
    mail_from = "private-sender@secret.example"

    with tempfile.TemporaryDirectory(prefix="fatext-logs-") as td:
        td_p = Path(td)
        data_dir = td_p / "data"
        log_dir = td_p / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        data_dir.mkdir(parents=True, exist_ok=True)

        # Seed expired (2020-01-01) and today's log files to test retention cleanup
        stale_access = log_dir / "access-2020-01-01.jsonl"
        stale_events = log_dir / "events-2020-01-01.jsonl"
        stale_access.write_text('{"ts":1577836800}\n', encoding="utf-8")
        stale_events.write_text('{"ts":1577836800}\n', encoding="utf-8")
        keep_today = log_dir / f"access-{today_s}.jsonl"
        keep_today.write_text("", encoding="utf-8")

        port = free_tcp_port()
        api_url = f"http://{HOST}:{port}"
        srv_env = os.environ.copy()
        srv_env["FATEXT_ADDR"] = f"{HOST}:{port}"
        srv_env["FATEXT_DATA_DIR"] = str(data_dir)
        srv_env["FATEXT_WWW_DIR"] = str(WWW_DIR)
        srv_env["FATEXT_TEMPLATES_DIR"] = str(TPL_DIR)
        srv_env["FATEXT_POW_BITS"] = "12"
        srv_env["FATEXT_MAIL_INTERNAL_SECRET"] = mail_secret
        srv_env["FATEXT_LOG_DIR"] = str(log_dir)
        srv_env["FATEXT_LOG_RETENTION_DAYS"] = "7"
        srv_env["FATEXT_SLOW_MS"] = "1"
        srv_env["FATEXT_METRICS_INTERVAL_SEC"] = "1"
        srv_env["FATEXT_TRUST_PROXY"] = "1"

        hh = str(td_p / "human")
        ah_a = str(td_p / "agent_a")
        ah_b = str(td_p / "agent_b")

        srv = subprocess.Popen(
            [str(SERVER_BIN)],
            env=srv_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            wait_http_ok(f"{api_url}/health", timeout=10.0)
            time.sleep(0.2)

            print("[1/5] Verifying startup retention GC & server_start event...")
            assert_true(not stale_access.exists(), "stale access-2020-01-01.jsonl removed")
            assert_true(not stale_events.exists(), "stale events-2020-01-01.jsonl removed")
            assert_true(keep_today.exists(), "today's log kept")

            print("[2/5] Generating proxy IP, HTTP read_fail, human control, DM, mail & SSE logs...")
            # Proxy XFF test
            req = urllib.request.Request(
                f"{api_url}/health",
                headers={"X-Forwarded-For": "203.0.113.77, 10.0.0.1"},
            )
            with urllib.request.urlopen(req, timeout=5.0) as r:
                assert_eq(r.status, 200, "XFF /health")

            # Malformed HTTP request to trigger http_read_fail
            with socket.create_connection((HOST, port), timeout=5.0) as bad_s:
                bad_s.sendall(b"GARBAGE\r\n\r\n")
                bad_s.recv(1024)

            rc, out, err = run_cli(["--json", "human", "init", "--name", "LogHuman"], human_home=hh, api_url=api_url)
            assert_eq(rc, 0, f"human init failed: {err}")
            hid = json.loads(out.strip())["human_id"]

            v1 = td_p / "v1.json"
            rc, _, err = run_cli(["--json", "human", "cred", "issue", "--scopes", "all", "--out", str(v1)], human_home=hh, api_url=api_url)
            assert_eq(rc, 0, f"cred issue failed: {err}")

            rc, out, err = run_cli(["--json", "init", "--name", "LogBotA", "--credential", str(v1)], agent_home=ah_a, api_url=api_url)
            assert_eq(rc, 0, f"init A failed: {err}")
            aid_a = json.loads(out.strip())["agent_id"]

            rc, out, err = run_cli(["--json", "init", "--name", "LogBotB"], agent_home=ah_b, api_url=api_url)
            assert_eq(rc, 0, f"init B failed: {err}")
            aid_b = json.loads(out.strip())["agent_id"]

            rc, _, err = run_cli(["friend", "add", aid_b], agent_home=ah_a, api_url=api_url)
            assert_eq(rc, 0, f"friend add failed: {err}")
            rc, _, err = run_cli(["friend", "accept", aid_a], agent_home=ah_b, api_url=api_url)
            assert_eq(rc, 0, f"friend accept failed: {err}")

            # Live SSE listen + DM relay
            sse = subprocess.Popen(
                [str(CLI_BIN), "--api", api_url, "--json", "listen", "--max-events", "1"],
                env={**os.environ, "FATEXT_HOME": ah_b},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            time.sleep(0.5)
            rc, _, err = run_cli(["--json", "dm", "send", aid_b, dm_secret], agent_home=ah_a, api_url=api_url)
            assert_eq(rc, 0, f"dm send failed: {err}")
            sse.communicate(timeout=10.0)
            # Wait >250ms so SSE ticker detects peer_closed and flushes sse_close event
            time.sleep(0.4)

            # Mail ingest (restart once so profile cooldown cleared -> enable accept_email)
            srv.terminate()
            srv.wait(timeout=5)
            srv = subprocess.Popen([str(SERVER_BIN)], env=srv_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            wait_http_ok(f"{api_url}/health", timeout=10.0)

            rc, _, err = run_cli(["profile", "set", "--accept-email", "true"], agent_home=ah_a, api_url=api_url)
            assert_eq(rc, 0, f"profile set accept-email failed: {err}")

            mail_body = json.dumps(
                {
                    "to_agent_id": aid_a,
                    "from": mail_from,
                    "subject": mail_subj,
                    "raw_snippet": mail_snip,
                    "spf_pass": True,
                    "dkim_pass": True,
                    "dmarc_pass": True,
                    "received_at": int(time.time()),
                }
            ).encode("utf-8")
            mreq = urllib.request.Request(
                f"{api_url}/internal/mail/ingest",
                data=mail_body,
                method="POST",
                headers={"Content-Type": "application/json", "X-Internal-Secret": mail_secret},
            )
            with urllib.request.urlopen(mreq, timeout=5.0) as mr:
                assert_eq(mr.status, 201, "mail ingest 201")

            # Human suspend control event + unauthorized 403 error code
            rc, _, err = run_cli(["--json", "human", "suspend", aid_a, "--reason", "log-check"], human_home=hh, api_url=api_url)
            assert_eq(rc, 0, f"human suspend failed: {err}")
            rc, _, _ = run_cli(["--json", "friend", "list"], agent_home=ah_a, api_url=api_url)
            assert_eq(rc, 5, "suspended 403 expected")

            # Wait for metrics ticker flush (>= 1s)
            time.sleep(1.3)
        finally:
            if srv.poll() is None:
                srv.terminate()
                srv.wait(timeout=5)

        print("[3/5] Verifying TLS handshake failure event in native TLS mode...")
        tls_port = free_tcp_port()
        cnf = td_p / "san.cnf"
        cnf.write_text("[req]\ndistinguished_name=d\nprompt=no\n[d]\nCN=localhost\n", encoding="utf-8")
        cert = td_p / "cert.pem"
        key = td_p / "key.pem"
        subprocess.run(
            ["/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-config", str(cnf), "-keyout", str(key), "-out", str(cert)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        tls_env = srv_env.copy()
        tls_env["FATEXT_ADDR"] = f"{HOST}:{tls_port}"
        tls_env["FATEXT_TLS_CERT"] = str(cert)
        tls_env["FATEXT_TLS_KEY"] = str(key)
        tsrv = subprocess.Popen([str(SERVER_BIN)], env=tls_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.time() + 10.0
            while time.time() < deadline:
                try:
                    with socket.create_connection((HOST, tls_port), timeout=0.3) as bs:
                        bs.sendall(b"NOT_TLS_CLIENT_HELLO\r\n")
                        bs.recv(64)
                    break
                except OSError:
                    time.sleep(0.05)
            time.sleep(0.3)
        finally:
            tsrv.terminate()
            tsrv.wait(timeout=5)

        print("[4/5] Asserting access/events/metrics schemas + strict privacy scan...")
        access_recs = load_jsonl_glob(log_dir, "access-*.jsonl")
        event_recs = load_jsonl_glob(log_dir, "events-*.jsonl")
        metric_recs = load_jsonl_glob(log_dir, "metrics-*.jsonl")

        assert_true(len(access_recs) >= 8, f"expected >= 8 access logs, got {len(access_recs)}")
        assert_true(any(r.get("ip") == "203.0.113.77" for r in access_recs), "missing XFF resolved IP 203.0.113.77")
        assert_true(any(r.get("route") == "/v1/dm/{id}" for r in access_recs), "missing normalized /v1/dm/{id} route")
        assert_true(any(r.get("err_code") == "ERR_AGENT_SUSPENDED" and r.get("status") == 403 for r in access_recs), "missing ERR_AGENT_SUSPENDED access record")
        assert_true(any(r.get("slow") is True for r in access_recs), "missing slow=true with FATEXT_SLOW_MS=1")
        for req_k in ("ts", "time", "req_id", "method", "route", "status", "err_code", "tls", "ip", "actor_type", "actor_id", "req_bytes", "resp_bytes", "tls_ms", "read_ms", "queue_ms", "handle_ms", "write_ms", "total_ms", "total_us", "slow"):
            assert_true(req_k in access_recs[0], f"missing access key {req_k}")

        ev_kinds = {e.get("kind") for e in event_recs}
        for need in ("server_start", "http_read_fail", "tls_handshake_fail", "sse_open", "dm_relay", "mail_ingest", "human_control", "sse_close"):
            assert_true(need in ev_kinds, f"missing event kind {need!r} in {ev_kinds}")

        assert_true(len(metric_recs) >= 1, f"expected >= 1 metrics snapshots, got {len(metric_recs)}")
        assert_true("latency_buckets" in metric_recs[0] and "req_total" in metric_recs[0], "invalid metrics schema")

        # Zero-leak scan across ALL files in log_dir
        forbidden_substrings = [
            dm_secret,
            mail_subj,
            mail_snip,
            mail_from,
            mail_secret,
            "BEGIN RSA PRIVATE KEY",
            "BEGIN PRIVATE KEY",
        ]
        for p in log_dir.rglob("*.jsonl"):
            txt = p.read_text(encoding="utf-8")
            for needle in forbidden_substrings:
                assert_true(needle not in txt, f"PRIVACY LEAK in {p.name}: found {needle!r}")

        print("[5/5] Verifying scripts/analyze_logs.py report output...")
        ar = subprocess.run(
            [sys.executable, str(ANALYZE_PY), "--log-dir", str(log_dir), "--date", today_s, "--json"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        rep = json.loads(ar.stdout)
        assert_true(rep["summary"]["total_requests"] >= 8, f"analyzer summary mismatch: {rep['summary']}")
        assert_true(len(rep["routes"]) >= 3, "analyzer routes missing")
        assert_true(rep["relay_and_mail"]["mail_ingests"] >= 1, "analyzer mail_ingests missing")
        assert_true("suspend" in rep["human_control_actions"], "analyzer human_control suspend missing")

    print("ALL 5 LOGGING, METRICS, PRIVACY & ANALYZER CHECKS PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
