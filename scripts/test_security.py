#!/usr/bin/env python3
"""Security regression test suite for fatext-server and deploy scripts (#1-#15)."""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVER_BIN = Path(os.environ.get("FATEXT_SERVER_BIN", str(ROOT / "build" / "fatext-server")))
CLI_BIN = Path(
    os.environ.get(
        "FATEXT_CLI_BIN",
        str(ROOT.parent / "fatext-cli" / "build" / "fatext"),
    )
)
WWW_DIR = ROOT / "www"
TPL_DIR = ROOT / "templates"
HOST = "127.0.0.1"


def free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, 0))
        return int(s.getsockname()[1])


def wait_tcp_ready(host: str, port: int, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.3):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"{host}:{port} not ready within {timeout}s")


def wait_http_ok(url: str, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1.0) as r:
                if r.status == 200:
                    return
        except Exception:
            time.sleep(0.05)
    raise TimeoutError(f"{url} did not return 200")


def assert_eq(a, b, msg: str = "") -> None:
    if a != b:
        raise AssertionError(f"{msg}: {a!r} != {b!r}")


def assert_true(cond: bool, msg: str = "") -> None:
    if not cond:
        raise AssertionError(f"assertion failed: {msg}")


def run_cli(args: list[str], *, home: str | None = None, api_url: str | None = None) -> tuple[int, str, str]:
    env = os.environ.copy()
    if home is not None:
        env["FATEXT_HOME"] = home
    cmd = [str(CLI_BIN)]
    if api_url is not None and "--api" not in args:
        cmd.extend(["--api", api_url])
    cmd.extend(args)
    res = subprocess.run(cmd, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30.0)
    return res.returncode, res.stdout, res.stderr


def sign_http_req(priv_pem_path: Path, method: str, path_and_query: str, body: bytes, ts: int) -> str:
    body_hex = hashlib.sha256(body).hexdigest()
    msg = f"{method}\n{path_and_query}\n{ts}\n{body_hex}".encode("utf-8")
    with tempfile.NamedTemporaryFile() as mf:
        mf.write(msg)
        mf.flush()
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
                str(priv_pem_path),
                mf.name,
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return base64.b64encode(res.stdout).decode("ascii")


def signed_http(
    host: str,
    port: int,
    agent_id: str,
    priv_pem_path: Path,
    method: str,
    path: str,
    body_bytes: bytes,
    extra_headers: dict[str, str] | None = None,
) -> tuple[int, dict]:
    ts = int(time.time())
    sig = sign_http_req(priv_pem_path, method, path, body_bytes, ts)
    hdrs = {
        "Content-Type": "application/json",
        "X-Agent-Id": agent_id,
        "X-Timestamp": str(ts),
        "X-Signature": sig,
    }
    if extra_headers:
        hdrs.update(extra_headers)
    conn = http.client.HTTPConnection(host, port, timeout=10.0)
    conn.request(method, path, body=body_bytes, headers=hdrs)
    resp = conn.getresponse()
    raw = resp.read().decode("utf-8", errors="replace")
    conn.close()
    try:
        return resp.status, json.loads(raw)
    except Exception:
        return resp.status, {"raw": raw}


def generate_san_cert(workdir: Path) -> tuple[Path, Path]:
    cnf = workdir / "san.cnf"
    cnf.write_text(
        "[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n"
        "[dn]\nCN=localhost\n[v3]\nsubjectAltName=IP:127.0.0.1,DNS:localhost\n",
        encoding="utf-8",
    )
    cert_p = workdir / "cert.pem"
    key_p = workdir / "key.pem"
    subprocess.run(
        ["/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-config", str(cnf), "-extensions", "v3", "-keyout", str(key_p), "-out", str(cert_p)],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return cert_p, key_p


def test_tls_redirect_and_headers(td_p: Path) -> None:
    print("[1/5] Port-80 redirect host/path sanitization + TLS/HTML security headers...")
    cert_p, key_p = generate_san_cert(td_p)
    tls_port = free_tcp_port()
    redir_port = free_tcp_port()
    data_dir = td_p / "tls_data"
    data_dir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["FATEXT_ADDR"] = f"{HOST}:{tls_port}"
    env["FATEXT_HTTP_REDIRECT_ADDR"] = f"{HOST}:{redir_port}"
    env["FATEXT_PUBLIC_HOST"] = "fatext.com"
    env["FATEXT_TLS_CERT"] = str(cert_p)
    env["FATEXT_TLS_KEY"] = str(key_p)
    env["FATEXT_DATA_DIR"] = str(data_dir)
    env["FATEXT_WWW_DIR"] = str(WWW_DIR)
    env["FATEXT_TEMPLATES_DIR"] = str(TPL_DIR)
    env["FATEXT_POW_BITS"] = "10"

    srv = subprocess.Popen([str(SERVER_BIN)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        wait_tcp_ready(HOST, tls_port)
        wait_tcp_ready(HOST, redir_port)

        # Arbitrary evil Host must NOT appear in 301 Location
        conn = http.client.HTTPConnection(HOST, redir_port, timeout=5.0)
        conn.request("GET", "/c/dev", headers={"Host": "evil.attacker"})
        r1 = conn.getresponse()
        r1.read()
        conn.close()
        assert_eq(r1.status, 301, "evil host redirect status")
        assert_eq(r1.getheader("Location"), "https://fatext.com/c/dev", "evil host forced to public_host")

        # Allowed www.fatext.com stays www.fatext.com
        conn = http.client.HTTPConnection(HOST, redir_port, timeout=5.0)
        conn.request("GET", "/help", headers={"Host": "www.fatext.com"})
        r2 = conn.getresponse()
        r2.read()
        conn.close()
        assert_eq(r2.status, 301, "www host redirect status")
        assert_eq(r2.getheader("Location"), "https://www.fatext.com/help", "www host allowed")

        # Protocol-relative open redirect GET //evil.com/x rejected
        with socket.create_connection((HOST, redir_port), timeout=5.0) as s:
            s.sendall(b"GET //evil.com/x HTTP/1.1\r\nHost: fatext.com\r\nConnection: close\r\n\r\n")
            raw = s.recv(4096).decode("utf-8", errors="replace")
        assert_true("400 Bad Request" in raw, f"expected 400 on //evil.com redirect: {raw}")

        # TLS response headers (HSTS, CSP on HTML, X-Frame-Options, Referrer-Policy, nosniff)
        ctx = ssl.create_default_context(cafile=str(cert_p))
        with urllib.request.urlopen(f"https://{HOST}:{tls_port}/", context=ctx, timeout=5.0) as resp:
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            html = resp.read().decode("utf-8")
        assert_eq(hdrs.get("x-content-type-options"), "nosniff", "nosniff header")
        assert_eq(hdrs.get("x-frame-options"), "DENY", "X-Frame-Options header")
        assert_eq(hdrs.get("referrer-policy"), "no-referrer", "Referrer-Policy header")
        assert_true("default-src 'none'" in hdrs.get("content-security-policy", ""), f"CSP missing: {hdrs}")
        assert_true("max-age=31536000" in hdrs.get("strict-transport-security", ""), f"HSTS missing over TLS: {hdrs}")
        assert_true("<nav" in html, "homepage HTML rendered")
    finally:
        srv.terminate()
        srv.wait(timeout=5)


def test_http_smuggling_and_slowloris(host: str, port: int) -> None:
    print("[2/5] HTTP CL/TE smuggling, malformed headers, and Slowloris cumulative deadline...")
    smuggle_payloads = [
        b"POST /health HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n0\r\n\r\n",
        b"POST /health HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello",
        b"POST /health HTTP/1.1\r\nHost: localhost\r\nContent-Length: -1\r\n\r\n",
        b"POST /health HTTP/1.1\r\nHost: localhost\r\nContent-Length: +5\r\n\r\nhello",
        b"POST /health HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding : chunked\r\n\r\n",
        b"GET //evil.com HTTP/1.1\r\nHost: localhost\r\n\r\n",
    ]
    for payload in smuggle_payloads:
        with socket.create_connection((host, port), timeout=5.0) as s:
            s.sendall(payload)
            resp = s.recv(4096).decode("utf-8", errors="replace")
        assert_true("400 Bad Request" in resp, f"expected 400 on smuggling payload {payload!r}, got {resp!r}")

    # Slowloris trickle: 1 header every 1.2s must still hit 10s cumulative deadline instead of extending forever
    t0 = time.time()
    with socket.create_connection((host, port), timeout=15.0) as s:
        s.sendall(b"GET /health HTTP/1.1\r\nHost: localhost\r\n")
        got = b""
        for i in range(11):
            time.sleep(1.2)
            try:
                s.sendall(f"X-Pad-{i}: val\r\n".encode("ascii"))
                s.settimeout(0.1)
                chunk = s.recv(1024)
                if chunk:
                    got += chunk
                    break
                if chunk == b"":
                    break
            except socket.timeout:
                s.settimeout(15.0)
                continue
            except OSError:
                break
        if not got:
            s.settimeout(2.0)
            try:
                got = s.recv(4096)
            except OSError:
                pass
    elapsed = time.time() - t0
    assert_true(elapsed < 13.5, f"Slowloris connection outlived cumulative 10s deadline ({elapsed:.2f}s)")


def test_restore_rejects_symlinks(td_p: Path) -> None:
    print("[3/5] deploy/restore.sh rejects symlinks in backup archive...")
    src_dir = td_p / "bad_backup_src"
    (src_dir / "keys").mkdir(parents=True, exist_ok=True)
    evil_link = src_dir / "keys" / "evil_link"
    evil_link.symlink_to("/etc/passwd")
    arch = td_p / "evil_symlink.tar.gz"
    with tarfile.open(arch, "w:gz") as tf:
        tf.add(src_dir / "keys", arcname="keys", recursive=True)
    res = subprocess.run(
        ["bash", str(ROOT / "deploy" / "restore.sh"), str(arch), str(td_p / "out_data"), "--dry-run"],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10.0,
    )
    assert_true(res.returncode != 0, f"restore.sh must fail on symlink archive, got rc={res.returncode} out={res.stdout}")
    assert_true("unsafe entry type" in res.stderr, f"expected unsafe entry type message, got {res.stderr}")


def main() -> int:
    if not SERVER_BIN.is_file() or not CLI_BIN.is_file():
        print("Missing built server or cli binary", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory(prefix="fatext-sec-") as td:
        td_p = Path(td)
        test_tls_redirect_and_headers(td_p)
        test_restore_rejects_symlinks(td_p)

        print("[4/5] Testing SSRF, SSR single-pass, XFF right-to-left, SSE compaction, room/post/mail bounds...")
        port = free_tcp_port()
        api_url = f"http://{HOST}:{port}"
        data_dir = td_p / "main_data"
        log_dir = td_p / "main_logs"
        data_dir.mkdir(parents=True, exist_ok=True)
        log_dir.mkdir(parents=True, exist_ok=True)
        mail_secret = "sec-mail-secret-42991"

        srv_env = os.environ.copy()
        srv_env["FATEXT_ADDR"] = f"{HOST}:{port}"
        srv_env["FATEXT_DATA_DIR"] = str(data_dir)
        srv_env["FATEXT_WWW_DIR"] = str(WWW_DIR)
        srv_env["FATEXT_TEMPLATES_DIR"] = str(TPL_DIR)
        srv_env["FATEXT_POW_BITS"] = "10"
        srv_env["FATEXT_LOG_DIR"] = str(log_dir)
        srv_env["FATEXT_TRUST_PROXY"] = "1"
        srv_env["FATEXT_MAIL_INTERNAL_SECRET"] = mail_secret

        srv = subprocess.Popen([str(SERVER_BIN)], env=srv_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            wait_http_ok(f"{api_url}/health")

            # Register Controller C, Agents A & B
            home_c = td_p / "home_c"
            home_a = td_p / "home_a"
            home_b = td_p / "home_b"
            rc, out, err = run_cli(["--json", "init", "--controller-only", "--name", "SecCtl"], home=str(home_c), api_url=api_url)
            assert_eq(rc, 0, f"init C failed: {err}")
            v1 = td_p / "cred.json"
            rc, _, err = run_cli(["--json", "ctl", "cred", "issue", "--scopes", "all", "--out", str(v1)], home=str(home_c), api_url=api_url)
            assert_eq(rc, 0, f"cred issue failed: {err}")

            rc, out, err = run_cli(["--json", "init", "--name", "SecA", "--credential", str(v1)], home=str(home_a), api_url=api_url)
            assert_eq(rc, 0, f"init A failed: {err}")
            aid_a = json.loads(out.strip())["agent_id"]

            rc, out, err = run_cli(["--json", "init", "--name", "SecB"], home=str(home_b), api_url=api_url)
            assert_eq(rc, 0, f"init B failed: {err}")
            aid_b = json.loads(out.strip())["agent_id"]

            # Become friends A <-> B
            rc, _, err = run_cli(["friend", "add", aid_b], home=str(home_a), api_url=api_url)
            assert_eq(rc, 0, f"friend add failed: {err}")
            rc, _, err = run_cli(["friend", "accept", aid_a], home=str(home_b), api_url=api_url)
            assert_eq(rc, 0, f"friend accept failed: {err}")

            # Restart server to clear 60s registration->profile cooldown
            srv.terminate()
            srv.wait(timeout=5)
            srv = subprocess.Popen([str(SERVER_BIN)], env=srv_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            wait_http_ok(f"{api_url}/health")

            # SSRF webhook rejections
            bad_webhooks = [
                "https://127.0.0.1/hook",
                "https://127.0.0.1:8080/hook",
                "https://169.254.169.254/latest/meta-data/",
                "https://localhost/hook",
                "https://[::1]/hook",
                "https://10.0.0.1/hook",
                "https://192.168.1.1/hook",
                "https://100.64.0.1/hook",
                "https://public.example@127.0.0.1/hook",
                "https://2130706433/hook",
                "https://internal-svc/hook",
            ]
            for wh in bad_webhooks:
                rc, _, err = run_cli(["--json", "profile", "set", "--webhook-url", wh], home=str(home_a), api_url=api_url)
                assert_eq(rc, 2, f"SSRF webhook {wh!r} should be rejected with rc=2 (400), got rc={rc} err={err}")

            # Valid public webhook succeeds (also enable accept-email for later mail ingest test)
            rc, _, err = run_cli(
                ["--json", "profile", "set", "--webhook-url", "https://example.com/hook", "--accept-email", "true"],
                home=str(home_a), api_url=api_url,
            )
            assert_eq(rc, 0, f"valid webhook profile set failed: {err}")

            # SSR template injection checks
            try:
                urllib.request.urlopen(f"{api_url}/foo$nav_items$content", timeout=5.0)
                raise AssertionError("expected 404")
            except urllib.error.HTTPError as e:
                assert_eq(e.code, 404, "404 status for /foo$nav_items")
                body_404 = e.read().decode("utf-8")
                assert_true("<nav class=" not in body_404 or body_404.count('href="/c/') < 20, "must not expand $nav_items/$content inside path")
                assert_true("/foo$nav_items$content" in body_404, f"escaped literal path missing in 404: {body_404}")

            marker_text = "Literal dollars: $text $ts $content $nav_items $title"
            rc, out, err = run_cli(["--json", "pub", "post", "general", marker_text], home=str(home_a), api_url=api_url)
            assert_eq(rc, 0, f"pub post with $tokens failed: {err}")
            msg_id = json.loads(out.strip())["msg_id"]
            with urllib.request.urlopen(f"{api_url}/t/{msg_id}", timeout=5.0) as tr:
                t_html = tr.read().decode("utf-8")
            assert_true(marker_text in t_html, f"expected unexpanded $tokens in rendered thread HTML")

            # Post body size cap (>8192)
            big_post = json.dumps({"text": "hi", "pad": "x" * 9000}).encode("utf-8")
            st_big, _ = signed_http(HOST, port, aid_a, home_a / "private.pem", "POST", "/v1/channels/general/posts", big_post)
            assert_eq(st_big, 413, "oversized post raw body rejected 413")

            # Block target newline injection rejected
            st_blk, _ = signed_http(HOST, port, aid_a, home_a / "private.pem", "POST", "/v1/blocks", b'{"target":"foo\\nbar"}')
            assert_eq(st_blk, 400, "newline in block target rejected 400")

            # Room invite_frame validation before mutation + epoch strictness + rekey step limit
            rc, out, err = run_cli(["--json", "room", "create", "--name", "SecRoom"], home=str(home_a), api_url=api_url)
            assert_eq(rc, 0, f"room create failed: {err}")
            rc_res = json.loads(out.strip())
            rid = rc_res.get("room_id") or rc_res["room"]["room_id"]
            if os.name != "nt":
                import stat as pystat
                assert_eq(pystat.S_IMODE(home_a.stat().st_mode), 0o700, "CLI home dir mode 0700")
                assert_eq(pystat.S_IMODE((home_a / "private.pem").stat().st_mode), 0o600, "CLI private.pem mode 0600")
                assert_eq(pystat.S_IMODE((home_a / "rooms").stat().st_mode), 0o700, "CLI rooms dir mode 0700")
                assert_eq(pystat.S_IMODE((home_a / "rooms" / f"{rid}.json").stat().st_mode), 0o600, "CLI room file mode 0600")

            oversized_inv = json.dumps({"agent_id": aid_b, "invite_frame": {"blob": "z" * 33000}}).encode("utf-8")
            st_inv, _ = signed_http(HOST, port, aid_a, home_a / "private.pem", "POST", f"/v1/rooms/{rid}/members", oversized_inv)
            assert_eq(st_inv, 413, "oversized invite_frame rejected 413")
            st_rg, rg = signed_http(HOST, port, aid_a, home_a / "private.pem", "GET", f"/v1/rooms/{rid}", b"")
            assert_eq(st_rg, 200, "room get 200")
            assert_eq(len(rg["room"]["members"]), 1, "B must NOT be added when invite_frame fails")

            # Rekey cannot jump epoch > +1
            st_rk, _ = signed_http(HOST, port, aid_a, home_a / "private.pem", "POST", f"/v1/rooms/{rid}/rekey", b'{"epoch":99}')
            assert_eq(st_rk, 400, "rekey epoch jump > 1 rejected 400")

            # Room send missing epoch or stale epoch -> 409
            st_rs1, _ = signed_http(HOST, port, aid_a, home_a / "private.pem", "POST", f"/v1/rooms/{rid}/send", b'{"v":1,"alg":"A256GCM","iv":"a","ct":"b"}')
            assert_eq(st_rs1, 409, "room send without epoch rejected 409")
            st_rs2, _ = signed_http(HOST, port, aid_a, home_a / "private.pem", "POST", f"/v1/rooms/{rid}/send", b'{"v":1,"alg":"A256GCM","epoch":0,"iv":"a","ct":"b"}')
            assert_eq(st_rs2, 409, "room send with epoch 0 rejected 409")

            # SSE pretty-printed multi-line DM JSON compaction check via raw SSE stream + signed DM POST
            ts_sse = int(time.time())
            sig_sse = sign_http_req(home_b / "private.pem", "GET", "/v1/stream", b"", ts_sse)
            sse_sock = socket.create_connection((HOST, port), timeout=5.0)
            sse_sock.sendall(
                (
                    f"GET /v1/stream HTTP/1.1\r\nHost: {HOST}\r\n"
                    f"X-Agent-Id: {aid_b}\r\nX-Timestamp: {ts_sse}\r\nX-Signature: {sig_sse}\r\n\r\n"
                ).encode("ascii")
            )
            hdr_buf = b""
            while b"\n\n" not in hdr_buf and b"\r\n\r\n" not in hdr_buf:
                hdr_buf += sse_sock.recv(4096)
            multiline_dm = b'{\n  "v": 1,\n  "alg": "RSA-OAEP-256+A256GCM",\n  "ek": "abc",\n  "iv": "def",\n  "ct": "ghi"\n}'
            st_dm, dm_res = signed_http(HOST, port, aid_a, home_a / "private.pem", "POST", f"/v1/dm/{aid_b}", multiline_dm)
            assert_eq(st_dm, 202, f"multiline DM send 202: {dm_res}")
            sse_sock.settimeout(3.0)
            ev_buf = sse_sock.recv(4096).decode("utf-8", errors="replace")
            sse_sock.close()
            data_lines = [ln[6:] for ln in ev_buf.splitlines() if ln.startswith("data: ")]
            assert_true(len(data_lines) >= 1, f"expected compacted SSE data line, got {ev_buf!r}")
            parsed_sse = json.loads(data_lines[0])
            assert_eq(parsed_sse["frame"]["ek"], "abc", "compacted multi-line DM intact in single SSE data line")

            # Mail ingest: wrong secret -> 401; oversized snippet -> 413; suspended recipient -> 403
            def post_mail(sec: str, payload: dict) -> int:
                req = urllib.request.Request(
                    f"{api_url}/internal/mail/ingest",
                    data=json.dumps(payload).encode("utf-8"),
                    method="POST",
                    headers={"Content-Type": "application/json", "X-Internal-Secret": sec},
                )
                try:
                    with urllib.request.urlopen(req, timeout=5.0) as mr:
                        return mr.status
                except urllib.error.HTTPError as e:
                    return e.code

            assert_eq(post_mail("wrong-secret", {"to_agent_id": aid_a, "from": "a@b.com", "subject": "s", "raw_snippet": "hi"}), 401, "mail bad secret 401")
            assert_eq(post_mail(mail_secret, {"to_agent_id": aid_a, "from": "a@b.com", "subject": "s", "raw_snippet": "x" * 17000}), 413, "mail huge snippet 413")
            rc, _, err = run_cli(["ctl", "suspend", aid_a, "--reason", "sec-check"], home=str(home_c), api_url=api_url)
            assert_eq(rc, 0, f"ctl suspend failed: {err}")
            assert_eq(post_mail(mail_secret, {"to_agent_id": aid_a, "from": "a@b.com", "subject": "s", "raw_snippet": "ok"}), 403, "mail to suspended agent rejected 403")

            # XFF right-to-left check: spoofed leftmost IP 1.2.3.4 ignored in favor of 198.51.100.9
            with urllib.request.urlopen(
                urllib.request.Request(f"{api_url}/health", headers={"X-Forwarded-For": "1.2.3.4, 198.51.100.9"}),
                timeout=5.0,
            ) as r:
                assert_eq(r.status, 200, "XFF multi-hop health")
            time.sleep(0.15)
            ips_logged = set()
            for p in log_dir.glob("access-*.jsonl"):
                for ln in p.read_text(encoding="utf-8").splitlines():
                    if ln.strip():
                        ips_logged.add(json.loads(ln).get("ip", ""))
            assert_true("198.51.100.9" in ips_logged, f"expected rightmost XFF IP 198.51.100.9 in {ips_logged}")
            assert_true("1.2.3.4" not in ips_logged, f"spoofed leftmost XFF IP 1.2.3.4 must not be logged: {ips_logged}")

            print("[5/5] Running HTTP smuggling & Slowloris test...")
            test_http_smuggling_and_slowloris(HOST, port)
        finally:
            if srv.poll() is None:
                srv.terminate()
                srv.wait(timeout=5)

    print("ALL 5 SERVER SECURITY REGRESSION TESTS PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
