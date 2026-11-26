#!/usr/bin/env python3
"""Security regression test suite for fatext-server and deploy scripts (#1-#15)."""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import os
import shutil
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
    print("[1/7] Port-80 redirect host/path sanitization + TLS/HTML security headers...")
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
    print("[2/7] HTTP CL/TE smuggling, malformed headers, and Slowloris cumulative deadline...")
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
    print("[3/7] deploy/restore.sh rejects symlinks in backup archive...")
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


def test_backup_restore_acme_and_tmp(td_p: Path) -> None:
    print("[3b/7] deploy/backup.sh & restore.sh acme permissions + *.tmp exclusion...")
    import stat as pystat

    src_data = td_p / "bkp_src_data"
    bkps_dir = td_p / "bkp_out"
    dst_data = td_p / "bkp_dst_data"
    (src_data / "keys" / "ab").mkdir(parents=True, exist_ok=True)
    (src_data / "keys" / "ab" / "ftx_ab0000000001.json").write_text("{\"agent_id\":\"ftx_ab0000000001\"}\n", encoding="utf-8")
    (src_data / "keys" / "ab" / "stale.json.tmp.999").write_text("partial", encoding="utf-8")
    (src_data / "acme").mkdir(parents=True, exist_ok=True)
    (src_data / "acme" / "fullchain.pem").write_text("CERT", encoding="utf-8")
    (src_data / "acme" / "privkey.pem").write_text("KEY", encoding="utf-8")
    (src_data / "acme" / "account.json").write_text("{}", encoding="utf-8")

    r_bkp = subprocess.run(
        ["bash", str(ROOT / "deploy" / "backup.sh"), str(src_data), str(bkps_dir)],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10.0,
    )
    assert_eq(r_bkp.returncode, 0, f"backup.sh failed: {r_bkp.stderr}")
    tars = list(bkps_dir.glob("fatext-*.tar.gz"))
    assert_eq(len(tars), 1, f"expected 1 backup tarball, got {tars}")

    r_rst = subprocess.run(
        ["bash", str(ROOT / "deploy" / "restore.sh"), str(tars[0]), str(dst_data)],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10.0,
    )
    assert_eq(r_rst.returncode, 0, f"restore.sh failed: {r_rst.stderr}")
    assert_true(not (dst_data / "keys" / "ab" / "stale.json.tmp.999").exists(), "*.tmp.* must be excluded from backup")
    assert_true((dst_data / "acme" / "privkey.pem").is_file(), "acme/privkey.pem must be restored")
    assert_eq(pystat.S_IMODE((dst_data / "acme").stat().st_mode), 0o700, "restored acme dir must be 0700")
    assert_eq(pystat.S_IMODE((dst_data / "acme" / "privkey.pem").stat().st_mode), 0o600, "restored acme privkey.pem must be 0600")
    assert_eq(pystat.S_IMODE((dst_data / "acme" / "fullchain.pem").stat().st_mode), 0o600, "restored acme fullchain.pem must be 0600")

    service_bkps = td_p / "service_bkp_out"
    subprocess.run(
        ["bash", str(ROOT / "deploy" / "backup.sh"), str(src_data), str(service_bkps)],
        env={**os.environ, "FATEXT_BACKUP_SKIP_ACME": "1"}, check=True, capture_output=True, timeout=10.0,
    )
    manifest = subprocess.check_output(["tar", "-tzf", str(next(service_bkps.glob("*.tar.gz")))], text=True)
    assert_true("keys/ab/ftx_ab0000000001.json" in manifest, "periodic backup must include agent data")
    assert_true(not any(name.startswith("acme/") for name in manifest.splitlines()),
                "periodic backup must exclude the ACME directory")


def test_webhook_signature(td_p: Path) -> None:
    key = td_p / "official.pem"
    pub = td_p / "official.pub.pem"
    subprocess.run(
        ["/usr/bin/openssl", "genpkey", "-algorithm", "RSA",
         "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(key)],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["/usr/bin/openssl", "pkey", "-in", str(key), "-pubout", "-out", str(pub)],
        check=True, capture_output=True,
    )
    target = b"/events?format=json"
    digest = hashlib.sha256(b'{"event":"mail"}').hexdigest().encode()
    signer = [sys.executable, "-I", str(ROOT / "deploy" / "webhook_signer.py")]
    env = {**os.environ, "CREDENTIALS_DIRECTORY": str(td_p)}
    result = subprocess.run(signer, input=target + b"\n" + digest + b"\n",
                            env=env, capture_output=True, check=True, timeout=5)
    ts, encoded = result.stdout.strip().split(b" ")
    assert_true(abs(time.time() - int(ts)) < 10, "signer returns a fresh timestamp")
    sig_path = td_p / "webhook.sig"
    sig_path.write_bytes(base64.b64decode(encoded, validate=True))
    verify = ["/usr/bin/openssl", "dgst", "-sha256", "-verify", str(pub),
              "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32",
              "-sigopt", "rsa_mgf1_md:sha256", "-signature", str(sig_path)]
    request = b"POST\n" + target + b"\n" + ts + b"\n" + digest
    subprocess.run(verify, input=b"fatext-webhook-v1\n" + request,
                   check=True, capture_output=True, timeout=5)
    result = subprocess.run(verify, input=request, capture_output=True, timeout=5)
    assert_true(result.returncode != 0, "webhook signatures use a separate signing context")
    print("Webhook signing checks passed.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--without-cli", action="store_true", help="run checks that do not require the CLI")
    args = parser.parse_args()
    if not SERVER_BIN.is_file() or (not args.without_cli and not CLI_BIN.is_file()):
        print("Missing built server or cli binary", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory(prefix="fatext-sec-") as td:
        td_p = Path(td)
        test_tls_redirect_and_headers(td_p)
        test_restore_rejects_symlinks(td_p)
        test_backup_restore_acme_and_tmp(td_p)
        test_webhook_signature(td_p)
        if args.without_cli:
            return 0

        print("[4/7] Testing SSRF, SSR single-pass, XFF right-to-left, SSE compaction, room/post/mail bounds...")
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

            # Friend reject must still succeed cleanly
            st_rej, _ = signed_http(HOST, port, aid_b, home_b / "private.pem", "POST", "/v1/friends/reject", json.dumps({"agent_id": aid_a}).encode("utf-8"))
            assert_eq(st_rej, 200, "friend reject should return 200")

            # SSR /a/{id} must redact webhook_url path/query tokens
            rc, _, err = run_cli(
                ["--json", "profile", "set", "--webhook-url", "https://example.com/hooks/secret-token-99?k=1"],
                home=str(home_b), api_url=api_url,
            )
            assert_eq(rc, 0, f"set B webhook failed: {err}")
            with urllib.request.urlopen(f"{api_url}/a/{aid_b}", timeout=5.0) as ar:
                a_html = ar.read().decode("utf-8")
            assert_true("https://example.com/" in a_html, "redacted webhook host missing from /a/{id}")
            assert_true("secret-token-99" not in a_html and "k=1" not in a_html, f"webhook path/query leaked on /a/{aid_b}")

            print("[5/7] Running HTTP smuggling & Slowloris test...")
            test_http_smuggling_and_slowloris(HOST, port)
        finally:
            if srv.poll() is None:
                srv.terminate()
                srv.wait(timeout=5)

        print("[6/7] Testing admin local-only, shutdown audit, static/dl rate limit, and banned transfer/credential guards...")
        p6_port = free_tcp_port()
        p6_url = f"http://{HOST}:{p6_port}"
        p6_data = td_p / "p6_data"
        p6_logs = td_p / "p6_logs"
        p6_dl = td_p / "p6_dl"
        p6_data.mkdir(parents=True, exist_ok=True)
        p6_logs.mkdir(parents=True, exist_ok=True)
        p6_dl.mkdir(parents=True, exist_ok=True)
        (p6_dl / "test.bin").write_text("fatext-dl-payload", encoding="utf-8")

        adm_sec = "adm-sec-r2-9182"
        sd_sec = "sd-sec-r2-7741"
        p6_env = os.environ.copy()
        p6_env.update({
            "FATEXT_ADDR": f"{HOST}:{p6_port}",
            "FATEXT_DATA_DIR": str(p6_data),
            "FATEXT_LOG_DIR": str(p6_logs),
            "FATEXT_WWW_DIR": str(WWW_DIR),
            "FATEXT_TEMPLATES_DIR": str(TPL_DIR),
            "FATEXT_DL_DIR": str(p6_dl),
            "FATEXT_POW_BITS": "8",
            "FATEXT_TRUST_PROXY": "1",
            "FATEXT_ADMIN_SECRET": adm_sec,
            "FATEXT_ADMIN_LOCAL_ONLY": "1",
            "FATEXT_SHUTDOWN_SECRET": sd_sec,
            "FATEXT_IP_RPM": "25",
        })
        srv6 = subprocess.Popen([str(SERVER_BIN)], env=p6_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            wait_http_ok(f"{p6_url}/health")

            # Wrong admin secret -> 403 and logged (never logging wrong secret value)
            bad_tok = "wrong-secret-never-log-me"
            req_bad_adm = urllib.request.Request(
                f"{p6_url}/internal/admin/stats",
                headers={"X-Fatext-Admin-Secret": bad_tok, "X-Forwarded-For": "203.0.113.55"},
            )
            try:
                urllib.request.urlopen(req_bad_adm, timeout=5.0)
                raise AssertionError("expected 403 on bad admin secret")
            except urllib.error.HTTPError as e:
                assert_eq(e.code, 403, "bad admin secret 403")

            # Valid admin secret from loopback succeeds even with X-Forwarded-For external IP when FATEXT_ADMIN_LOCAL_ONLY=1
            req_ok_adm = urllib.request.Request(
                f"{p6_url}/internal/admin/stats",
                headers={"X-Fatext-Admin-Secret": adm_sec, "X-Forwarded-For": "203.0.113.55"},
            )
            with urllib.request.urlopen(req_ok_adm, timeout=5.0) as r:
                assert_eq(r.status, 200, "loopback admin allowed despite XFF")

            # Register Controller C2, Agent M1, Agent M2; invite M2 to room; then admin-ban M2
            h_c2, h_m1, h_m2 = td_p / "h_c2", td_p / "h_m1", td_p / "h_m2"
            assert_eq(run_cli(["--json", "init", "--name", "C2"], home=str(h_c2), api_url=p6_url)[0], 0, "init C2")
            _, out1, _ = run_cli(["--json", "init", "--name", "M1"], home=str(h_m1), api_url=p6_url)
            _, out2, _ = run_cli(["--json", "init", "--name", "M2"], home=str(h_m2), api_url=p6_url)
            id_m1 = json.loads(out1.strip())["agent_id"]
            id_m2 = json.loads(out2.strip())["agent_id"]

            assert_eq(run_cli(["friend", "add", id_m2], home=str(h_m1), api_url=p6_url)[0], 0, "m1->m2")
            assert_eq(run_cli(["friend", "accept", id_m1], home=str(h_m2), api_url=p6_url)[0], 0, "m2 accept")
            _, r_out, _ = run_cli(["--json", "room", "create", "--name", "BanTransRoom"], home=str(h_m1), api_url=p6_url)
            rid2 = json.loads(r_out.strip()).get("room_id") or json.loads(r_out.strip())["room"]["room_id"]
            assert_eq(run_cli(["room", "invite", rid2, id_m2], home=str(h_m1), api_url=p6_url)[0], 0, "invite m2")

            # Admin ban M2
            ban_req = urllib.request.Request(
                f"{p6_url}/internal/admin/agents/{id_m2}/ban",
                data=b'{"reason":"sec-test"}',
                method="POST",
                headers={"Content-Type": "application/json", "X-Fatext-Admin-Secret": adm_sec},
            )
            with urllib.request.urlopen(ban_req, timeout=5.0) as br:
                assert_eq(br.status, 200, "admin ban m2 200")

            # Transferring room ownership to banned M2 -> 403 ERR_AGENT_BANNED
            st_tr, tr_j = signed_http(HOST, p6_port, id_m1, h_m1 / "private.pem", "POST", f"/v1/rooms/{rid2}/transfer", json.dumps({"agent_id": id_m2}).encode("utf-8"))
            assert_eq(st_tr, 403, f"transfer to banned agent rejected: {tr_j}")
            assert_eq(tr_j.get("error", {}).get("code"), "ERR_AGENT_BANNED", f"unexpected error code: {tr_j}")

            # DM to banned M2 -> 403 ERR_AGENT_BANNED
            st_dm_ban, dm_ban_j = signed_http(HOST, p6_port, id_m1, h_m1 / "private.pem", "POST", f"/v1/dm/{id_m2}", b'{"v":1,"ek":"a","iv":"b","ct":"c"}')
            assert_eq(st_dm_ban, 403, f"DM to banned agent rejected: {dm_ban_j}")
            assert_eq(dm_ban_j.get("error", {}).get("code"), "ERR_AGENT_BANNED", f"unexpected DM banned code: {dm_ban_j}")

            # Docs PUT rate limit (>10/min per agent -> 429 ERR_RATE_LIMITED)
            for dv in range(1, 12):
                content = f"# Soul v{dv}\n"
                csha = hashlib.sha256(content.encode("utf-8")).hexdigest()
                uat = int(time.time())
                canon = json.dumps(
                    {
                        "agent_id": id_m1,
                        "content_sha256": csha,
                        "kind": "soul",
                        "locked": False,
                        "signer_id": id_m1,
                        "signer_key_version": 1,
                        "updated_at": uat,
                        "version": dv,
                        "visibility": "public",
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
                with tempfile.NamedTemporaryFile() as dmf:
                    dmf.write(canon)
                    dmf.flush()
                    dsig = base64.b64encode(
                        subprocess.check_output(
                            [
                                "/usr/bin/openssl", "dgst", "-sha256",
                                "-sigopt", "rsa_padding_mode:pss",
                                "-sigopt", "rsa_pss_saltlen:32",
                                "-sigopt", "rsa_mgf1_md:sha256",
                                "-sign", str(h_m1 / "private.pem"), dmf.name,
                            ]
                        )
                    ).decode("ascii")
                d_body = json.dumps({
                    "version": dv,
                    "visibility": "public",
                    "format": "markdown",
                    "locked": False,
                    "content": content,
                    "content_sha256": csha,
                    "updated_at": uat,
                    "signature": dsig,
                }).encode("utf-8")
                st_doc, doc_j = signed_http(HOST, p6_port, id_m1, h_m1 / "private.pem", "PUT", "/v1/agents/docs/soul", d_body)
                if dv <= 10:
                    assert_eq(st_doc, 200, f"doc PUT v{dv} failed: {doc_j}")
                else:
                    assert_eq(st_doc, 429, f"11th doc PUT within 60s must hit 429: {doc_j}")
                    assert_eq(doc_j.get("error", {}).get("code"), "ERR_RATE_LIMITED", f"unexpected doc 429 code: {doc_j}")

            # Unauthenticated 401 probe with forged X-Agent-Id must log actor_type="anon", actor_id=""
            st_forged, _ = signed_http(HOST, p6_port, "ftx_forged00000001", h_m1 / "private.pem", "GET", "/v1/friends", b"")
            assert_eq(st_forged, 401, "forged X-Agent-Id 401")

            # Granting controller credential to banned M2 -> 403 ERR_AGENT_BANNED
            _, cid_out, _ = run_cli(["--json", "whoami"], home=str(h_c2), api_url=p6_url)
            id_c2 = json.loads(cid_out.strip())["agent_id"]
            ts_g = int(time.time())
            grant_body = json.dumps({"payload": {"kind": "agent_cert", "agent_id": id_m2, "agent_key_version": 1, "agent_pub_fp": "sha256:00", "cred_id": "crd_banned", "controller_id": id_c2, "controller_key_version": 1, "issued_at": ts_g, "expires_at": ts_g + 3600, "scopes": ["all"], "label": "x"}, "controller_sig": "ZmFrZQ=="}).encode("utf-8")
            st_gr, gr_j = signed_http(HOST, p6_port, id_c2, h_c2 / "private.pem", "POST", f"/v1/ctl/agents/{id_m2}/credential", grant_body)
            assert_eq(st_gr, 403, f"credential grant to banned agent rejected: {gr_j}")
            assert_eq(gr_j.get("error", {}).get("code"), "ERR_AGENT_BANNED", f"unexpected error code: {gr_j}")

            # /dl/ and /llms.txt share static IP_RPM rate limit (use distinct XFF IP to start from 0/25)
            hit_429 = False
            for i in range(30):
                st_req = urllib.request.Request(
                    f"{p6_url}/dl/test.bin" if i % 2 == 0 else f"{p6_url}/llms.txt",
                    headers={"X-Forwarded-For": "198.51.100.77"},
                )
                try:
                    with urllib.request.urlopen(st_req, timeout=5.0) as sr:
                        assert_eq(sr.status, 200, "static pre-limit 200")
                except urllib.error.HTTPError as e:
                    assert_eq(e.code, 429, f"expected 429 on static rate limit, got {e.code}")
                    hit_429 = True
                    break
            assert_true(hit_429, "static /dl/ route bypassed FATEXT_IP_RPM")

            # Shutdown wrong secret -> 403 + logged; right secret -> 200 + clean exit
            bad_sd_tok = "wrong-sd-never-log"
            try:
                urllib.request.urlopen(urllib.request.Request(f"{p6_url}/internal/shutdown", data=b"", method="POST", headers={"X-Fatext-Shutdown-Secret": bad_sd_tok}), timeout=5.0)
                raise AssertionError("expected 403 on bad shutdown secret")
            except urllib.error.HTTPError as e:
                assert_eq(e.code, 403, "bad shutdown secret 403")

            with urllib.request.urlopen(urllib.request.Request(f"{p6_url}/internal/shutdown", data=b"", method="POST", headers={"X-Fatext-Shutdown-Secret": sd_sec}), timeout=5.0) as sdr:
                assert_eq(sdr.status, 200, "valid loopback shutdown 200")
            rc_exit = srv6.wait(timeout=8.0)
            assert_eq(rc_exit, 0, f"server shutdown exit code {rc_exit}")

            ev6 = "\n".join(p.read_text(encoding="utf-8") for p in p6_logs.glob("events-*.jsonl"))
            assert_true('"kind":"admin_auth_fail"' in ev6, "missing admin_auth_fail audit event")
            assert_true('"kind":"shutdown_auth_fail"' in ev6, "missing shutdown_auth_fail audit event")
            assert_true('"kind":"shutdown_requested"' in ev6, "missing shutdown_requested audit event")
            assert_true(bad_tok not in ev6 and adm_sec not in ev6 and sd_sec not in ev6 and bad_sd_tok not in ev6, "secrets leaked into events log!")

            acc6 = [json.loads(ln) for p in p6_logs.glob("access-*.jsonl") for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]
            forged_entries = [e for e in acc6 if e.get("route") == "/v1/friends" and e.get("status") == 401]
            assert_true(len(forged_entries) >= 1, "missing 401 /v1/friends access log entry")
            assert_true(all(e.get("actor_type") == "anon" and e.get("actor_id") == "" for e in forged_entries), f"401 attributed forged actor: {forged_entries}")
            bad_adm_entries = [e for e in acc6 if e.get("route") == "/internal/admin/stats" and e.get("status") == 403]
            assert_true(len(bad_adm_entries) >= 1 and all(e.get("actor_type") == "anon" for e in bad_adm_entries), f"403 admin probe attributed as admin: {bad_adm_entries}")
        finally:
            if srv6.poll() is None:
                srv6.terminate()
                srv6.wait(timeout=5)

        print("[6b/7] Testing FATEXT_PROXY_HEADER validation/isolation and mail_ingest received_at clamping...")
        bad_ph_env = os.environ.copy()
        bad_ph_env.update({
            "FATEXT_ADDR": f"{HOST}:{free_tcp_port()}",
            "FATEXT_DATA_DIR": str(td_p / "bad_ph_data"),
            "FATEXT_WWW_DIR": str(WWW_DIR),
            "FATEXT_TEMPLATES_DIR": str(TPL_DIR),
            "FATEXT_PROXY_HEADER": "bogus",
        })
        r_bad_ph = subprocess.run([str(SERVER_BIN)], env=bad_ph_env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5.0)
        assert_true(r_bad_ph.returncode != 0, f"invalid FATEXT_PROXY_HEADER must exit non-zero, got rc={r_bad_ph.returncode}")

        p6b_port = free_tcp_port()
        p6b_url = f"http://{HOST}:{p6b_port}"
        p6b_data = td_p / "p6b_data"
        p6b_logs = td_p / "p6b_logs"
        p6b_data.mkdir(parents=True, exist_ok=True)
        p6b_logs.mkdir(parents=True, exist_ok=True)
        m_sec_b = "mail-sec-r3-5521"
        sd_sec_b = "sd-sec-r3-5521"
        p6b_env = os.environ.copy()
        p6b_env.update({
            "FATEXT_ADDR": f"{HOST}:{p6b_port}",
            "FATEXT_DATA_DIR": str(p6b_data),
            "FATEXT_LOG_DIR": str(p6b_logs),
            "FATEXT_WWW_DIR": str(WWW_DIR),
            "FATEXT_TEMPLATES_DIR": str(TPL_DIR),
            "FATEXT_POW_BITS": "8",
            "FATEXT_TRUST_PROXY": "1",
            "FATEXT_PROXY_HEADER": "x-real-ip",
            "FATEXT_MAIL_INTERNAL_SECRET": m_sec_b,
            "FATEXT_SHUTDOWN_SECRET": sd_sec_b,
        })
        srv6b = subprocess.Popen([str(SERVER_BIN)], env=p6b_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            wait_http_ok(f"{p6b_url}/health")
            h_mail = td_p / "h_mail"
            rc, m_out, m_err = run_cli(["--json", "init", "--name", "MailClamp"], home=str(h_mail), api_url=p6b_url)
            assert_eq(rc, 0, f"init MailClamp failed: {m_err}")
            aid_mc = json.loads(m_out.strip())["agent_id"]
            rc, _, m_err2 = run_cli(["--json", "profile", "set", "--accept-email", "true"], home=str(h_mail), api_url=p6b_url)
            # Wait: 60s register->profile cooldown applies unless restarted or wait; check:
            if rc != 0:
                srv6b.terminate()
                srv6b.wait(timeout=5)
                srv6b = subprocess.Popen([str(SERVER_BIN)], env=p6b_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                wait_http_ok(f"{p6b_url}/health")
                rc, _, m_err2 = run_cli(["--json", "profile", "set", "--accept-email", "true"], home=str(h_mail), api_url=p6b_url)
            assert_eq(rc, 0, f"enable accept_email failed: {m_err2}")

            with urllib.request.urlopen(
                urllib.request.Request(
                    f"{p6b_url}/health",
                    headers={
                        "CF-Connecting-IP": "198.51.100.1",
                        "X-Forwarded-For": "198.51.100.2",
                        "X-Real-IP": "203.0.113.77",
                    },
                ),
                timeout=5.0,
            ) as hr:
                assert_eq(hr.status, 200, "x-real-ip health 200")

            now_mc = int(time.time())
            for bad_rat in (now_mc + 9999999, now_mc - 9999999):
                m_req = urllib.request.Request(
                    f"{p6b_url}/internal/mail/ingest",
                    data=json.dumps({
                        "to_agent_id": aid_mc,
                        "from": "sender@example.com",
                        "subject": "clamp-test",
                        "raw_snippet": "hello",
                        "received_at": bad_rat,
                    }).encode("utf-8"),
                    method="POST",
                    headers={"Content-Type": "application/json", "X-Internal-Secret": m_sec_b},
                )
                with urllib.request.urlopen(m_req, timeout=5.0) as mr:
                    assert_eq(mr.status, 201, f"mail_ingest clamp status for {bad_rat}")

            with urllib.request.urlopen(
                urllib.request.Request(f"{p6b_url}/internal/shutdown", data=b"", method="POST", headers={"X-Fatext-Shutdown-Secret": sd_sec_b}),
                timeout=5.0,
            ) as sdr_b:
                assert_eq(sdr_b.status, 200, "6b shutdown 200")
            assert_eq(srv6b.wait(timeout=8.0), 0, "6b shutdown clean exit")

            acc6b = [json.loads(ln) for p in p6b_logs.glob("access-*.jsonl") for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]
            ips6b = {e.get("ip") for e in acc6b if e.get("route") == "/health"}
            assert_true("203.0.113.77" in ips6b, f"x-real-ip expected 203.0.113.77 in {ips6b}")
            assert_true("198.51.100.1" not in ips6b and "198.51.100.2" not in ips6b, f"FATEXT_PROXY_HEADER=x-real-ip leaked CF/XFF: {ips6b}")

            mail_files = list((p6b_data / "mail").rglob("*.json"))
            assert_eq(len(mail_files), 2, f"expected 2 ingested mail files, got {mail_files}")
            for mf in mail_files:
                rat_saved = json.loads(mf.read_text(encoding="utf-8"))["received_at"]
                assert_true(abs(rat_saved - int(time.time())) <= 15, f"received_at was not clamped: {rat_saved}")
        finally:
            if srv6b.poll() is None:
                srv6b.terminate()
                srv6b.wait(timeout=5)

        print("[6c/7] Testing persistent daily friend request limit & UTF-8 note hardening...")
        bad_fr_env = os.environ.copy()
        bad_fr_env.update({
            "FATEXT_ADDR": f"{HOST}:{free_tcp_port()}",
            "FATEXT_DATA_DIR": str(td_p / "bad_fr_data"),
            "FATEXT_WWW_DIR": str(WWW_DIR),
            "FATEXT_TEMPLATES_DIR": str(TPL_DIR),
            "FATEXT_DAILY_FRIEND_REQUESTS": "201",
        })
        r_bad_fr = subprocess.run([str(SERVER_BIN)], env=bad_fr_env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5.0)
        assert_true(r_bad_fr.returncode != 0, f"invalid FATEXT_DAILY_FRIEND_REQUESTS must exit non-zero, got rc={r_bad_fr.returncode}")

        p6c_port = free_tcp_port()
        p6c_url = f"http://{HOST}:{p6c_port}"
        p6c_data = td_p / "p6c_data"
        p6c_data.mkdir(parents=True, exist_ok=True)
        sd_sec_c = "sd-sec-r4-8812"
        p6c_env = os.environ.copy()
        p6c_env.update({
            "FATEXT_ADDR": f"{HOST}:{p6c_port}",
            "FATEXT_DATA_DIR": str(p6c_data),
            "FATEXT_WWW_DIR": str(WWW_DIR),
            "FATEXT_TEMPLATES_DIR": str(TPL_DIR),
            "FATEXT_POW_BITS": "8",
            "FATEXT_DAILY_FRIEND_REQUESTS": "3",
            "FATEXT_SHUTDOWN_SECRET": sd_sec_c,
        })
        srv6c = subprocess.Popen([str(SERVER_BIN)], env=p6c_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            wait_http_ok(f"{p6c_url}/health")
            homes_fr = {}
            ids_fr = {}
            for tag in ("a", "b", "c", "d"):
                hp = td_p / f"fr_{tag}"
                rc, out, err = run_cli(["--json", "init", "--name", f"Fr{tag.upper()}"], home=str(hp), api_url=p6c_url)
                assert_eq(rc, 0, f"init Fr{tag} failed: {err}")
                homes_fr[tag] = hp
                ids_fr[tag] = json.loads(out.strip())["agent_id"]

            # >256 UTF-8 chars or control chars in note rejected without consuming daily quota
            for bad_note in ("你" * 257, "hello\x07world"):
                st_bn, bn_j = signed_http(
                    HOST, p6c_port, ids_fr["a"], homes_fr["a"] / "private.pem",
                    "POST", "/v1/friends/request", json.dumps({"agent_id": ids_fr["b"], "note": bad_note}).encode("utf-8"),
                )
                assert_eq(st_bn, 400, f"bad friend note should return 400, got {st_bn}: {bn_j}")

            # 1st request: Chinese UTF-8 note (100 chars, >256 bytes, <=256 UTF-8 chars) succeeds
            utf8_note = "你好交个朋友吧！" * 12  # 96 chars, 288 bytes
            rc, _, err = run_cli(["--json", "friend", "add", ids_fr["b"], "--note", utf8_note], home=str(homes_fr["a"]), api_url=p6c_url)
            assert_eq(rc, 0, f"UTF-8 friend add failed: {err}")
            st_fl, fl_j = signed_http(HOST, p6c_port, ids_fr["b"], homes_fr["b"] / "private.pem", "GET", "/v1/friends", b"")
            assert_eq(st_fl, 200, "friend list failed")
            assert_eq(fl_j["incoming"][0]["note"], utf8_note, "UTF-8 friend note corrupted")

            # Reject does not refund daily quota; 2nd + 3rd requests consume remaining quota; become friends with B
            rc, _, err = run_cli(["friend", "reject", ids_fr["a"]], home=str(homes_fr["b"]), api_url=p6c_url)
            assert_eq(rc, 0, f"reject failed: {err}")
            rc, _, err = run_cli(["friend", "add", ids_fr["c"], "--note", "req2"], home=str(homes_fr["a"]), api_url=p6c_url)
            assert_eq(rc, 0, f"2nd request failed: {err}")
            rc, _, err = run_cli(["friend", "add", ids_fr["b"], "--note", "req3"], home=str(homes_fr["a"]), api_url=p6c_url)
            assert_eq(rc, 0, f"3rd request failed: {err}")
            rc, _, err = run_cli(["friend", "accept", ids_fr["a"]], home=str(homes_fr["b"]), api_url=p6c_url)
            assert_eq(rc, 0, f"accept failed: {err}")

            # 4th request hits ERR_DAILY_FRIEND_LIMIT; existing friend B still returns 200 already_friends
            st_lim, lim_j = signed_http(
                HOST, p6c_port, ids_fr["a"], homes_fr["a"] / "private.pem",
                "POST", "/v1/friends/request", json.dumps({"agent_id": ids_fr["d"], "note": "over"}).encode("utf-8"),
            )
            assert_eq(st_lim, 429, f"4th friend request must hit 429: {lim_j}")
            assert_eq(lim_j.get("error", {}).get("code"), "ERR_DAILY_FRIEND_LIMIT", f"unexpected 429 code: {lim_j}")
            assert_true(lim_j.get("error", {}).get("retry_after", 0) > 0, f"missing retry_after: {lim_j}")
            st_af, af_j = signed_http(
                HOST, p6c_port, ids_fr["a"], homes_fr["a"] / "private.pem",
                "POST", "/v1/friends/request", json.dumps({"agent_id": ids_fr["b"], "note": "dup"}).encode("utf-8"),
            )
            assert_eq(st_af, 200, f"already_friends must return 200: {af_j}")
            assert_eq(af_j.get("status"), "already_friends", f"unexpected status: {af_j}")

            # Restart server -> daily friend request count persists on disk
            with urllib.request.urlopen(
                urllib.request.Request(f"{p6c_url}/internal/shutdown", data=b"", method="POST", headers={"X-Fatext-Shutdown-Secret": sd_sec_c}),
                timeout=5.0,
            ) as sdr_c:
                assert_eq(sdr_c.status, 200, "6c shutdown 200")
            assert_eq(srv6c.wait(timeout=8.0), 0, "6c shutdown clean exit")
            srv6c = subprocess.Popen([str(SERVER_BIN)], env=p6c_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            wait_http_ok(f"{p6c_url}/health")
            st_lim2, lim2_j = signed_http(
                HOST, p6c_port, ids_fr["a"], homes_fr["a"] / "private.pem",
                "POST", "/v1/friends/request", json.dumps({"agent_id": ids_fr["d"], "note": "after restart"}).encode("utf-8"),
            )
            assert_eq(st_lim2, 429, f"post-restart friend limit must persist: {lim2_j}")
            assert_eq(lim2_j.get("error", {}).get("code"), "ERR_DAILY_FRIEND_LIMIT", f"post-restart code mismatch: {lim2_j}")
        finally:
            if srv6c.poll() is None:
                srv6c.terminate()
                srv6c.wait(timeout=5)

        print("[7/7] Testing Cloudflare Email Worker spoofing resistance & deploy script hardening...")
        for sh_file in sorted((ROOT / "deploy").glob("*.sh")):
            r_sh = subprocess.run(["bash", "-n", str(sh_file)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            assert_eq(r_sh.returncode, 0, f"bash -n failed on {sh_file}: {r_sh.stderr}")
        gs_txt = (ROOT / "deploy" / "graceful_stop.sh").read_text(encoding="utf-8")
        assert_true("FATEXT_ACME_DOMAINS" in gs_txt, "graceful_stop.sh must detect FATEXT_ACME_DOMAINS")
        sync_bad = subprocess.run(
            ["bash", str(ROOT / "deploy" / "sync_dl.sh"), "latest", str(td_p / "dl_out"), "http://127.0.0.1/key.pem"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5.0,
        )
        assert_true(sync_bad.returncode != 0 and "http://" in sync_bad.stderr, f"sync_dl.sh must reject http:// OFFICIAL_PEM: {sync_bad.stderr}")

        node_bin = shutil.which("node") or next(
            (p for p in ("/opt/homebrew/bin/node", "/usr/local/bin/node") if Path(p).is_file()),
            None,
        )
        for js_rel in ("deploy/email-worker/worker.js", "workers/email-worker/src/index.js"):
            js_txt = (ROOT / js_rel).read_text(encoding="utf-8")
            assert_true("const first = parts[0] || \"\";" in js_txt, f"{js_rel} must inspect only topmost auth-results header")
            assert_true("for (const part of parts)" not in js_txt, f"{js_rel} still scans all comma-separated auth-results parts")
            assert_true(r"/^(?:[a-z0-9-]+\.)*cloudflare\.(?:net|com)$/" in js_txt, f"{js_rel} missing strict CLOUDFLARE_AUTHSERV_RE")
        if node_bin is not None:
            for js_rel in ("deploy/email-worker/worker.js", "workers/email-worker/src/index.js"):
                js_path = ROOT / js_rel
                r_chk = subprocess.run([node_bin, "--check", str(js_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                assert_eq(r_chk.returncode, 0, f"node --check failed on {js_rel}: {r_chk.stderr}")
            js_test = r'''
import * as w1 from "./deploy/email-worker/worker.js";
import * as w2 from "./workers/email-worker/src/index.js";
function assert(cond, msg) { if (!cond) throw new Error(msg); }
const okHdr = "mx.cloudflare.net; spf=pass smtp.mailfrom=a@b.com; dkim=pass; dmarc=pass";
assert(w1.parseAuthResults(okHdr).spf_pass === true, "w1 legit spf");
assert(w1.parseAuthResults(okHdr).dkim_pass === true, "w1 legit dkim");
assert(w2.parseAuthResult(okHdr, "spf") === true, "w2 legit spf");
assert(w2.parseAuthResult(okHdr, "dmarc") === true, "w2 legit dmarc");
for (const spoof of [
  "evil-cloudflare.com; spf=pass; dkim=pass; dmarc=pass",
  "notcloudflare.net; spf=pass; dkim=pass",
  "mx.cloudflare.org; spf=pass",
  "mx.attacker.example; spf=fail, mx.cloudflare.net; spf=pass; dkim=pass"
]) {
  const r1 = w1.parseAuthResults(spoof);
  assert(!r1.spf_pass && !r1.dkim_pass && !r1.dmarc_pass, "w1 accepted spoof: " + spoof);
  assert(!w2.parseAuthResult(spoof, "spf") && !w2.parseAuthResult(spoof, "dkim"), "w2 accepted spoof: " + spoof);
}
'''
            r_js = subprocess.run([node_bin, "--input-type=module", "-e", js_test], cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            assert_eq(r_js.returncode, 0, f"email worker security check failed: {r_js.stderr}")
        elif sys.platform == "darwin" and shutil.which("osascript"):
            for js_rel, fn_check in [
                ("deploy/email-worker/worker.js", "parseAuthResults(okHdr).spf_pass === true && !parseAuthResults(spoof).spf_pass"),
                ("workers/email-worker/src/index.js", "parseAuthResult(okHdr, 'spf') === true && !parseAuthResult(spoof, 'spf')"),
            ]:
                src_raw = (ROOT / js_rel).read_text(encoding="utf-8")
                src_stripped = src_raw.split("export {")[0]
                jxa = (
                    src_stripped
                    + "\nconst okHdr = 'mx.cloudflare.net; spf=pass; dkim=pass; dmarc=pass';"
                    + "\nconst spoofs = ['evil-cloudflare.com; spf=pass', 'notcloudflare.net; spf=pass', 'mx.cloudflare.org; spf=pass', 'mx.attacker.example; spf=fail, mx.cloudflare.net; spf=pass'];"
                    + f"\nfor (var i = 0; i < spoofs.length; i++) {{ var spoof = spoofs[i]; if (!({fn_check})) throw new Error('failed ' + spoof); }}"
                    + "\n'ok';"
                )
                r_jxa = subprocess.run(["osascript", "-l", "JavaScript", "-e", jxa], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                assert_eq(r_jxa.returncode, 0, f"JXA worker check failed for {js_rel}: {r_jxa.stderr}")

    print("ALL 7 SERVER SECURITY REGRESSION TESTS PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
