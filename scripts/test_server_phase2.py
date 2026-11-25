#!/usr/bin/env python3
"""End-to-end Phase 2 integration tests for fatext-server:
- Native built-in TLS 1.3 (X25519/P-256, PKCS#8 + PKCS#1 keys) & HTTP->HTTPS 301 redirect
- Real fatext-cli <-> real fatext-server:
  * version --check
  * init, whoami, profile set, pub post/list/reply/thread/pins
  * friend add/list/reject/accept/rm & block add/list/rm
  * zero-disk E2EE DM (friend check + 403 non-friend + SSE live decrypt)
  * zero-disk E2EE Room (create/invite/send + SSE auto-store + decrypt)
  * dual-signed key rotate (v1 archive -> v2 active)
  * encrypted mail ingest (/internal/mail/ingest) pre- & post-rotate + mail pull --delete
  * P2P over real server SSE signaling (--stdio AND --expose/--forward TCP echo)
  * /dl/<artifact> serving + path traversal rejection
  * scripts/init_official.py bootstrap verification
"""

from __future__ import annotations

import http.client
import json
import os
import re
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
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
    raise TimeoutError(f"{host}:{port} did not become ready within {timeout}s")


def wait_http_ok(url: str, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1.0) as r:
                if r.status == 200:
                    return
        except Exception:
            time.sleep(0.05)
    raise TimeoutError(f"{url} did not return 200 OK within {timeout}s")


def assert_eq(a, b, msg: str = "") -> None:
    if a != b:
        raise AssertionError(f"{msg}: {a!r} != {b!r}")


def assert_true(cond: bool, msg: str = "") -> None:
    if not cond:
        raise AssertionError(f"assertion failed: {msg}")


def run_cli(
    args: list[str],
    *,
    env_home: str | None = None,
    api_url: str | None = None,
    stdin_text: str | None = None,
    timeout: float = 30.0,
) -> tuple[int, str, str]:
    env = os.environ.copy()
    if env_home is not None:
        env["FATEXT_HOME"] = env_home
    cmd = [str(CLI_BIN)]
    if api_url is not None and "--api" not in args:
        cmd.extend(["--api", api_url])
    cmd.extend(args)
    res = subprocess.run(
        cmd,
        env=env,
        input=stdin_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    return res.returncode, res.stdout, res.stderr


def generate_san_cert(workdir: Path, *, pkcs1: bool = False) -> tuple[Path, Path]:
    cnf = workdir / "san.cnf"
    cnf.write_text(
        "[req]\n"
        "distinguished_name = req_dn\n"
        "x509_extensions = v3_req\n"
        "prompt = no\n\n"
        "[req_dn]\n"
        "CN = localhost\n\n"
        "[v3_req]\n"
        "subjectAltName = IP:127.0.0.1,DNS:localhost\n",
        encoding="utf-8",
    )
    cert_path = workdir / ("cert_pkcs1.pem" if pkcs1 else "cert.pem")
    key_pkcs8 = workdir / "key_pkcs8.pem"
    key_out = workdir / ("key_pkcs1.pem" if pkcs1 else "key.pem")
    subprocess.run(
        [
            "/usr/bin/openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-config",
            str(cnf),
            "-extensions",
            "v3_req",
            "-keyout",
            str(key_pkcs8),
            "-out",
            str(cert_path),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if pkcs1:
        subprocess.run(
            ["/usr/bin/openssl", "rsa", "-in", str(key_pkcs8), "-out", str(key_out)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        assert_true("BEGIN RSA PRIVATE KEY" in key_out.read_text(encoding="utf-8"), "expected PKCS#1 header")
    else:
        key_pkcs8.replace(key_out)
    return cert_path, key_out


def test_native_tls_and_redirect() -> None:
    print("[1/8] Native built-in TLS 1.3 (PKCS#8 & PKCS#1) + HTTP->HTTPS 301...")
    with tempfile.TemporaryDirectory(prefix="fatext-tls-") as td:
        td_p = Path(td)
        for pkcs1 in (False, True):
            cert_path, key_path = generate_san_cert(td_p, pkcs1=pkcs1)
            tls_port = free_tcp_port()
            redir_port = free_tcp_port()
            data_dir = td_p / ("data1" if pkcs1 else "data8")
            data_dir.mkdir(parents=True, exist_ok=True)
            env = os.environ.copy()
            env["FATEXT_ADDR"] = f"{HOST}:{tls_port}"
            env["FATEXT_HTTP_REDIRECT_ADDR"] = f"{HOST}:{redir_port}"
            env["FATEXT_TLS_CERT"] = str(cert_path)
            env["FATEXT_TLS_KEY"] = str(key_path)
            env["FATEXT_DATA_DIR"] = str(data_dir)
            env["FATEXT_WWW_DIR"] = str(WWW_DIR)
            env["FATEXT_TEMPLATES_DIR"] = str(TPL_DIR)
            env["FATEXT_POW_BITS"] = "10"

            srv = subprocess.Popen(
                [str(SERVER_BIN)],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                wait_tcp_ready(HOST, tls_port, timeout=10.0)
                wait_tcp_ready(HOST, redir_port, timeout=10.0)

                # curl HTTPS (negotiates TLS 1.3 on OpenSSL / SecureTransport builds)
                curl_res = subprocess.run(
                    [
                        "curl",
                        "--cacert",
                        str(cert_path),
                        "-fsS",
                        f"https://{HOST}:{tls_port}/health",
                    ],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=10.0,
                )
                assert_eq(curl_res.returncode, 0, f"curl TLS failed (pkcs1={pkcs1}): {curl_res.stderr}")
                assert_eq(curl_res.stdout.strip(), "ok", f"curl /health body (pkcs1={pkcs1})")

                ossl3 = Path("/opt/homebrew/bin/openssl")
                if ossl3.is_file():
                    sc = subprocess.run(
                        [
                            str(ossl3),
                            "s_client",
                            "-connect",
                            f"{HOST}:{tls_port}",
                            "-CAfile",
                            str(cert_path),
                            "-tls1_3",
                        ],
                        input="GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n",
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=10.0,
                    )
                    assert_eq(sc.returncode, 0, f"openssl3 s_client -tls1_3 failed (pkcs1={pkcs1}): {sc.stderr}")
                    assert_true("Protocol: TLSv1.3" in sc.stdout, f"openssl3 TLSv1.3 missing (pkcs1={pkcs1})")
                    assert_true("Verify return code: 0 (ok)" in sc.stdout, f"openssl3 verify failed (pkcs1={pkcs1})")

                # Python ssl TLS client
                ctx = ssl.create_default_context(cafile=str(cert_path))
                with urllib.request.urlopen(
                    f"https://{HOST}:{tls_port}/.well-known/fatext.json",
                    context=ctx,
                    timeout=10.0,
                ) as resp:
                    assert_eq(resp.status, 200, "python ssl status")
                    wk = json.loads(resp.read().decode("utf-8"))
                    assert_eq(wk["official"]["agent_id"], "ftx_fatextoffice", "discovery official")

                # HTTP -> HTTPS 301 redirect
                conn = http.client.HTTPConnection(HOST, redir_port, timeout=5.0)
                conn.request("GET", "/channels/dev", headers={"Host": "fatext.com"})
                r301 = conn.getresponse()
                r301.read()
                conn.close()
                assert_eq(r301.status, 301, "HTTP redirect status")
                assert_eq(r301.getheader("Location"), "https://fatext.com/channels/dev", "redirect Location")
            finally:
                srv.terminate()
                try:
                    srv.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    srv.kill()
                    srv.wait(timeout=5)


def http_json(url: str, *, method: str = "GET", headers: dict[str, str] | None = None, body: dict | None = None) -> tuple[int, dict]:
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


def scan_files_for_substring(root_dir: Path, needle: str) -> list[str]:
    hits = []
    if not root_dir.exists():
        return hits
    for p in root_dir.rglob("*"):
        if p.is_file():
            try:
                txt = p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if needle in txt:
                hits.append(str(p))
    return hits


def run_phase2_cli_suite() -> None:
    port = free_tcp_port()
    api_url = f"http://{HOST}:{port}"
    mail_secret = "phase2-test-internal-mail-secret-9f12"

    with tempfile.TemporaryDirectory(prefix="fatext-phase2-") as td:
        td_p = Path(td)
        data_dir = td_p / "data"
        dl_dir = data_dir / "dl"
        dl_dir.mkdir(parents=True, exist_ok=True)
        (dl_dir / "hello.txt").write_text("fatext-dl-artifact-v1\n", encoding="utf-8")
        (data_dir / "secrets.txt").write_text("do-not-leak\n", encoding="utf-8")

        home_a = td_p / "home_a"
        home_b = td_p / "home_b"
        official_out = td_p / "official_out"

        # Bootstrap official identity into data_dir BEFORE server starts
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "init_official.py"),
                "--data-dir",
                str(data_dir),
                "--out-dir",
                str(official_out),
            ],
            check=True,
        )
        off_priv = official_out / "official_private.pem"
        assert_eq(stat.S_IMODE(off_priv.stat().st_mode), 0o600, "official_private.pem 0600")
        assert_true((data_dir / "keys" / "fa" / "ftx_fatextoffice.json").is_file(), "official json")
        assert_true((data_dir / "keys" / "fa" / "ftx_fatextoffice.pem").is_file(), "official pem")

        srv_env = os.environ.copy()
        srv_env["FATEXT_ADDR"] = f"{HOST}:{port}"
        srv_env["FATEXT_DATA_DIR"] = str(data_dir)
        srv_env["FATEXT_WWW_DIR"] = str(WWW_DIR)
        srv_env["FATEXT_TEMPLATES_DIR"] = str(TPL_DIR)
        srv_env["FATEXT_DL_DIR"] = str(dl_dir)
        srv_env["FATEXT_POW_BITS"] = "12"
        srv_env["FATEXT_MAIL_INTERNAL_SECRET"] = mail_secret

        srv = subprocess.Popen(
            [str(SERVER_BIN)],
            env=srv_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        def restart_server() -> None:
            nonlocal srv
            srv.terminate()
            try:
                srv.wait(timeout=5)
            except subprocess.TimeoutExpired:
                srv.kill()
                srv.wait(timeout=5)
            srv = subprocess.Popen(
                [str(SERVER_BIN)],
                env=srv_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            wait_http_ok(f"{api_url}/health", timeout=10.0)

        try:
            wait_http_ok(f"{api_url}/health", timeout=10.0)

            print("[2/8] /dl/, official key discovery, version --check & registration...")
            # /dl/ index HTML + artifact serving + traversal block
            with urllib.request.urlopen(f"{api_url}/dl/", timeout=5.0) as r_idx:
                assert_eq(r_idx.status, 200, "/dl/ HTML status")
                dl_page = r_idx.read().decode("utf-8")
                assert_true("Download fatext CLI" in dl_page and "hello.txt" in dl_page, "/dl/ lists hello.txt")
            with urllib.request.urlopen(f"{api_url}/dl/hello.txt", timeout=5.0) as r:
                assert_eq(r.status, 200, "/dl/hello.txt status")
                assert_eq(r.read().decode("utf-8"), "fatext-dl-artifact-v1\n", "/dl/hello.txt body")
            conn = http.client.HTTPConnection(HOST, port, timeout=5.0)
            conn.request("GET", "/dl/../secrets.txt")
            tr_resp = conn.getresponse()
            tr_resp.read()
            conn.close()
            assert_true(tr_resp.status in (400, 404), f"traversal status {tr_resp.status}")

            # Official key serving
            st, off_doc = http_json(f"{api_url}/k/ftx_fatextoffice.json")
            assert_eq(st, 200, "official key json 200")
            assert_eq(off_doc["agent_id"], "ftx_fatextoffice", "official id")

            # version --check
            rc, out, err = run_cli(["--json", "version", "--check"], api_url=api_url)
            assert_eq(rc, 0, f"version --check failed: {err}")
            vdoc = json.loads(out.strip())
            assert_eq(vdoc.get("status"), "ok", f"version status: {vdoc}")

            # Register A and B
            rc, out, err = run_cli(["--json", "init", "--name", "Alpha", "--owner", "Alice"], env_home=str(home_a), api_url=api_url)
            assert_eq(rc, 0, f"init A failed: {err}")
            aid_a = json.loads(out.strip())["agent_id"]

            rc, out, err = run_cli(["--json", "init", "--name", "Beta", "--owner", "Bob"], env_home=str(home_b), api_url=api_url)
            assert_eq(rc, 0, f"init B failed: {err}")
            aid_b = json.loads(out.strip())["agent_id"]

            rc, out, err = run_cli(["--json", "whoami"], env_home=str(home_a), api_url=api_url)
            assert_eq(rc, 0, f"whoami A failed: {err}")
            assert_eq(json.loads(out.strip())["agent_id"], aid_a, "whoami A id")

            # Restart once to reset in-memory 60s registration->profile cooldown
            restart_server()

            print("[3/8] profile set & public channel/thread/pins roundtrip...")
            for home in (home_a, home_b):
                rc, _, err = run_cli(
                    ["profile", "set", "--accept-email", "true", "--dm-policy", "friends"],
                    env_home=home,
                    api_url=api_url,
                )
                assert_eq(rc, 0, f"profile set failed: {err}")

            rc, out, err = run_cli(
                ["--json", "pub", "post", "dev", "Phase 2 public smoke post"],
                env_home=str(home_a),
                api_url=api_url,
            )
            assert_eq(rc, 0, f"pub post failed: {err}")
            root_id = json.loads(out.strip())["msg_id"]

            rc, out, err = run_cli(
                ["--json", "pub", "reply", root_id, "Phase 2 reply from Beta", "--state", "open"],
                env_home=str(home_b),
                api_url=api_url,
            )
            assert_eq(rc, 0, f"pub reply failed: {err}")

            rc, out, err = run_cli(["--json", "pub", "thread", root_id], env_home=str(home_a), api_url=api_url)
            assert_eq(rc, 0, f"pub thread failed: {err}")
            th_lines = [json.loads(line) for line in out.strip().splitlines() if line.strip()]
            assert_true(len(th_lines) >= 2 and all(x.get("verified") for x in th_lines), f"verified thread lines: {th_lines}")

            rc, out, err = run_cli(["--json", "pub", "pins", "general"], env_home=str(home_a), api_url=api_url)
            assert_eq(rc, 0, f"pub pins failed: {err}")

            print("[4/8] Friends & Blocks enforcement + zero-disk E2EE DM...")
            # Non-friend DM must fail with EXIT_FORBIDDEN (5)
            rc, _, err = run_cli(
                ["dm", "send", aid_b, "Should be blocked before friendship"],
                env_home=str(home_a),
                api_url=api_url,
            )
            assert_eq(rc, 5, f"non-friend dm expected exit 5, got rc={rc} err={err}")

            # Reject then re-add then accept
            rc, _, err = run_cli(["friend", "add", aid_b, "--note", "hi"], env_home=str(home_a), api_url=api_url)
            assert_eq(rc, 0, f"friend add failed: {err}")
            rc, out, err = run_cli(["--json", "friend", "list"], env_home=str(home_b), api_url=api_url)
            assert_eq(rc, 0, f"friend list B failed: {err}")
            fl = json.loads(out.strip())
            assert_true(any(x.get("from") == aid_a for x in fl.get("incoming", [])), f"incoming req missing: {fl}")

            rc, _, err = run_cli(["friend", "reject", aid_a], env_home=str(home_b), api_url=api_url)
            assert_eq(rc, 0, f"friend reject failed: {err}")
            rc, _, err = run_cli(["friend", "add", aid_b], env_home=str(home_a), api_url=api_url)
            assert_eq(rc, 0, f"friend re-add failed: {err}")
            rc, _, err = run_cli(["friend", "accept", aid_a], env_home=str(home_b), api_url=api_url)
            assert_eq(rc, 0, f"friend accept failed: {err}")

            # Block & unblock pattern test
            rc, _, err = run_cli(["block", "add", "*@spam.example"], env_home=str(home_b), api_url=api_url)
            assert_eq(rc, 0, f"block add failed: {err}")
            rc, out, err = run_cli(["--json", "block", "list"], env_home=str(home_b), api_url=api_url)
            assert_eq(rc, 0, f"block list failed: {err}")
            assert_true("*@spam.example" in json.loads(out.strip()).get("blocks", []), "block pattern present")
            rc, _, err = run_cli(["block", "rm", "*@spam.example"], env_home=str(home_b), api_url=api_url)
            assert_eq(rc, 0, f"block rm failed: {err}")

            # Live E2EE DM over SSE
            dm_secret_text = "ZERO_DISK_DM_SECRET_9481"
            listener_b = subprocess.Popen(
                [str(CLI_BIN), "--api", api_url, "--json", "listen", "--max-events", "1"],
                env={**os.environ, "FATEXT_HOME": str(home_b)},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            time.sleep(0.5)
            rc, out, err = run_cli(["--json", "dm", "send", aid_b, dm_secret_text], env_home=str(home_a), api_url=api_url)
            assert_eq(rc, 0, f"friend dm send failed: {err}")
            l_out, l_err = listener_b.communicate(timeout=10.0)
            assert_eq(listener_b.returncode, 0, f"listen B DM failed: {l_err}")
            dm_ev = json.loads(l_out.strip().splitlines()[0])
            assert_eq(dm_ev["type"], "dm", f"dm event: {dm_ev}")
            assert_eq(dm_ev["from"], aid_a, "dm sender")
            assert_eq(dm_ev["text"], dm_secret_text, "dm decrypted text")
            assert_true(dm_ev.get("verified") is True, "dm signature verified")
            assert_eq(scan_files_for_substring(data_dir, dm_secret_text), [], "DM zero-disk violation")

            print("[5/8] Zero-disk E2EE Room (create/invite/send + listen)...")
            rc, out, err = run_cli(["--json", "room", "create", "--name", "secret-lab"], env_home=str(home_a), api_url=api_url)
            assert_eq(rc, 0, f"room create failed: {err}")
            room_id = json.loads(out.strip())["room_id"]

            room_secret_text = "ZERO_DISK_ROOM_MSG_7712"
            listener_b = subprocess.Popen(
                [str(CLI_BIN), "--api", api_url, "--json", "listen", "--rooms", room_id, "--max-events", "2"],
                env={**os.environ, "FATEXT_HOME": str(home_b)},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            time.sleep(0.5)
            rc, _, err = run_cli(["--json", "room", "invite", room_id, aid_b], env_home=str(home_a), api_url=api_url)
            assert_eq(rc, 0, f"room invite failed: {err}")
            time.sleep(0.4)
            rc, _, err = run_cli(["--json", "room", "send", room_id, room_secret_text], env_home=str(home_a), api_url=api_url)
            assert_eq(rc, 0, f"room send failed: {err}")
            l_out, l_err = listener_b.communicate(timeout=10.0)
            assert_eq(listener_b.returncode, 0, f"listen B room failed: {l_err}")
            evs = [json.loads(x) for x in l_out.strip().splitlines() if x.strip()]
            assert_eq(len(evs), 2, f"expected 2 room events (invite + msg): {evs}")
            assert_true((home_b / "rooms" / f"{room_id}.json").is_file(), "B auto-stored room key")
            assert_eq(evs[0]["type"], "room_invite", f"room invite event: {evs[0]}")
            assert_eq(evs[1]["type"], "room", f"room msg event: {evs[1]}")
            assert_eq(evs[1]["text"], room_secret_text, "room decrypted text")
            assert_true(evs[1].get("verified") is True, "room sig verified")
            assert_eq(scan_files_for_substring(data_dir, room_secret_text), [], "Room zero-disk violation")

            print("[6/8] Mail ingest pre-rotate + dual-signed key rotate + mail ingest post-rotate + pull...")
            subj_v1 = "Secret Email Before Rotate V1"
            snip_v1 = "BODY_V1_CONFIDENTIAL_8821"
            st, m1 = http_json(
                f"{api_url}/internal/mail/ingest",
                method="POST",
                headers={"X-Internal-Secret": mail_secret},
                body={
                    "to_agent_id": aid_b,
                    "from": "sender1@example.com",
                    "subject": subj_v1,
                    "raw_snippet": snip_v1,
                    "spf_pass": True,
                    "dkim_pass": True,
                    "dmarc_pass": True,
                    "received_at": int(time.time()),
                },
            )
            assert_eq(st, 201, f"mail ingest v1 failed: {m1}")
            assert_eq(m1["to_key_version"], 1, "mail v1 key_version")

            # Dual-signed key rotate on B
            rc, out, err = run_cli(["--json", "key", "rotate"], env_home=str(home_b), api_url=api_url)
            assert_eq(rc, 0, f"key rotate B failed: {err}")
            rdoc = json.loads(out.strip())
            assert_eq(rdoc["key_version"], 2, "rotated key_version=2")
            v1_priv = home_b / "keys" / "private.v1.pem"
            assert_true(v1_priv.is_file(), "archived private.v1.pem exists")
            assert_eq(stat.S_IMODE(v1_priv.stat().st_mode), 0o600, "private.v1.pem mode 0600")

            # Second email encrypted under v2
            subj_v2 = "Secret Email After Rotate V2"
            snip_v2 = "BODY_V2_CONFIDENTIAL_9934"
            st, m2 = http_json(
                f"{api_url}/internal/mail/ingest",
                method="POST",
                headers={"X-Internal-Secret": mail_secret},
                body={
                    "to_agent_id": aid_b,
                    "from": "sender2@example.com",
                    "subject": subj_v2,
                    "raw_snippet": snip_v2,
                    "spf_pass": True,
                    "dkim_pass": False,
                    "dmarc_pass": False,
                    "received_at": int(time.time()),
                },
            )
            assert_eq(st, 201, f"mail ingest v2 failed: {m2}")
            assert_eq(m2["to_key_version"], 2, "mail v2 key_version")

            # Verify stored mail is strictly encrypted on disk
            mail_root = data_dir / "mail"
            assert_eq(scan_files_for_substring(mail_root, subj_v1), [], "plaintext v1 subject on disk")
            assert_eq(scan_files_for_substring(mail_root, snip_v1), [], "plaintext v1 snippet on disk")
            assert_eq(scan_files_for_substring(mail_root, subj_v2), [], "plaintext v2 subject on disk")
            assert_eq(scan_files_for_substring(mail_root, snip_v2), [], "plaintext v2 snippet on disk")

            # mail pull --delete decrypts both v1 and v2 and cleans server storage
            rc, out, err = run_cli(["--json", "mail", "pull", "--delete"], env_home=str(home_b), api_url=api_url)
            assert_eq(rc, 0, f"mail pull --delete failed: {err}")
            pulled = [json.loads(line) for line in out.strip().splitlines() if line.strip()]
            assert_eq(len(pulled), 2, f"expected 2 decrypted emails: {pulled}")
            by_subj = {m["subject"]: m for m in pulled}
            assert_eq(by_subj[subj_v1]["text"], snip_v1, "v1 mail decrypted snippet")
            assert_eq(by_subj[subj_v2]["text"], snip_v2, "v2 mail decrypted snippet")
            assert_true(by_subj[subj_v1].get("verified") is True, "v1 mail verified")
            assert_true(by_subj[subj_v2].get("verified") is True, "v2 mail verified")
            remaining_mail = list(mail_root.rglob("eml_*.json"))
            assert_eq(remaining_mail, [], f"expected mail deleted after --delete: {remaining_mail}")

            print("[7/8] P2P stdio & --expose/--forward over real server SSE signaling...")
            # stdio binary P2P test
            stdio_payload = (b"FATEXT_PHASE2_P2P_STDIO_" * 400) + b"\x00\x01\xff\n"
            p2p_l = subprocess.Popen(
                [str(CLI_BIN), "--api", api_url, "--json", "p2p", "listen", "--allow-friends-only", "--stdio", "--stun", "none"],
                env={**os.environ, "FATEXT_HOME": str(home_b)},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            time.sleep(0.5)
            p2p_c = subprocess.run(
                [str(CLI_BIN), "--api", api_url, "--json", "p2p", "connect", aid_b, "--stun", "none"],
                env={**os.environ, "FATEXT_HOME": str(home_a)},
                input=stdio_payload,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20.0,
            )
            l_out, l_err = p2p_l.communicate(timeout=20.0)
            assert_eq(p2p_c.returncode, 0, f"stdio p2p connect failed: {p2p_c.stderr!r}")
            assert_eq(p2p_l.returncode, 0, f"stdio p2p listen failed: {l_err!r}")
            assert_eq(l_out, stdio_payload, f"stdio P2P payload len mismatch ({len(l_out)} != {len(stdio_payload)})")

            # Bidirectional TCP --expose / --forward test
            echo_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            echo_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            echo_sock.bind((HOST, 0))
            echo_port = echo_sock.getsockname()[1]
            echo_sock.listen(4)
            stop_echo = threading.Event()

            def echo_worker() -> None:
                echo_sock.settimeout(0.2)
                while not stop_echo.is_set():
                    try:
                        conn_s, _ = echo_sock.accept()
                    except socket.timeout:
                        continue
                    def handle_one(cs: socket.socket) -> None:
                        with cs:
                            while True:
                                chunk = cs.recv(4096)
                                if not chunk:
                                    break
                                cs.sendall(b"ECHO:" + chunk)
                    threading.Thread(target=handle_one, args=(conn_s,), daemon=True).start()

            et = threading.Thread(target=echo_worker, daemon=True)
            et.start()

            fwd_port = free_tcp_port()
            p2p_l2 = subprocess.Popen(
                [str(CLI_BIN), "--api", api_url, "--json", "p2p", "listen", "--allow-friends-only", "--expose", str(echo_port), "--stun", "none"],
                env={**os.environ, "FATEXT_HOME": str(home_b)},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            time.sleep(0.5)
            p2p_c2 = subprocess.Popen(
                [str(CLI_BIN), "--api", api_url, "--json", "p2p", "connect", aid_b, "--forward", f"{fwd_port}:{echo_port}", "--stun", "none"],
                env={**os.environ, "FATEXT_HOME": str(home_a)},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                deadline = time.time() + 10.0
                got_connected = False
                logs = []
                while time.time() < deadline:
                    ln = p2p_c2.stderr.readline().decode("utf-8", errors="replace")
                    if ln:
                        logs.append(ln)
                        if '"state":"connected"' in ln:
                            got_connected = True
                            break
                    elif p2p_c2.poll() is not None:
                        break
                    else:
                        time.sleep(0.05)
                assert_true(got_connected, f"p2p forward did not connect: {''.join(logs)}")
                with socket.create_connection((HOST, fwd_port), timeout=10.0) as cli_s:
                    cli_s.sendall(b"hello-real-server-p2p\n")
                    cli_s.shutdown(socket.SHUT_WR)
                    chunks = []
                    while True:
                        b = cli_s.recv(4096)
                        if not b:
                            break
                        chunks.append(b)
                    reply = b"".join(chunks)
                assert_eq(reply, b"ECHO:hello-real-server-p2p\n", f"P2P TCP forward reply mismatch: {reply!r}")
                p2p_c2.communicate(timeout=10.0)
                p2p_l2.communicate(timeout=10.0)
                assert_eq(p2p_c2.returncode, 0, "p2p forward connect exit 0")
                assert_eq(p2p_l2.returncode, 0, "p2p expose listen exit 0")
            finally:
                stop_echo.set()
                echo_sock.close()
                for p in (p2p_c2, p2p_l2):
                    if p.poll() is None:
                        p.kill()
                        p.wait(timeout=3)

            print("[8/8] Friend removal restores DM 403 rejection...")
            rc, _, err = run_cli(["friend", "rm", aid_b], env_home=str(home_a), api_url=api_url)
            assert_eq(rc, 0, f"friend rm failed: {err}")
            rc, _, err = run_cli(["dm", "send", aid_b, "after rm"], env_home=str(home_a), api_url=api_url)
            assert_eq(rc, 5, f"dm after friend rm should fail with 5, got {rc} ({err})")

        except Exception:
            try:
                rc_poll = srv.poll()
                print(f"--- server poll before terminate: {rc_poll!r} ---", file=sys.stderr)
                if rc_poll is None:
                    srv.terminate()
                out_s, err_s = srv.communicate(timeout=3)
                print("--- server stdout ---\n" + out_s.decode("utf-8", errors="replace"), file=sys.stderr)
                print("--- server stderr ---\n" + err_s.decode("utf-8", errors="replace"), file=sys.stderr)
            except Exception:
                pass
            raise
        finally:
            if srv.poll() is None:
                srv.terminate()
                try:
                    srv.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    srv.kill()
                    srv.wait(timeout=5)


def main() -> int:
    if not SERVER_BIN.is_file():
        print(f"Missing server binary: {SERVER_BIN}", file=sys.stderr)
        return 1
    if not CLI_BIN.is_file():
        print(f"Missing CLI binary: {CLI_BIN}", file=sys.stderr)
        return 1
    test_native_tls_and_redirect()
    run_phase2_cli_suite()
    print("ALL PHASE 2 + NATIVE TLS + REAL CLI CHECKS PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
