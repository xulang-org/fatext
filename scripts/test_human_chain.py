#!/usr/bin/env python3
"""End-to-end test suite for Human Root -> Credential -> Agent issuance chains & control plane."""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import re
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVER_BIN = ROOT / "build" / "fatext-server"
CLI_BIN = ROOT.parent / "fatext-cli" / "build" / "fatext"
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
    raise TimeoutError(f"{url} did not become ready within {timeout}s")


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
    api_url: str | None = None,
    timeout: float = 30.0,
) -> tuple[int, str, str]:
    env = os.environ.copy()
    if agent_home is not None:
        env["FATEXT_HOME"] = agent_home
    if human_home is not None:
        env["FATEXT_HUMAN_HOME"] = human_home
    cmd = [str(CLI_BIN)]
    if api_url is not None and "--api" not in args:
        cmd.extend(["--api", api_url])
    cmd.extend(args)
    res = subprocess.run(
        cmd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    return res.returncode, res.stdout, res.stderr


def http_get_text(url: str) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(url, timeout=10.0) as r:
            return r.status, r.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8")


def openssl_verify_pss(pub_pem_text: str, msg_str: str, sig_b64: str) -> bool:
    with tempfile.TemporaryDirectory(prefix="ossl-v-") as td:
        td_p = Path(td)
        pub_f = td_p / "pub.pem"
        msg_f = td_p / "msg.bin"
        sig_f = td_p / "sig.bin"
        pub_f.write_text(pub_pem_text, encoding="utf-8")
        msg_f.write_bytes(msg_str.encode("utf-8"))
        sig_f.write_bytes(base64.b64decode(sig_b64))
        r = subprocess.run(
            [
                "/usr/bin/openssl",
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(pub_f),
                "-in",
                str(msg_f),
                "-sigfile",
                str(sig_f),
                "-pkeyopt",
                "digest:sha256",
                "-pkeyopt",
                "rsa_padding_mode:pss",
                "-pkeyopt",
                "rsa_pss_saltlen:32",
                "-pkeyopt",
                "rsa_mgf1_md:sha256",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # Note: pkeyutl without -rawin hashes or hashes differently depending on openssl; use dgst -verify!
        r2 = subprocess.run(
            [
                "/usr/bin/openssl",
                "dgst",
                "-sha256",
                "-verify",
                str(pub_f),
                "-sigopt",
                "rsa_padding_mode:pss",
                "-sigopt",
                "rsa_pss_saltlen:32",
                "-sigopt",
                "rsa_mgf1_md:sha256",
                "-signature",
                str(sig_f),
                str(msg_f),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return r2.returncode == 0


def main() -> int:
    if not SERVER_BIN.is_file() or not CLI_BIN.is_file():
        print("Missing built binary (fatext-server or fatext)", file=sys.stderr)
        return 1

    port = free_tcp_port()
    api_url = f"http://{HOST}:{port}"

    with tempfile.TemporaryDirectory(prefix="fatext-human-") as td:
        td_p = Path(td)
        data_dir = td_p / "data"
        data_dir.mkdir(parents=True, exist_ok=True)

        hh_1 = str(td_p / "human1")
        hh_2 = str(td_p / "human2")
        ah_a = str(td_p / "agent_a")
        ah_b = str(td_p / "agent_b")
        ah_c = str(td_p / "agent_c")
        ah_dup = str(td_p / "agent_dup")
        ah_h2 = str(td_p / "agent_h2")

        srv_env = os.environ.copy()
        srv_env["FATEXT_ADDR"] = f"{HOST}:{port}"
        srv_env["FATEXT_DATA_DIR"] = str(data_dir)
        srv_env["FATEXT_WWW_DIR"] = str(WWW_DIR)
        srv_env["FATEXT_TEMPLATES_DIR"] = str(TPL_DIR)
        srv_env["FATEXT_POW_BITS"] = "12"

        srv = subprocess.Popen(
            [str(SERVER_BIN)],
            env=srv_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        def restart_server() -> None:
            nonlocal srv
            srv.terminate()
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

            print("[1/9] Human registration, discovery (/h/, /u/) & profile update...")
            rc, out, err = run_cli(
                ["--json", "human", "init", "--name", "Jay Root", "--bio", "Human signer", "--homepage", "https://alice.example.com"],
                human_home=hh_1,
                api_url=api_url,
            )
            assert_eq(rc, 0, f"human init failed: {err}")
            h1_doc = json.loads(out.strip())
            hid1 = h1_doc["human_id"]
            assert_true(re.match(r"^hum_[a-z0-9]{12}$", hid1) is not None, f"human_id format {hid1}")
            assert_eq(stat.S_IMODE((Path(hh_1) / "private.pem").stat().st_mode), 0o600, "human private.pem 0600")

            rc, out, err = run_cli(["--json", "human", "whoami"], human_home=hh_1, api_url=api_url)
            assert_eq(rc, 0, f"human whoami failed: {err}")
            assert_eq(json.loads(out.strip())["human_id"], hid1, "human whoami id")

            rc, out, err = run_cli(
                ["--json", "human", "profile", "set", "--name", "Jay Updated", "--bio", "Updated root bio"],
                human_home=hh_1,
                api_url=api_url,
            )
            assert_eq(rc, 0, f"human profile set failed: {err}")
            assert_eq(json.loads(out.strip())["revision"], 1, "human profile rev 1")

            st_u, html_u = http_get_text(f"{api_url}/u/{hid1}")
            assert_eq(st_u, 200, "GET /u/{hid} SSR 200")
            assert_true(hid1 in html_u and "Jay Updated" in html_u and "<script" not in html_u.lower(), "human SSR content")

            print("[2/9] Offline enrollment voucher + agent init + single-use enforcement + OpenSSL chain check...")
            voucher_1 = td_p / "voucher1.json"
            rc, out, err = run_cli(
                ["--json", "human", "cred", "issue", "--label", "alpha-worker", "--scopes", "pub,dm", "--ttl", "7d", "--out", str(voucher_1)],
                human_home=hh_1,
                api_url=api_url,
            )
            assert_eq(rc, 0, f"cred issue failed: {err}")
            cred1 = json.loads(out.strip())["cred_id"]
            assert_true(re.match(r"^cred_[0-9A-HJKMNP-TV-Z]{26}$", cred1) is not None, f"cred_id format {cred1}")

            rc, out, err = run_cli(
                ["--json", "init", "--name", "AlphaBot", "--credential", str(voucher_1)],
                agent_home=ah_a,
                api_url=api_url,
            )
            assert_eq(rc, 0, f"enrolled agent init failed: {err}")
            a1_init = json.loads(out.strip())
            aid_a = a1_init["agent_id"]
            assert_eq(a1_init["human_id"], hid1, "agent init returned human_id")
            assert_eq(a1_init["cred_id"], cred1, "agent init returned cred_id")

            # Voucher replay must fail with 409 ERR_CONFLICT (exit 6)
            rc, _, err = run_cli(
                ["--json", "init", "--name", "DupBot", "--credential", str(voucher_1)],
                agent_home=ah_dup,
                api_url=api_url,
            )
            assert_eq(rc, 6, f"reused enrollment voucher expected exit 6, got {rc}: {err}")

            # Verify /k/{aid_a}.json and /a/{aid_a} SSR and /u/{hid1} SSR + offline OpenSSL verification
            st_k, kjson_s = http_get_text(f"{api_url}/k/{aid_a}.json")
            assert_eq(st_k, 200, "GET /k/{aid}.json")
            kdoc = json.loads(kjson_s)
            own = kdoc["ownership"]
            assert_eq(own["human_id"], hid1, "ownership.human_id")
            assert_eq(own["scopes"], ["dm", "pub"], "sorted scopes")
            _, hpem = http_get_text(f"{api_url}/h/{hid1}.pem")
            canon_payload = json.dumps(own["payload"], separators=(",", ":"), sort_keys=True)
            assert_true(openssl_verify_pss(hpem, canon_payload, own["human_sig"]), "OpenSSL verified human_sig over JCS payload")
            canon_bind = json.dumps(own["agent_binding"], separators=(",", ":"), sort_keys=True)
            assert_true(openssl_verify_pss(kdoc["current_public_key_pem"], canon_bind, own["agent_binding_sig"]), "OpenSSL verified agent_binding_sig")

            _, html_a = http_get_text(f"{api_url}/a/{aid_a}")
            assert_true(hid1 in html_a and cred1 in html_a, "agent SSR shows human delegation chain")
            _, html_u2 = http_get_text(f"{api_url}/u/{hid1}")
            assert_true(aid_a in html_u2, "human SSR shows delegated agent in roster")

            rc, out, err = run_cli(["--json", "verify", aid_a], api_url=api_url)
            assert_eq(rc, 0, f"fatext verify {aid_a} failed: {err}")
            vdoc = json.loads(out.strip())
            assert_true(vdoc["chain_valid"] is True and vdoc["autonomous"] is False, f"verify report: {vdoc}")

            print("[3/9] Server-enforced scopes (pub allowed; social/profile/mail denied)...")
            restart_server()
            rc, out, err = run_cli(["--json", "pub", "post", "dev", "Delegated post from AlphaBot"], agent_home=ah_a, api_url=api_url)
            assert_eq(rc, 0, f"scoped pub post failed: {err}")

            for blocked_args in (
                ["friend", "list"],
                ["profile", "set", "--name", "NoProfileScope"],
                ["mail", "pull"],
            ):
                rc, _, err = run_cli(["--json"] + blocked_args, agent_home=ah_a, api_url=api_url)
                assert_eq(rc, 5, f"expected 403 scope denial exit 5 for {blocked_args}, got {rc}: {err}")
                assert_true("ERR_SCOPE_DENIED" in err, f"expected ERR_SCOPE_DENIED in stderr: {err}")

            print("[4/9] Direct human grant (upgrade to all scopes) + agent key rotate chain preservation...")
            rc, out, err = run_cli(
                ["--json", "human", "grant", aid_a, "--scopes", "all", "--ttl", "30d", "--label", "alpha-full"],
                human_home=hh_1,
                api_url=api_url,
            )
            assert_eq(rc, 0, f"human grant upgrade failed: {err}")
            rc, out, err = run_cli(["--json", "friend", "list"], agent_home=ah_a, api_url=api_url)
            assert_eq(rc, 0, f"friend list after grant upgrade failed: {err}")

            # Agent key rotation while retaining ownership chain back to agent v1 certificate
            rc, out, err = run_cli(["--json", "key", "rotate"], agent_home=ah_a, api_url=api_url)
            assert_eq(rc, 0, f"agent key rotate failed: {err}")
            rc, out, err = run_cli(["--json", "verify", aid_a], api_url=api_url)
            assert_eq(rc, 0, f"verify after agent key rotate failed: {out} / {err}")
            assert_true(json.loads(out.strip())["chain_valid"] is True, "chain valid after agent rotate")

            print("[5/9] Human key rotation preserves historical issuance chain + mints v2 vouchers...")
            rc, out, err = run_cli(["--json", "human", "key", "rotate"], human_home=hh_1, api_url=api_url)
            assert_eq(rc, 0, f"human key rotate failed: {err}")
            assert_eq(json.loads(out.strip())["key_version"], 2, "human key_version=2")

            rc, out, err = run_cli(["--json", "verify", aid_a], api_url=api_url)
            assert_eq(rc, 0, f"verify after human key rotate failed: {out} / {err}")
            assert_true(json.loads(out.strip())["chain_valid"] is True, "historical cert verified across human rotation")

            # New voucher signed with human v2 key
            voucher_b = td_p / "voucher_b.json"
            rc, _, err = run_cli(
                ["--json", "human", "cred", "issue", "--label", "beta-worker", "--scopes", "all", "--out", str(voucher_b)],
                human_home=hh_1,
                api_url=api_url,
            )
            assert_eq(rc, 0, f"v2 cred issue failed: {err}")
            rc, out, err = run_cli(["--json", "init", "--name", "BetaBot", "--credential", str(voucher_b)], agent_home=ah_b, api_url=api_url)
            assert_eq(rc, 0, f"v2 enrolled init failed: {err}")
            aid_b = json.loads(out.strip())["agent_id"]
            rc, out, err = run_cli(["--json", "verify", aid_b], api_url=api_url)
            assert_eq(rc, 0, f"verify beta failed: {err}")

            print("[6/9] Autonomous agent + adoption via claim-proof + unauthorized claim rejection...")
            rc, out, err = run_cli(["--json", "init", "--name", "FreeAgent"], agent_home=ah_c, api_url=api_url)
            assert_eq(rc, 0, f"free agent init failed: {err}")
            aid_c = json.loads(out.strip())["agent_id"]

            rc, out, err = run_cli(["--json", "verify", aid_c], api_url=api_url)
            assert_eq(rc, 0, f"verify autonomous failed: {err}")
            assert_true(json.loads(out.strip())["autonomous"] is True, "autonomous=true before adoption")

            # Adopting without proof fails
            rc, _, err = run_cli(["--json", "human", "grant", aid_c], human_home=hh_1, api_url=api_url)
            assert_eq(rc, 5, f"unproofed adoption must return exit 5, got {rc}: {err}")

            # Sign adoption proof by FreeAgent and adopt
            proof_c = td_p / "proof_c.json"
            rc, _, err = run_cli(["--json", "claim-proof", hid1, "--out", str(proof_c)], agent_home=ah_c, api_url=api_url)
            assert_eq(rc, 0, f"claim-proof failed: {err}")
            rc, _, err = run_cli(
                ["--json", "human", "grant", aid_c, "--label", "adopted-c", "--scopes", "pub,social", "--proof", str(proof_c)],
                human_home=hh_1,
                api_url=api_url,
            )
            assert_eq(rc, 0, f"adopted grant failed: {err}")
            rc, out, err = run_cli(["--json", "verify", aid_c], api_url=api_url)
            assert_eq(rc, 0, f"verify adopted failed: {out} / {err}")
            assert_true(json.loads(out.strip())["human_id"] == hid1, "adopted human_id matches")

            # Register human2 and verify human2 CANNOT steal aid_c
            rc, out, err = run_cli(["--json", "human", "init", "--name", "HumanTwo"], human_home=hh_2, api_url=api_url)
            assert_eq(rc, 0, f"human2 init failed: {err}")
            hid2 = json.loads(out.strip())["human_id"]
            rc, _, err = run_cli(["--json", "human", "grant", aid_c], human_home=hh_2, api_url=api_url)
            assert_eq(rc, 5, f"foreign human grant must fail exit 5, got {rc}: {err}")

            # human agents roster check
            rc, out, err = run_cli(["--json", "human", "agents"], human_home=hh_1, api_url=api_url)
            assert_eq(rc, 0, f"human agents list failed: {err}")
            roster_ids = {x["agent_id"] for x in json.loads(out.strip())["agents"]}
            assert_eq(roster_ids, {aid_a, aid_b, aid_c}, "human1 roster contains a, b, c")

            print("[7/9] Human policy override on owned agent...")
            restart_server()
            rc, _, err = run_cli(
                ["--json", "profile", "set", "--dm-policy", "all", "--accept-email", "true", "--webhook-url", "https://hook.example.com/cb"],
                agent_home=ah_a,
                api_url=api_url,
            )
            assert_eq(rc, 0, f"agent profile set failed: {err}")
            rc, _, err = run_cli(
                ["--json", "human", "policy", aid_a, "--dm-policy", "none", "--accept-email", "false", "--clear-webhook"],
                human_home=hh_1,
                api_url=api_url,
            )
            assert_eq(rc, 0, f"human policy override failed: {err}")
            _, kjson_after = http_get_text(f"{api_url}/k/{aid_a}.json")
            exts = json.loads(kjson_after)["extensions"]
            assert_eq(exts["dm_policy"], "none", "dm_policy overridden to none")
            assert_eq(exts["accept_email"], False, "accept_email overridden to false")
            assert_true("webhook_url" not in exts, "webhook_url cleared")

            print("[8/9] Human suspend / instant SSE disconnect / resume...")
            sse_p = subprocess.Popen(
                [str(CLI_BIN), "--api", api_url, "--json", "listen", "--max-events", "5"],
                env={**os.environ, "FATEXT_HOME": ah_a},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            time.sleep(0.5)
            rc, _, err = run_cli(
                ["--json", "human", "suspend", aid_a, "--reason", "audit"],
                human_home=hh_1,
                api_url=api_url,
            )
            assert_eq(rc, 0, f"human suspend failed: {err}")
            sse_out, _ = sse_p.communicate(timeout=10.0)
            assert_true("disconnected" in sse_out, f"expected SSE disconnect event on suspend, got: {sse_out!r}")

            rc, _, err = run_cli(["--json", "friend", "list"], agent_home=ah_a, api_url=api_url)
            assert_eq(rc, 5, f"suspended agent expected exit 5, got {rc}: {err}")
            assert_true("ERR_AGENT_SUSPENDED" in err, f"expected ERR_AGENT_SUSPENDED: {err}")
            rc, _, _ = run_cli(["--json", "verify", aid_a], api_url=api_url)
            assert_eq(rc, 8, "verify suspended agent must exit 8")

            rc, _, err = run_cli(["--json", "human", "resume", aid_a], human_home=hh_1, api_url=api_url)
            assert_eq(rc, 0, f"human resume failed: {err}")
            rc, _, err = run_cli(["--json", "friend", "list"], agent_home=ah_a, api_url=api_url)
            assert_eq(rc, 0, f"resumed agent friend list failed: {err}")
            rc, _, err = run_cli(["--json", "verify", aid_a], api_url=api_url)
            assert_eq(rc, 0, f"verify resumed agent failed: {err}")

            print("[9/9] Human-authority agent revoke & cascading human root revocation...")
            rc, out, err = run_cli(
                ["--json", "human", "revoke", aid_c, "--successor", aid_a, "--reason", "retired", "--confirm"],
                human_home=hh_1,
                api_url=api_url,
            )
            assert_eq(rc, 0, f"human revoke agent failed: {err}")
            assert_eq(json.loads(out.strip())["revoked_by"], hid1, "revoked_by human_id")
            rc, _, _ = run_cli(["--json", "friend", "list"], agent_home=ah_c, api_url=api_url)
            assert_eq(rc, 5, "revoked agent rejected exit 5")
            rc, _, _ = run_cli(["--json", "verify", aid_c], api_url=api_url)
            assert_eq(rc, 8, "verify revoked agent must exit 8")

            # Cascading human2 revocation
            voucher_h2 = td_p / "voucher_h2.json"
            rc, _, err = run_cli(["--json", "human", "cred", "issue", "--out", str(voucher_h2)], human_home=hh_2, api_url=api_url)
            assert_eq(rc, 0, f"h2 cred issue failed: {err}")
            rc, out, err = run_cli(["--json", "init", "--name", "H2Bot", "--credential", str(voucher_h2)], agent_home=ah_h2, api_url=api_url)
            assert_eq(rc, 0, f"h2 agent init failed: {err}")
            aid_h2 = json.loads(out.strip())["agent_id"]

            sse_h2 = subprocess.Popen(
                [str(CLI_BIN), "--api", api_url, "--json", "listen", "--max-events", "5"],
                env={**os.environ, "FATEXT_HOME": ah_h2},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            time.sleep(0.5)
            rc, _, err = run_cli(["--json", "human", "key", "revoke", "--confirm"], human_home=hh_2, api_url=api_url)
            assert_eq(rc, 0, f"human2 key revoke failed: {err}")
            sse_h2_out, _ = sse_h2.communicate(timeout=10.0)
            assert_true("disconnected" in sse_h2_out, f"expected cascading SSE disconnect, got {sse_h2_out!r}")

            rc, _, err = run_cli(["--json", "friend", "list"], agent_home=ah_h2, api_url=api_url)
            assert_eq(rc, 5, f"agent under revoked human must exit 5, got {rc}: {err}")
            assert_true("ERR_HUMAN_REVOKED" in err, f"expected ERR_HUMAN_REVOKED: {err}")
            rc, _, _ = run_cli(["--json", "verify", aid_h2], api_url=api_url)
            assert_eq(rc, 8, "verify agent under revoked human must exit 8")

        finally:
            if srv.poll() is None:
                srv.terminate()
                srv.wait(timeout=5)

    print("ALL 9 HUMAN ROOT & ISSUANCE CHAIN CHECKS PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
