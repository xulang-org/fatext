#!/usr/bin/env python3
"""End-to-end test for unified ftx_ 1-hop Controller -> Managed Agent delegation chain."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
SERVER_BIN = Path(os.environ.get("FATEXT_SERVER_BIN", str(ROOT / "build" / "fatext-server")))
CLI_BIN = Path(os.environ.get("FATEXT_CLI_BIN", str(ROOT.parent / "fatext-cli" / "build" / "fatext")))
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
    raise RuntimeError(f"server failed to become healthy at {url}")


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
    api_url: str | None = None,
    timeout: float = 30.0,
) -> tuple[int, str, str]:
    env = os.environ.copy()
    if agent_home is not None:
        env["FATEXT_HOME"] = agent_home
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


def http_req(url: str, method: str = "GET", body: bytes | None = None, headers: dict[str, str] | None = None) -> tuple[int, str]:
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=10.0) as r:
            return r.status, r.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8")


def openssl_verify_pss(pub_pem: str, msg: str, sig_b64: str) -> bool:
    sig = base64.b64decode(sig_b64)
    with tempfile.TemporaryDirectory() as td:
        td_p = Path(td)
        pk_p = td_p / "pub.pem"
        msg_p = td_p / "msg.bin"
        sig_p = td_p / "sig.bin"
        pk_p.write_text(pub_pem, encoding="utf-8")
        msg_p.write_bytes(msg.encode("utf-8"))
        sig_p.write_bytes(sig)
        r = subprocess.run(
            [
                "/usr/bin/openssl",
                "dgst",
                "-sha256",
                "-verify",
                str(pk_p),
                "-sigopt",
                "rsa_padding_mode:pss",
                "-sigopt",
                "rsa_pss_saltlen:32",
                "-sigopt",
                "rsa_mgf1_md:sha256",
                "-signature",
                str(sig_p),
                str(msg_p),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return r.returncode == 0


def openssl_sign_pss(priv_pem_path: Path, msg: str) -> str:
    with tempfile.TemporaryDirectory() as td:
        msg_p = Path(td) / "msg.bin"
        sig_p = Path(td) / "sig.bin"
        msg_p.write_bytes(msg.encode("utf-8"))
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
                str(sig_p),
                str(msg_p),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return base64.b64encode(sig_p.read_bytes()).decode("ascii")


def solve_pow_register(pub_pem: str, bits: int = 12) -> tuple[int, str]:
    pub_sha = hashlib.sha256(pub_pem.encode("utf-8")).hexdigest()
    ts = int(time.time())
    nonce = 0
    while True:
        ns = str(nonce)
        digest = hashlib.sha256(f"{pub_sha}:{ts}:{ns}".encode("utf-8")).digest()
        full, rem = divmod(bits, 8)
        ok = all(digest[i] == 0 for i in range(full))
        if ok and rem > 0:
            ok = (digest[full] >> (8 - rem)) == 0
        if ok:
            return ts, ns
        nonce += 1


def canonical_enrollment(pl: dict) -> str:
    return json.dumps(
        {
            "controller_id": pl["controller_id"],
            "controller_key_version": pl["controller_key_version"],
            "cred_id": pl["cred_id"],
            "expires_at": pl["expires_at"],
            "issued_at": pl["issued_at"],
            "kind": "enrollment",
            "label": pl["label"],
            "scopes": pl["scopes"],
        },
        separators=(",", ":"),
        ensure_ascii=False,
    )


def main() -> int:
    if not SERVER_BIN.is_file() or not CLI_BIN.is_file():
        print("Missing built binaries; build server and fatext-cli first.", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory(prefix="fatext-ctl-chain-") as td:
        td_p = Path(td)
        data_dir = td_p / "data"
        log_dir = td_p / "logs"
        data_dir.mkdir(parents=True, exist_ok=True)
        log_dir.mkdir(parents=True, exist_ok=True)

        port = free_tcp_port()
        api_url = f"http://{HOST}:{port}"
        srv_env = os.environ.copy()
        srv_env["FATEXT_ADDR"] = f"{HOST}:{port}"
        srv_env["FATEXT_DATA_DIR"] = str(data_dir)
        srv_env["FATEXT_WWW_DIR"] = str(WWW_DIR)
        srv_env["FATEXT_TEMPLATES_DIR"] = str(TPL_DIR)
        srv_env["FATEXT_POW_BITS"] = "12"
        srv_env["FATEXT_LOG_DIR"] = str(log_dir)

        srv = subprocess.Popen([str(SERVER_BIN)], env=srv_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            wait_http_ok(f"{api_url}/health", timeout=10.0)

            ch_root = str(td_p / "ctl_root")
            ch_sub_ctl = str(td_p / "ctl_sub")
            ah_bota = str(td_p / "bot_a")
            ah_botb = str(td_p / "bot_b")
            ah_standalone = str(td_p / "standalone")
            ah_reuse = str(td_p / "reuse_try")
            ah_nested = str(td_p / "nested_try")

            print("[1/7] Init controller (--controller-only) & issue single-use enrollment voucher...")
            rc, out, err = run_cli(
                ["--json", "init", "--controller-only", "--name", "RootCtl", "--bio", "Primary orchestrator"],
                agent_home=ch_root,
                api_url=api_url,
            )
            assert_eq(rc, 0, f"controller init failed: {err}")
            cid = json.loads(out.strip())["agent_id"]
            assert_true(cid.startswith("ftx_"), f"controller must use ftx_ id, got {cid}")

            st_k, raw_ck = http_req(f"{api_url}/k/{cid}.json")
            assert_eq(st_k, 200, "GET /k/{cid}.json")
            ck = json.loads(raw_ck)
            assert_eq(ck["extensions"]["dm_policy"], "none", "controller-only dm_policy=none")
            assert_eq(ck["extensions"]["accept_email"], False, "controller-only accept_email=false")
            assert_true(ck.get("ownership") is None, "controller ownership=null")

            # Legacy /h/ / /u/ routes must 404
            st_old, _ = http_req(f"{api_url}/h/{cid}.json")
            assert_eq(st_old, 404, "legacy /h/ route removed")

            v1 = td_p / "v1.json"
            rc, _, err = run_cli(
                ["--json", "ctl", "cred", "issue", "--scopes", "pub,social,dm,stream", "--label", "bot-a", "--ttl", "30d", "--out", str(v1)],
                agent_home=ch_root,
                api_url=api_url,
            )
            assert_eq(rc, 0, f"ctl cred issue failed: {err}")
            v1_obj = json.loads(v1.read_text(encoding="utf-8"))
            _, ctl_pem = http_req(f"{api_url}/k/{cid}.pem")
            assert_true(
                openssl_verify_pss(ctl_pem, canonical_enrollment(v1_obj["payload"]), v1_obj["controller_sig"]),
                "OpenSSL verified v1 enrollment voucher",
            )

            print("[2/7] Enroll BotA with v1, verify ownership & single-use voucher replay rejection...")
            rc, out, err = run_cli(
                ["--json", "init", "--name", "BotA", "--credential", str(v1)],
                agent_home=ah_bota,
                api_url=api_url,
            )
            assert_eq(rc, 0, f"BotA enrolled init failed: {err}")
            bota_init = json.loads(out.strip())
            aid_a = bota_init["agent_id"]
            assert_eq(bota_init["controller_id"], cid, "BotA init controller_id")

            _, raw_ba = http_req(f"{api_url}/k/{aid_a}.json")
            ka = json.loads(raw_ba)
            assert_eq(ka["ownership"]["controller_id"], cid, "BotA ownership.controller_id")
            assert_eq(ka["ownership"]["label"], "bot-a", "BotA label")

            # Single-use replay of v1 must fail
            rc, _, err = run_cli(["--json", "init", "--name", "ReuseTry", "--credential", str(v1)], agent_home=ah_reuse, api_url=api_url)
            assert_true(rc != 0, f"v1 replay must fail, got rc={rc}")

            print("[3/7] Enforce strictly 1-hop delegation (ERR_NESTED_DELEGATION across CLI & API)...")
            rc, _, err = run_cli(["--json", "ctl", "agents"], agent_home=ah_bota, api_url=api_url)
            assert_eq(rc, 5, f"managed agent ctl agents expected exit 5, got {rc}: {err}")
            assert_true("ERR_NESTED_DELEGATION" in err, f"expected ERR_NESTED_DELEGATION: {err}")

            # Even if a managed agent signs an offline voucher locally, server /v1/agents/register rejects 403 ERR_NESTED_DELEGATION
            v_nested = td_p / "v_nested.json"
            rc, _, err = run_cli(
                ["--json", "ctl", "cred", "issue", "--scopes", "pub", "--label", "illegal-grandchild", "--out", str(v_nested)],
                agent_home=ah_bota,
                api_url=api_url,
            )
            assert_eq(rc, 0, f"local voucher sign failed: {err}")
            rc, _, err = run_cli(
                ["--json", "init", "--name", "NestedTry", "--credential", str(v_nested)],
                agent_home=ah_nested,
                api_url=api_url,
            )
            assert_eq(rc, 5, f"grandchild register expected exit 5 (403), got {rc}: {err}")
            assert_true("ERR_NESTED_DELEGATION" in err, f"expected ERR_NESTED_DELEGATION on enroll: {err}")

            # Sub-controller already owning an agent cannot itself be adopted
            rc, out, err = run_cli(["--json", "init", "--name", "SubCtl"], agent_home=ch_sub_ctl, api_url=api_url)
            assert_eq(rc, 0, f"SubCtl init failed: {err}")
            sub_cid = json.loads(out.strip())["agent_id"]
            v_sub = td_p / "v_sub.json"
            rc, _, _ = run_cli(["--json", "ctl", "cred", "issue", "--scopes", "pub", "--out", str(v_sub)], agent_home=ch_sub_ctl, api_url=api_url)
            assert_eq(rc, 0, "SubCtl issue voucher")
            rc, _, err = run_cli(["--json", "init", "--name", "SubChild", "--credential", str(td_p / "v_sub.json")], agent_home=str(td_p / "sub_child"), api_url=api_url)
            assert_eq(rc, 0, f"SubChild init failed: {err}")
            sub_proof = td_p / "sub_proof.json"
            rc, _, err = run_cli(["--json", "claim-proof", cid, "--out", str(sub_proof)], agent_home=ch_sub_ctl, api_url=api_url)
            assert_eq(rc, 0, f"SubCtl claim-proof failed: {err}")
            rc, _, err = run_cli(["--json", "ctl", "grant", sub_cid, "--scopes", "all", "--proof", str(sub_proof)], agent_home=ch_root, api_url=api_url)
            assert_eq(rc, 5, f"adopting controller with managed_agents must fail 403 (exit 5), got {rc}: {err}")
            assert_true("ERR_NESTED_DELEGATION" in err, f"expected ERR_NESTED_DELEGATION on adopt controller: {err}")

            print("[4/7] Scope denial (rotate omitted), ctl grant upgrade, rotate + offline verify...")
            rc, _, err = run_cli(["--json", "key", "rotate"], agent_home=ah_bota, api_url=api_url)
            assert_eq(rc, 5, f"BotA rotate without scope expected exit 5, got {rc}: {err}")
            assert_true("ERR_SCOPE_DENIED" in err, f"expected ERR_SCOPE_DENIED: {err}")

            rc, _, err = run_cli(["--json", "ctl", "grant", aid_a, "--scopes", "all", "--label", "bot-a-v2"], agent_home=ch_root, api_url=api_url)
            assert_eq(rc, 0, f"ctl grant all failed: {err}")
            rc, _, err = run_cli(["--json", "key", "rotate"], agent_home=ah_bota, api_url=api_url)
            assert_eq(rc, 0, f"BotA rotate after grant failed: {err}")

            rc, ver_out, err = run_cli(["--json", "verify", aid_a], agent_home=ah_bota, api_url=api_url)
            assert_eq(rc, 0, f"verify BotA failed: {err}")
            ver_j = json.loads(ver_out)
            assert_true(ver_j["chain_valid"] is True, f"BotA verify true: {ver_j}")
            assert_eq(ver_j["controller_id"], cid, "verify delegation controller_id")

            print("[5/7] Controller key rotation, v2 voucher enrollment & claim-proof adoption...")
            unused_v1 = td_p / "unused-v1.json"
            rc, _, err = run_cli(
                ["--json", "ctl", "cred", "issue", "--out", str(unused_v1)],
                agent_home=ch_root, api_url=api_url,
            )
            assert_eq(rc, 0, f"v1 voucher issue failed: {err}")
            rc, _, err = run_cli(["--json", "key", "rotate"], agent_home=ch_root, api_url=api_url)
            assert_eq(rc, 0, f"controller rotate failed: {err}")

            rc, _, err = run_cli(
                ["--json", "init", "--credential", str(unused_v1)],
                agent_home=str(td_p / "stale-enrollment"), api_url=api_url,
            )
            assert_true(rc != 0 and "ERR_BAD_SIGNATURE" in err, f"retired voucher should fail: {err}")

            v2 = td_p / "v2.json"
            rc, _, err = run_cli(["--json", "ctl", "cred", "issue", "--scopes", "pub,social,dm,stream", "--label", "bot-b", "--out", str(v2)], agent_home=ch_root, api_url=api_url)
            assert_eq(rc, 0, f"v2 voucher issue failed: {err}")
            assert_eq(json.loads(v2.read_text(encoding="utf-8"))["payload"]["controller_key_version"], 2, "v2 controller_key_version=2")

            rc, out, err = run_cli(["--json", "init", "--name", "BotB", "--credential", str(v2)], agent_home=ah_botb, api_url=api_url)
            assert_eq(rc, 0, f"BotB init failed: {err}")
            aid_b = json.loads(out.strip())["agent_id"]

            rc, out, err = run_cli(["--json", "init", "--name", "StandAlone"], agent_home=ah_standalone, api_url=api_url)
            assert_eq(rc, 0, f"StandAlone init failed: {err}")
            aid_s = json.loads(out.strip())["agent_id"]

            proof_f = td_p / "adopt.json"
            rc, _, err = run_cli(["--json", "claim-proof", cid, "--out", str(proof_f)], agent_home=ah_standalone, api_url=api_url)
            assert_eq(rc, 0, f"claim-proof failed: {err}")
            rc, _, err = run_cli(["--json", "ctl", "grant", aid_s, "--scopes", "all", "--label", "adopted", "--proof", str(proof_f)], agent_home=ch_root, api_url=api_url)
            assert_eq(rc, 0, f"ctl grant adoption failed: {err}")

            rc, ver_b, err = run_cli(["--json", "verify", aid_b], agent_home=ch_root, api_url=api_url)
            assert_eq(rc, 0, f"verify BotB after controller rotate failed: {err}")
            assert_true(json.loads(ver_b)["chain_valid"] is True, "BotB verified")

            _, html_c = http_req(f"{api_url}/a/{cid}")
            assert_true("Controller Roster (3 managed)" in html_c and aid_a in html_c and aid_b in html_c and aid_s in html_c, "/a/{cid} shows Controller Roster (3 managed)")

            print("[6/7] Control plane: ctl policy, suspend (SSE disconnect) / resume, revoke child...")
            rc, out, err = run_cli(["--json", "ctl", "policy", aid_a, "--name", "BotA-Renamed"], agent_home=ch_root, api_url=api_url)
            assert_eq(rc, 0, f"ctl policy failed: {err}")
            assert_eq(json.loads(out)["name"], "BotA-Renamed", "policy updated name")

            sse_a = subprocess.Popen(
                [str(CLI_BIN), "--api", api_url, "--json", "listen"],
                env={**os.environ, "FATEXT_HOME": ah_bota},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            time.sleep(0.5)
            rc, _, err = run_cli(["--json", "ctl", "suspend", aid_a, "--reason", "audit"], agent_home=ch_root, api_url=api_url)
            assert_eq(rc, 0, f"ctl suspend failed: {err}")
            sse_a.wait(timeout=5.0)
            rc, _, err = run_cli(["--json", "profile", "set", "--bio", "nope"], agent_home=ah_bota, api_url=api_url)
            assert_eq(rc, 5, f"suspended BotA expected exit 5: {err}")
            assert_true("ERR_AGENT_SUSPENDED" in err, f"expected ERR_AGENT_SUSPENDED: {err}")

            rc, _, err = run_cli(["--json", "ctl", "resume", aid_a], agent_home=ch_root, api_url=api_url)
            assert_eq(rc, 0, f"ctl resume failed: {err}")

            rc, _, err = run_cli(
                ["--json", "ctl", "grant", aid_b, "--scopes", "stream", "--ttl", "5s"],
                agent_home=ch_root, api_url=api_url,
            )
            assert_eq(rc, 0, f"short-lived grant failed: {err}")
            stream_path = "/v1/stream"
            stamp = str(int(time.time()))
            signature = openssl_sign_pss(
                Path(ah_botb) / "private.pem",
                f"GET\n{stream_path}\n{stamp}\n{hashlib.sha256(b'').hexdigest()}",
            )
            req = urllib.request.Request(api_url + stream_path, headers={
                "X-Agent-Id": aid_b, "X-Timestamp": stamp, "X-Signature": signature,
            })
            with urllib.request.urlopen(req, timeout=8) as stream:
                assert_eq(stream.status, 200, "stream opens before credential expiry")
                assert_true(b": connected" in stream.read(), "stream closes at credential expiry")

            rc, _, err = run_cli(["--json", "ctl", "revoke", aid_b, "--successor", aid_a, "--reason", "decom", "--confirm"], agent_home=ch_root, api_url=api_url)
            assert_eq(rc, 0, f"ctl revoke BotB failed: {err}")
            rc, _, err = run_cli(["--json", "friend", "list"], agent_home=ah_botb, api_url=api_url)
            assert_eq(rc, 5, f"revoked BotB expected exit 5: {err}")
            assert_true("ERR_REVOKED" in err, f"expected ERR_REVOKED: {err}")

            print("[7/7] Cascading controller revocation -> disconnects & invalidates managed agents...")
            sse_s = subprocess.Popen(
                [str(CLI_BIN), "--api", api_url, "--json", "listen"],
                env={**os.environ, "FATEXT_HOME": ah_standalone},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            time.sleep(0.5)

            rc, _, err = run_cli(["--json", "key", "revoke", "--confirm"], agent_home=ch_root, api_url=api_url)
            assert_eq(rc, 0, f"controller key revoke failed: {err}")
            sse_s.wait(timeout=5.0)

            rc, _, err = run_cli(["--json", "friend", "list"], agent_home=ah_bota, api_url=api_url)
            assert_eq(rc, 5, f"managed BotA after controller revoke expected exit 5: {err}")
            assert_true("ERR_CONTROLLER_REVOKED" in err, f"expected ERR_CONTROLLER_REVOKED: {err}")

            rc, _, err = run_cli(["--json", "verify", aid_a], agent_home=ah_bota, api_url=api_url)
            assert_eq(rc, 8, f"verify after controller revoke expected exit 8: {err}")

        finally:
            if srv.poll() is None:
                srv.terminate()
                srv.wait(timeout=5)

    print("ALL 7 UNIFIED CONTROLLER DELEGATION CHAIN TESTS PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
