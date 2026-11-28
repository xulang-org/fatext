#!/usr/bin/env python3
"""Server integration tests for RAM-only 1-hop Controller pairing relay (/v1/ctl/pair and /v1/pair)."""

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


def http_req(
    url: str,
    method: str = "GET",
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, str]:
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=10.0) as r:
            return r.status, r.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8")


def gen_rsa_keypair(td: Path, tag: str) -> tuple[Path, str]:
    priv = td / f"{tag}_priv.pem"
    pub = td / f"{tag}_pub.pem"
    subprocess.run(
        ["/usr/bin/openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(priv)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    subprocess.run(
        ["/usr/bin/openssl", "rsa", "-pubout", "-in", str(priv), "-out", str(pub)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return priv, pub.read_text(encoding="utf-8")


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


def pub_fingerprint(pub_pem: str) -> str:
    b64_body = "".join(line.strip() for line in pub_pem.splitlines() if not line.startswith("-----"))
    der = base64.b64decode(b64_body)
    return "SHA256:" + base64.b64encode(hashlib.sha256(der).digest()).decode("ascii")


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


def signed_headers(agent_id: str, priv_pem: Path, method: str, path: str, body: bytes) -> dict[str, str]:
    ts = str(int(time.time()))
    bhex = hashlib.sha256(body).hexdigest()
    sts = f"{method}\n{path}\n{ts}\n{bhex}"
    sig = openssl_sign_pss(priv_pem, sts)
    return {
        "Content-Type": "application/json",
        "X-Agent-Id": agent_id,
        "X-Timestamp": ts,
        "X-Signature": sig,
    }


def register_agent(api_url: str, td: Path, tag: str, *, controller_only: bool = False, enrollment: dict | None = None) -> tuple[str, Path, str]:
    priv, pub_pem = gen_rsa_keypair(td, tag)
    ts, nonce = solve_pow_register(pub_pem, bits=12)
    payload: dict = {"public_key_pem": pub_pem, "profile": {"name": tag, "bio": ""}}
    if controller_only:
        payload["controller_only"] = True
    if enrollment is not None:
        fp = pub_fingerprint(pub_pem)
        pl = enrollment["payload"]
        ab_pl = {
            "agent_pub_fp": fp,
            "controller_id": pl["controller_id"],
            "cred_id": pl["cred_id"],
            "timestamp": ts,
        }
        ab_canon = json.dumps(ab_pl, separators=(",", ":"), sort_keys=True)
        payload["enrollment"] = enrollment
        payload["agent_binding"] = ab_pl
        payload["agent_binding_sig"] = openssl_sign_pss(priv, ab_canon)

    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    bhex = hashlib.sha256(body).hexdigest()
    sts = f"POST\n/v1/agents/register\n{ts}\n{bhex}"
    sig = openssl_sign_pss(priv, sts)
    st, raw = http_req(
        f"{api_url}/v1/agents/register",
        method="POST",
        body=body,
        headers={
            "Content-Type": "application/json",
            "X-Timestamp": str(ts),
            "X-Signature": sig,
            "X-PoW-Nonce": nonce,
        },
    )
    assert_eq(st, 201, f"register {tag}: {raw}")
    aid = json.loads(raw)["agent_id"]
    return aid, priv, pub_pem


def main() -> int:
    if not SERVER_BIN.is_file():
        print(f"Missing server binary: {SERVER_BIN}", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory(prefix="fatext-pair-srv-") as td:
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

            print("[1/6] Register controllers & one managed agent...")
            ctl_id, ctl_priv, _ = register_agent(api_url, td_p, "ctl1", controller_only=True)
            ctl2_id, ctl2_priv, _ = register_agent(api_url, td_p, "ctl2", controller_only=True)

            # Register a managed child via standard enrollment voucher to test ERR_NESTED_DELEGATION
            enr_pl = {
                "controller_id": ctl_id,
                "controller_key_version": 1,
                "cred_id": "cred_01JAAAAAAAAAAAAAAAAAAAAAAA",
                "expires_at": int(time.time()) + 3600,
                "issued_at": int(time.time()),
                "kind": "enrollment",
                "label": "child",
                "scopes": ["pub"],
            }
            enr_canon = json.dumps(enr_pl, separators=(",", ":"), sort_keys=True)
            enr = {"payload": enr_pl, "controller_sig": openssl_sign_pss(ctl_priv, enr_canon)}
            child_id, child_priv, _ = register_agent(api_url, td_p, "child", enrollment=enr)

            print("[2/6] Verify open validation, bad signature, and ERR_NESTED_DELEGATION...")
            c_xpub = base64.b64encode(os.urandom(32)).decode("ascii")
            exp = int(time.time()) + 120
            pid = "pair_abcdefgh2345"
            open_msg = f"fatext-pair-v1\nopen\n{child_id}\n{pid}\n{c_xpub}\n{exp}"
            body_child = json.dumps(
                {"pair_id": pid, "c_xpub": c_xpub, "c_xpub_sig": openssl_sign_pss(child_priv, open_msg), "expires_at": exp}
            ).encode("utf-8")
            st, raw = http_req(
                f"{api_url}/v1/ctl/pair",
                method="POST",
                body=body_child,
                headers=signed_headers(child_id, child_priv, "POST", "/v1/ctl/pair", body_child),
            )
            assert_eq(st, 403, f"managed agent should get 403: {raw}")
            assert_eq(json.loads(raw)["error"]["code"], "ERR_NESTED_DELEGATION", raw)

            # Bad signature on valid controller
            body_bad_sig = json.dumps(
                {"pair_id": pid, "c_xpub": c_xpub, "c_xpub_sig": openssl_sign_pss(ctl2_priv, open_msg), "expires_at": exp}
            ).encode("utf-8")
            st, raw = http_req(
                f"{api_url}/v1/ctl/pair",
                method="POST",
                body=body_bad_sig,
                headers=signed_headers(ctl_id, ctl_priv, "POST", "/v1/ctl/pair", body_bad_sig),
            )
            assert_eq(st, 401, f"bad c_xpub_sig should fail 401: {raw}")
            assert_eq(json.loads(raw)["error"]["code"], "ERR_BAD_SIGNATURE", raw)

            print("[3/6] Happy path: open -> info -> join -> poll -> deliver -> single-use voucher pickup...")
            open_msg = f"fatext-pair-v1\nopen\n{ctl_id}\n{pid}\n{c_xpub}\n{exp}"
            open_sig = openssl_sign_pss(ctl_priv, open_msg)
            open_body = json.dumps(
                {"pair_id": pid, "c_xpub": c_xpub, "c_xpub_sig": open_sig, "expires_at": exp}
            ).encode("utf-8")
            st, raw = http_req(
                f"{api_url}/v1/ctl/pair",
                method="POST",
                body=open_body,
                headers=signed_headers(ctl_id, ctl_priv, "POST", "/v1/ctl/pair", open_body),
            )
            assert_eq(st, 201, f"open pair: {raw}")

            # Info check
            st, raw = http_req(f"{api_url}/v1/pair/{pid}")
            assert_eq(st, 200, f"GET /v1/pair/{pid}: {raw}")
            info = json.loads(raw)
            assert_eq(info["controller_id"], ctl_id)
            assert_eq(info["c_xpub"], c_xpub)
            assert_eq(info["status"], "waiting")

            # Another controller cannot poll or deliver
            st, raw = http_req(
                f"{api_url}/v1/ctl/pair/{pid}",
                headers=signed_headers(ctl2_id, ctl2_priv, "GET", f"/v1/ctl/pair/{pid}", b""),
            )
            assert_eq(st, 403, f"other controller poll must fail 403: {raw}")

            # Worker join
            w_xpub = base64.b64encode(os.urandom(32)).decode("ascii")
            w_confirm = hashlib.sha256(b"confirm").hexdigest()
            claim_secret = hashlib.sha256(b"secret").hexdigest()
            claim_hash = hashlib.sha256(claim_secret.encode("ascii")).hexdigest()
            join_body = json.dumps(
                {"w_xpub": w_xpub, "worker_confirm": w_confirm, "claim_hash": claim_hash}
            ).encode("utf-8")
            st, raw = http_req(f"{api_url}/v1/pair/{pid}/join", method="POST", body=join_body, headers={"Content-Type": "application/json"})
            assert_eq(st, 202, f"join pair: {raw}")

            # Pending voucher check & wrong claim check
            wrong_claim = hashlib.sha256(b"wrong").hexdigest()
            st, _ = http_req(f"{api_url}/v1/pair/{pid}/voucher", headers={"X-Pair-Claim": wrong_claim})
            assert_eq(st, 403, "wrong claim must return 403")
            st, raw = http_req(f"{api_url}/v1/pair/{pid}/voucher", headers={"X-Pair-Claim": claim_secret})
            assert_eq(st, 202, f"pending voucher must return 202: {raw}")

            # Controller polls and sees w_xpub
            st, raw = http_req(
                f"{api_url}/v1/ctl/pair/{pid}",
                headers=signed_headers(ctl_id, ctl_priv, "GET", f"/v1/ctl/pair/{pid}", b""),
            )
            assert_eq(st, 200, f"ctl poll: {raw}")
            poll = json.loads(raw)
            assert_eq(poll["status"], "joined")
            assert_eq(poll["w_xpub"], w_xpub)
            assert_eq(poll["worker_confirm"], w_confirm)

            # Controller delivers ciphertext
            iv_b64 = base64.b64encode(os.urandom(12)).decode("ascii")
            ct_b64 = base64.b64encode(os.urandom(64)).decode("ascii")
            deliv_body = json.dumps({"iv": iv_b64, "ct": ct_b64}).encode("utf-8")
            st, raw = http_req(
                f"{api_url}/v1/ctl/pair/{pid}/deliver",
                method="POST",
                body=deliv_body,
                headers=signed_headers(ctl_id, ctl_priv, "POST", f"/v1/ctl/pair/{pid}/deliver", deliv_body),
            )
            assert_eq(st, 200, f"deliver: {raw}")

            # Worker pops voucher once -> 200, second fetch -> 404
            st, raw = http_req(f"{api_url}/v1/pair/{pid}/voucher", headers={"X-Pair-Claim": claim_secret})
            assert_eq(st, 200, f"voucher fetch 1: {raw}")
            v = json.loads(raw)
            assert_eq(v["iv"], iv_b64)
            assert_eq(v["ct"], ct_b64)
            st, _ = http_req(f"{api_url}/v1/pair/{pid}/voucher", headers={"X-Pair-Claim": claim_secret})
            assert_eq(st, 404, "voucher must be deleted from RAM after single pickup")

            print("[4/6] Test 3-strike bad code burn...")
            pid2 = "pair_zzzzzzzz2345"
            open_msg2 = f"fatext-pair-v1\nopen\n{ctl_id}\n{pid2}\n{c_xpub}\n{exp}"
            open_body2 = json.dumps(
                {"pair_id": pid2, "c_xpub": c_xpub, "c_xpub_sig": openssl_sign_pss(ctl_priv, open_msg2), "expires_at": exp}
            ).encode("utf-8")
            st, raw = http_req(
                f"{api_url}/v1/ctl/pair",
                method="POST",
                body=open_body2,
                headers=signed_headers(ctl_id, ctl_priv, "POST", "/v1/ctl/pair", open_body2),
            )
            assert_eq(st, 201, f"open pair2: {raw}")

            for attempt in range(1, 4):
                c_sec = hashlib.sha256(f"bad_{attempt}".encode("ascii")).hexdigest()
                c_h = hashlib.sha256(c_sec.encode("ascii")).hexdigest()
                jb = json.dumps({"w_xpub": w_xpub, "worker_confirm": w_confirm, "claim_hash": c_h}).encode("utf-8")
                st, raw = http_req(f"{api_url}/v1/pair/{pid2}/join", method="POST", body=jb, headers={"Content-Type": "application/json"})
                assert_eq(st, 202, f"join bad {attempt}: {raw}")

                st, raw = http_req(
                    f"{api_url}/v1/ctl/pair/{pid2}/reject",
                    method="POST",
                    body=b"{}",
                    headers=signed_headers(ctl_id, ctl_priv, "POST", f"/v1/ctl/pair/{pid2}/reject", b"{}"),
                )
                assert_eq(st, 200, f"reject {attempt}: {raw}")
                rj = json.loads(raw)
                assert_eq(rj["burned"], attempt == 3)

                st, raw = http_req(f"{api_url}/v1/pair/{pid2}/voucher", headers={"X-Pair-Claim": c_sec})
                assert_eq(st, 401, f"voucher reject status {attempt}: {raw}")
                want_code = "ERR_PAIR_EXHAUSTED" if attempt == 3 else "ERR_BAD_PAIR_CODE"
                assert_eq(json.loads(raw)["error"]["code"], want_code, raw)

            st, _ = http_req(f"{api_url}/v1/pair/{pid2}")
            assert_eq(st, 404, "burned pair session should be deleted after worker gets ERR_PAIR_EXHAUSTED")

            print("[5/6] Test DELETE /v1/ctl/pair/{id} cancel...")
            pid3 = "pair_cancelme2345"
            open_msg3 = f"fatext-pair-v1\nopen\n{ctl_id}\n{pid3}\n{c_xpub}\n{exp}"
            open_body3 = json.dumps(
                {"pair_id": pid3, "c_xpub": c_xpub, "c_xpub_sig": openssl_sign_pss(ctl_priv, open_msg3), "expires_at": exp}
            ).encode("utf-8")
            st, _ = http_req(
                f"{api_url}/v1/ctl/pair",
                method="POST",
                body=open_body3,
                headers=signed_headers(ctl_id, ctl_priv, "POST", "/v1/ctl/pair", open_body3),
            )
            assert_eq(st, 201)
            st, raw = http_req(
                f"{api_url}/v1/ctl/pair/{pid3}",
                method="DELETE",
                headers=signed_headers(ctl_id, ctl_priv, "DELETE", f"/v1/ctl/pair/{pid3}", b""),
            )
            assert_eq(st, 200, f"cancel: {raw}")
            st, _ = http_req(f"{api_url}/v1/pair/{pid3}")
            assert_eq(st, 404, "canceled pair must be 404")

            print("[6/6] Verify zero disk persistence for pairing sessions...")
            disk_matches = [str(p) for p in data_dir.rglob("*") if "pair_" in p.name or "pairing" in p.name]
            assert_eq(disk_matches, [], f"unexpected pairing files on disk: {disk_matches}")

            print("OK: RAM-only controller pairing server tests passed.")
            return 0
        finally:
            srv.terminate()
            try:
                srv.wait(timeout=5)
            except subprocess.TimeoutExpired:
                srv.kill()
                srv.wait()


if __name__ == "__main__":
    raise SystemExit(main())
