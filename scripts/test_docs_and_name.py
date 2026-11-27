#!/usr/bin/env python3
"""End-to-end test suite for agent display names and Soul/Rules documents."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

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


def http_get(url: str) -> tuple[int, dict[str, str], str]:
    try:
        with urllib.request.urlopen(url, timeout=10.0) as r:
            hdrs = {k.lower(): v for k, v in r.headers.items()}
            return r.status, hdrs, r.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        hdrs = {k.lower(): v for k, v in e.headers.items()}
        return e.code, hdrs, e.read().decode("utf-8")


def openssl_sign_pss(priv_pem_path: Path, msg_str: str) -> str:
    with tempfile.TemporaryDirectory(prefix="ossl-s-") as td:
        mp = Path(td) / "msg.bin"
        sp = Path(td) / "sig.bin"
        mp.write_bytes(msg_str.encode("utf-8"))
        subprocess.run(
            [
                "/usr/bin/openssl", "dgst", "-sha256",
                "-sigopt", "rsa_padding_mode:pss",
                "-sigopt", "rsa_pss_saltlen:32",
                "-sign", str(priv_pem_path),
                "-out", str(sp),
                str(mp),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return base64.b64encode(sp.read_bytes()).decode("ascii")


def openssl_verify_pss(pub_pem_text: str, msg_str: str, sig_b64: str) -> bool:
    with tempfile.TemporaryDirectory(prefix="ossl-v-") as td:
        td_p = Path(td)
        pp = td_p / "pub.pem"
        mp = td_p / "msg.bin"
        sp = td_p / "sig.bin"
        pp.write_text(pub_pem_text, encoding="utf-8")
        mp.write_bytes(msg_str.encode("utf-8"))
        sp.write_bytes(base64.b64decode(sig_b64))
        rc = subprocess.run(
            [
                "/usr/bin/openssl", "dgst", "-sha256",
                "-sigopt", "rsa_padding_mode:pss",
                "-sigopt", "rsa_pss_saltlen:32",
                "-verify", str(pp),
                "-signature", str(sp),
                str(mp),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode
        return rc == 0


def canonical_doc_payload(agent_id: str, content_sha256: str, kind: str, locked: bool, signer_id: str, signer_kv: int, updated_at: int, version: int, visibility: str) -> str:
    return json.dumps(
        {
            "agent_id": agent_id,
            "content_sha256": content_sha256,
            "kind": kind,
            "locked": locked,
            "signer_id": signer_id,
            "signer_key_version": signer_kv,
            "updated_at": updated_at,
            "version": version,
            "visibility": visibility,
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def signed_agent_put(api_url: str, aid: str, priv_path: Path, path: str, body_obj: dict) -> tuple[int, str]:
    raw = json.dumps(body_obj, separators=(",", ":")).encode("utf-8")
    ts = str(int(time.time()))
    bhex = hashlib.sha256(raw).hexdigest()
    sts = f"PUT\n{path}\n{ts}\n{bhex}"
    sig = openssl_sign_pss(priv_path, sts)
    req = urllib.request.Request(
        f"{api_url}{path}",
        data=raw,
        method="PUT",
        headers={
            "Content-Type": "application/json",
            "X-Agent-Id": aid,
            "X-Timestamp": ts,
            "X-Signature": sig,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10.0) as r:
            return r.status, r.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8")


def main() -> int:
    assert_true(SERVER_BIN.exists(), f"missing server bin {SERVER_BIN}")
    assert_true(CLI_BIN.exists(), f"missing cli bin {CLI_BIN}")

    with tempfile.TemporaryDirectory(prefix="fatext_docs_") as td:
        td_p = Path(td)
        data_dir = td_p / "data"
        log_dir = data_dir / "logs"
        port = free_tcp_port()
        api_url = f"http://{HOST}:{port}"
        srv_env = os.environ.copy()
        srv_env["FATEXT_ADDR"] = f"{HOST}:{port}"
        srv_env["FATEXT_DATA_DIR"] = str(data_dir)
        srv_env["FATEXT_WWW_DIR"] = str(WWW_DIR)
        srv_env["FATEXT_TEMPLATES_DIR"] = str(TPL_DIR)
        srv_env["FATEXT_POW_BITS"] = "12"
        srv_env["FATEXT_LOG_DIR"] = str(log_dir)
        srv_env["FATEXT_METRICS_INTERVAL_SEC"] = "60"
        mail_sec = "docs-test-mail-secret-123"
        srv_env["FATEXT_MAIL_INTERNAL_SECRET"] = mail_sec

        srv = subprocess.Popen([str(SERVER_BIN)], env=srv_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            wait_http_ok(f"{api_url}/health", timeout=10.0)

            ch_1 = str(td_p / "ctl1")
            ch_2 = str(td_p / "ctl2")
            ah_owned = str(td_p / "agent_owned")
            ah_dup = str(td_p / "agent_dup")
            ah_auto = str(td_p / "agent_auto")

            print("[1/5] Registration display names (no profile scope needed, duplicate names allowed, surfacing)...")
            rc, out, err = run_cli(["--json", "init", "--controller-only", "--name", "OwnerOne"], agent_home=ch_1, api_url=api_url)
            assert_eq(rc, 0, f"ctl1 init failed: {err}")
            cid1 = json.loads(out.strip())["agent_id"]

            rc, out, err = run_cli(["--json", "init", "--controller-only", "--name", "OwnerTwo"], agent_home=ch_2, api_url=api_url)
            assert_eq(rc, 0, f"ctl2 init failed: {err}")
            cid2 = json.loads(out.strip())["agent_id"]

            # Voucher WITHOUT profile scope; agent must STILL persist initial --name/--bio on register!
            v1 = td_p / "v1.json"
            rc, _, err = run_cli(
                ["--json", "ctl", "cred", "issue", "--scopes", "pub,social,dm,stream,rotate", "--out", str(v1)],
                agent_home=ch_1,
                api_url=api_url,
            )
            assert_eq(rc, 0, f"cred issue failed: {err}")

            rc, out, err = run_cli(
                ["--json", "init", "--name", "TwinSpark", "--bio", "Owned scout", "--credential", str(v1)],
                agent_home=ah_owned,
                api_url=api_url,
            )
            assert_eq(rc, 0, f"owned init failed: {err}")
            init_o = json.loads(out.strip())
            aid_owned = init_o["agent_id"]
            assert_eq(init_o["name"], "TwinSpark", "init json returned name")

            # Second autonomous agent with IDENTICAL display name "TwinSpark" (non-unique allowed)
            rc, out, err = run_cli(
                ["--json", "init", "--name", "TwinSpark", "--bio", "Free twin"],
                agent_home=ah_auto,
                api_url=api_url,
            )
            assert_eq(rc, 0, f"auto init failed: {err}")
            aid_auto = json.loads(out.strip())["agent_id"]
            assert_true(aid_auto != aid_owned, "duplicate names produce distinct agent_ids")

            # Another identical name
            rc, _, err = run_cli(["--json", "init", "--name", "TwinSpark"], agent_home=ah_dup, api_url=api_url)
            assert_eq(rc, 0, f"dup init failed: {err}")

            # Check whoami plain text shows name=..., ctl agents shows name, /a/{id} shows name & roster
            rc, w_txt, err = run_cli(["whoami"], agent_home=ah_owned, api_url=api_url)
            assert_eq(rc, 0, f"whoami plain failed: {err}")
            assert_true('name="TwinSpark"' in w_txt, f"whoami plain missing name: {w_txt!r}")

            rc, ha_txt, err = run_cli(["ctl", "agents"], agent_home=ch_1, api_url=api_url)
            assert_eq(rc, 0, f"ctl agents plain failed: {err}")
            assert_true('name="TwinSpark"' in ha_txt and aid_owned in ha_txt, f"ctl agents missing name: {ha_txt!r}")

            rc, ha_json, err = run_cli(["--json", "ctl", "agents"], agent_home=ch_1, api_url=api_url)
            assert_eq(rc, 0, f"ctl agents json failed: {err}")
            assert_eq(json.loads(ha_json)["agents"][0]["name"], "TwinSpark", "ctl agents JSON name")

            _, _, html_a = http_get(f"{api_url}/a/{aid_owned}")
            assert_true("TwinSpark" in html_a and cid1 in html_a, "/a/{id} missing agent name or controller_id")
            _, _, html_c = http_get(f"{api_url}/a/{cid1}")
            assert_true("TwinSpark" in html_c and "<th>Name</th>" in html_c, "/a/{cid} missing Name column/value")

            # Friends surfacing (pending incoming & friend list include from_name / name)
            rc, _, err = run_cli(["friend", "add", aid_owned], agent_home=ah_auto, api_url=api_url)
            assert_eq(rc, 0, f"friend add failed: {err}")
            rc, fl_in, err = run_cli(["--json", "friend", "list"], agent_home=ah_owned, api_url=api_url)
            assert_eq(rc, 0, f"friend list incoming failed: {err}")
            assert_eq(json.loads(fl_in)["incoming"][0]["from_name"], "TwinSpark", "incoming from_name")
            rc, _, err = run_cli(["friend", "accept", aid_auto], agent_home=ah_owned, api_url=api_url)
            assert_eq(rc, 0, f"friend accept failed: {err}")
            rc, fl_fr, err = run_cli(["--json", "friend", "list"], agent_home=ah_auto, api_url=api_url)
            assert_eq(rc, 0, f"friend list failed: {err}")
            assert_eq(json.loads(fl_fr)["friends"][0]["name"], "TwinSpark", "friends[0].name")

            # Controller rename via ctl policy --name
            rc, out, err = run_cli(["--json", "ctl", "policy", aid_owned, "--name", "RenamedSpark"], agent_home=ch_1, api_url=api_url)
            assert_eq(rc, 0, f"ctl policy --name failed: {err}")
            assert_eq(json.loads(out)["name"], "RenamedSpark", "ctl policy response name")
            _, _, k_after = http_get(f"{api_url}/k/{aid_owned}.json")
            assert_eq(json.loads(k_after)["profile"]["name"], "RenamedSpark", "updated agent profile name")

            print("[2/5] Public soul & rules, offline PSS verification, raw .md headers & XSS escaping...")
            public_soul = "# Soul of FreeTwin\nBe concise.\n<script>alert(1)</script>\n"
            public_rules = "# Rules of FreeTwin\nNever exfiltrate secrets.\n"
            soul_f = td_p / "soul.md"
            soul_f.write_text(public_soul, encoding="utf-8")

            rc, out, err = run_cli(["--json", "soul", "set", str(soul_f), "--public"], agent_home=ah_auto, api_url=api_url)
            assert_eq(rc, 0, f"auto soul set failed: {err}")
            s_doc = json.loads(out)
            assert_eq(s_doc["version"], 1, "soul v1")
            assert_eq(s_doc["visibility"], "public", "soul visibility=public")

            rc, out, err = run_cli(["--json", "rules", "set", "--text", public_rules, "--public"], agent_home=ah_auto, api_url=api_url)
            assert_eq(rc, 0, f"auto rules set failed: {err}")
            assert_eq(json.loads(out)["version"], 1, "rules v1")

            # Raw .md + headers
            st_md, hdrs_md, body_md = http_get(f"{api_url}/k/{aid_auto}/soul.md")
            assert_eq(st_md, 200, "GET /k/{id}/soul.md 200")
            assert_eq(body_md, public_soul, "soul.md exact content")
            assert_eq(hdrs_md.get("x-fatext-version"), "1", "X-Fatext-Version header")
            assert_eq(hdrs_md.get("x-fatext-sha256"), hashlib.sha256(public_soul.encode("utf-8")).hexdigest(), "X-Fatext-Sha256 header")
            assert_eq(hdrs_md.get("x-fatext-signed-by"), "agent", "X-Fatext-Signed-By header")
            assert_eq(hdrs_md.get("x-fatext-locked"), "false", "X-Fatext-Locked header")

            # Public docs.json + OpenSSL verify + HTML escaping on /a/{id}
            st_dj, _, dj_txt = http_get(f"{api_url}/k/{aid_auto}/docs.json")
            assert_eq(st_dj, 200, "docs.json 200")
            assert_eq(json.loads(dj_txt)["soul"]["version"], 1, "docs.json soul.version")

            _, _, sj_txt = http_get(f"{api_url}/k/{aid_auto}/soul.json")
            sj = json.loads(sj_txt)
            _, _, auto_pem = http_get(f"{api_url}/k/{aid_auto}.pem")
            canon_s = canonical_doc_payload(aid_auto, sj["content_sha256"], "soul", False, aid_auto, 1, sj["updated_at"], 1, "public")
            assert_true(openssl_verify_pss(auto_pem, canon_s, sj["signature"]), "OpenSSL verified public soul RSA-PSS sig")

            _, _, html_auto = http_get(f"{api_url}/a/{aid_auto}")
            assert_true("<script>alert(1)</script>" not in html_auto and "&lt;script&gt;alert(1)&lt;/script&gt;" in html_auto, "SSR HTML escaped soul")
            assert_true("RULES.md" in html_auto, "SSR shows RULES.md")

            rc, pulled_s, err = run_cli(["--json", "soul", "pull", aid_auto], agent_home=ah_owned, api_url=api_url)
            assert_eq(rc, 0, f"cross-agent public soul pull failed: {err}")
            ps_j = json.loads(pulled_s)
            assert_true(ps_j["verified"] is True and ps_j["content"] == public_soul, "verified public soul pull")

            print("[3/5] Private E2EE soul (multi-recipient, disk secrecy, foreign reject, key rotation recovery)...")
            priv_soul_secret = "SUPER_SECRET_SOUL_PROMPT_XYZ_987654"
            priv_soul_v2 = "SUPER_SECRET_SOUL_V2_AFTER_ROTATE_111"

            # Grant profile scope to owned agent so it can upload its own soul
            rc, _, err = run_cli(["--json", "ctl", "grant", aid_owned, "--scopes", "all"], agent_home=ch_1, api_url=api_url)
            assert_eq(rc, 0, f"grant all failed: {err}")

            rc, out, err = run_cli(["--json", "soul", "set", "--text", priv_soul_secret, "--private"], agent_home=ah_owned, api_url=api_url)
            assert_eq(rc, 0, f"owned agent private soul set failed: {err}")
            ps_resp = json.loads(out)
            assert_eq(ps_resp["visibility"], "private", "private visibility")
            assert_true(ps_resp["content"] is None, "server stores null content for private doc")
            assert_eq(len(ps_resp["envelope"]["recipients"]), 2, "2 recipients (agent + controller)")

            # Autonomous agent private soul -> 1 recipient
            auto_priv_rules = "AUTO_PRIVATE_RULES_555"
            rc, out, err = run_cli(["--json", "rules", "set", "--text", auto_priv_rules, "--private"], agent_home=ah_auto, api_url=api_url)
            assert_eq(rc, 0, f"auto private rules v2 failed: {err}")
            assert_eq(len(json.loads(out)["envelope"]["recipients"]), 1, "autonomous 1 recipient")

            # Verify plaintext NEVER touches disk on server
            bucket = aid_owned[4:6]
            disk_file = data_dir / "docs" / bucket / aid_owned / "soul.json"
            assert_true(priv_soul_secret not in disk_file.read_text(encoding="utf-8"), "plaintext must NOT be on server disk")

            # Public endpoints must reject private doc with 403 ERR_DOC_PRIVATE
            for pub_u in (f"{api_url}/k/{aid_owned}/soul.json", f"{api_url}/k/{aid_owned}/soul.md"):
                st_p, _, b_p = http_get(pub_u)
                assert_eq(st_p, 403, f"expected 403 on private {pub_u}")
                assert_eq(json.loads(b_p)["error"]["code"], "ERR_DOC_PRIVATE", "ERR_DOC_PRIVATE")

            st_meta, _, meta_txt = http_get(f"{api_url}/k/{aid_owned}/docs.json")
            assert_eq(st_meta, 200, "public document index")
            assert_eq(json.loads(meta_txt)["soul"], {"visibility": "private"}, "private metadata minimized")
            st_html, _, html = http_get(f"{api_url}/a/{aid_owned}")
            assert_eq(st_html, 200, "agent profile with private document")
            assert_true(ps_resp["content_sha256"][:16] not in html, "private digest hidden from profile")
            assert_true(f'{len(priv_soul_secret)} bytes' not in html, "private length hidden from profile")

            # Both agent AND controller can decrypt private soul; foreign controller gets 403
            rc, ap_out, err = run_cli(["--json", "soul", "pull"], agent_home=ah_owned, api_url=api_url)
            assert_eq(rc, 0, f"agent pull private soul failed: {err}")
            assert_eq(json.loads(ap_out)["content"], priv_soul_secret, "agent decrypted private soul")

            rc, hp_out, err = run_cli(["--json", "ctl", "soul", "pull", aid_owned], agent_home=ch_1, api_url=api_url)
            assert_eq(rc, 0, f"controller pull private soul failed: {err}")
            assert_eq(json.loads(hp_out)["content"], priv_soul_secret, "controller decrypted private soul")

            rc, _, _ = run_cli(["--json", "ctl", "soul", "pull", aid_owned], agent_home=ch_2, api_url=api_url)
            assert_eq(rc, 5, "foreign controller must get exit 5 (403)")

            # Server rejects managed agent's private doc omitting controller recipient (400 ERR_BAD_REQUEST)
            bad_sha = hashlib.sha256(b"missing-ctrl-test").hexdigest()
            bad_uat = int(time.time())
            bad_canon = canonical_doc_payload(aid_owned, bad_sha, "soul", False, aid_owned, 1, bad_uat, 2, "private")
            bad_sig = openssl_sign_pss(Path(ah_owned) / "private.pem", bad_canon)
            st_bad, b_bad = signed_agent_put(
                api_url, aid_owned, Path(ah_owned) / "private.pem", "/v1/agents/docs/soul",
                {
                    "version": 2,
                    "visibility": "private",
                    "locked": False,
                    "format": "markdown",
                    "content_sha256": bad_sha,
                    "content_bytes": 17,
                    "envelope": {"v": 1, "alg": "RSA-OAEP-256+A256GCM", "iv": "AAAA", "ct": "BBBB", "recipients": [{"role": "agent", "id": aid_owned, "key_version": 1, "ek": "CCCC"}]},
                    "updated_at": bad_uat,
                    "signature": bad_sig,
                },
            )
            assert_eq(st_bad, 400, f"missing controller recipient must fail 400, got {st_bad}: {b_bad}")

            # Rotate agent key -> v2, still able to decrypt v1-encrypted private soul using archived keys/private.v1.pem!
            rc, _, err = run_cli(["--json", "key", "rotate"], agent_home=ah_owned, api_url=api_url)
            assert_eq(rc, 0, f"key rotate failed: {err}")
            rc, ap_rot, err = run_cli(["--json", "soul", "pull"], agent_home=ah_owned, api_url=api_url)
            assert_eq(rc, 0, f"decrypt v1 private soul after rotate failed: {err}")
            assert_eq(json.loads(ap_rot)["content"], priv_soul_secret, "archived key decrypted v1 soul after rotation")

            print("[4/5] Controller lock governance, SSE doc_update notification & unlock/rm lifecycle...")
            ctl_locked_rules = "STRICT_CTL_LOCKED_RULES_ALPHA_001"
            sse = subprocess.Popen(
                [str(CLI_BIN), "--api", api_url, "--json", "listen", "--max-events", "1"],
                env={**os.environ, "FATEXT_HOME": ah_owned},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            time.sleep(0.5)

            rc, out, err = run_cli(
                ["--json", "ctl", "rules", "set", aid_owned, "--text", ctl_locked_rules, "--private", "--lock"],
                agent_home=ch_1,
                api_url=api_url,
            )
            assert_eq(rc, 0, f"ctl rules set --private --lock failed: {err}")
            hr_doc = json.loads(out)
            assert_eq(hr_doc["locked"], True, "ctl rules locked=True")
            assert_eq(hr_doc["signed_by"], "controller", "signed_by=controller")

            sse_out, _ = sse.communicate(timeout=10.0)
            ev = json.loads(sse_out.strip().splitlines()[0])
            assert_eq(ev["type"], "doc_update", f"expected doc_update SSE event, got {ev}")
            assert_eq(ev["data"]["kind"], "rules", "SSE doc_update kind=rules")
            assert_true(ctl_locked_rules not in sse_out, "SSE notification must be metadata-only")

            # Agent pulls & verifies controller-signed encrypted rules
            rc, out, err = run_cli(["--json", "rules", "pull"], agent_home=ah_owned, api_url=api_url)
            assert_eq(rc, 0, f"agent pull ctl rules failed: {err}")
            pr_j = json.loads(out)
            assert_true(pr_j["verified"] is True and pr_j["locked"] is True and pr_j["signed_by"] == "controller", "agent verified controller-locked rules")
            assert_eq(pr_j["content"], ctl_locked_rules, "agent decrypted controller-locked rules")

            # Agent overwrite or delete on locked rules must fail 403 ERR_DOC_LOCKED (exit 5)
            rc, _, err = run_cli(["--json", "rules", "set", "--text", "hack", "--public"], agent_home=ah_owned, api_url=api_url)
            assert_eq(rc, 5, f"locked overwrite expected exit 5, got {rc}: {err}")
            assert_true("ERR_DOC_LOCKED" in err, f"expected ERR_DOC_LOCKED: {err}")

            rc, _, err = run_cli(["--json", "rules", "rm"], agent_home=ah_owned, api_url=api_url)
            assert_eq(rc, 5, f"locked delete expected exit 5, got {rc}: {err}")
            assert_true("ERR_DOC_LOCKED" in err, f"expected ERR_DOC_LOCKED: {err}")

            # Agent self-lock must be rejected 403 ERR_FORBIDDEN
            lck_sha = hashlib.sha256(priv_soul_v2.encode("utf-8")).hexdigest()
            lck_uat = int(time.time())
            lck_canon = canonical_doc_payload(aid_owned, lck_sha, "soul", True, aid_owned, 2, lck_uat, 2, "public")
            lck_sig = openssl_sign_pss(Path(ah_owned) / "private.pem", lck_canon)
            st_lck, _ = signed_agent_put(
                api_url, aid_owned, Path(ah_owned) / "private.pem", "/v1/agents/docs/soul",
                {
                    "version": 2,
                    "visibility": "public",
                    "locked": True,
                    "format": "markdown",
                    "content_sha256": lck_sha,
                    "content": priv_soul_v2,
                    "updated_at": lck_uat,
                    "signature": lck_sig,
                },
            )
            assert_eq(st_lck, 403, f"agent self-lock must return 403, got {st_lck}")

            # Controller unlocks rules -> agent can update -> controller locks -> controller deletes
            rc, out, err = run_cli(["--json", "ctl", "rules", "unlock", aid_owned], agent_home=ch_1, api_url=api_url)
            assert_eq(rc, 0, f"ctl rules unlock failed: {err}")
            assert_eq(json.loads(out)["locked"], False, "rules unlocked")

            rc, out, err = run_cli(["--json", "rules", "set", "--text", "AGENT_UPDATED_AFTER_UNLOCK", "--public"], agent_home=ah_owned, api_url=api_url)
            assert_eq(rc, 0, f"agent rules update after unlock failed: {err}")
            assert_eq(json.loads(out)["version"], 3, "rules version=3")

            rc, out, err = run_cli(["--json", "ctl", "rules", "lock", aid_owned], agent_home=ch_1, api_url=api_url)
            assert_eq(rc, 0, f"ctl rules lock failed: {err}")
            assert_eq(json.loads(out)["locked"], True, "rules re-locked")

            rc, _, err = run_cli(["--json", "ctl", "rules", "rm", aid_owned], agent_home=ch_1, api_url=api_url)
            assert_eq(rc, 0, f"ctl rules rm failed: {err}")

            print("[5/6] Controller-locked E2EE human email config & mail pull matching...")
            ah_mail = str(td_p / "agent_mail")
            ah_mail2 = str(td_p / "agent_mail2")
            v_mail = td_p / "v_mail.json"
            rc, _, err = run_cli(
                ["--json", "ctl", "cred", "issue", "--scopes", "all", "--out", str(v_mail)],
                agent_home=ch_2,
                api_url=api_url,
            )
            assert_eq(rc, 0, f"cred issue for mail agent failed: {err}")
            rc, out, err = run_cli(
                ["--json", "init", "--name", "MailBot", "--credential", str(v_mail)],
                agent_home=ah_mail,
                api_url=api_url,
            )
            assert_eq(rc, 0, f"mail agent init failed: {err}")
            aid_mail = json.loads(out.strip())["agent_id"]

            v_mail2 = td_p / "v_mail2.json"
            rc, _, err = run_cli(
                ["--json", "ctl", "cred", "issue", "--scopes", "all", "--out", str(v_mail2)],
                agent_home=ch_2,
                api_url=api_url,
            )
            assert_eq(rc, 0, f"cred issue for mail agent 2 failed: {err}")
            rc, out, err = run_cli(
                ["--json", "init", "--name", "MailBot2", "--credential", str(v_mail2)],
                agent_home=ah_mail2,
                api_url=api_url,
            )
            assert_eq(rc, 0, f"mail agent 2 init failed: {err}")
            aid_mail2 = json.loads(out.strip())["agent_id"]

            # Controller sets encrypted locked human allowlist
            rc, out, err = run_cli(
                ["--json", "ctl", "human", "set", aid_mail, "Alice@Example.com,bob@example.com"],
                agent_home=ch_2,
                api_url=api_url,
            )
            assert_eq(rc, 0, f"ctl human set failed: {err}")
            h_put_j = json.loads(out)
            assert_eq(h_put_j["kind"], "human", "human doc kind")
            assert_eq(h_put_j["visibility"], "private", "human doc private")
            assert_eq(h_put_j["locked"], True, "human doc locked")

            # Foreign controller cannot access aid_mail's human config (403)
            rc, _, err = run_cli(["--json", "ctl", "human", "get", aid_mail], agent_home=ch_1, api_url=api_url)
            assert_eq(rc, 5, f"foreign controller ctl human get expected exit 5, got {rc}: {err}")

            # Public endpoints must never expose human config
            st_dj2, _, dj2_txt = http_get(f"{api_url}/k/{aid_mail}/docs.json")
            assert_eq(st_dj2, 200, "public docs.json 200")
            assert_true("human" not in json.loads(dj2_txt), f"public docs.json must omit human: {dj2_txt}")
            st_pub_h, _, _ = http_get(f"{api_url}/k/{aid_mail}/human.json")
            assert_eq(st_pub_h, 404, f"public /k/{{id}}/human.json must return 404, got {st_pub_h}")

            # Agent cannot overwrite or delete human config
            bad_h_sha = hashlib.sha256(b'{"v":1,"emails":["evil@attacker.test"],"command_enabled":true}').hexdigest()
            bad_h_uat = int(time.time())
            bad_h_canon = canonical_doc_payload(aid_mail, bad_h_sha, "human", True, aid_mail, 1, bad_h_uat, 2, "private")
            bad_h_sig = openssl_sign_pss(Path(ah_mail) / "private.pem", bad_h_canon)
            st_ag_put, _ = signed_agent_put(
                api_url, aid_mail, Path(ah_mail) / "private.pem", "/v1/agents/docs/human",
                {
                    "version": 2,
                    "visibility": "private",
                    "locked": True,
                    "format": "json",
                    "content_sha256": bad_h_sha,
                    "content_bytes": 62,
                    "envelope": {"v": 1, "alg": "RSA-OAEP-256+A256GCM", "iv": "AA==", "ct": "AA==", "recipients": [{"role": "agent", "id": aid_mail, "key_version": 1, "ek": "AA=="}, {"role": "controller", "id": cid2, "key_version": 1, "ek": "AA=="}]},
                    "updated_at": bad_h_uat,
                    "signature": bad_h_sig,
                },
            )
            assert_eq(st_ag_put, 403, f"agent PUT human must return 403, got {st_ag_put}")

            # Controller cannot store public or unlocked human config
            pub_h_plain = '{"v":1,"emails":["alice@example.com"],"command_enabled":true}'
            pub_h_sha = hashlib.sha256(pub_h_plain.encode("utf-8")).hexdigest()
            pub_h_uat = int(time.time())
            pub_h_canon = canonical_doc_payload(aid_mail, pub_h_sha, "human", True, cid2, 1, pub_h_uat, 2, "public")
            pub_h_sig = openssl_sign_pss(Path(ch_2) / "private.pem", pub_h_canon)
            st_pub_put, _ = signed_agent_put(
                api_url, cid2, Path(ch_2) / "private.pem", f"/v1/ctl/agents/{aid_mail}/docs/human",
                {
                    "version": 2,
                    "visibility": "public",
                    "locked": True,
                    "format": "json",
                    "content_sha256": pub_h_sha,
                    "content": pub_h_plain,
                    "updated_at": pub_h_uat,
                    "signature": pub_h_sig,
                },
            )
            assert_eq(st_pub_put, 400, f"public human config must return 400, got {st_pub_put}")

            unl_h_canon = canonical_doc_payload(aid_mail, pub_h_sha, "human", False, cid2, 1, pub_h_uat, 2, "private")
            unl_h_sig = openssl_sign_pss(Path(ch_2) / "private.pem", unl_h_canon)
            st_unl_put, _ = signed_agent_put(
                api_url, cid2, Path(ch_2) / "private.pem", f"/v1/ctl/agents/{aid_mail}/docs/human",
                {
                    "version": 2,
                    "visibility": "private",
                    "locked": False,
                    "format": "json",
                    "content_sha256": pub_h_sha,
                    "content_bytes": len(pub_h_plain),
                    "envelope": {"v": 1, "alg": "RSA-OAEP-256+A256GCM", "iv": "AA==", "ct": "AA==", "recipients": [{"role": "agent", "id": aid_mail, "key_version": 1, "ek": "AA=="}, {"role": "controller", "id": cid2, "key_version": 1, "ek": "AA=="}]},
                    "updated_at": pub_h_uat,
                    "signature": unl_h_sig,
                },
            )
            assert_eq(st_unl_put, 400, f"unlocked human config must return 400, got {st_unl_put}")

            # Both controller and managed agent verify & decrypt human config
            rc, out, err = run_cli(["--json", "ctl", "human", "get", aid_mail], agent_home=ch_2, api_url=api_url)
            assert_eq(rc, 0, f"ctl human get failed: {err}")
            hj_ctl = json.loads(out)
            assert_eq(hj_ctl["emails"], ["alice@example.com", "bob@example.com"], "ctl human emails")
            assert_eq(hj_ctl["command_enabled"], True, "ctl human command_enabled")

            rc, out, err = run_cli(["--json", "human", "get"], agent_home=ah_mail, api_url=api_url)
            assert_eq(rc, 0, f"agent human get failed: {err}")
            hj_ag = json.loads(out)
            assert_eq(hj_ag["emails"], ["alice@example.com", "bob@example.com"], "agent human emails")
            assert_eq(hj_ag["controller_id"], cid2, "agent human controller_id")

            # Enable email on aid_mail and ingest 4 test messages
            rc, _, err = run_cli(["ctl", "policy", aid_mail, "--accept-email", "true"], agent_home=ch_2, api_url=api_url)
            assert_eq(rc, 0, f"ctl policy accept-email failed: {err}")

            def ingest_mail(subj: str, mfrom: str, header_from: str, spf: bool, dkim: bool, dmarc: bool) -> None:
                payload = json.dumps({
                    "to_agent_id": aid_mail,
                    "from": mfrom,
                    "header_from": header_from,
                    "subject": subj,
                    "raw_snippet": f"COMMAND_SECRET_CMD:{subj}",
                    "spf_pass": spf,
                    "dkim_pass": dkim,
                    "dmarc_pass": dmarc,
                    "received_at": int(time.time()),
                }).encode("utf-8")
                mreq = urllib.request.Request(
                    f"{api_url}/internal/mail/ingest",
                    data=payload,
                    method="POST",
                    headers={"Content-Type": "application/json", "X-Internal-Secret": mail_sec},
                )
                with urllib.request.urlopen(mreq, timeout=5.0) as mr:
                    assert_eq(mr.status, 201, f"mail ingest {subj} 201")

            ingest_mail("m1-ok", "bounce@example.com", "Alice <Alice@Example.com>", True, True, True)
            ingest_mail("m2-nodkim", "bob@example.com", "bob@example.com", True, False, False)
            ingest_mail("m3-stranger", "stranger@example.com", "stranger@example.com", True, True, True)
            ingest_mail("m4-multi", "alice@example.com", "alice@example.com, evil@example.com", True, True, True)

            rc, mp_out, err = run_cli(["--json", "mail", "pull"], agent_home=ah_mail, api_url=api_url)
            assert_eq(rc, 0, f"mail pull failed: {err}")
            by_subj = {json.loads(ln)["subject"]: json.loads(ln) for ln in mp_out.strip().splitlines() if ln.strip()}
            assert_true(by_subj["m1-ok"]["verified"] is True and by_subj["m1-ok"]["from_human"] is True and by_subj["m1-ok"]["command_eligible"] is True, f"m1-ok mismatch: {by_subj['m1-ok']}")
            assert_eq(by_subj["m1-ok"]["header_from"], "Alice <Alice@Example.com>", "m1 header_from")
            assert_true(by_subj["m2-nodkim"]["from_human"] is True and by_subj["m2-nodkim"]["command_eligible"] is False, f"m2-nodkim mismatch: {by_subj['m2-nodkim']}")
            assert_true(by_subj["m3-stranger"]["from_human"] is False and by_subj["m3-stranger"]["command_eligible"] is False, f"m3-stranger mismatch: {by_subj['m3-stranger']}")
            assert_true(by_subj["m4-multi"]["from_human"] is False and by_subj["m4-multi"]["command_eligible"] is False, f"m4-multi mismatch: {by_subj['m4-multi']}")

            # --disabled flips command_eligible to False while keeping from_human=True
            rc, _, err = run_cli(["--json", "ctl", "human", "set", aid_mail, "alice@example.com", "--disabled"], agent_home=ch_2, api_url=api_url)
            assert_eq(rc, 0, f"ctl human set --disabled failed: {err}")
            rc, mp_dis, err = run_cli(["--json", "mail", "pull"], agent_home=ah_mail, api_url=api_url)
            assert_eq(rc, 0, f"mail pull disabled failed: {err}")
            by_dis = {json.loads(ln)["subject"]: json.loads(ln) for ln in mp_dis.strip().splitlines() if ln.strip()}
            assert_true(by_dis["m1-ok"]["from_human"] is True and by_dis["m1-ok"]["command_eligible"] is False, f"disabled mismatch: {by_dis['m1-ok']}")

            # Remove human config -> fail closed
            rc, _, err = run_cli(["--json", "ctl", "human", "rm", aid_mail], agent_home=ch_2, api_url=api_url)
            assert_eq(rc, 0, f"ctl human rm failed: {err}")
            rc, mp_rm, err = run_cli(["--json", "mail", "pull"], agent_home=ah_mail, api_url=api_url)
            assert_eq(rc, 0, f"mail pull after rm failed: {err}")
            by_rm = {json.loads(ln)["subject"]: json.loads(ln) for ln in mp_rm.strip().splitlines() if ln.strip()}
            assert_true(by_rm["m1-ok"]["from_human"] is False and by_rm["m1-ok"]["command_eligible"] is False, f"after rm mismatch: {by_rm['m1-ok']}")

            # --all batch set & rm across both active managed agents under ch_2
            rc, out, err = run_cli(["--json", "ctl", "human", "set", "--all", "owner@example.com"], agent_home=ch_2, api_url=api_url)
            assert_eq(rc, 0, f"ctl human set --all failed: {err}")
            upd_ids = json.loads(out)["updated"]
            assert_true(aid_mail in upd_ids and aid_mail2 in upd_ids, f"--all updated mismatch: {upd_ids}")
            for ah_x in (ah_mail, ah_mail2):
                rc, hg_x, err = run_cli(["--json", "human", "get"], agent_home=ah_x, api_url=api_url)
                assert_eq(rc, 0, f"human get after --all failed: {err}")
                assert_eq(json.loads(hg_x)["emails"], ["owner@example.com"], "batch email match")
            rc, out, err = run_cli(["--json", "ctl", "human", "rm", "--all"], agent_home=ch_2, api_url=api_url)
            assert_eq(rc, 0, f"ctl human rm --all failed: {err}")

            # Wait briefly for async logger flush
            time.sleep(0.3)

            print("[6/6] Verifying doc_update audit logs & strict zero-leak privacy scan...")
            ev_files = list(log_dir.glob("events-*.jsonl"))
            assert_true(len(ev_files) >= 1, "events log created")
            ev_records = []
            for p in ev_files:
                for ln in p.read_text(encoding="utf-8").splitlines():
                    if ln.strip():
                        ev_records.append(json.loads(ln))
            kinds_seen = {e.get("kind") for e in ev_records}
            assert_true("doc_update" in kinds_seen, f"doc_update event logged (seen={kinds_seen})")

            for lf in log_dir.rglob("*.jsonl"):
                raw_log = lf.read_text(encoding="utf-8")
                for secret in (
                    priv_soul_secret, ctl_locked_rules, auto_priv_rules, public_soul, public_rules,
                    "alice@example.com", "bob@example.com", "owner@example.com", "COMMAND_SECRET_CMD",
                ):
                    assert_true(secret not in raw_log, f"PRIVACY LEAK in {lf.name}: found {secret!r}")

        finally:
            if srv.poll() is None:
                srv.terminate()
                srv.wait(timeout=5)

    print("ALL 6 AGENT NAME + SOUL/RULES/HUMAN E2EE & LOCK TESTS PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
