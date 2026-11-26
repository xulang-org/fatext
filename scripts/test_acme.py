#!/usr/bin/env python3
"""Hermetic End-to-End Test Suite for Built-in ACME v2 Auto-TLS (Scheme A).

Tests:
  1. Initial ACME v2 issuance against an in-process RFC 8555 Mock CA:
     - Directory discovery, HEAD /new-nonce, intentional badNonce 400 retry.
     - Cryptographic ES256 JWS signature & JWK/KID/URL/Content-Type checks via openssl.
     - Live HTTP-01 callback to FATEXT_HTTP_REDIRECT_ADDR (/.well-known/acme-challenge/<token>).
     - Cryptographic PKCS#10 DER CSR verification via `openssl req -inform DER -verify`.
     - Real X.509v3 leaf cert + Intermediate CA chain signed by ephemeral Root CA.
  2. Strict TLS 1.3 + SNI + CA chain + HSTS verification on HTTPS port.
  3. Port-80 HTTP-01 404/405 guards and multi-domain / anti-host-injection 301 redirect.
  4. Strict filesystem permissions (0700 acme_dir, 0600 account.key.pem & privkey.pem).
  5. Admin stats (`tls` section) and structured audit events (`acme_start`, `acme_cert_issued`),
     with strict zero-private-key leakage check.
  6. Zero-downtime background renewal (`FATEXT_ACME_CHECK_SEC=2`, Order #1 2d < renew_days=30 ->
     Order #2 90d) while an existing HTTPS SSE stream remains connected and continues receiving events.
  7. Restart with valid cached cert reuses disk cache (0 new CA orders, `acme_cert_loaded` event),
     and adding a new SAN domain triggers automatic re-issuance.
  8. Static TLS cert hot-reload via POST /internal/admin/reload (bad cert/key rejected atomically
     without disrupting active cert; valid new cert hot-swapped live).
  9. Required native TLS rejects missing config, wrong names and untrusted chains.
     The graceful-stop hook verifies the configured hostname before sending its secret.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

ROOT = Path(__file__).resolve().parent.parent
SERVER_BIN = Path(os.environ.get("FATEXT_SERVER_BIN", str(ROOT / "build" / "fatext-server")))
OPENSSL = shutil.which("openssl") or "/usr/bin/openssl"
WWW_DIR = ROOT / "www"
TPL_DIR = ROOT / "templates"
HOST = "127.0.0.1"
ADMIN_SECRET = "adm_acme_test_secret_9a8b7c6d"
POW_BITS = 6


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


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(s: str) -> bytes:
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode(s + pad)


def der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def der_int(raw: bytes) -> bytes:
    v = raw.lstrip(b"\x00") or b"\x00"
    if v[0] & 0x80:
        v = b"\x00" + v
    return b"\x02" + der_len(len(v)) + v


def raw_p256_sig_to_der(sig_raw: bytes) -> bytes:
    assert_eq(len(sig_raw), 64, "ES256 raw sig length")
    r_der = der_int(sig_raw[:32])
    s_der = der_int(sig_raw[32:])
    body = r_der + s_der
    return b"\x30" + der_len(len(body)) + body


def p256_jwk_to_pem(jwk: dict) -> str:
    assert_eq(jwk.get("kty"), "EC", "jwk kty")
    assert_eq(jwk.get("crv"), "P-256", "jwk crv")
    x = b64u_decode(jwk["x"])
    y = b64u_decode(jwk["y"])
    assert_eq(len(x), 32, "jwk x len")
    assert_eq(len(y), 32, "jwk y len")
    spki_prefix = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004")
    spki = spki_prefix + x + y
    b64 = base64.encodebytes(spki).decode("ascii")
    return f"-----BEGIN PUBLIC KEY-----\n{b64}-----END PUBLIC KEY-----\n"


def canonical_jwk_thumbprint(jwk: dict) -> str:
    canon = json.dumps({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]}, separators=(",", ":"), sort_keys=True)
    return b64u_encode(hashlib.sha256(canon.encode("utf-8")).digest())


def openssl_verify_es256(pub_pem: str, signing_input: bytes, raw_sig: bytes, work_dir: Path) -> None:
    sig_der = raw_p256_sig_to_der(raw_sig)
    with tempfile.NamedTemporaryFile("w", dir=work_dir, suffix=".pub", delete=False) as pf, \
         tempfile.NamedTemporaryFile("wb", dir=work_dir, suffix=".msg", delete=False) as mf, \
         tempfile.NamedTemporaryFile("wb", dir=work_dir, suffix=".sig", delete=False) as sf:
        pf.write(pub_pem)
        mf.write(signing_input)
        sf.write(sig_der)
        ppath, mpath, spath = Path(pf.name), Path(mf.name), Path(sf.name)
    try:
        res = subprocess.run(
            [OPENSSL, "dgst", "-sha256", "-verify", str(ppath), "-signature", str(spath), str(mpath)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert_eq(res.returncode, 0, f"ES256 JWS signature verify failed: {res.stderr}")
    finally:
        ppath.unlink(missing_ok=True)
        mpath.unlink(missing_ok=True)
        spath.unlink(missing_ok=True)


def run_openssl(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    res = subprocess.run(
        [OPENSSL] + args,
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if res.returncode != 0:
        raise RuntimeError(f"openssl {' '.join(args)} failed: {res.stderr}")
    return res


class TestCA:
    """Ephemeral Root CA + Intermediate CA for signing test certificates."""

    def __init__(self, base_dir: Path):
        self.dir = base_dir / "ca"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.root_key = self.dir / "root.key"
        self.root_crt = self.dir / "root.crt"
        self.int_key = self.dir / "int.key"
        self.int_csr = self.dir / "int.csr"
        self.int_crt = self.dir / "int.crt"
        self._serial_seq = 0x1000
        self._lock = threading.Lock()
        self._init_ca()

    def _init_ca(self) -> None:
        run_openssl(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(self.root_key)])
        root_ext = self.dir / "root_ext.cnf"
        root_ext.write_text(
            "[v3_ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n",
            encoding="utf-8",
        )
        run_openssl([
            "req", "-new", "-x509", "-days", "365", "-key", str(self.root_key),
            "-subj", "/CN=Fatext Test Root CA",
            "-extensions", "v3_ca", "-config", str(root_ext),
            "-out", str(self.root_crt),
        ] if False else [
            "req", "-new", "-key", str(self.root_key), "-subj", "/CN=Fatext Test Root CA",
            "-out", str(self.dir / "root.csr"),
        ])
        run_openssl([
            "x509", "-req", "-in", str(self.dir / "root.csr"),
            "-signkey", str(self.root_key), "-days", "365",
            "-set_serial", "0x01",
            "-extfile", str(root_ext), "-extensions", "v3_ca",
            "-out", str(self.root_crt),
        ])

        run_openssl(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(self.int_key)])
        run_openssl(["req", "-new", "-key", str(self.int_key), "-subj", "/CN=Fatext Test Intermediate CA", "-out", str(self.int_csr)])
        int_ext = self.dir / "int_ext.cnf"
        int_ext.write_text(
            "[v3_int]\nbasicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n",
            encoding="utf-8",
        )
        run_openssl([
            "x509", "-req", "-in", str(self.int_csr),
            "-CA", str(self.root_crt), "-CAkey", str(self.root_key),
            "-set_serial", "0x02", "-days", "365",
            "-extfile", str(int_ext), "-extensions", "v3_int",
            "-out", str(self.int_crt),
        ])

    def next_serial_hex(self) -> tuple[int, str]:
        with self._lock:
            self._serial_seq += 1
            return self._serial_seq, hex(self._serial_seq)

    def sign_csr_der(self, csr_der: bytes, expected_domains: list[str], days: int) -> tuple[int, str]:
        with tempfile.TemporaryDirectory(dir=self.dir) as td:
            tpath = Path(td)
            csr_file = tpath / "req.der"
            csr_pem_file = tpath / "req.pem"
            csr_file.write_bytes(csr_der)
            res = run_openssl(["req", "-inform", "DER", "-in", str(csr_file), "-verify", "-noout", "-text"])
            run_openssl(["req", "-inform", "DER", "-in", str(csr_file), "-outform", "PEM", "-out", str(csr_pem_file)])
            txt = res.stdout
            assert_true("sha256WithRSAEncryption" in txt, "CSR must be signed with sha256WithRSAEncryption")
            assert_true("2048 bit" in txt, "CSR public key must be 2048-bit RSA")
            for dom in expected_domains:
                assert_true(f"DNS:{dom}" in txt, f"CSR missing SAN DNS:{dom}")

            serial_int, serial_hex = self.next_serial_hex()
            ext_file = tpath / "leaf_ext.cnf"
            sans = ",".join(f"DNS:{d}" for d in expected_domains)
            ext_file.write_text(
                f"[v3_leaf]\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName={sans}\n",
                encoding="utf-8",
            )
            leaf_crt = tpath / "leaf.crt"
            run_openssl([
                "x509", "-req", "-in", str(csr_pem_file),
                "-CA", str(self.int_crt), "-CAkey", str(self.int_key),
                "-set_serial", serial_hex, "-days", str(days),
                "-extfile", str(ext_file), "-extensions", "v3_leaf",
                "-out", str(leaf_crt),
            ])
            fullchain = leaf_crt.read_text(encoding="utf-8") + "\n" + self.int_crt.read_text(encoding="utf-8")
            return serial_int, fullchain

    def issue_static_cert(self, domains: list[str], days: int = 90) -> tuple[int, str, str]:
        with tempfile.TemporaryDirectory(dir=self.dir) as td:
            tpath = Path(td)
            key_p = tpath / "srv.key"
            csr_der_p = tpath / "srv.der"
            run_openssl(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(key_p)])
            sans = ",".join(f"DNS:{d}" for d in domains)
            cnf = tpath / "csr.cnf"
            cnf.write_text(
                f"[req]\ndistinguished_name=dn\nreq_extensions=ext\nprompt=no\n[dn]\nCN={domains[0]}\n[ext]\nsubjectAltName={sans}\n",
                encoding="utf-8",
            )
            run_openssl(["req", "-new", "-key", str(key_p), "-config", str(cnf), "-outform", "DER", "-out", str(csr_der_p)])
            serial_int, fullchain = self.sign_csr_der(csr_der_p.read_bytes(), domains, days)
            return serial_int, fullchain, key_p.read_text(encoding="utf-8")


class MockACMEState:
    def __init__(self, base_url: str, http_challenge_port: int, ca: TestCA, work_dir: Path, days_sequence: list[int]):
        self.base_url = base_url
        self.http_challenge_port = http_challenge_port
        self.ca = ca
        self.work_dir = work_dir
        self.days_sequence = list(days_sequence)
        self.lock = threading.RLock()
        self.nonces: set[str] = set()
        self.accounts: dict[str, tuple[str, str]] = {}  # kid -> (pub_pem, thumbprint)
        self.orders: dict[str, dict] = {}
        self.authzs: dict[str, dict] = {}
        self.chals: dict[str, dict] = {}
        self.order_count = 0
        self.bad_nonce_injected = False
        self.http01_verified_tokens: list[str] = []

    def new_nonce(self) -> str:
        n = "nonce_" + secrets.token_urlsafe(12)
        with self.lock:
            self.nonces.add(n)
        return n

    def consume_nonce(self, n: str) -> bool:
        with self.lock:
            if n in self.nonces:
                self.nonces.remove(n)
                return True
            return False


def make_acme_handler(state: MockACMEState):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format, *args):
            return

        def _send(self, code: int, ctype: str, body: bytes, extra_headers: dict[str, str] | None = None, head_only: bool = False):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            if extra_headers:
                for k, v in extra_headers.items():
                    self.send_header(k, v)
            self.end_headers()
            if not head_only:
                self.wfile.write(body)

        def _send_json(self, code: int, obj: dict, extra_headers: dict[str, str] | None = None):
            raw = json.dumps(obj).encode("utf-8")
            hdrs = dict(extra_headers or {})
            if "Replay-Nonce" not in hdrs:
                hdrs["Replay-Nonce"] = state.new_nonce()
            self._send(code, "application/json", raw, hdrs)

        def _verify_jws(self, expect_new_account: bool = False):
            clen = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(clen) if clen > 0 else b""
            ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            assert_eq(ctype, "application/jose+json", "ACME POST Content-Type")
            doc = json.loads(raw.decode("utf-8"))
            prot_b64 = doc["protected"]
            pay_b64 = doc["payload"]
            sig_b64 = doc["signature"]
            prot = json.loads(b64u_decode(prot_b64).decode("utf-8"))
            assert_eq(prot.get("alg"), "ES256", "JWS alg")
            expected_url = f"{state.base_url}{self.path}"
            assert_eq(prot.get("url"), expected_url, "JWS url")

            nonce = prot.get("nonce", "")
            if not state.consume_nonce(nonce):
                self._send_json(400, {"type": "urn:ietf:params:acme:error:badNonce", "detail": "invalid or used nonce"})
                return None

            if expect_new_account:
                assert_true("jwk" in prot and "kid" not in prot, "newAccount must carry jwk")
                jwk = prot["jwk"]
                pub_pem = p256_jwk_to_pem(jwk)
                thumb = canonical_jwk_thumbprint(jwk)
            else:
                assert_true("kid" in prot and "jwk" not in prot, "non-newAccount must carry kid")
                kid = prot["kid"]
                assert_true(kid in state.accounts, f"unknown kid {kid}")
                pub_pem, thumb = state.accounts[kid]

            signing_input = f"{prot_b64}.{pay_b64}".encode("ascii")
            openssl_verify_es256(pub_pem, signing_input, b64u_decode(sig_b64), state.work_dir)
            payload_bytes = b64u_decode(pay_b64) if pay_b64 else b""
            payload_obj = json.loads(payload_bytes.decode("utf-8")) if payload_bytes else None
            return prot, payload_obj, pub_pem, thumb

        def do_HEAD(self):
            if self.path == "/new-nonce":
                hdrs = {"Replay-Nonce": state.new_nonce(), "Cache-Control": "no-store"}
                self._send(200, "text/plain", b"", hdrs, head_only=True)
                return
            self._send(404, "text/plain", b"", head_only=True)

        def do_GET(self):
            if self.path == "/directory":
                self._send_json(
                    200,
                    {
                        "newNonce": f"{state.base_url}/new-nonce",
                        "newAccount": f"{state.base_url}/new-account",
                        "newOrder": f"{state.base_url}/new-order",
                    },
                    extra_headers={},
                )
                return
            if self.path == "/new-nonce":
                hdrs = {"Replay-Nonce": state.new_nonce(), "Cache-Control": "no-store"}
                self._send(204, "text/plain", b"", hdrs, head_only=True)
                return
            self._send(404, "text/plain", b"not found")

        def do_POST(self):
            if self.path == "/new-account":
                res = self._verify_jws(expect_new_account=True)
                if res is None:
                    return
                prot, payload, pub_pem, thumb = res
                assert_true(payload is not None and payload.get("termsOfServiceAgreed") is True, "ToS must be agreed")
                kid = f"{state.base_url}/acct/{thumb[:12]}"
                with state.lock:
                    state.accounts[kid] = (pub_pem, thumb)
                self._send_json(201, {"status": "valid", "contact": payload.get("contact", [])}, {"Location": kid})
                return

            if self.path == "/new-order":
                res = self._verify_jws()
                if res is None:
                    return
                prot, payload, _, thumb = res
                inject_bad = False
                with state.lock:
                    if not state.bad_nonce_injected:
                        state.bad_nonce_injected = True
                        inject_bad = True
                    else:
                        state.order_count += 1
                        idx = state.order_count
                        days = state.days_sequence[idx - 1] if idx - 1 < len(state.days_sequence) else 90
                if inject_bad:
                    self._send_json(400, {"type": "urn:ietf:params:acme:error:badNonce", "detail": "synthetic badNonce"})
                    return
                domains = [it["value"] for it in payload["identifiers"]]
                oid = f"ord_{idx}"
                authz_urls = []
                for di, dom in enumerate(domains):
                    aid = f"authz_{idx}_{di}"
                    cid = f"chal_{idx}_{di}"
                    tok = secrets.token_urlsafe(24)
                    with state.lock:
                        state.chals[cid] = {
                            "type": "http-01",
                            "url": f"{state.base_url}/chal/{cid}",
                            "token": tok,
                            "status": "pending",
                            "authz_id": aid,
                            "thumb": thumb,
                        }
                        state.authzs[aid] = {
                            "status": "pending",
                            "identifier": {"type": "dns", "value": dom},
                            "challenges": [
                                {
                                    "type": "http-01",
                                    "url": f"{state.base_url}/chal/{cid}",
                                    "token": tok,
                                    "status": "pending",
                                }
                            ],
                        }
                    authz_urls.append(f"{state.base_url}/authz/{aid}")

                order_url = f"{state.base_url}/order/{oid}"
                finalize_url = f"{state.base_url}/finalize/{oid}"
                order_obj = {
                    "status": "pending",
                    "identifiers": payload["identifiers"],
                    "authorizations": authz_urls,
                    "finalize": finalize_url,
                }
                with state.lock:
                    state.orders[oid] = {
                        "obj": order_obj,
                        "domains": domains,
                        "days": days,
                        "cert_pem": "",
                        "serial": 0,
                        "thumb": thumb,
                    }
                self._send_json(201, order_obj, {"Location": order_url})
                return

            if self.path.startswith("/authz/"):
                res = self._verify_jws()
                if res is None:
                    return
                _, payload, _, _ = res
                assert_true(payload is None, "POST-as-GET authz payload must be empty")
                aid = self.path[len("/authz/"):]
                with state.lock:
                    az = state.authzs.get(aid)
                if not az:
                    self._send_json(404, {"type": "urn:ietf:params:acme:error:malformed", "detail": "unknown authz"})
                    return
                self._send_json(200, az)
                return

            if self.path.startswith("/chal/"):
                res = self._verify_jws()
                if res is None:
                    return
                _, payload, _, thumb = res
                assert_eq(payload, {}, "challenge response payload must be {}")
                cid = self.path[len("/chal/"):]
                with state.lock:
                    ch = state.chals.get(cid)
                assert_true(ch is not None, f"unknown challenge {cid}")
                tok = ch["token"]
                expected_key_auth = f"{tok}.{thumb}"

                # Wrong Host on active ACME token MUST be rejected (404)
                bad_conn = http.client.HTTPConnection(HOST, state.http_challenge_port, timeout=5.0)
                bad_conn.request("GET", f"/.well-known/acme-challenge/{tok}", headers={"Host": "evil.attacker.com"})
                bad_resp = bad_conn.getresponse()
                bad_resp.read()
                bad_conn.close()
                assert_eq(bad_resp.status, 404, f"HTTP-01 callback with mismatched Host must return 404 for {tok}")

                # Real HTTP-01 callback to fatext-server's port-80 listener!
                conn = http.client.HTTPConnection(HOST, state.http_challenge_port, timeout=5.0)
                conn.request("GET", f"/.well-known/acme-challenge/{tok}", headers={"Host": "app.fatext.test"})
                cresp = conn.getresponse()
                cbody = cresp.read().decode("utf-8")
                cct = cresp.getheader("Content-Type", "")
                conn.close()
                assert_eq(cresp.status, 200, f"HTTP-01 callback status for {tok}")
                assert_true("text/plain" in cct, f"HTTP-01 Content-Type must be text/plain, got {cct}")
                assert_eq(cbody, expected_key_auth, "HTTP-01 key authorization mismatch")

                with state.lock:
                    state.http01_verified_tokens.append(tok)
                    ch["status"] = "valid"
                    aid = ch["authz_id"]
                    state.authzs[aid]["status"] = "valid"
                    state.authzs[aid]["challenges"][0]["status"] = "valid"
                self._send_json(200, {k: ch[k] for k in ("type", "url", "token", "status")})
                return

            if self.path.startswith("/finalize/"):
                res = self._verify_jws()
                if res is None:
                    return
                _, payload, _, _ = res
                oid = self.path[len("/finalize/"):]
                with state.lock:
                    ord_rec = state.orders[oid]
                csr_der = b64u_decode(payload["csr"])
                serial_int, fullchain = state.ca.sign_csr_der(csr_der, ord_rec["domains"], ord_rec["days"])
                cert_url = f"{state.base_url}/cert/{oid}"
                with state.lock:
                    ord_rec["cert_pem"] = fullchain
                    ord_rec["serial"] = serial_int
                    ord_rec["obj"]["status"] = "valid"
                    ord_rec["obj"]["certificate"] = cert_url
                    resp_obj = dict(ord_rec["obj"])
                self._send_json(200, resp_obj, {"Location": f"{state.base_url}/order/{oid}"})
                return

            if self.path.startswith("/order/"):
                res = self._verify_jws()
                if res is None:
                    return
                _, payload, _, _ = res
                assert_true(payload is None, "POST-as-GET order payload must be empty")
                oid = self.path[len("/order/"):]
                with state.lock:
                    resp_obj = dict(state.orders[oid]["obj"])
                self._send_json(200, resp_obj)
                return

            if self.path.startswith("/cert/"):
                res = self._verify_jws()
                if res is None:
                    return
                _, payload, _, _ = res
                assert_true(payload is None, "POST-as-GET cert payload must be empty")
                oid = self.path[len("/cert/"):]
                with state.lock:
                    cert_pem = state.orders[oid]["cert_pem"]
                self._send(
                    200,
                    "application/pem-certificate-chain",
                    cert_pem.encode("utf-8"),
                    {"Replay-Nonce": state.new_nonce()},
                )
                return

            self._send_json(404, {"type": "urn:ietf:params:acme:error:malformed", "detail": "unknown path"})

    return Handler


def sni_https_request(tls_port: int, sni: str, ca_crt: Path, method: str, path: str, body: bytes | None = None, headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], bytes, dict]:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=str(ca_crt))
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    raw_sock = socket.create_connection((HOST, tls_port), timeout=10.0)
    tls_sock = ctx.wrap_socket(raw_sock, server_hostname=sni)
    try:
        if ssl.HAS_TLSv1_3:
            assert_eq(tls_sock.version(), "TLSv1.3", "server must negotiate TLSv1.3")
        else:
            assert_true(tls_sock.version() in ("TLSv1.2", "TLSv1.3"), f"unexpected TLS version: {tls_sock.version()}")
        peer_cert = tls_sock.getpeercert()
        peer_der = tls_sock.getpeercert(binary_form=True)
        # Extract serialNumber from peer_cert dict
        serial_hex = peer_cert.get("serialNumber", "")
        hdrs = dict(headers or {})
        hdrs.setdefault("Host", sni)
        hdrs.setdefault("Connection", "close")
        if body is not None:
            hdrs.setdefault("Content-Type", "application/json")
            hdrs["Content-Length"] = str(len(body))
        req_lines = [f"{method} {path} HTTP/1.1"] + [f"{k}: {v}" for k, v in hdrs.items()] + ["", ""]
        tls_sock.sendall("\r\n".join(req_lines).encode("utf-8") + (body or b""))

        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = tls_sock.recv(8192)
            if not chunk:
                break
            buf += chunk
        hend = buf.index(b"\r\n\r\n")
        head_s = buf[:hend].decode("utf-8")
        rest = buf[hend + 4:]
        lines = head_s.split("\r\n")
        status = int(lines[0].split(" ")[1])
        rhdrs: dict[str, str] = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                rhdrs[k.strip().lower()] = v.strip()
        if "content-length" in rhdrs:
            want = int(rhdrs["content-length"])
            while len(rest) < want:
                chunk = tls_sock.recv(8192)
                if not chunk:
                    break
                rest += chunk
            rest = rest[:want]
        else:
            while True:
                chunk = tls_sock.recv(8192)
                if not chunk:
                    break
                rest += chunk
        return status, rhdrs, rest, {"serial_hex": serial_hex, "peer_cert": peer_cert, "der_len": len(peer_der or b"")}
    finally:
        tls_sock.close()


def openssl_sign_pss(priv_pem: Path, msg: str) -> str:
    with tempfile.NamedTemporaryFile("wb", delete=False) as mf:
        mf.write(msg.encode("utf-8"))
        mpath = Path(mf.name)
    spath = Path(str(mpath) + ".sig")
    try:
        run_openssl([
            "dgst", "-sha256",
            "-sigopt", "rsa_padding_mode:pss",
            "-sigopt", "rsa_pss_saltlen:32",
            "-sigopt", "rsa_mgf1_md:sha256",
            "-sign", str(priv_pem),
            "-out", str(spath),
            str(mpath),
        ])
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


def solve_pow(seed_prefix: str, bits: int) -> str:
    nonce = 0
    while True:
        cand = str(nonce)
        if leading_zero_bits(hashlib.sha256((seed_prefix + cand).encode("utf-8")).digest()) >= bits:
            return cand
        nonce += 1


def register_agent_https(tls_port: int, sni: str, ca_crt: Path, tmp_dir: Path, name: str) -> tuple[str, Path]:
    priv = tmp_dir / f"{name}.priv.pem"
    pub = tmp_dir / f"{name}.pub.pem"
    run_openssl(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(priv)])
    run_openssl(["rsa", "-in", str(priv), "-pubout", "-out", str(pub)])
    pub_pem = pub.read_text(encoding="utf-8")
    ts = str(int(time.time()))
    body = json.dumps({"public_key_pem": pub_pem, "name": name, "bio": f"{name} bio"}).encode("utf-8")
    pub_sha = hashlib.sha256(pub_pem.encode("utf-8")).hexdigest()
    pow_nonce = solve_pow(f"{pub_sha}:{ts}:", POW_BITS)
    bhash = hashlib.sha256(body).hexdigest()
    sig = openssl_sign_pss(priv, f"POST\n/v1/agents/register\n{ts}\n{bhash}")
    st, _, resp_b, _ = sni_https_request(
        tls_port, sni, ca_crt, "POST", "/v1/agents/register", body,
        {"X-Timestamp": ts, "X-Signature": sig, "X-PoW-Nonce": pow_nonce},
    )
    assert_eq(st, 201, f"register agent failed: {resp_b}")
    return json.loads(resp_b.decode("utf-8"))["agent_id"], priv


def open_https_sse(tls_port: int, sni: str, ca_crt: Path, aid: str, priv: Path) -> ssl.SSLSocket:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=str(ca_crt))
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    raw = socket.create_connection((HOST, tls_port), timeout=15.0)
    tsock = ctx.wrap_socket(raw, server_hostname=sni)
    ts = str(int(time.time()))
    bhash = hashlib.sha256(b"").hexdigest()
    sig = openssl_sign_pss(priv, f"GET\n/v1/stream\n{ts}\n{bhash}")
    req = (
        f"GET /v1/stream HTTP/1.1\r\n"
        f"Host: {sni}\r\n"
        f"X-Agent-Id: {aid}\r\n"
        f"X-Timestamp: {ts}\r\n"
        f"X-Signature: {sig}\r\n\r\n"
    )
    tsock.sendall(req.encode("utf-8"))
    buf = b""
    while b": connected\n\n" not in buf:
        chunk = tsock.recv(4096)
        assert_true(len(chunk) > 0, f"SSE closed prematurely during handshake: {buf!r}")
        buf += chunk
    assert_true(b"HTTP/1.1 200 OK" in buf, f"SSE open did not return 200: {buf!r}")
    return tsock


def post_channel_https(tls_port: int, sni: str, ca_crt: Path, aid: str, priv: Path, text: str) -> None:
    ts = str(int(time.time()))
    body = json.dumps({"text": text}).encode("utf-8")
    pow_nonce = solve_pow(f"{aid}:{ts}:", POW_BITS)
    bhash = hashlib.sha256(body).hexdigest()
    path = "/v1/channels/general/posts"
    sig = openssl_sign_pss(priv, f"POST\n{path}\n{ts}\n{bhash}")
    st, _, resp_b, _ = sni_https_request(
        tls_port, sni, ca_crt, "POST", path, body,
        {"X-Agent-Id": aid, "X-Timestamp": ts, "X-Signature": sig, "X-PoW-Nonce": pow_nonce},
    )
    assert_eq(st, 201, f"channel post failed: {resp_b}")


def wait_https_ready(tls_port: int, sni: str, ca_crt: Path, proc: subprocess.Popen, timeout: float = 20.0) -> dict:
    deadline = time.time() + timeout
    last_err = None
    while time.time() < deadline:
        if proc.poll() is not None:
            out, err = proc.communicate()
            raise RuntimeError(f"fatext-server exited early ({proc.returncode}): stdout={out.decode()} stderr={err.decode()}")
        try:
            st, hdrs, body, tls_info = sni_https_request(tls_port, sni, ca_crt, "GET", "/health")
            if st == 200:
                assert_true("strict-transport-security" in hdrs, "HTTPS response missing HSTS header")
                return tls_info
        except Exception as e:
            last_err = e
            time.sleep(0.1)
    raise TimeoutError(f"HTTPS server never became ready: {last_err}")


def stop_proc(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def assert_startup_rejected(env: dict[str, str], expected: str) -> None:
    result = subprocess.run([str(SERVER_BIN)], env=env, capture_output=True, text=True, timeout=5.0)
    assert result.returncode != 0 and expected in result.stdout, (expected, result.stdout, result.stderr)


def http_port80_raw(port: int, method: str, path: str, host_hdr: str) -> tuple[int, dict[str, str], bytes]:
    conn = http.client.HTTPConnection(HOST, port, timeout=5.0)
    conn.request(method, path, headers={"Host": host_hdr})
    resp = conn.getresponse()
    body = resp.read()
    hdrs = {k.lower(): v for k, v in resp.getheaders()}
    st = resp.status
    conn.close()
    return st, hdrs, body


def main() -> int:
    assert_true(SERVER_BIN.exists(), f"missing binary {SERVER_BIN}")
    with tempfile.TemporaryDirectory(prefix="fatext_acme_test_") as td:
        work = Path(td)
        ca = TestCA(work)

        acme_port = free_tcp_port()
        http_port = free_tcp_port()
        https_port = free_tcp_port()
        acme_base = f"http://127.0.0.1:{acme_port}"

        # Order #1 = 2 days (< renew_days=30), Order #2 = 90 days, Order #3 = 90 days
        acme_state = MockACMEState(acme_base, http_port, ca, work, days_sequence=[2, 90, 90])
        acme_srv = ThreadingHTTPServer((HOST, acme_port), make_acme_handler(acme_state))
        acme_thr = threading.Thread(target=acme_srv.serve_forever, daemon=True)
        acme_thr.start()

        data_dir = work / "data"
        acme_dir = data_dir / "acme"
        log_dir = data_dir / "logs"

        try:
            # --- Phase 9 pre-check: Mutual exclusion fails closed ---
            print("[1/8] Checking ACME + static TLS mutual-exclusion guard...")
            dummy_s, dummy_crt, dummy_key = ca.issue_static_cert(["app.fatext.test"])
            _ = dummy_s
            dc_p = work / "dummy.crt"
            dk_p = work / "dummy.key"
            dc_p.write_text(dummy_crt, encoding="utf-8")
            dk_p.write_text(dummy_key, encoding="utf-8")
            bad_env = os.environ.copy()
            bad_env.update({
                "FATEXT_ADDR": f"{HOST}:{https_port}",
                "FATEXT_HTTP_REDIRECT_ADDR": f"{HOST}:{http_port}",
                "FATEXT_DATA_DIR": str(data_dir),
                "FATEXT_WWW_DIR": str(WWW_DIR),
                "FATEXT_TEMPLATES_DIR": str(TPL_DIR),
                "FATEXT_ACME_DOMAINS": "app.fatext.test",
                "FATEXT_TLS_CERT": str(dc_p),
                "FATEXT_TLS_KEY": str(dk_p),
            })
            bad_res = subprocess.run([str(SERVER_BIN)], env=bad_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5.0)
            assert_true(bad_res.returncode != 0, "combining FATEXT_ACME_DOMAINS and FATEXT_TLS_CERT must fail")

            # --- Phase 1-5: Initial ACME Issuance, TLS 1.3, Port-80, Perms, Admin Stats ---
            print("[2/8] Starting fatext-server in ACME Auto-TLS mode (Order #1 = 2d validity)...")
            srv_env = os.environ.copy()
            srv_env.update({
                "FATEXT_ADDR": f"{HOST}:{https_port}",
                "FATEXT_HTTP_REDIRECT_ADDR": f"{HOST}:{http_port}",
                "FATEXT_ACME_DOMAINS": "app.fatext.test,www.fatext.test",
                "FATEXT_ACME_EMAIL": "ops@fatext.test",
                "FATEXT_ACME_DIR": str(acme_dir),
                "FATEXT_ACME_DIRECTORY_URL": f"{acme_base}/directory",
                "FATEXT_ACME_RENEW_DAYS": "30",
                "FATEXT_ACME_CHECK_SEC": "2",
                "FATEXT_DATA_DIR": str(data_dir),
                "FATEXT_WWW_DIR": str(WWW_DIR),
                "FATEXT_TEMPLATES_DIR": str(TPL_DIR),
                "FATEXT_POW_BITS": str(POW_BITS),
                "FATEXT_IP_RPM": "5000",
                "FATEXT_ADMIN_SECRET": ADMIN_SECRET,
                "FATEXT_METRICS_INTERVAL_SEC": "1",
            })
            proc = subprocess.Popen([str(SERVER_BIN)], env=srv_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                t1 = wait_https_ready(https_port, "app.fatext.test", ca.root_crt, proc, timeout=20.0)
            except Exception as exc:
                stop_proc(proc)
                out, err = proc.communicate()
                print("SERVER STDOUT:", out.decode(errors="replace"))
                print("SERVER STDERR:", err.decode(errors="replace"))
                for ef in sorted(log_dir.glob("*.jsonl")):
                    print("LOG", ef.name, ef.read_text(encoding="utf-8", errors="replace"))
                raise exc
            try:
                serial1 = int(t1["serial_hex"], 16)
                assert_eq(serial1, acme_state.orders["ord_1"]["serial"], "TLS peer serial must match Order #1")
                assert_true(acme_state.bad_nonce_injected, "badNonce retry must have been exercised")
                assert_eq(len(acme_state.http01_verified_tokens), 2, "must verify HTTP-01 for both SAN domains")

                # Verify alternate SAN works
                st_www, _, _, _ = sni_https_request(https_port, "www.fatext.test", ca.root_crt, "GET", "/health")
                assert_eq(st_www, 200, "second SAN www.fatext.test HTTPS health failed")

                # Verify real TLS 1.3 + SNI + CA verification when OpenSSL 3 is available
                tls13_ossl = None
                if Path("/opt/homebrew/bin/openssl").is_file():
                    tls13_ossl = "/opt/homebrew/bin/openssl"
                else:
                    ver_out = run_openssl(["version"]).stdout
                    if ver_out.startswith("OpenSSL 3") or ver_out.startswith("OpenSSL 1.1.1"):
                        tls13_ossl = OPENSSL
                if tls13_ossl:
                    sc = subprocess.run(
                        [
                            tls13_ossl,
                            "s_client",
                            "-connect",
                            f"{HOST}:{https_port}",
                            "-servername",
                            "app.fatext.test",
                            "-CAfile",
                            str(ca.root_crt),
                            "-verify_return_error",
                            "-tls1_3",
                        ],
                        input="GET /health HTTP/1.1\r\nHost: app.fatext.test\r\nConnection: close\r\n\r\n",
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=10.0,
                    )
                    assert_eq(sc.returncode, 0, f"openssl s_client -tls1_3 failed: {sc.stderr}")
                    assert_true("TLSv1.3" in sc.stdout, "openssl s_client did not negotiate TLSv1.3")
                    assert_true("Verify return code: 0 (ok)" in sc.stdout, "openssl s_client CA verify failed")

                print("[3/8] Verifying port-80 challenge isolation, redirect whitelist, & disk perms...")
                c404_1, _, _ = http_port80_raw(http_port, "GET", "/.well-known/acme-challenge/nonexistent_tok", "app.fatext.test")
                assert_eq(c404_1, 404, "unknown ACME token must return 404, not 301")
                c404_2, _, _ = http_port80_raw(http_port, "GET", "/.well-known/acme-challenge/bad..tok", "app.fatext.test")
                assert_eq(c404_2, 404, "invalid ACME token syntax must return 404")
                c301, c301_h, _ = http_port80_raw(http_port, "GET", "/c/general", "www.fatext.test")
                assert_eq(c301, 301, "normal path on allowed SAN host should 301")
                assert_eq(c301_h.get("location"), "https://www.fatext.test/c/general", "allowed SAN redirect location mismatch")
                c301_evil, c301_eh, _ = http_port80_raw(http_port, "GET", "/c/general", "evil.attacker.com")
                assert_eq(c301_evil, 301, "evil host redirect status")
                assert_eq(c301_eh.get("location"), "https://app.fatext.test/c/general", "evil Host header leaked into redirect")

                # Check permissions (0700 dir, 0600 private keys)
                assert_eq(acme_dir.stat().st_mode & 0o777, 0o700, "acme_dir must be 0700")
                assert_eq((acme_dir / "account.key.pem").stat().st_mode & 0o777, 0o600, "account.key.pem must be 0600")
                assert_eq((acme_dir / "privkey.pem").stat().st_mode & 0o777, 0o600, "privkey.pem must be 0600")
                fullchain_txt = (acme_dir / "fullchain.pem").read_text(encoding="utf-8")
                assert_eq(fullchain_txt.count("BEGIN CERTIFICATE"), 2, "fullchain.pem must contain leaf + intermediate")

                print("[4/8] Checking /internal/admin/stats TLS status...")
                st_adm, _, adm_b, _ = sni_https_request(
                    https_port, "app.fatext.test", ca.root_crt, "GET", "/internal/admin/stats",
                    headers={"X-Fatext-Admin-Secret": ADMIN_SECRET},
                )
                assert_eq(st_adm, 200, "admin stats over HTTPS failed")
                adm_j = json.loads(adm_b.decode("utf-8"))
                tls_j = adm_j["tls"]
                assert_eq(tls_j["enabled"], True, "tls.enabled")
                assert_eq(tls_j["mode"], "acme", "tls.mode")
                assert_true("app.fatext.test" in tls_j["domains"] and "www.fatext.test" in tls_j["domains"], f"tls.domains: {tls_j}")
                assert_true(tls_j["days_remaining"] <= 2, f"expected <=2 days remaining for Order #1, got {tls_j}")

                # --- Phase 6: Zero-downtime renewal while SSE stays open ---
                print("[5/8] Opening HTTPS SSE stream and waiting for zero-downtime background renewal...")
                aid, apriv = register_agent_https(https_port, "app.fatext.test", ca.root_crt, work, "acme_sse_agent")
                sse_sock = open_https_sse(https_port, "app.fatext.test", ca.root_crt, aid, apriv)
                try:
                    renew_deadline = time.time() + 12.0
                    serial2 = 0
                    while time.time() < renew_deadline:
                        if "ord_2" in acme_state.orders and acme_state.orders["ord_2"]["serial"] != 0:
                            _, _, _, ti = sni_https_request(https_port, "app.fatext.test", ca.root_crt, "GET", "/health")
                            cur_s = int(ti["serial_hex"], 16)
                            if cur_s == acme_state.orders["ord_2"]["serial"]:
                                serial2 = cur_s
                                break
                        time.sleep(0.25)
                    assert_true(serial2 != 0 and serial2 != serial1, "background renewal did not hot-swap to Order #2 cert")

                    # Confirm admin stats reflects renewed 90-day cert
                    _, _, adm_b2, _ = sni_https_request(
                        https_port, "app.fatext.test", ca.root_crt, "GET", "/internal/admin/stats",
                        headers={"X-Fatext-Admin-Secret": ADMIN_SECRET},
                    )
                    tls_j2 = json.loads(adm_b2.decode("utf-8"))["tls"]
                    assert_true(tls_j2["days_remaining"] >= 80, f"renewed cert should have >=80 days remaining, got {tls_j2}")

                    # Now push a post and verify the PRE-RENEWAL SSE stream STILL receives it!
                    marker = f"post_after_hotswap_{secrets.token_hex(4)}"
                    post_channel_https(https_port, "app.fatext.test", ca.root_crt, aid, apriv, marker)
                    sse_sock.settimeout(5.0)
                    sse_buf = b""
                    while marker.encode("utf-8") not in sse_buf:
                        chunk = sse_sock.recv(4096)
                        assert_true(len(chunk) > 0, "pre-renewal SSE stream dropped after cert hot-swap!")
                        sse_buf += chunk
                finally:
                    sse_sock.close()
            finally:
                stop_proc(proc)

            # Check audit logs & ensure zero private key material leaked
            ev_files = list(log_dir.glob("events-*.jsonl"))
            assert_true(len(ev_files) >= 1, "events log missing")
            ev_text = "\n".join(f.read_text(encoding="utf-8") for f in ev_files)
            assert_true('"kind":"acme_start"' in ev_text, "missing acme_start event")
            assert_true('"kind":"acme_cert_issued"' in ev_text, "missing acme_cert_issued event")
            assert_true("PRIVATE KEY" not in ev_text, "private key material leaked into events log!")

            # --- Phase 7a: Restart reuses valid cached cert (0 new orders) ---
            print("[6/8] Testing restart with cached valid 90-day cert (0 new orders)...")
            orders_before_restart = acme_state.order_count
            proc2 = subprocess.Popen([str(SERVER_BIN)], env=srv_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                t_cached = wait_https_ready(https_port, "app.fatext.test", ca.root_crt, proc2)
                assert_eq(int(t_cached["serial_hex"], 16), serial2, "restart should reuse cached Order #2 cert")
                time.sleep(2.5)
                assert_eq(acme_state.order_count, orders_before_restart, "cached valid 90d cert must not trigger new CA order")
            finally:
                stop_proc(proc2)

            # Check acme_cert_loaded event
            ev_text2 = "\n".join(f.read_text(encoding="utf-8") for f in log_dir.glob("events-*.jsonl"))
            assert_true('"kind":"acme_cert_loaded"' in ev_text2, "missing acme_cert_loaded event")

            # --- Phase 7b: Domain expansion triggers new order ---
            print("[7/8] Testing domain expansion triggers automatic new ACME order...")
            srv_env_expand = dict(srv_env)
            srv_env_expand["FATEXT_ACME_DOMAINS"] = "app.fatext.test,www.fatext.test,api.fatext.test"
            proc3 = subprocess.Popen([str(SERVER_BIN)], env=srv_env_expand, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                t_exp = wait_https_ready(https_port, "api.fatext.test", ca.root_crt, proc3)
                assert_eq(acme_state.order_count, orders_before_restart + 1, "adding SAN domain must trigger new order")
                assert_eq(int(t_exp["serial_hex"], 16), acme_state.orders["ord_3"]["serial"], "expanded SAN must use Order #3 cert")
            finally:
                stop_proc(proc3)

            strict_acme_env = dict(srv_env_expand)
            strict_acme_env.update({
                "FATEXT_TLS_REQUIRED": "1",
                "FATEXT_PUBLIC_HOST": "app.fatext.test",
                "SSL_CERT_FILE": str(ca.root_crt),
            })
            assert_startup_rejected(strict_acme_env, "disallowed http URL")
            assert_startup_rejected({**strict_acme_env, "FATEXT_ACME_STAGING": "1"}, "disallows ACME staging")
            assert_startup_rejected({**strict_acme_env, "FATEXT_ACME_INSECURE_TLS": "1"}, "insecure ACME TLS")
            assert_startup_rejected({
                **strict_acme_env, "FATEXT_PUBLIC_HOST": "unknown.fatext.test",
            }, "FATEXT_ACME_DOMAINS must include FATEXT_PUBLIC_HOST")
            # Require a verified cache hit without contacting a real CA.
            strict_acme_env["FATEXT_ACME_DIRECTORY_URL"] = "https://acme.fatext.invalid/directory"
            strict_acme_env["FATEXT_ACME_CHECK_SEC"] = "21600"
            with subprocess.Popen([str(SERVER_BIN)], env=strict_acme_env, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE) as strict_acme_proc:
                try:
                    t_strict = wait_https_ready(https_port, "app.fatext.test", ca.root_crt, strict_acme_proc)
                    assert_eq(t_strict["serial_hex"], t_exp["serial_hex"], "strict ACME uses the trusted cache")
                finally:
                    stop_proc(strict_acme_proc)

            # --- Phase 8: Static TLS cert hot-reload via POST /internal/admin/reload ---
            print("[8/8] Testing static TLS cert hot-reload via POST /internal/admin/reload...")
            sa_serial, sa_crt, sa_key = ca.issue_static_cert(["static.fatext.test"], 30)
            sb_serial, sb_crt, sb_key = ca.issue_static_cert(["static.fatext.test"], 90)
            assert_true(sa_serial != sb_serial, "static test serials must differ")
            st_crt_p = work / "static.fullchain.pem"
            st_key_p = work / "static.privkey.pem"
            st_crt_p.write_text(sa_crt, encoding="utf-8")
            st_key_p.write_text(sa_key, encoding="utf-8")

            st_https_port = free_tcp_port()
            st_data_dir = work / "static_data"
            st_env = os.environ.copy()
            st_env.update({
                "FATEXT_ADDR": f"{HOST}:{st_https_port}",
                "FATEXT_TLS_REQUIRED": "1",
                "FATEXT_PUBLIC_HOST": "static.fatext.test",
                "SSL_CERT_FILE": str(ca.root_crt),
                "FATEXT_TLS_CERT": str(st_crt_p),
                "FATEXT_TLS_KEY": str(st_key_p),
                "FATEXT_DATA_DIR": str(st_data_dir),
                "FATEXT_WWW_DIR": str(WWW_DIR),
                "FATEXT_TEMPLATES_DIR": str(TPL_DIR),
                "FATEXT_POW_BITS": str(POW_BITS),
                "FATEXT_ADMIN_SECRET": ADMIN_SECRET,
                "FATEXT_SHUTDOWN_SECRET": "tls-verified-shutdown-fixture",
            })
            no_tls_env = dict(st_env)
            no_tls_env.pop("FATEXT_TLS_CERT")
            no_tls_env.pop("FATEXT_TLS_KEY")
            assert_startup_rejected(no_tls_env, "FATEXT_TLS_REQUIRED needs native TLS")
            assert_startup_rejected({**st_env, "FATEXT_PUBLIC_HOST": "unknown.fatext.test"}, "not valid for")
            st_crt_p.write_text(sa_crt.split("-----END CERTIFICATE-----", 1)[0] + "-----END CERTIFICATE-----\n",
                                encoding="utf-8")
            assert_startup_rejected(st_env, "unknown authority")
            st_crt_p.write_text(sa_crt, encoding="utf-8")
            proc4 = subprocess.Popen([str(SERVER_BIN)], env=st_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                ts_a = wait_https_ready(st_https_port, "static.fatext.test", ca.root_crt, proc4)
                assert_eq(int(ts_a["serial_hex"], 16), sa_serial, "initial static serial mismatch")

                # Write mismatched cert/key -> reload must fail with 400 and keep serving Cert A!
                st_key_p.write_text(sb_key, encoding="utf-8")
                rc_bad, _, _, _ = sni_https_request(
                    st_https_port, "static.fatext.test", ca.root_crt, "POST", "/internal/admin/reload", b"",
                    {"X-Fatext-Admin-Secret": ADMIN_SECRET},
                )
                assert_eq(rc_bad, 400, "mismatched cert/key reload must return 400")
                _, _, _, ts_still_a = sni_https_request(st_https_port, "static.fatext.test", ca.root_crt, "GET", "/health")
                assert_eq(int(ts_still_a["serial_hex"], 16), sa_serial, "failed reload must leave active Cert A untouched")

                # A trusted, matching key pair for another domain cannot replace the active cert.
                st_key_p.write_text(dummy_key, encoding="utf-8")
                st_crt_p.write_text(dummy_crt, encoding="utf-8")
                rc_name, _, body_name, _ = sni_https_request(
                    st_https_port, "static.fatext.test", ca.root_crt, "POST", "/internal/admin/reload", b"",
                    {"X-Fatext-Admin-Secret": ADMIN_SECRET},
                )
                assert rc_name == 400 and b"not valid for" in body_name, (rc_name, body_name)
                _, _, _, tls_after_name_error = sni_https_request(
                    st_https_port, "static.fatext.test", ca.root_crt, "GET", "/health",
                )
                assert_eq(int(tls_after_name_error["serial_hex"], 16), sa_serial, "wrong domain must leave Cert A active")

                # Now write matching Cert B + Key B -> reload must return 200 & swap immediately!
                st_crt_p.write_text(sb_crt, encoding="utf-8")
                st_key_p.write_text(sb_key, encoding="utf-8")
                rc_ok, _, rel_b, _ = sni_https_request(
                    st_https_port, "static.fatext.test", ca.root_crt, "POST", "/internal/admin/reload", b"",
                    {"X-Fatext-Admin-Secret": ADMIN_SECRET},
                )
                assert_eq(rc_ok, 200, f"valid TLS reload failed: {rel_b}")
                rel_j = json.loads(rel_b.decode("utf-8"))
                assert_eq(rel_j["tls_reloaded"], True, "tls_reloaded flag")

                _, _, _, ts_b = sni_https_request(st_https_port, "static.fatext.test", ca.root_crt, "GET", "/health")
                assert_eq(int(ts_b["serial_hex"], 16), sb_serial, "hot-reloaded static TLS must serve Cert B immediately")

                # Append a corrupted intermediate certificate block -> reload must fail with 400 and keep Cert B
                corrupt_chain = sb_crt + "\n-----BEGIN CERTIFICATE-----\naW52YWxpZC1jZXJ0\n-----END CERTIFICATE-----\n"
                st_crt_p.write_text(corrupt_chain, encoding="utf-8")
                rc_corrupt, _, _, _ = sni_https_request(
                    st_https_port, "static.fatext.test", ca.root_crt, "POST", "/internal/admin/reload", b"",
                    {"X-Fatext-Admin-Secret": ADMIN_SECRET},
                )
                assert_eq(rc_corrupt, 400, "corrupted intermediate certificate reload must return 400")
                _, _, _, ts_still_b = sni_https_request(st_https_port, "static.fatext.test", ca.root_crt, "GET", "/health")
                assert_eq(int(ts_still_b["serial_hex"], 16), sb_serial, "failed chain reload must leave active Cert B untouched")

                stop_hook = ["bash", str(ROOT / "deploy" / "graceful_stop.sh")]
                subprocess.run(stop_hook, env={**st_env, "FATEXT_PUBLIC_HOST": "wrong.fatext.test"},
                               check=True, timeout=8)
                assert proc4.poll() is None, "shutdown hook accepted a certificate for the wrong host"
                subprocess.run(stop_hook, env=st_env, check=True, timeout=8)
                assert_eq(proc4.wait(timeout=5), 0, "shutdown hook must use the validated TLS connection")
            finally:
                stop_proc(proc4)

            st_ev_text = "\n".join(f.read_text(encoding="utf-8") for f in (st_data_dir / "logs").glob("events-*.jsonl"))
            assert_true('"kind":"tls_cert_reloaded"' in st_ev_text, "missing tls_cert_reloaded event")

            # --- Phase 9: ACME SSRF/redirect guards & port-80/port-443 connection isolation ---
            print("[9/9] Testing ACME 302/cross-origin rejection & port-80/443 conn isolation...")

            class BadAcmeHandler(BaseHTTPRequestHandler):
                protocol_version = "HTTP/1.1"
                mode = "redirect"

                def log_message(self, format, *args):
                    return

                def do_GET(self):
                    if BadAcmeHandler.mode == "redirect":
                        self.send_response(302)
                        self.send_header("Location", f"{acme_base}/directory")
                        self.send_header("Content-Length", "0")
                        self.send_header("Connection", "close")
                        self.end_headers()
                    else:
                        payload = json.dumps({
                            "newNonce": f"{acme_base}/new-nonce",
                            "newAccount": f"{acme_base}/new-account",
                            "newOrder": f"{acme_base}/new-order",
                        }).encode("utf-8")
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(payload)))
                        self.send_header("Connection", "close")
                        self.end_headers()
                        self.wfile.write(payload)

            bad_acme_port = free_tcp_port()
            bad_acme_srv = ThreadingHTTPServer((HOST, bad_acme_port), BadAcmeHandler)
            bad_thr = threading.Thread(target=bad_acme_srv.serve_forever, daemon=True)
            bad_thr.start()
            try:
                for test_mode, expect_substr in [("redirect", "directory http 302"), ("cross_origin", "cross-origin")]:
                    BadAcmeHandler.mode = test_mode
                    bad_tdir = work / f"bad_acme_{test_mode}"
                    bad_https = free_tcp_port()
                    bad_http = free_tcp_port()
                    bad_aenv = os.environ.copy()
                    bad_aenv.update({
                        "FATEXT_ADDR": f"{HOST}:{bad_https}",
                        "FATEXT_HTTP_REDIRECT_ADDR": f"{HOST}:{bad_http}",
                        "FATEXT_ACME_DOMAINS": "app.fatext.test",
                        "FATEXT_ACME_DIR": str(bad_tdir / "acme"),
                        "FATEXT_ACME_DIRECTORY_URL": f"http://127.0.0.1:{bad_acme_port}/directory",
                        "FATEXT_DATA_DIR": str(bad_tdir),
                        "FATEXT_WWW_DIR": str(WWW_DIR),
                        "FATEXT_TEMPLATES_DIR": str(TPL_DIR),
                    })
                    r_bad = subprocess.run([str(SERVER_BIN)], env=bad_aenv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15.0)
                    assert_true(r_bad.returncode != 0, f"ACME mode={test_mode} must fail closed")
                    comb = (r_bad.stdout + r_bad.stderr).lower()
                    assert_true(expect_substr in comb, f"ACME mode={test_mode} expected {expect_substr!r} in output: {comb!r}")
            finally:
                bad_acme_srv.shutdown()

            # Port-80 connection limit must NOT starve HTTPS port-443
            iso_https = free_tcp_port()
            iso_http = free_tcp_port()
            iso_dir = work / "iso_data"
            st_crt_p.write_text(sa_crt, encoding="utf-8")
            st_key_p.write_text(sa_key, encoding="utf-8")
            iso_env = dict(st_env)
            iso_env.update({
                "FATEXT_ADDR": f"{HOST}:{iso_https}",
                "FATEXT_HTTP_REDIRECT_ADDR": f"{HOST}:{iso_http}",
                "FATEXT_DATA_DIR": str(iso_dir),
                "FATEXT_MAX_CONNS": "32",
                "FATEXT_MAX_CONNS_PER_IP": "32",
                "FATEXT_REDIRECT_MAX_CONNS": "2",
                "FATEXT_REDIRECT_MAX_CONNS_PER_IP": "2",
            })
            proc5 = subprocess.Popen([str(SERVER_BIN)], env=iso_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            held_socks = []
            try:
                wait_https_ready(iso_https, "static.fatext.test", ca.root_crt, proc5)
                redir_status, redir_headers, _ = http_port80_raw(
                    iso_http, "GET", "/health", "www.static.fatext.test",
                )
                assert_eq(redir_status, 301, "uncertified alias redirects to the configured public hostname")
                assert_eq(redir_headers.get("location"), "https://static.fatext.test/health", "redirect uses valid name")
                for _ in range(2):
                    held_socks.append(socket.create_connection((HOST, iso_http), timeout=5.0))
                time.sleep(0.1)
                with socket.create_connection((HOST, iso_http), timeout=2.0) as s3:
                    s3.sendall(b"GET /health HTTP/1.1\r\nHost: static.fatext.test\r\nConnection: close\r\n\r\n")
                    s3.settimeout(1.5)
                    extra_r = b""
                    try:
                        extra_r = s3.recv(1024)
                    except OSError:
                        pass
                    assert_eq(extra_r, b"", f"3rd port-80 socket should be rejected at FATEXT_REDIRECT_MAX_CONNS=2, got {extra_r!r}")
                st_iso, _, _, _ = sni_https_request(iso_https, "static.fatext.test", ca.root_crt, "GET", "/health")
                assert_eq(st_iso, 200, "HTTPS port-443 must remain healthy when port-80 slots are full")
            finally:
                for hs in held_socks:
                    try:
                        hs.close()
                    except OSError:
                        pass
                stop_proc(proc5)

            print("ALL ACME v2 & ZERO-DOWNTIME TLS TESTS PASSED!")
            return 0
        finally:
            acme_srv.shutdown()


if __name__ == "__main__":
    sys.exit(main())
