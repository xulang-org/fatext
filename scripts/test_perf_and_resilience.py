#!/usr/bin/env python3
"""Integration & resilience tests for P0/P1/P2 hardening:
  1. Zero-plaintext encrypted room key-box + `fatext room sync` + `listen` auto-sync
     across offline invite and offline kick/rekey, plus zero-key/zero-plaintext disk audit.
  2. `fatext listen` auto-reconnect across real `fatext-server` SIGTERM restart
     (`reconnected` system event + resumed DM delivery) + `server_stop` log flush on SIGTERM exit 0.
  3. Multi-chunk (>8 KB) P2P transfer (`--stdio` 16 KB & `--expose`/`--forward` 12 KB
     with byte-for-byte SHA-256 verification) + P2P 60s stale offer rejection.
  4. CLI 24h `nonce` replay cache (`nonces.jsonl` mode 0600 + `replay_nonce` rejection).
"""

from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import http.client
import http.server
import json
import os
import queue
import signal
import socket
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
CLI_BIN = Path(os.environ.get("FATEXT_CLI_BIN", str(ROOT.parent / "fatext-cli" / "build" / "fatext")))
HOST = "127.0.0.1"


def free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, 0))
        return int(s.getsockname()[1])


def wait_tcp_ready(host: str, port: int, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"{host}:{port} not ready within {timeout}s")


def assert_eq(a, b, msg: str = "") -> None:
    if a != b:
        raise AssertionError(f"{msg}: expected {b!r}, got {a!r}")


def assert_true(cond: bool, msg: str = "") -> None:
    if not cond:
        raise AssertionError(f"Assertion failed: {msg}")


def run_cli(
    args: list[str],
    *,
    home: Path,
    api_url: str,
    timeout: float = 40.0,
) -> tuple[int, str, str]:
    env = os.environ.copy()
    env["FATEXT_HOME"] = str(home)
    p = subprocess.run(
        [str(CLI_BIN), "--api", api_url] + args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        timeout=timeout,
    )
    return p.returncode, p.stdout, p.stderr


def cli_json(args: list[str], *, home: Path, api_url: str) -> dict:
    rc, out, err = run_cli(["--json"] + args, home=home, api_url=api_url)
    assert_eq(rc, 0, f"CLI {args} failed (rc={rc}): stdout={out!r} stderr={err!r}")
    return json.loads(out.strip().splitlines()[-1])


def scan_files_for_substrings(root: Path, needles: list[str]) -> list[str]:
    hits: list[str] = []
    if not root.exists():
        return hits
    for p in root.rglob("*"):
        if p.is_file():
            data = p.read_text(encoding="utf-8", errors="ignore")
            for n in needles:
                if n and n in data:
                    hits.append(f"{p.relative_to(root)}:{n}")
    return hits


class LineProc:
    def __init__(self, args: list[str], *, home: Path, api_url: str, binary: bool = False) -> None:
        env = os.environ.copy()
        env["FATEXT_HOME"] = str(home)
        self.proc = subprocess.Popen(
            [str(CLI_BIN), "--api", api_url] + args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=not binary,
            bufsize=1 if not binary else 0,
            env=env,
        )
        self.out_q: queue.Queue[dict] = queue.Queue()
        self.raw_out: list[str] = []
        self.raw_err: list[str] = []
        if not binary:
            threading.Thread(target=self._pump_txt, args=(self.proc.stdout, self.out_q, self.raw_out), daemon=True).start()
            threading.Thread(target=self._pump_txt, args=(self.proc.stderr, None, self.raw_err), daemon=True).start()
        else:
            threading.Thread(target=self._pump_bytes, args=(self.proc.stderr, self.raw_err), daemon=True).start()

    def _pump_txt(self, pipe, q: queue.Queue[dict] | None, raw_buf: list[str]) -> None:
        if pipe is None:
            return
        try:
            for line in iter(pipe.readline, ""):
                s = line.strip()
                if not s:
                    continue
                raw_buf.append(s)
                if q is not None:
                    try:
                        q.put(json.loads(s))
                    except Exception:
                        pass
        except Exception:
            pass

    def _pump_bytes(self, pipe, raw_buf: list[str]) -> None:
        if pipe is None:
            return
        try:
            for line in iter(pipe.readline, b""):
                s = line.decode("utf-8", errors="replace").strip()
                if s:
                    raw_buf.append(s)
        except Exception:
            pass

    def wait_event(self, pred, *, timeout: float = 12.0, label: str = "") -> dict:
        deadline = time.time() + timeout
        kept: list[dict] = []
        try:
            while time.time() < deadline:
                rem = max(0.05, deadline - time.time())
                try:
                    ev = self.out_q.get(timeout=min(0.3, rem))
                except queue.Empty:
                    continue
                if pred(ev):
                    return ev
                kept.append(ev)
        finally:
            for ev in kept:
                self.out_q.put(ev)
        raise AssertionError(f"Timeout waiting for {label}; out={self.raw_out}, err={self.raw_err}")

    def wait_stderr(self, substr: str, *, timeout: float = 12.0) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if any(substr in ln for ln in list(self.raw_err)):
                return
            time.sleep(0.05)
        raise AssertionError(f"Timeout waiting for stderr {substr!r}; err={self.raw_err}")

    def close(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=3)


def sign_pss_openssl(priv_pem_path: Path, msg: bytes) -> str:
    with tempfile.NamedTemporaryFile("wb", delete=False) as tf:
        tf.write(msg)
        msg_path = tf.name
    try:
        res = subprocess.run(
            [
                "openssl", "dgst", "-sha256",
                "-sigopt", "rsa_padding_mode:pss",
                "-sigopt", "rsa_pss_saltlen:32",
                "-sign", str(priv_pem_path),
                msg_path,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        return base64.b64encode(res.stdout).decode("ascii")
    finally:
        try:
            os.unlink(msg_path)
        except OSError:
            pass


def signed_headers(aid: str, priv_pem: Path, method: str, path_q: str, body: bytes = b"") -> dict[str, str]:
    ts = str(int(time.time()))
    bhash = hashlib.sha256(body).hexdigest()
    sts = f"{method}\n{path_q}\n{ts}\n{bhash}".encode("utf-8")
    sig = sign_pss_openssl(priv_pem, sts)
    return {
        "Content-Type": "application/json",
        "X-Agent-Id": aid,
        "X-Timestamp": ts,
        "X-Signature": sig,
    }


def signed_post(api_url: str, aid: str, priv_pem: Path, path_q: str, body: bytes) -> tuple[int, dict]:
    hdrs = signed_headers(aid, priv_pem, "POST", path_q, body)
    req = urllib.request.Request(api_url + path_q, data=body, method="POST", headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


def signed_http(host: str, port: int, method: str, path_q: str, aid: str | None = None, priv_pem: Path | None = None, body: bytes = b"") -> tuple[int, dict[str, str], bytes]:
    hdrs = signed_headers(aid, priv_pem, method, path_q, body) if (aid and priv_pem) else {}
    conn = http.client.HTTPConnection(host, port, timeout=10)
    try:
        conn.request(method, path_q, body=body if body else None, headers=hdrs)
        resp = conn.getresponse()
        r_hdrs = {k.lower(): v for k, v in resp.getheaders()}
        data = resp.read()
        return resp.status, r_hdrs, data
    finally:
        conn.close()


def open_signed_sse(host: str, port: int, aid: str, priv_pem: Path, path_q: str = "/v1/stream"):
    hdrs = signed_headers(aid, priv_pem, "GET", path_q, b"")
    hdrs["Accept"] = "text/event-stream"
    conn = http.client.HTTPConnection(host, port, timeout=10)
    conn.request("GET", path_q, headers=hdrs)
    resp = conn.getresponse()
    r_hdrs = {k.lower(): v for k, v in resp.getheaders()}
    return conn, resp.status, r_hdrs, resp


# Pure-Python AES-256-GCM + openssl RSA-OAEP for building stale p2p_offer frame
_SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]
_RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]


def _xtime(a: int) -> int:
    return ((a << 1) ^ 0x1b) & 0xff if (a & 0x80) else ((a << 1) & 0xff)


def _aes256_expand_key(key: bytes):
    w = [int.from_bytes(key[i:i+4], "big") for i in range(0, 32, 4)]
    for i in range(8, 60):
        t = w[i - 1]
        if i % 8 == 0:
            t = ((t << 8) | (t >> 24)) & 0xffffffff
            t = ((_SBOX[(t >> 24) & 0xff] << 24) | (_SBOX[(t >> 16) & 0xff] << 16) |
                 (_SBOX[(t >> 8) & 0xff] << 8) | _SBOX[t & 0xff]) ^ (_RCON[(i // 8) - 1] << 24)
        elif i % 8 == 4:
            t = ((_SBOX[(t >> 24) & 0xff] << 24) | (_SBOX[(t >> 16) & 0xff] << 16) |
                 (_SBOX[(t >> 8) & 0xff] << 8) | _SBOX[t & 0xff])
        w.append(w[i - 8] ^ t)
    return [b"".join(w[4*r + c].to_bytes(4, "big") for c in range(4)) for r in range(15)]


def _aes256_block(rk, block: bytes) -> bytes:
    s = bytearray(a ^ b for a, b in zip(block, rk[0]))
    for r in range(1, 15):
        s = bytearray(_SBOX[b] for b in s)
        s[1], s[5], s[9], s[13] = s[5], s[9], s[13], s[1]
        s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
        s[3], s[7], s[11], s[15] = s[15], s[3], s[7], s[11]
        if r < 14:
            for c in range(0, 16, 4):
                a0, a1, a2, a3 = s[c], s[c+1], s[c+2], s[c+3]
                t = a0 ^ a1 ^ a2 ^ a3
                s[c] ^= t ^ _xtime(a0 ^ a1)
                s[c+1] ^= t ^ _xtime(a1 ^ a2)
                s[c+2] ^= t ^ _xtime(a2 ^ a3)
                s[c+3] ^= t ^ _xtime(a3 ^ a0)
        k = rk[r]
        for i in range(16):
            s[i] ^= k[i]
    return bytes(s)


def _ghash_mul(x: int, y: int) -> int:
    z = 0
    v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        lsb = v & 1
        v >>= 1
        if lsb:
            v ^= 0xe1 << 120
    return z


def _ghash(h_bytes: bytes, aad: bytes, ct: bytes) -> bytes:
    h = int.from_bytes(h_bytes, "big")
    y = 0
    for data in (aad, ct):
        for off in range(0, len(data), 16):
            blk = data[off:off+16]
            if len(blk) < 16:
                blk = blk + b"\x00" * (16 - len(blk))
            y = _ghash_mul(y ^ int.from_bytes(blk, "big"), h)
    lens = ((len(aad) * 8) << 64) | (len(ct) * 8)
    y = _ghash_mul(y ^ lens, h)
    return y.to_bytes(16, "big")


def aes256_gcm_encrypt(key: bytes, iv12: bytes, pt: bytes, aad: bytes) -> bytes:
    rk = _aes256_expand_key(key)
    h = _aes256_block(rk, b"\x00" * 16)
    j0 = iv12 + b"\x00\x00\x00\x01"
    ctr = 2
    out = bytearray()
    for off in range(0, len(pt), 16):
        ks = _aes256_block(rk, iv12 + ctr.to_bytes(4, "big"))
        chunk = pt[off:off+16]
        out.extend(a ^ b for a, b in zip(chunk, ks[:len(chunk)]))
        ctr += 1
    ct = bytes(out)
    s = _ghash(h, aad, ct)
    e_j0 = _aes256_block(rk, j0)
    return ct + bytes(a ^ b for a, b in zip(s, e_j0))


def build_dm_frame(sender_id: str, sender_priv: Path, to_id: str, to_pub_pem: str, to_kv: int, msg_type: str, body_obj: dict, ts: int) -> bytes:
    nonce = base64.b64encode(os.urandom(16)).decode("ascii")
    body_s = json.dumps(body_obj, separators=(",", ":"), sort_keys=True)
    nosig = (
        f'{{"body":{body_s},"conversation_state":"open","from":{json.dumps(sender_id)},'
        f'"nonce":{json.dumps(nonce)},"to":{json.dumps(to_id)},"ts":{ts},'
        f'"type":{json.dumps(msg_type)},"v":1}}'
    ).encode("utf-8")
    sig = sign_pss_openssl(sender_priv, nosig)
    pt = (
        f'{{"body":{body_s},"conversation_state":"open","from":{json.dumps(sender_id)},'
        f'"nonce":{json.dumps(nonce)},"sig":{json.dumps(sig)},"to":{json.dumps(to_id)},'
        f'"ts":{ts},"type":{json.dumps(msg_type)},"v":1}}'
    ).encode("utf-8")
    cek = os.urandom(32)
    iv = os.urandom(12)
    with tempfile.TemporaryDirectory() as td:
        pk_p = Path(td) / "pub.pem"
        cek_p = Path(td) / "cek.bin"
        pk_p.write_text(to_pub_pem, encoding="utf-8")
        cek_p.write_bytes(cek)
        ek = subprocess.run(
            [
                "openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey", str(pk_p),
                "-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha256",
                "-in", str(cek_p),
            ],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
        ).stdout
    aad = f"fatext-dm\n{sender_id}\n{to_id}\n{to_kv}".encode("utf-8")
    ct = aes256_gcm_encrypt(cek, iv, pt, aad)
    return json.dumps({
        "v": 1,
        "alg": "RSA-OAEP-256+A256GCM",
        "to_key_version": to_kv,
        "ek": base64.b64encode(ek).decode("ascii"),
        "iv": base64.b64encode(iv).decode("ascii"),
        "ct": base64.b64encode(ct).decode("ascii"),
    }, separators=(",", ":")).encode("utf-8")


def start_server(port: int, data_dir: Path, extra_env: dict[str, str] | None = None) -> subprocess.Popen:
    env = os.environ.copy()
    env["FATEXT_ADDR"] = f"{HOST}:{port}"
    env["FATEXT_DATA_DIR"] = str(data_dir)
    env["FATEXT_WWW_DIR"] = str(ROOT / "www")
    env["FATEXT_TEMPLATES_DIR"] = str(ROOT / "templates")
    env["FATEXT_POW_BITS"] = "10"
    env["FATEXT_SHUTDOWN_SECRET"] = "test-shutdown-secret"
    if extra_env:
        env.update(extra_env)
    srv = subprocess.Popen(
        [str(SERVER_BIN)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    wait_tcp_ready(HOST, port, timeout=10.0)
    return srv


def main() -> int:
    assert_true(SERVER_BIN.is_file(), f"missing {SERVER_BIN}")
    assert_true(CLI_BIN.is_file(), f"missing {CLI_BIN}")

    port = free_tcp_port()
    api_url = f"http://{HOST}:{port}"

    with tempfile.TemporaryDirectory(prefix="fatext-resilience-") as td:
        tmp = Path(td)
        data_dir = tmp / "data"
        home_a = tmp / "alice"
        home_b = tmp / "bob"
        home_c = tmp / "carol"

        srv = start_server(port, data_dir)
        ls_a = None
        ls_b = None
        p2p_ls = None
        p2p_bus_b = None
        try:
            # Register Alice, Bob, Carol
            a = cli_json(["init", "--name", "Alice"], home=home_a, api_url=api_url)
            b = cli_json(["init", "--name", "Bob"], home=home_b, api_url=api_url)
            c = cli_json(["init", "--name", "Carol"], home=home_c, api_url=api_url)
            aid, bid, cid = a["agent_id"], b["agent_id"], c["agent_id"]

            # Become friends so invite/P2P default policies are also satisfied
            cli_json(["friend", "add", bid], home=home_a, api_url=api_url)
            cli_json(["friend", "accept", aid], home=home_b, api_url=api_url)

            # -----------------------------------------------------------------
            # 1. Zero-plaintext room key-box + `room sync` + `listen` auto-sync
            # -----------------------------------------------------------------
            print("[1/7] Testing offline room key-box, room sync, and listen auto-sync...")
            rm = cli_json(["room", "create", "--name", "resilience-room"], home=home_a, api_url=api_url)
            rid = rm["room_id"]
            secret_room_key = json.loads((home_a / "rooms" / f"{rid}.json").read_text(encoding="utf-8"))["key"]

            # Invite Bob while Bob is completely offline -> dropped DM, but stored in key-box!
            inv_b = cli_json(["room", "invite", rid, bid], home=home_a, api_url=api_url)
            assert_eq(inv_b["delivered"], "dropped_offline", "Bob offline at invite time")
            assert_true(not (home_b / "rooms" / f"{rid}.json").exists(), "Bob has no local key before sync")

            # Bob runs `fatext room sync` -> pulls encrypted key-box & verifies Alice sig
            syn_b = cli_json(["room", "sync"], home=home_b, api_url=api_url)
            assert_eq(syn_b["synced"], 1, "Bob synced 1 room keybox")
            b_room = json.loads((home_b / "rooms" / f"{rid}.json").read_text(encoding="utf-8"))
            assert_eq(b_room["key"], secret_room_key, "Synced room key matches")
            assert_eq(b_room["epoch"], 1, "Synced epoch=1")

            # Re-running room sync is idempotent (skipped=1)
            syn_b2 = cli_json(["room", "sync", rid], home=home_b, api_url=api_url)
            assert_eq(syn_b2["skipped"], 1, "Repeat sync skips cleanly")

            # Alice listens, Bob sends epoch-1 message
            ls_a = LineProc(["listen", "--rooms", rid, "--json"], home=home_a, api_url=api_url)
            time.sleep(0.3)
            msg1 = "OFFLINE_KEYBOX_MSG_EPOCH_1"
            cli_json(["room", "send", rid, msg1], home=home_b, api_url=api_url)
            ev1 = ls_a.wait_event(lambda e: e.get("type") == "room" and e.get("text") == msg1, label="epoch1 msg")
            assert_eq(ev1["verified"], True, "epoch1 verified")
            ls_a.close()
            ls_a = None

            # Invite Carol (offline), then kick Carol (epoch -> 2 + rekey) while Bob is STILL offline!
            cli_json(["room", "invite", rid, cid], home=home_a, api_url=api_url)
            kick_r = cli_json(["room", "kick", rid, cid], home=home_a, api_url=api_url)
            assert_eq(kick_r["epoch"], 2, "kick bumps epoch=2")
            assert_eq(kick_r["rekeyed"], True, "kick rekeyed")

            # Carol was kicked -> Carol keybox entry removed & GET returns 403
            rc_ck, _, _ = run_cli(["room", "sync", rid], home=home_c, api_url=api_url)
            assert_eq(rc_ck, 5, "kicked Carol rejected with EXIT_FORBIDDEN (5) on key-box")

            # Bob starts `fatext listen` WITHOUT manual `room sync` -> auto-syncs epoch=2!
            ls_b = LineProc(["listen", "--rooms", rid, "--json"], home=home_b, api_url=api_url)
            time.sleep(0.6)
            msg2 = "AUTO_SYNCED_EPOCH_2_MSG"
            cli_json(["room", "send", rid, msg2], home=home_a, api_url=api_url)
            ev2 = ls_b.wait_event(lambda e: e.get("type") == "room" and e.get("text") == msg2, label="epoch2 msg")
            assert_eq(ev2["verified"], True, "epoch2 verified")

            b_room2 = json.loads((home_b / "rooms" / f"{rid}.json").read_text(encoding="utf-8"))
            assert_eq(b_room2["epoch"], 2, "Bob local room updated to epoch 2")

            # Zero-plaintext / zero-room-key disk audit across data/rooms/
            leaks = scan_files_for_substrings(data_dir / "rooms", [msg1, msg2, secret_room_key])
            assert_eq(leaks, [], f"disk leak found: {leaks}")

            # -----------------------------------------------------------------
            # 2. HA /ready + gated graceful shutdown + `listen` & `p2p --star` reconnect
            # -----------------------------------------------------------------
            print("[2/7] Testing HA /ready, SSE drain on shutdown, listen & p2p --star auto-reconnect...")
            r_st, _, r_body = signed_http(HOST, port, "GET", "/ready")
            assert_eq(r_st, 200, "/ready returns 200")
            assert_eq(json.loads(r_body.decode("utf-8"))["status"], "ready", "/ready status=ready")

            p2p_bus_b = LineProc(["--json", "p2p", "listen", "--allow-friends-only", "--star", "--bus", "--stun", "none"], home=home_b, api_url=api_url)
            p2p_bus_b.wait_stderr('"state":"listening"', timeout=10.0)

            bad_req = urllib.request.Request(api_url + "/internal/shutdown", data=b"", method="POST")
            try:
                urllib.request.urlopen(bad_req, timeout=5)
                raise AssertionError("unauthenticated /internal/shutdown unexpectedly succeeded")
            except urllib.error.HTTPError as e:
                assert_eq(e.code, 403, "unauthenticated /internal/shutdown returns 403")

            ok_req = urllib.request.Request(
                api_url + "/internal/shutdown",
                data=b"",
                method="POST",
                headers={"X-Fatext-Shutdown-Secret": "test-shutdown-secret"},
            )
            with urllib.request.urlopen(ok_req, timeout=5) as resp:
                assert_eq(resp.status, 200, "authenticated /internal/shutdown returns 200")

            # Active SSE listener must receive system/shutdown notice during drain
            ev_sd = ls_b.wait_event(
                lambda e: e.get("type") == "system" and isinstance(e.get("data"), dict) and e["data"].get("kind") == "shutdown",
                timeout=5.0,
                label="system shutdown notice",
            )
            assert_eq(ev_sd["data"]["kind"], "shutdown", "shutdown event kind")

            rc_srv = srv.wait(timeout=8)
            assert_eq(rc_srv, 0, "fatext-server exits 0 on graceful shutdown")

            log_dir = data_dir / "logs"
            log_text = "\n".join(p.read_text(encoding="utf-8", errors="ignore") for p in log_dir.glob("events-*.jsonl"))
            assert_true('"kind":"server_stop"' in log_text, f"server_stop missing from logs: {log_text}")

            # Restart server on the same port & data_dir after a brief gap
            time.sleep(0.4)
            srv = start_server(port, data_dir)

            # Both Bob's `listen` and `p2p listen --star --bus` must auto-reconnect!
            ev_rec = ls_b.wait_event(
                lambda e: e.get("type") == "system" and e.get("kind") == "reconnected",
                timeout=12.0,
                label="system reconnected",
            )
            assert_eq(ev_rec["missed_dm_possible"], True, "missed_dm_possible flag")
            p2p_bus_b.wait_stderr('"state":"reconnected"', timeout=12.0)

            # Send DM after reconnect -> Bob receives immediately
            dm_post_rec = "DM_AFTER_RECONNECT_OK"
            cli_json(["dm", "send", bid, dm_post_rec], home=home_a, api_url=api_url)
            ev_dm = ls_b.wait_event(lambda e: e.get("type") == "dm" and e.get("text") == dm_post_rec, label="post-reconnect dm")
            assert_eq(ev_dm["verified"], True, "post-reconnect dm verified")

            # Send star-bus message through the reconnected p2p --star hub!
            env_a = os.environ.copy()
            env_a["FATEXT_HOME"] = str(home_a)
            bus_tx = subprocess.run(
                [str(CLI_BIN), "--api", api_url, "--json", "p2p", "connect", bid, "--bus", "--stun", "none"],
                input=f'{{"to":{json.dumps(bid)},"text":"BUS_AFTER_RECONNECT_OK"}}\n',
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env_a,
                timeout=20,
            )
            assert_eq(bus_tx.returncode, 0, f"p2p bus after reconnect failed: {bus_tx.stderr}")
            ev_bus = p2p_bus_b.wait_event(lambda e: e.get("type") == "p2p_msg" and e.get("text") == "BUS_AFTER_RECONNECT_OK", timeout=10.0, label="bus msg post reconnect")
            assert_eq(ev_bus["from"], aid, "bus msg sender matches")
            p2p_bus_b.close()
            p2p_bus_b = None

            # -----------------------------------------------------------------
            # 3. High-Concurrency Overload Guards (SSE limits + Cache-Control + 20-thread burst)
            # -----------------------------------------------------------------
            print("[3/7] Testing SSE overload guards (429/503), Cache-Control, and 20-thread 200-req burst...")
            ov_port = free_tcp_port()
            ov_data = tmp / "ov_data"
            ov_home_a = tmp / "ov_a"
            ov_home_b = tmp / "ov_b"
            ov_home_c = tmp / "ov_c"
            ov_api = f"http://{HOST}:{ov_port}"
            ov_srv = start_server(
                ov_port, ov_data,
                extra_env={"FATEXT_MAX_SSE_PER_AGENT": "2", "FATEXT_MAX_SSE": "3", "FATEXT_IP_RPM": "5000"},
            )
            ov_conns = []
            try:
                oa = cli_json(["init", "--name", "OvA"], home=ov_home_a, api_url=ov_api)["agent_id"]
                ob = cli_json(["init", "--name", "OvB"], home=ov_home_b, api_url=ov_api)["agent_id"]
                oc = cli_json(["init", "--name", "OvC"], home=ov_home_c, api_url=ov_api)["agent_id"]
                cli_json(["friend", "add", ob], home=ov_home_a, api_url=ov_api)
                cli_json(["friend", "accept", oa], home=ov_home_b, api_url=ov_api)

                # Cache-Control headers on /k/{id}.json and /k/{id}.pem
                kst, khdr, _ = signed_http(HOST, ov_port, "GET", f"/k/{oa}.json")
                assert_eq(kst, 200, "/k/{id}.json 200")
                assert_true("max-age=30" in khdr.get("cache-control", ""), f"missing Cache-Control on key json: {khdr}")

                c1, st_c1, _, _ = open_signed_sse(HOST, ov_port, oa, ov_home_a / "private.pem")
                ov_conns.append(c1)
                assert_eq(st_c1, 200, "Alice SSE #1 allowed")

                c2, st_c2, _, _ = open_signed_sse(HOST, ov_port, oa, ov_home_a / "private.pem")
                ov_conns.append(c2)
                assert_eq(st_c2, 200, "Alice SSE #2 allowed")

                # 3rd stream for Alice hits per-agent limit 429
                c3, st_c3, hdr_c3, r_c3 = open_signed_sse(HOST, ov_port, oa, ov_home_a / "private.pem")
                _ = r_c3.read()
                c3.close()
                assert_eq(st_c3, 429, "Alice SSE #3 rejected 429 ERR_RATE_LIMITED")
                assert_true(int(hdr_c3.get("retry-after", "0")) > 0, "429 includes Retry-After")

                # Bob opens 1 SSE (total=3 == FATEXT_MAX_SSE)
                cb, st_cb, _, _ = open_signed_sse(HOST, ov_port, ob, ov_home_b / "private.pem")
                ov_conns.append(cb)
                assert_eq(st_cb, 200, "Bob SSE #1 allowed (total=3)")

                # Carol rejected with global 503 ERR_OVERLOADED
                cc1, st_cc1, hdr_cc1, r_cc1 = open_signed_sse(HOST, ov_port, oc, ov_home_c / "private.pem")
                _ = r_cc1.read()
                cc1.close()
                assert_eq(st_cc1, 503, "Carol rejected 503 ERR_OVERLOADED when max_sse=3 reached")
                assert_true(int(hdr_cc1.get("retry-after", "0")) > 0, "503 includes Retry-After")

                # Close Alice SSE #1 -> slot frees -> Carol succeeds with 200
                ov_conns.pop(0).close()
                time.sleep(0.25)
                cc2, st_cc2, _, _ = open_signed_sse(HOST, ov_port, oc, ov_home_c / "private.pem")
                ov_conns.append(cc2)
                assert_eq(st_cc2, 200, "Carol allowed after SSE slot freed")

                # 20-thread 200-request parallel mixed burst
                ov_ob_pub = json.loads(cli_json(["key", "fetch", ob], home=ov_home_a, api_url=ov_api)["current_public_key_pem"] if False else run_cli(["key", "fetch", ob], home=ov_home_a, api_url=ov_api)[1])["current_public_key_pem"]
                sample_dm = build_dm_frame(oa, ov_home_a / "private.pem", ob, ov_ob_pub, 1, "text", {"text": "BURST"}, int(time.time()))

                def burst_task(idx: int) -> int:
                    kind = idx % 4
                    if kind == 0:
                        s, _, _ = signed_http(HOST, ov_port, "GET", "/ready")
                        return s
                    if kind == 1:
                        s, _, _ = signed_http(HOST, ov_port, "GET", f"/k/{ob}.json")
                        return s
                    if kind == 2:
                        s, _, _ = signed_http(HOST, ov_port, "GET", "/v1/friends", oa, ov_home_a / "private.pem")
                        return s
                    s, _, _ = signed_http(HOST, ov_port, "POST", f"/v1/dm/{ob}", oa, ov_home_a / "private.pem", sample_dm)
                    return s

                with ThreadPoolExecutor(max_workers=20) as pool:
                    futs = [pool.submit(burst_task, idx) for idx in range(200)]
                    statuses = [f.result() for f in as_completed(futs)]
                bad_statuses = [s for s in statuses if s < 200 or s >= 300]
                assert_eq(bad_statuses, [], f"20-thread burst had non-2xx statuses: {bad_statuses[:10]}")
            finally:
                for conn in ov_conns:
                    try:
                        conn.close()
                    except Exception:
                        pass
                if ov_srv.poll() is None:
                    ov_srv.terminate()
                    ov_srv.wait(timeout=5)

            # -----------------------------------------------------------------
            # 4. CLI 24h nonce replay cache
            # -----------------------------------------------------------------
            print("[4/7] Testing CLI 24h nonce replay cache...")
            nonce_file = home_b / "nonces.jsonl"
            assert_true(nonce_file.is_file(), "nonces.jsonl exists")
            assert_eq(stat.S_IMODE(nonce_file.stat().st_mode), 0o600, "nonces.jsonl mode 0600")

            # Build one signed DM frame and deliver it twice over HTTP
            rc_k, b_key_out, _ = run_cli(["key", "fetch", bid], home=home_a, api_url=api_url)
            assert_eq(rc_k, 0, "fetch Bob key")
            b_pub_pem = json.loads(b_key_out)["current_public_key_pem"]
            replay_txt = "ONCE_ONLY_NONCE_MSG"
            frame_bytes = build_dm_frame(aid, home_a / "private.pem", bid, b_pub_pem, 1, "text", {"text": replay_txt}, int(time.time()))

            st1, res1 = signed_post(api_url, aid, home_a / "private.pem", f"/v1/dm/{bid}", frame_bytes)
            assert_eq(st1, 202, f"1st dm send status={st1} body={res1}")
            ev_once = ls_b.wait_event(lambda e: e.get("type") == "dm" and e.get("text") == replay_txt, label="first nonce msg")
            assert_eq(ev_once["verified"], True, "first nonce msg verified")

            st2, res2 = signed_post(api_url, aid, home_a / "private.pem", f"/v1/dm/{bid}", frame_bytes)
            assert_eq(st2, 202, f"2nd dm relay status={st2} body={res2}")
            ev_rep = ls_b.wait_event(lambda e: e.get("type") == "error" and e.get("code") == "replay_nonce", label="replay_nonce reject")
            assert_eq(ev_rep["from"], aid, "replay error cites sender")

            # -----------------------------------------------------------------
            # 5. Multi-chunk (>8 KB) P2P stdio & 5x TCP forward + stale offer rejection
            # -----------------------------------------------------------------
            print("[5/7] Testing P2P 60s stale offer, 16KB --stdio, and 5 consecutive 12KB --forward rounds...")
            payload_16k = (b"FATEXT_P2P_CHUNK_VERIFY_0123456789ABCDEF\n" * 410)[:16384]
            out_stdio = tmp / "p2p_stdio_out.bin"

            p2p_ls = LineProc(["--json", "p2p", "listen", "--allow-friends-only", "--stdio", "--stun", "none"], home=home_b, api_url=api_url, binary=True)
            p2p_ls.wait_stderr('"state":"listening"', timeout=10.0)

            stale_ts = int(time.time()) - 120
            stale_frame = build_dm_frame(
                aid, home_a / "private.pem", bid, b_pub_pem, 1, "p2p_offer",
                {
                    "session": "s_stale0000000000",
                    "candidates": [{"t": "host", "a": "127.0.0.1:45555"}],
                    "x25519_pub": base64.b64encode(os.urandom(32)).decode("ascii"),
                    "mode": "stdio",
                    "remote_port": 0,
                    "relay": False,
                    "expires_at": int(time.time()) + 60,
                },
                stale_ts,
            )
            st_stale, _ = signed_post(api_url, aid, home_a / "private.pem", f"/v1/dm/{bid}", stale_frame)
            assert_eq(st_stale, 202, "stale offer relayed to SSE")
            time.sleep(0.4)
            assert_true(p2p_ls.proc.poll() is None, "p2p listener stayed alive ignoring stale offer")

            p2p_ls.close()
            p2p_ls = None
            with open(out_stdio, "wb") as fout:
                env_b = os.environ.copy()
                env_b["FATEXT_HOME"] = str(home_b)
                proc_rx = subprocess.Popen(
                    [str(CLI_BIN), "--api", api_url, "--json", "p2p", "listen", "--allow-friends-only", "--stdio", "--stun", "none"],
                    stdout=fout,
                    stderr=subprocess.PIPE,
                    env=env_b,
                )
                try:
                    dl = time.time() + 10.0
                    while time.time() < dl:
                        ln = proc_rx.stderr.readline().decode("utf-8", errors="replace")
                        if '"state":"listening"' in ln:
                            break
                    tx = subprocess.run(
                        [str(CLI_BIN), "--api", api_url, "--json", "p2p", "connect", bid, "--stun", "none"],
                        input=payload_16k,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        env=env_a,
                        timeout=30,
                    )
                    assert_eq(tx.returncode, 0, f"p2p stdio 16KB tx failed: {tx.stderr.decode()}")
                    proc_rx.wait(timeout=15)
                    assert_eq(proc_rx.returncode, 0, "p2p stdio rx exit 0")
                finally:
                    if proc_rx.poll() is None:
                        proc_rx.terminate()
                        proc_rx.wait(timeout=5)
            got_16k = out_stdio.read_bytes()
            assert_eq(len(got_16k), len(payload_16k), f"P2P 16KB stdio length {len(got_16k)}")
            assert_eq(hashlib.sha256(got_16k).hexdigest(), hashlib.sha256(payload_16k).hexdigest(), "P2P 16KB stdio SHA-256")

            # 5 consecutive rounds of 12 KB --expose / --forward round-trip verification (zero race!)
            payload_12k = (b"FWD_MTU_CHUNK_TEST_9876543210\n" * 410)[:12288]
            want_12k_sha = hashlib.sha256(payload_12k).hexdigest()
            for rnd in range(5):
                echo_port = free_tcp_port()
                fwd_port = free_tcp_port()
                echo_stop = threading.Event()
                echo_ready = threading.Event()

                def echo_server(ep=echo_port, stop_ev=echo_stop, rdy_ev=echo_ready):
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv_sock:
                        srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        srv_sock.bind((HOST, ep))
                        srv_sock.listen(4)
                        srv_sock.settimeout(0.2)
                        rdy_ev.set()
                        while not stop_ev.is_set():
                            try:
                                conn, _ = srv_sock.accept()
                            except socket.timeout:
                                continue
                            with conn:
                                conn.settimeout(None)
                                while True:
                                    chunk = conn.recv(4096)
                                    if not chunk:
                                        break
                                    conn.sendall(chunk)

                th_echo = threading.Thread(target=echo_server, daemon=True)
                th_echo.start()
                echo_ready.wait(timeout=3.0)
                p2p_fwd_rx = LineProc(["--json", "p2p", "listen", "--allow-friends-only", "--expose", str(echo_port), "--stun", "none"], home=home_b, api_url=api_url)
                p2p_fwd_tx = None
                try:
                    p2p_fwd_rx.wait_stderr('"state":"listening"', timeout=10.0)
                    p2p_fwd_tx = LineProc(["--json", "p2p", "connect", bid, "--forward", f"{fwd_port}:{echo_port}", "--stun", "none"], home=home_a, api_url=api_url)
                    p2p_fwd_tx.wait_stderr('"state":"connected"', timeout=12.0)
                    with socket.create_connection((HOST, fwd_port), timeout=15) as sock:
                        sock.sendall(payload_12k)
                        sock.shutdown(socket.SHUT_WR)
                        recvd = bytearray()
                        while len(recvd) < len(payload_12k):
                            d = sock.recv(4096)
                            if not d:
                                break
                            recvd.extend(d)
                    assert_eq(len(recvd), len(payload_12k), f"round {rnd}: P2P 12KB forward len mismatch ({len(recvd)})")
                    assert_eq(hashlib.sha256(bytes(recvd)).hexdigest(), want_12k_sha, f"round {rnd}: P2P 12KB forward SHA-256 mismatch")
                finally:
                    echo_stop.set()
                    if p2p_fwd_tx is not None:
                        p2p_fwd_tx.close()
                    p2p_fwd_rx.close()
                    th_echo.join(timeout=3)

            # -----------------------------------------------------------------
            # 6. Hard Crash (SIGKILL) Recovery
            # -----------------------------------------------------------------
            print("[6/7] Testing hard crash (SIGKILL) recovery and state persistence...")
            srv.kill()
            srv.wait(timeout=5)
            time.sleep(0.3)
            srv = start_server(port, data_dir)

            r_st2, _, r_body2 = signed_http(HOST, port, "GET", "/ready")
            assert_eq(r_st2, 200, "/ready 200 after SIGKILL restart")
            assert_eq(json.loads(r_body2.decode("utf-8"))["status"], "ready", "/ready=ready after crash")

            ev_rec2 = ls_b.wait_event(
                lambda e: e.get("type") == "system" and e.get("kind") == "reconnected",
                timeout=12.0,
                label="listen reconnected after SIGKILL",
            )
            assert_eq(ev_rec2["missed_dm_possible"], True, "reconnected flag after SIGKILL")

            # Verify persisted rooms, friends, key-boxes, and DM delivery
            rms_b = cli_json(["room", "list"], home=home_b, api_url=api_url)
            assert_true(any(r["room_id"] == rid and r["epoch"] == 2 for r in rms_b["rooms"]), "persisted room intact after crash")
            fr_b = cli_json(["friend", "list"], home=home_b, api_url=api_url)
            assert_true(any(f["agent_id"] == aid for f in fr_b["friends"]), "persisted friend intact after crash")
            dm_crash = "DM_AFTER_SIGKILL_RECOVERY"
            cli_json(["dm", "send", bid, dm_crash], home=home_a, api_url=api_url)
            ev_dm2 = ls_b.wait_event(lambda e: e.get("type") == "dm" and e.get("text") == dm_crash, label="dm post SIGKILL")
            assert_eq(ev_dm2["verified"], True, "dm post SIGKILL verified")

            ls_b.close()
            ls_b = None

            # -----------------------------------------------------------------
            # 7. Production Ops Drill: backup.sh, graceful_stop.sh, restore.sh
            # -----------------------------------------------------------------
            print("[7/7] Testing deploy/backup.sh, deploy/restore.sh, and deploy/graceful_stop.sh end-to-end...")
            pub_text = "Pre-backup channel post for DR restore verification."
            post_res = cli_json(["pub", "post", "general", pub_text], home=home_a, api_url=api_url)
            post_id = post_res["msg_id"]
            soul_text = "Role: Bob HA disaster recovery soul document."
            cli_json(["soul", "set", "--text", soul_text, "--public"], home=home_b, api_url=api_url)

            backup_dir = tmp / "backups"
            bk = subprocess.run(
                ["bash", str(ROOT / "deploy" / "backup.sh"), str(data_dir), str(backup_dir)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True,
                timeout=15,
            )
            archives = sorted(backup_dir.glob("fatext-*.tar.gz"))
            assert_eq(len(archives), 1, f"expected 1 backup archive: {bk.stdout}")
            archive = archives[0]
            assert_eq(stat.S_IMODE(archive.stat().st_mode), 0o600, "backup archive mode 0600")

            # Verify deploy/graceful_stop.sh triggers clean exit 0
            stop_env = os.environ.copy()
            stop_env["FATEXT_ADDR"] = f"{HOST}:{port}"
            stop_env["FATEXT_SHUTDOWN_SECRET"] = "test-shutdown-secret"
            stop_env["MAINPID"] = str(srv.pid)
            gs = subprocess.run(
                ["bash", str(ROOT / "deploy" / "graceful_stop.sh")],
                env=stop_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=15,
            )
            assert_eq(gs.returncode, 0, f"graceful_stop.sh failed: {gs.stderr}")
            assert_eq(srv.wait(timeout=8), 0, "server exited 0 via graceful_stop.sh")

            restored_data = tmp / "restored_data"
            dr_dry = subprocess.run(
                ["bash", str(ROOT / "deploy" / "restore.sh"), str(archive), str(restored_data), "--dry-run"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True,
                timeout=15,
            )
            for root_name in ("keys/", "friends/", "docs/", "rooms/", "public/"):
                assert_true(root_name in dr_dry.stdout, f"restore dry-run missing {root_name}: {dr_dry.stdout}")

            subprocess.run(
                ["bash", str(ROOT / "deploy" / "restore.sh"), str(archive), str(restored_data)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True,
                timeout=15,
            )

            # Boot fresh server from restored_data and verify full state integrity
            srv = start_server(port, restored_data)
            for check_id in (aid, bid):
                ks, _, kb = signed_http(HOST, port, "GET", f"/k/{check_id}.json")
                assert_eq(ks, 200, f"restored key lookup failed for {check_id}: {kb}")
            fr_r = cli_json(["friend", "list"], home=home_b, api_url=api_url)
            assert_true(any(f["agent_id"] == aid for f in fr_r["friends"]), "restored friend missing")
            rm_r = cli_json(["room", "list"], home=home_b, api_url=api_url)
            assert_true(any(r["room_id"] == rid and r["epoch"] == 2 for r in rm_r["rooms"]), "restored room missing")
            sync_r = cli_json(["room", "sync", rid], home=home_b, api_url=api_url)
            assert_true(sync_r.get("ok") is True, f"restored room key-box sync failed: {sync_r}")
            rc_pub, pub_out, pub_err = run_cli(["--json", "pub", "list", "general"], home=home_b, api_url=api_url)
            assert_eq(rc_pub, 0, f"restored pub list failed: {pub_err}")
            pub_recs = [json.loads(ln) for ln in pub_out.splitlines() if ln.strip()]
            assert_true(any(r.get("msg_id") == post_id and r.get("verified") is True and r.get("text") == pub_text for r in pub_recs), f"restored channel post missing or unverified: {pub_recs}")
            doc_st, _, doc_body = signed_http(HOST, port, "GET", f"/k/{bid}/soul.json")
            assert_eq(doc_st, 200, "restored soul doc status 200")
            assert_true(soul_text.encode("utf-8") in doc_body, "restored soul text missing")

            print("ALL 7 HIGH-CONCURRENCY, HA & DISASTER-RECOVERY TESTS PASSED!")
            return 0
        finally:
            if ls_a:
                ls_a.close()
            if ls_b:
                ls_b.close()
            if p2p_ls:
                p2p_ls.close()
            if p2p_bus_b:
                p2p_bus_b.close()
            if srv and srv.poll() is None:
                srv.terminate()
                try:
                    srv.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    srv.kill()
                    srv.wait(timeout=3)


if __name__ == "__main__":
    raise SystemExit(main())
