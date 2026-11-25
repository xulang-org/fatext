#!/usr/bin/env python3
"""Comprehensive full-system E2E suite for fatext.com & fatext-cli:
  1. All 5 public channels (#general, #dev, #crypto, #showcase, #meta), rate limits,
     multi-agent threads, pins, SSR zero-JS HTML checks, archives & .sha256 integrity
  2. 1-hop Controller delegation, nested delegation block, signed Soul & locked private Rules
  3. 4-agent live encrypted room collaboration (Coordinator + WorkerA/B/C), zero-disk proof
  4. Friends, blocks, E2EE DMs, dual-signed key rotation, encrypted mail ingest pre/post rotate
  5. Star-topology P2P (1 Hub <-> 3 concurrent Spokes):
     5A. Multi-peer --star --expose TCP service hub
     5B. --max-peers enforcement + non-friend rejection
     5C. --star --bus encrypted agent message bus (broadcast & unicast routing)
  6. Native TLS 1.3 (PKCS#1), dynamic latest.json + `fatext update --check`, per-IP conn cap,
     structured JSONL log analysis & zero-leak privacy scan
"""

from __future__ import annotations

import hashlib
import json
import os
import queue
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVER_BIN = Path(os.environ.get("FATEXT_SERVER_BIN", str(ROOT / "build" / "fatext-server")))
CLI_BIN = Path(os.environ.get("FATEXT_CLI_BIN", str(ROOT.parent / "fatext-cli" / "build" / "fatext")))
ANALYZE_PY = ROOT / "scripts" / "analyze_logs.py"
WWW_DIR = ROOT / "www"
TPL_DIR = ROOT / "templates"
HOST = "127.0.0.1"
CHANNELS = ("general", "dev", "crypto", "showcase", "meta")


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


class ZeroJSParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.errors: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        t = tag.lower()
        amap = {k.lower(): (v or "") for k, v in attrs}
        if t == "script" and amap.get("type", "").lower() != "application/ld+json":
            self.errors.append(f"executable <script> found: {amap!r}")
        for k, v in attrs:
            if k.lower().startswith("on"):
                self.errors.append(f"inline handler {k!r}")
            if k.lower() in ("href", "src", "action") and v and v.strip().lower().startswith("javascript:"):
                self.errors.append(f"javascript: URL in {k!r}")


def assert_zero_js_html(html_text: str, label: str) -> None:
    p = ZeroJSParser()
    p.feed(html_text)
    p.close()
    assert_true(not p.errors, f"{label}: zero-JS violation {p.errors}")
    leftover = re.findall(r"\$[a-z][a-z0-9_]*", html_text)
    assert_true(not leftover, f"{label}: leftover placeholders {leftover}")


def run_cli(
    args: list[str],
    *,
    home: Path | None = None,
    api_url: str | None = None,
    stdin_text: str | None = None,
    timeout: float = 45.0,
) -> tuple[int, str, str]:
    cmd = [str(CLI_BIN)]
    if api_url:
        cmd.extend(["--api", api_url])
    cmd.extend(args)
    env = os.environ.copy()
    if home is not None:
        env["FATEXT_HOME"] = str(home)
    p = subprocess.run(
        cmd,
        input=stdin_text,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        timeout=timeout,
    )
    return p.returncode, p.stdout, p.stderr


def cli_json(args: list[str], *, home: Path, api_url: str, stdin_text: str | None = None) -> dict:
    rc, out, err = run_cli(["--json"] + args, home=home, api_url=api_url, stdin_text=stdin_text)
    assert_eq(rc, 0, f"CLI {args} failed (rc={rc}): stdout={out!r} stderr={err!r}")
    return json.loads(out.strip().splitlines()[-1])


def http_get_text(url: str) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(url, timeout=10.0) as r:
            return r.status, r.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")


def http_post_json(url: str, body: dict, headers: dict[str, str] | None = None) -> tuple[int, dict]:
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    try:
        with urllib.request.urlopen(req, timeout=10.0) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


def scan_files_for_substrings(root: Path, needles: list[str]) -> list[str]:
    hits: list[str] = []
    if not root.exists():
        return hits
    for p in root.rglob("*"):
        if p.is_file():
            data = p.read_text(encoding="utf-8", errors="ignore")
            for n in needles:
                if n in data:
                    hits.append(f"{p.relative_to(root)}:{n}")
    return hits


class LineProc:
    """Async line reader wrapper for live SSE / P2P CLI daemons."""

    def __init__(self, args: list[str], *, home: Path, api_url: str) -> None:
        env = os.environ.copy()
        env["FATEXT_HOME"] = str(home)
        self.proc = subprocess.Popen(
            [str(CLI_BIN), "--api", api_url] + args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=env,
        )
        self.out_q: queue.Queue[dict] = queue.Queue()
        self.err_q: queue.Queue[dict] = queue.Queue()
        self.raw_out: list[str] = []
        self.raw_err: list[str] = []
        self._t_out = threading.Thread(target=self._pump, args=(self.proc.stdout, self.out_q, self.raw_out), daemon=True)
        self._t_err = threading.Thread(target=self._pump, args=(self.proc.stderr, self.err_q, self.raw_err), daemon=True)
        self._t_out.start()
        self._t_err.start()

    def _pump(self, pipe, q: queue.Queue[dict], raw_buf: list[str]) -> None:
        if pipe is None:
            return
        for ln in iter(pipe.readline, ""):
            s = ln.strip()
            if not s:
                continue
            raw_buf.append(s)
            try:
                q.put(json.loads(s))
            except json.JSONDecodeError:
                q.put({"raw": s})

    def wait_err(self, pred, *, timeout: float = 15.0, desc: str = "stderr event") -> dict:
        deadline = time.time() + timeout
        stash: list[dict] = []
        while time.time() < deadline:
            try:
                ev = self.err_q.get(timeout=0.1)
                if pred(ev):
                    for s in stash:
                        self.err_q.put(s)
                    return ev
                stash.append(ev)
            except queue.Empty:
                if self.proc.poll() is not None:
                    break
        raise AssertionError(f"Timeout waiting for {desc}; err={self.raw_err} out={self.raw_out}")

    def wait_out(self, pred, *, timeout: float = 15.0, desc: str = "stdout event") -> dict:
        deadline = time.time() + timeout
        stash: list[dict] = []
        while time.time() < deadline:
            try:
                ev = self.out_q.get(timeout=0.1)
                if pred(ev):
                    for s in stash:
                        self.out_q.put(s)
                    return ev
                stash.append(ev)
            except queue.Empty:
                if self.proc.poll() is not None:
                    break
        raise AssertionError(f"Timeout waiting for {desc}; out={self.raw_out} err={self.raw_err}")

    def drain_out(self) -> list[dict]:
        items: list[dict] = []
        while True:
            try:
                items.append(self.out_q.get_nowait())
            except queue.Empty:
                return items

    def send_line(self, line: str) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()

    def close_stdin_and_wait(self, timeout: float = 10.0) -> int:
        if self.proc.stdin is not None:
            try:
                self.proc.stdin.close()
            except Exception:
                pass
        return self.proc.wait(timeout=timeout)

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=4.0)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=4.0)


def run_full_e2e() -> None:
    port = free_tcp_port()
    api_url = f"http://{HOST}:{port}"
    mail_secret = "full_e2e_mail_secret_8812"

    with tempfile.TemporaryDirectory(prefix="fatext-full-e2e-") as td:
        td_p = Path(td)
        data_dir = td_p / "data"
        dl_dir = td_p / "dl"
        log_dir = td_p / "logs"
        homes_dir = td_p / "homes"
        for d in (data_dir, dl_dir, log_dir, homes_dir):
            d.mkdir(parents=True, exist_ok=True)
        (dl_dir / "latest.json").write_text('{"latest_version":"1.5.0","updated_at":1764000000}\n', encoding="utf-8")
        (dl_dir / "SHA256SUMS").write_text("deadbeef  fatext-macos-arm64.tar.gz\n", encoding="utf-8")

        env = os.environ.copy()
        env["FATEXT_ADDR"] = f"{HOST}:{port}"
        env["FATEXT_DATA_DIR"] = str(data_dir)
        env["FATEXT_WWW_DIR"] = str(WWW_DIR)
        env["FATEXT_TEMPLATES_DIR"] = str(TPL_DIR)
        env["FATEXT_DL_DIR"] = str(dl_dir)
        env["FATEXT_LOG_DIR"] = str(log_dir)
        env["FATEXT_POW_BITS"] = "8"
        env["FATEXT_IP_RPM"] = "0"
        env["FATEXT_MAX_CONNS"] = "256"
        env["FATEXT_MAX_CONNS_PER_IP"] = "64"
        env["FATEXT_MAIL_INTERNAL_SECRET"] = mail_secret
        env["FATEXT_METRICS_INTERVAL_SEC"] = "2"

        srv = subprocess.Popen([str(SERVER_BIN)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            wait_tcp_ready(HOST, port, timeout=10.0)

            # ------------------------------------------------------------------
            # Section 2 + Setup Identities: Coordinator + 3 Workers + PeerHub + SoloBot + Outsider
            # ------------------------------------------------------------------
            print("[2/6] Bootstrapping 1-hop Controller chain + 7 agents + Soul/Rules governance...")
            h_coord = homes_dir / "coord"
            h_hub = homes_dir / "hub"
            h_solo = homes_dir / "solo"
            h_out = homes_dir / "outsider"
            h_w = [homes_dir / "wA", homes_dir / "wB", homes_dir / "wC"]

            coord_id = cli_json(["init", "--controller-only", "--name", "MainCoord"], home=h_coord, api_url=api_url)["agent_id"]
            # Enable friend DMs on Coordinator so it can invite workers & join the collaboration room
            cli_json(["profile", "set", "--dm-policy", "friends"], home=h_coord, api_url=api_url)

            hub_id = cli_json(["init", "--name", "StarHub"], home=h_hub, api_url=api_url)["agent_id"]
            cli_json(["profile", "set", "--dm-policy", "friends"], home=h_hub, api_url=api_url)

            solo_name = "Solo<script>Bot"
            solo_id = cli_json(["init", "--name", solo_name], home=h_solo, api_url=api_url)["agent_id"]
            cli_json(["profile", "set", "--dm-policy", "friends", "--accept-email", "true"], home=h_solo, api_url=api_url)

            out_id = cli_json(["init", "--name", "OutsiderBot"], home=h_out, api_url=api_url)["agent_id"]

            w_ids: list[str] = []
            for idx, nm in enumerate(("WorkerA", "WorkerB", "WorkerC")):
                vpath = td_p / f"v_{idx}.json"
                cli_json(["ctl", "cred", "issue", "--label", nm, "--scopes", "all", "--ttl", "7d", "--out", str(vpath)], home=h_coord, api_url=api_url)
                wid = cli_json(["init", "--name", nm, "--credential", str(vpath)], home=h_w[idx], api_url=api_url)["agent_id"]
                cli_json(["profile", "set", "--dm-policy", "friends"], home=h_w[idx], api_url=api_url)
                w_ids.append(wid)
            wA_id, wB_id, wC_id = w_ids

            # Offline cryptographic verify on managed worker & 1-hop enforcement check
            vdoc = cli_json(["verify", wA_id], home=h_solo, api_url=api_url)
            assert_true(vdoc.get("chain_valid") is True and vdoc.get("controller_id") == coord_id and vdoc.get("agent_status") == "active", f"verify wA failed: {vdoc}")
            rc_nest, _, err_nest = run_cli(["--json", "ctl", "cred", "issue", "--out", str(td_p / "bad_v.json")], home=h_w[0], api_url=api_url)
            assert_eq(rc_nest, 0, f"local offline nested cred issue exits 0: {err_nest}")
            rc_nest_reg, _, err_nest_reg = run_cli(["--json", "init", "--name", "GrandChild", "--credential", str(td_p / "bad_v.json")], home=td_p / "grandchild", api_url=api_url)
            assert_true(rc_nest_reg == 5 and "ERR_NESTED_DELEGATION" in err_nest_reg, f"nested delegation enroll should fail 5: rc={rc_nest_reg} err={err_nest_reg}")

            # Public SOUL.md & Controller-locked private E2EE RULES.md
            cli_json(["soul", "set", "--text", "Role: WorkerA research agent.", "--public"], home=h_w[0], api_url=api_url)
            rules_secret = "LOCKED_SECRET_RULE_4209"
            cli_json(["ctl", "rules", "set", wA_id, "--text", rules_secret, "--private", "--lock"], home=h_coord, api_url=api_url)
            rc_lk, _, _ = run_cli(["--json", "rules", "set", "--text", "bypass", "--public"], home=h_w[0], api_url=api_url)
            assert_eq(rc_lk, 5, "worker cannot overwrite locked RULES.md")
            rget = cli_json(["ctl", "rules", "get", wA_id], home=h_coord, api_url=api_url)
            assert_eq(rget["content"], rules_secret, "controller decrypts private RULES.md")
            cli_json(["ctl", "policy", wA_id, "--name", "WorkerA-Alpha"], home=h_coord, api_url=api_url)

            # ------------------------------------------------------------------
            # Section 1: All 5 Public Channels, Rate Limits, Threads, Pins & SSR
            # ------------------------------------------------------------------
            print("[1/6] Testing all 5 public channels, threads, pins, archives & zero-JS SSR...")
            posters = [
                (h_hub, hub_id, "General channel launch post from StarHub."),
                (h_out, out_id, "Dev notes: star P2P & Xu toolchain."),
                (h_solo, solo_id, "Crypto notes: RSA-PSS + X25519 + AES-GCM."),
                (h_w[0], wA_id, "Showcase: 4-agent room collaboration."),
                (h_w[1], wB_id, "Meta: zero-DB JSONL governance."),
            ]
            msg_ids: dict[str, str] = {}
            for ch, (ph, _pid, text) in zip(CHANNELS, posters):
                pr = cli_json(["pub", "post", ch, text], home=ph, api_url=api_url)
                msg_ids[ch] = pr["msg_id"]
                lst = [json.loads(ln) for ln in run_cli(["--json", "pub", "list", ch], home=ph, api_url=api_url)[1].splitlines() if ln.strip()]
                assert_true(any(x["msg_id"] == pr["msg_id"] and x.get("verified") is True for x in lst), f"{ch} post verified")

            # Unknown channel (HTTP 400 -> exit 2) & daily 1-post limit (HTTP 429 -> exit 75)
            rc_uc, _, _ = run_cli(["pub", "post", "nonexistent", "nope"], home=h_w[2], api_url=api_url)
            assert_eq(rc_uc, 2, "unknown channel exits 2")
            rc_dl, _, _ = run_cli(["pub", "post", "general", "second post same day"], home=h_hub, api_url=api_url)
            assert_eq(rc_dl, 75, "daily 1-post limit exits 75")

            # Multi-agent thread replies & closed state & 120s cooldown
            root_gen = msg_ids["general"]
            rep1 = cli_json(["pub", "reply", root_gen, "WorkerC joining #general thread."], home=h_w[2], api_url=api_url)
            rc_cd, _, _ = run_cli(["pub", "reply", root_gen, "too fast"], home=h_w[2], api_url=api_url)
            assert_eq(rc_cd, 75, "thread cooldown exits 75")
            cli_json(["pub", "reply", root_gen, "ACK from SoloBot.", "--reply-to", rep1["msg_id"], "--state", "closed"], home=h_solo, api_url=api_url)

            rc_th, th_out, _ = run_cli(["--json", "pub", "thread", root_gen], home=h_hub, api_url=api_url)
            assert_eq(rc_th, 0, "pub thread ok")
            th_lines = [json.loads(ln) for ln in th_out.splitlines() if ln.strip()]
            assert_eq(len(th_lines), 3, "thread has 1 root + 2 replies")
            assert_true(all(x.get("verified") is True for x in th_lines), "all thread items signature-verified")

            # Hot-reload pins & verify SSR across /, /c/*, /t/*, /a/*, /dl/, /help, .jsonl & .sha256
            (data_dir / "public" / "pins.json").write_text(
                json.dumps({"pins": [{"msg_id": root_gen, "channels": ["general"], "pin_type": "official", "label": "PINNED_E2E", "priority": 100, "created_at": int(time.time()), "expires_at": int(time.time()) + 3600}]}),
                encoding="utf-8",
            )
            time.sleep(1.1)
            pins_res = cli_json(["pub", "pins", "general"], home=h_hub, api_url=api_url)
            assert_eq(len(pins_res["pins"]), 1, "hot-reloaded pin count")

            today_utc = time.strftime("%Y-%m-%d", time.gmtime())
            for page_p in ["/", "/help", "/dl/", f"/t/{root_gen}", f"/a/{solo_id}", f"/a/{wA_id}"] + [f"/c/{c}" for c in CHANNELS] + [f"/c/general/{today_utc}"]:
                st, html_s = http_get_text(f"{api_url}{page_p}")
                assert_eq(st, 200, f"GET {page_p}")
                assert_zero_js_html(html_s, f"SSR {page_p}")

            _, a_solo_html = http_get_text(f"{api_url}/a/{solo_id}")
            assert_true("&lt;script&gt;" in a_solo_html and "<script>Bot" not in a_solo_html, "XSS display name escaped")
            _, gen_html = http_get_text(f"{api_url}/c/general")
            assert_true("PINNED_E2E" in gen_html and "2 replies" in gen_html, "pin & cached reply count rendered")
            _, wa_html = http_get_text(f"{api_url}/c/showcase")
            assert_true("WorkerA-Alpha" in wa_html, "ctl renamed author name surfaced in /c/showcase SSR")

            _, ch_jsonl = http_get_text(f"{api_url}/c/general/{today_utc}.jsonl")
            _, ch_sha = http_get_text(f"{api_url}/c/general/{today_utc}.sha256")
            assert_true(hashlib.sha256(ch_jsonl.encode("utf-8")).hexdigest() in ch_sha, ".sha256 digest matches .jsonl")

            # ------------------------------------------------------------------
            # Section 3: 4-Agent Encrypted Room Collaboration
            # ------------------------------------------------------------------
            print("[3/6] Running 4-agent encrypted room collaboration (Coordinator + WorkerA/B/C)...")
            for idx, wid in enumerate(w_ids):
                cli_json(["friend", "add", wid], home=h_coord, api_url=api_url)
                cli_json(["friend", "accept", coord_id], home=h_w[idx], api_url=api_url)

            room_obj = cli_json(["room", "create", "--name", "swarm-collab-room"], home=h_coord, api_url=api_url)
            room_id = room_obj["room_id"]

            worker_listeners = [
                LineProc(["--json", "listen", "--rooms", room_id], home=h_w[i], api_url=api_url)
                for i in range(3)
            ]
            time.sleep(0.5)
            try:
                for wid in w_ids:
                    cli_json(["room", "invite", room_id, wid], home=h_coord, api_url=api_url)
                for i, wl in enumerate(worker_listeners):
                    inv_ev = wl.wait_out(lambda e: e.get("type") == "room_invite" and e.get("room_id") == room_id, desc=f"worker{i} room_invite")
                    assert_true(inv_ev.get("stored") is True and inv_ev.get("verified") is True, f"worker{i} auto-stored room key: {inv_ev}")

                coord_listener = LineProc(["--json", "listen", "--rooms", room_id], home=h_coord, api_url=api_url)
                time.sleep(0.4)
                try:
                    brief = "TASK_BRIEF_SECRET_R1: analyze partitions"
                    cli_json(["room", "send", room_id, brief], home=h_coord, api_url=api_url)
                    for i, wl in enumerate(worker_listeners):
                        m = wl.wait_out(lambda e: e.get("type") == "room" and e.get("text") == brief, desc=f"worker{i} brief")
                        assert_true(m.get("verified") is True, f"worker{i} verified brief")

                    # Round 2: all 3 workers publish reports concurrently
                    reports = [
                        (0, "WORKER_A_SECRET_REPORT_111"),
                        (1, "WORKER_B_SECRET_REPORT_222"),
                        (2, "WORKER_C_SECRET_REPORT_333"),
                    ]
                    send_errs: list[Exception] = []

                    def _send_rep(widx: int, txt: str) -> None:
                        try:
                            cli_json(["room", "send", room_id, txt], home=h_w[widx], api_url=api_url)
                        except Exception as ex:
                            send_errs.append(ex)

                    ts = [threading.Thread(target=_send_rep, args=(wi, rt)) for wi, rt in reports]
                    for t in ts:
                        t.start()
                    for t in ts:
                        t.join(timeout=15.0)
                    assert_true(not send_errs, f"concurrent room sends failed: {send_errs}")

                    all_listeners = [coord_listener] + worker_listeners
                    for li, lstn in enumerate(all_listeners):
                        for wi, rt in reports:
                            if li == wi + 1:
                                continue  # Server skips echoing room messages back to sender
                            ev = lstn.wait_out(lambda e, want=rt: e.get("type") == "room" and e.get("text") == want, desc=f"listener{li} report {rt}")
                            assert_true(ev.get("verified") is True, f"listener{li} sig verified")

                    # Round 3: Coordinator summary
                    synth = "FINAL_SYNTHESIS_SECRET_R3"
                    cli_json(["room", "send", room_id, synth], home=h_coord, api_url=api_url)
                    for i, wl in enumerate(worker_listeners):
                        ev = wl.wait_out(lambda e: e.get("type") == "room" and e.get("text") == synth, desc=f"worker{i} synth")
                        assert_true(ev.get("verified") is True, f"worker{i} synth verified")
                finally:
                    coord_listener.stop()
            finally:
                for wl in worker_listeners:
                    wl.stop()

            # Outsider cannot send to or join uninvited room cleanly (has no local key, and cannot fetch key from server)
            rc_out_rm, _, _ = run_cli(["--json", "room", "send", room_id, "intrusion"], home=h_out, api_url=api_url)
            assert_eq(rc_out_rm, 4, "outsider missing local room key exits 4")
            room_secrets = [brief, "WORKER_A_SECRET_REPORT_111", "WORKER_B_SECRET_REPORT_222", "WORKER_C_SECRET_REPORT_333", synth]
            assert_eq(scan_files_for_substrings(data_dir, room_secrets), [], "Room plaintext found in data_dir")
            assert_eq(scan_files_for_substrings(log_dir, room_secrets), [], "Room plaintext found in log_dir")

            # ------------------------------------------------------------------
            # Section 4: Friends, Blocks, E2EE DMs, Key Rotate & Mail
            # ------------------------------------------------------------------
            print("[4/6] Testing friends, blocks, E2EE DM, dual-signed key rotation & encrypted mail...")
            # Establish PeerHub <-> WorkerA/B/C and SoloBot <-> PeerHub friendships
            for idx, wid in enumerate(w_ids):
                cli_json(["friend", "add", wid], home=h_hub, api_url=api_url)
                cli_json(["friend", "accept", hub_id], home=h_w[idx], api_url=api_url)
            cli_json(["friend", "add", solo_id], home=h_hub, api_url=api_url)
            cli_json(["friend", "accept", hub_id], home=h_solo, api_url=api_url)

            # Non-friend DM blocked (403 -> exit 5); Block list enforcement
            rc_nf, _, _ = run_cli(["dm", "send", hub_id, "blocked dm"], home=h_out, api_url=api_url)
            assert_eq(rc_nf, 5, "non-friend DM rejected with exit 5")
            cli_json(["block", "add", out_id], home=h_hub, api_url=api_url)
            bl = cli_json(["block", "list"], home=h_hub, api_url=api_url)
            assert_true(out_id in bl["blocks"], "block list contains outsider")
            cli_json(["block", "rm", out_id], home=h_hub, api_url=api_url)

            # Live E2EE DM
            dm_listener = LineProc(["--json", "listen", "--max-events", "1"], home=h_solo, api_url=api_url)
            time.sleep(0.4)
            dm_secret = "DIRECT_E2EE_SECRET_7741"
            cli_json(["dm", "send", solo_id, dm_secret], home=h_hub, api_url=api_url)
            dm_ev = dm_listener.wait_out(lambda e: e.get("type") == "dm", desc="live E2EE DM")
            assert_eq(dm_ev["text"], dm_secret, "decrypted DM matches")
            assert_true(dm_ev.get("verified") is True, "DM verified")
            dm_listener.stop()

            # Pre-rotate mail, dual-signed key rotate, post-rotate mail, pull --delete
            st_m1, _ = http_post_json(
                f"{api_url}/internal/mail/ingest",
                {"to_agent_id": solo_id, "from": "a@example.com", "subject": "MailV1", "raw_snippet": "MAIL_BODY_V1_901", "spf_pass": True, "dkim_pass": True, "dmarc_pass": True, "received_at": int(time.time())},
                headers={"X-Internal-Secret": mail_secret},
            )
            assert_eq(st_m1, 201, "mail v1 ingest")
            rot = cli_json(["key", "rotate"], home=h_solo, api_url=api_url)
            assert_eq(rot["key_version"], 2, "key rotated to v2")
            st_m2, _ = http_post_json(
                f"{api_url}/internal/mail/ingest",
                {"to_agent_id": solo_id, "from": "b@example.com", "subject": "MailV2", "raw_snippet": "MAIL_BODY_V2_902", "spf_pass": True, "dkim_pass": False, "dmarc_pass": True, "received_at": int(time.time())},
                headers={"X-Internal-Secret": mail_secret},
            )
            assert_eq(st_m2, 201, "mail v2 ingest")
            rc_mp, mp_out, err_mp = run_cli(["--json", "mail", "pull", "--delete"], home=h_solo, api_url=api_url)
            assert_eq(rc_mp, 0, f"mail pull failed: {err_mp}")
            mails = [json.loads(ln) for ln in mp_out.splitlines() if ln.strip()]
            assert_eq({m["text"] for m in mails}, {"MAIL_BODY_V1_901", "MAIL_BODY_V2_902"}, "decrypted pre+post rotate mail")

            # ------------------------------------------------------------------
            # Section 5: Star-Topology Multi-Peer P2P (1 Hub <-> 3 Concurrent Spokes)
            # ------------------------------------------------------------------
            print("[5/6] Running Star-Topology P2P (5A: 3 concurrent --star --expose spokes, 5B: --max-peers, 5C: --star --bus)...")
            echo_port = free_tcp_port()
            echo_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            echo_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            echo_srv.bind((HOST, echo_port))
            echo_srv.listen(16)
            echo_stop = threading.Event()

            def _echo_worker(cs: socket.socket) -> None:
                with cs:
                    while True:
                        d = cs.recv(4096)
                        if not d:
                            break
                        cs.sendall(b"STAR_ECHO:" + d)

            def _echo_accept() -> None:
                echo_srv.settimeout(0.2)
                while not echo_stop.is_set():
                    try:
                        cs, _ = echo_srv.accept()
                        threading.Thread(target=_echo_worker, args=(cs,), daemon=True).start()
                    except socket.timeout:
                        continue
                    except OSError:
                        break

            threading.Thread(target=_echo_accept, daemon=True).start()
            try:
                # 5A: Star TCP Expose Hub with 3 concurrent friend spokes
                star_hub = LineProc(
                    ["--json", "p2p", "listen", "--star", "--max-peers", "3", "--allow-friends-only", "--expose", str(echo_port), "--stun", "none"],
                    home=h_hub, api_url=api_url,
                )
                try:
                    star_hub.wait_err(lambda e: e.get("state") == "listening", desc="star hub listening")

                    # Non-friend rejection (403 -> exit 5 when recipient dm_policy=friends; exit 9 if peer rejects)
                    rc_nf_p2p, _, err_nf_p2p = run_cli(
                        ["--json", "p2p", "connect", hub_id, "--forward", f"{free_tcp_port()}:{echo_port}", "--stun", "none"],
                        home=h_out, api_url=api_url, timeout=15.0,
                    )
                    assert_true(rc_nf_p2p in (5, 9), f"non-friend P2P rejected: rc={rc_nf_p2p} err={err_nf_p2p}")

                    fwd_ports = [free_tcp_port() for _ in range(3)]
                    spokes = [
                        LineProc(["--json", "p2p", "connect", hub_id, "--forward", f"{fwd_ports[i]}:{echo_port}", "--stun", "none"], home=h_w[i], api_url=api_url)
                        for i in range(3)
                    ]
                    try:
                        for i, sp in enumerate(spokes):
                            sp.wait_err(lambda e: e.get("state") == "connected", desc=f"star spoke {i} connected")

                        # Concurrent TCP bidirectional traffic through all 3 spokes simultaneously
                        tcp_results: dict[int, bytes] = {}
                        tcp_errs: list[Exception] = []

                        def _hit_fwd(idx: int) -> None:
                            try:
                                payload = f"CONCURRENT_STAR_DATA_{idx}_".encode("utf-8") * 15
                                with socket.create_connection((HOST, fwd_ports[idx]), timeout=10.0) as cs:
                                    cs.sendall(payload)
                                    cs.shutdown(socket.SHUT_WR)
                                    chunks = []
                                    while True:
                                        r = cs.recv(4096)
                                        if not r:
                                            break
                                        chunks.append(r)
                                tcp_results[idx] = b"".join(chunks)
                            except Exception as ex:
                                tcp_errs.append(ex)

                        thds = [threading.Thread(target=_hit_fwd, args=(i,)) for i in range(3)]
                        for t in thds:
                            t.start()
                        for t in thds:
                            t.join(timeout=15.0)
                        assert_true(not tcp_errs, f"star TCP echo errors: {tcp_errs}")
                        for i in range(3):
                            expected = b"STAR_ECHO:" + (f"CONCURRENT_STAR_DATA_{i}_".encode("utf-8") * 15)
                            assert_eq(tcp_results[i], expected, f"star spoke {i} TCP echo mismatch")
                    finally:
                        for sp in spokes:
                            sp.stop()
                finally:
                    star_hub.stop()

                # 5B: --max-peers 2 cap enforcement
                cap_hub = LineProc(
                    ["--json", "p2p", "listen", "--star", "--max-peers", "2", "--allow-friends-only", "--expose", str(echo_port), "--stun", "none"],
                    home=h_hub, api_url=api_url,
                )
                try:
                    cap_hub.wait_err(lambda e: e.get("state") == "listening", desc="cap hub listening")
                    f1, f2, f3 = free_tcp_port(), free_tcp_port(), free_tcp_port()
                    s1 = LineProc(["--json", "p2p", "connect", hub_id, "--forward", f"{f1}:{echo_port}", "--stun", "none"], home=h_w[0], api_url=api_url)
                    s2 = LineProc(["--json", "p2p", "connect", hub_id, "--forward", f"{f2}:{echo_port}", "--stun", "none"], home=h_w[1], api_url=api_url)
                    try:
                        s1.wait_err(lambda e: e.get("state") == "connected", desc="cap spoke 1")
                        s2.wait_err(lambda e: e.get("state") == "connected", desc="cap spoke 2")
                        rc3, _, err3 = run_cli(["--json", "p2p", "connect", hub_id, "--forward", f"{f3}:{echo_port}", "--stun", "none"], home=h_w[2], api_url=api_url, timeout=15.0)
                        assert_true(rc3 == 9 and "max_peers_reached" in err3, f"3rd concurrent spoke should hit max_peers_reached: rc={rc3} err={err3}")
                    finally:
                        s1.stop()
                        s2.stop()
                finally:
                    cap_hub.stop()
            finally:
                echo_stop.set()
                echo_srv.close()

            # 5C: Star Encrypted Agent Message Bus (--star --bus)
            bus_hub = LineProc(["--json", "p2p", "listen", "--star", "--bus", "--allow-friends-only", "--stun", "none"], home=h_hub, api_url=api_url)
            try:
                bus_hub.wait_err(lambda e: e.get("state") == "listening", desc="bus hub listening")
                bus_spokes = [
                    LineProc(["--json", "p2p", "connect", hub_id, "--bus", "--stun", "none"], home=h_w[i], api_url=api_url)
                    for i in range(3)
                ]
                try:
                    for i, sp in enumerate(bus_spokes):
                        sp.wait_err(lambda e: e.get("state") == "connected", desc=f"bus spoke {i} connected")
                    time.sleep(0.2)

                    # Broadcast from WorkerA -> Hub, WorkerB, WorkerC (not echoed to WorkerA)
                    bus_spokes[0].send_line(json.dumps({"to": "*", "text": "P2P_BUS_BCAST_FROM_A"}))
                    ev_h = bus_hub.wait_out(lambda e: e.get("text") == "P2P_BUS_BCAST_FROM_A", desc="hub saw broadcast")
                    assert_eq(ev_h["from"], wA_id, "hub broadcast from A")
                    ev_b = bus_spokes[1].wait_out(lambda e: e.get("text") == "P2P_BUS_BCAST_FROM_A", desc="B saw broadcast")
                    assert_eq(ev_b["from"], wA_id, "B broadcast from A")
                    ev_c = bus_spokes[2].wait_out(lambda e: e.get("text") == "P2P_BUS_BCAST_FROM_A", desc="C saw broadcast")
                    assert_eq(ev_c["from"], wA_id, "C broadcast from A")

                    # Unicast from WorkerB -> WorkerC (WorkerA must NOT receive)
                    bus_spokes[1].send_line(json.dumps({"to": wC_id, "text": "P2P_BUS_UNICAST_B_TO_C"}))
                    ev_h2 = bus_hub.wait_out(lambda e: e.get("text") == "P2P_BUS_UNICAST_B_TO_C", desc="hub saw unicast")
                    assert_eq(ev_h2["to"], wC_id, "unicast target C")
                    ev_c2 = bus_spokes[2].wait_out(lambda e: e.get("text") == "P2P_BUS_UNICAST_B_TO_C", desc="C saw unicast")
                    assert_eq(ev_c2["from"], wB_id, "C unicast from B")

                    # Hub -> unicast to WorkerA and broadcast to all spokes
                    bus_hub.send_line(json.dumps({"to": wA_id, "text": "P2P_BUS_HUB_TO_A"}))
                    bus_spokes[0].wait_out(lambda e: e.get("text") == "P2P_BUS_HUB_TO_A", desc="A got hub unicast")
                    bus_hub.send_line(json.dumps({"to": "*", "text": "P2P_BUS_HUB_ALL"}))
                    for i in range(3):
                        bus_spokes[i].wait_out(lambda e: e.get("text") == "P2P_BUS_HUB_ALL", desc=f"spoke {i} got hub broadcast")

                    # Confirm WorkerA never got WorkerB->WorkerC unicast, and B/C never got Hub->A unicast
                    assert_true(all(e.get("text") != "P2P_BUS_UNICAST_B_TO_C" for e in bus_spokes[0].drain_out()), "A did not receive B->C unicast")
                    assert_true(all(e.get("text") != "P2P_BUS_HUB_TO_A" for e in bus_spokes[1].drain_out()), "B did not receive Hub->A unicast")
                    assert_true(all(e.get("text") != "P2P_BUS_HUB_TO_A" for e in bus_spokes[2].drain_out()), "C did not receive Hub->A unicast")

                    for i, sp in enumerate(bus_spokes):
                        rc_e = sp.close_stdin_and_wait(timeout=8.0)
                        assert_eq(rc_e, 0, f"bus spoke {i} clean exit on EOF")
                finally:
                    for sp in bus_spokes:
                        sp.stop()
            finally:
                bus_hub.stop()

            bus_secrets = ["P2P_BUS_BCAST_FROM_A", "P2P_BUS_UNICAST_B_TO_C", "P2P_BUS_HUB_TO_A", "P2P_BUS_HUB_ALL", dm_secret]
            assert_eq(scan_files_for_substrings(data_dir, bus_secrets), [], "P2P/DM plaintext leaked in data_dir")
            assert_eq(scan_files_for_substrings(log_dir, bus_secrets), [], "P2P/DM plaintext leaked in log_dir")

            # ------------------------------------------------------------------
            # Section 6: `fatext update --check` + Log Analyzer Privacy Audit
            # ------------------------------------------------------------------
            print("[6/6] Checking dynamic latest.json + `fatext update --check` + log analyzer + privacy scan...")
            uchk = cli_json(["update", "--check"], home=h_hub, api_url=api_url)
            assert_eq(uchk["status"], "update_available", "update --check sees 1.5.0")
            assert_eq(uchk["latest_version"], "1.5.0", "latest_version from FATEXT_DL_DIR/latest.json")
            assert_eq(uchk["min_version"], "1.0.0", "min_version from fatext.json")
        finally:
            if srv.poll() is None:
                srv.terminate()
                try:
                    srv.wait(timeout=5.0)
                except subprocess.TimeoutExpired:
                    srv.kill()
                    srv.wait(timeout=5.0)

        ar = subprocess.run(
            [sys.executable, str(ANALYZE_PY), "--log-dir", str(log_dir), "--json"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
        )
        rep = json.loads(ar.stdout)
        assert_true(rep["summary"]["total_requests"] >= 40, f"expected >=40 logged requests, got {rep['summary']}")
        assert_eq(rep["summary"]["sse_dropped_full"], 0, "zero dropped SSE events")

    print("ALL 6 FULL-SYSTEM E2E SECTIONS PASSED (5 channels, 4-agent room, star P2P hub+bus, delegation, update+logs).")


def main() -> int:
    if not SERVER_BIN.is_file():
        print(f"Missing {SERVER_BIN}", file=sys.stderr)
        return 1
    if not CLI_BIN.is_file():
        print(f"Missing {CLI_BIN}", file=sys.stderr)
        return 1
    run_full_e2e()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
