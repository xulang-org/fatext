#!/usr/bin/env python3
"""End-to-end tests for Fatext Room Permissions, Settings, Roles, Lifecycle, and Automatic Rekey:
  1. room create with settings, list, info, members
  2. SSE privacy isolation (non-members never receive room frames, even with --rooms)
  3. Roles & permission matrix (owner, admin, member, readonly)
  4. Settings enforcement (send_policy, invite_policy, join_policy incl. controller_only, max_members, slow_mode_sec, locked)
  5. mute / unmute
  6. kick + automatic epoch+1 rekey (remaining decrypt, kicked rejected)
  7. ban / unban + automatic rekey
  8. Manual room rotate
  9. transfer, leave, close
 10. Server restart recovery & zero-plaintext / zero-room-key disk & log audit
"""

from __future__ import annotations

import json
import os
import queue
import socket
import subprocess
import sys
import tempfile
import threading
import time
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
        self.raw_out: list[str] = []
        self.raw_err: list[str] = []
        threading.Thread(target=self._pump, args=(self.proc.stdout, self.out_q, self.raw_out), daemon=True).start()
        threading.Thread(target=self._pump, args=(self.proc.stderr, None, self.raw_err), daemon=True).start()

    def _pump(self, pipe, q: queue.Queue[dict] | None, raw_buf: list[str]) -> None:
        if pipe is None:
            return
        for ln in iter(pipe.readline, ""):
            s = ln.strip()
            if not s:
                continue
            raw_buf.append(s)
            if q is not None:
                try:
                    q.put(json.loads(s))
                except json.JSONDecodeError:
                    q.put({"raw": s})

    def wait_out(self, pred, *, timeout: float = 12.0, desc: str = "stdout event") -> dict:
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

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=4.0)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=4.0)


def start_server(port: int, data_dir: Path, log_dir: Path) -> subprocess.Popen:
    env = os.environ.copy()
    env["FATEXT_ADDR"] = f"{HOST}:{port}"
    env["FATEXT_DATA_DIR"] = str(data_dir)
    env["FATEXT_WWW_DIR"] = str(ROOT / "www")
    env["FATEXT_TEMPLATES_DIR"] = str(ROOT / "templates")
    env["FATEXT_LOG_DIR"] = str(log_dir)
    env["FATEXT_POW_BITS"] = "8"
    env["FATEXT_IP_RPM"] = "0"
    srv = subprocess.Popen([str(SERVER_BIN)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    wait_tcp_ready(HOST, port, timeout=10.0)
    return srv


def stop_server(srv: subprocess.Popen) -> None:
    if srv.poll() is None:
        srv.terminate()
        try:
            srv.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            srv.kill()
            srv.wait(timeout=5.0)


def main() -> int:
    if not SERVER_BIN.is_file() or not CLI_BIN.is_file():
        print(f"Missing binaries: server={SERVER_BIN} cli={CLI_BIN}", file=sys.stderr)
        return 1

    port = free_tcp_port()
    api_url = f"http://{HOST}:{port}"

    with tempfile.TemporaryDirectory(prefix="fatext-rooms-e2e-") as td:
        td_p = Path(td)
        data_dir = td_p / "data"
        log_dir = td_p / "logs"
        homes = td_p / "homes"
        for d in (data_dir, log_dir, homes):
            d.mkdir(parents=True, exist_ok=True)

        srv = start_server(port, data_dir, log_dir)
        captured_secrets: list[str] = []
        try:
            h_ctrl = homes / "ctrl"
            h_own = homes / "owner"
            h_adm = homes / "admin"
            h_m1 = homes / "mem1"
            h_m2 = homes / "mem2"
            h_ro = homes / "readonly"
            h_out = homes / "outsider"
            h_out2 = homes / "outsider2"

            ctrl_id = cli_json(["init", "--controller-only", "--name", "RoomCtrl"], home=h_ctrl, api_url=api_url)["agent_id"]

            def enroll_under_ctrl(home: Path, name: str, idx: int) -> str:
                vp = td_p / f"v_{idx}.json"
                cli_json(["ctl", "cred", "issue", "--label", name, "--scopes", "all", "--ttl", "7d", "--out", str(vp)], home=h_ctrl, api_url=api_url)
                aid = cli_json(["init", "--name", name, "--credential", str(vp)], home=home, api_url=api_url)["agent_id"]
                cli_json(["profile", "set", "--dm-policy", "friends"], home=home, api_url=api_url)
                return aid

            own_id = enroll_under_ctrl(h_own, "Owner", 0)
            adm_id = enroll_under_ctrl(h_adm, "Admin", 1)
            m1_id = enroll_under_ctrl(h_m1, "MemCtrl", 2)  # Intentionally NOT friends with owner for controller_only check

            m2_id = cli_json(["init", "--name", "MemFriend"], home=h_m2, api_url=api_url)["agent_id"]
            cli_json(["profile", "set", "--dm-policy", "friends"], home=h_m2, api_url=api_url)
            ro_id = cli_json(["init", "--name", "ReadOnly"], home=h_ro, api_url=api_url)["agent_id"]
            cli_json(["profile", "set", "--dm-policy", "friends"], home=h_ro, api_url=api_url)
            out_id = cli_json(["init", "--name", "Outsider"], home=h_out, api_url=api_url)["agent_id"]
            out2_id = cli_json(["init", "--name", "Outsider2"], home=h_out2, api_url=api_url)["agent_id"]
            assert_true(bool(ctrl_id and out2_id), "identities initialized")

            # Friendships for own <-> adm, own <-> m2, own <-> ro (NOT m1, NOT out)
            for fh, fid in ((h_adm, adm_id), (h_m2, m2_id), (h_ro, ro_id)):
                cli_json(["friend", "add", fid], home=h_own, api_url=api_url)
                cli_json(["friend", "accept", own_id], home=fh, api_url=api_url)

            # --------------------------------------------------------------
            # 1. Create room with settings, list, info, members
            # --------------------------------------------------------------
            print("[1/10] Testing room create with settings, list, info, members...")
            cr = cli_json([
                "room", "create",
                "--name", "SecOps",
                "--topic", "Encrypted Coordination",
                "--send-policy", "all",
                "--invite-policy", "admins",
                "--join-policy", "invite_only",
                "--max-members", "5",
                "--slow-mode", "0",
            ], home=h_own, api_url=api_url)
            rid = cr["room_id"]
            assert_eq(cr["epoch"], 1, "initial epoch")
            assert_eq(cr["max_members"], 5, "initial max_members")

            lst = cli_json(["room", "list"], home=h_own, api_url=api_url)
            assert_true(any(x["room_id"] == rid for x in lst["rooms"]), "room in owner list")
            inf = cli_json(["room", "info", rid], home=h_own, api_url=api_url)["room"]
            assert_eq(inf["topic"], "Encrypted Coordination", "topic stored")
            assert_eq(inf["your_role"], "owner", "owner role")

            # Outsider cannot inspect room metadata
            rc_oi, _, _ = run_cli(["room", "info", rid], home=h_out, api_url=api_url)
            assert_eq(rc_oi, 5, "outsider room info rejected exit 5")

            # --------------------------------------------------------------
            # 2. Invite Admin, MemFriend, ReadOnly + SSE privacy isolation
            # --------------------------------------------------------------
            print("[2/10] Testing SSE privacy isolation & role invites...")
            l_adm = LineProc(["--json", "listen", "--rooms", rid], home=h_adm, api_url=api_url)
            l_m2 = LineProc(["--json", "listen", "--rooms", rid], home=h_m2, api_url=api_url)
            l_ro = LineProc(["--json", "listen", "--rooms", rid], home=h_ro, api_url=api_url)
            l_out_all = LineProc(["--json", "listen"], home=h_out, api_url=api_url)
            l_out_sub = LineProc(["--json", "listen", "--rooms", rid], home=h_out2, api_url=api_url)
            time.sleep(0.5)
            try:
                inv_adm = cli_json(["room", "invite", rid, adm_id, "--role", "admin"], home=h_own, api_url=api_url)
                assert_eq(inv_adm["role"], "admin", "invited as admin")
                ev_adm_inv = l_adm.wait_out(lambda e: e.get("type") == "room_invite" and e.get("room_id") == rid, desc="admin invite")
                assert_true(ev_adm_inv.get("stored") is True and ev_adm_inv.get("verified") is True, "admin invite stored")

                cli_json(["room", "invite", rid, m2_id, "--role", "member"], home=h_adm, api_url=api_url)
                cli_json(["room", "invite", rid, ro_id, "--role", "readonly"], home=h_adm, api_url=api_url)

                for lbl, lp in (("mem2", l_m2), ("ro", l_ro)):
                    ev = lp.wait_out(lambda e: e.get("type") == "room_invite" and e.get("room_id") == rid, desc=f"{lbl} invite")
                    assert_true(ev.get("stored") is True and ev.get("verified") is True, f"{lbl} invite stored")

                msg_r1 = "SECRET_ROOM_MSG_E1_HELLO"
                captured_secrets.append(msg_r1)
                cli_json(["room", "send", rid, msg_r1], home=h_own, api_url=api_url)
                for lbl, lp in (("admin", l_adm), ("mem2", l_m2), ("ro", l_ro)):
                    ev = lp.wait_out(lambda e: e.get("type") == "room" and e.get("text") == msg_r1, desc=f"{lbl} recv E1")
                    assert_true(ev.get("verified") is True, f"{lbl} verified E1")

                time.sleep(0.3)
                assert_true(all(e.get("type") != "room" for e in l_out_all.drain_out()), "non-member without --rooms gets 0 room frames")
                assert_true(all(e.get("type") != "room" for e in l_out_sub.drain_out()), "non-member with --rooms gets 0 room frames")

                # ----------------------------------------------------------
                # 3. Roles & permission matrix + 4. Settings enforcement
                # ----------------------------------------------------------
                print("[3/10] Testing roles & permission boundaries...")
                rc_ro_send, _, _ = run_cli(["room", "send", rid, "ro try"], home=h_ro, api_url=api_url)
                assert_eq(rc_ro_send, 5, "readonly cannot send")
                rc_ro_inv, _, _ = run_cli(["room", "invite", rid, out_id], home=h_ro, api_url=api_url)
                assert_eq(rc_ro_inv, 5, "readonly cannot invite")
                rc_m2_inv, _, _ = run_cli(["room", "invite", rid, out_id], home=h_m2, api_url=api_url)
                assert_eq(rc_m2_inv, 5, "member cannot invite when invite_policy=admins")

                # Admin cannot change owner/join_policy/invite_policy or send_policy=owner
                rc_adm_jp, _, _ = run_cli(["room", "set", rid, "--join-policy", "friends_only"], home=h_adm, api_url=api_url)
                assert_eq(rc_adm_jp, 5, "admin cannot change join_policy")
                rc_adm_ip, _, _ = run_cli(["room", "set", rid, "--invite-policy", "owner"], home=h_adm, api_url=api_url)
                assert_eq(rc_adm_ip, 5, "admin cannot change invite_policy")
                rc_adm_sp, _, _ = run_cli(["room", "set", rid, "--send-policy", "owner"], home=h_adm, api_url=api_url)
                assert_eq(rc_adm_sp, 5, "admin cannot set send_policy=owner")
                rc_adm_kick_own, _, _ = run_cli(["room", "kick", rid, own_id], home=h_adm, api_url=api_url)
                assert_eq(rc_adm_kick_own, 5, "admin cannot kick owner")

                print("[4/10] Testing send_policy, invite_policy, join_policy (friends_only & controller_only), max_members, slow_mode, locked...")
                cli_json(["room", "set", rid, "--send-policy", "admins"], home=h_own, api_url=api_url)
                rc_m2_adm_sp, _, _ = run_cli(["room", "send", rid, "blocked by send_policy"], home=h_m2, api_url=api_url)
                assert_eq(rc_m2_adm_sp, 5, "member blocked by send_policy=admins")
                cli_json(["room", "send", rid, "ADMIN_OK_POLICY"], home=h_adm, api_url=api_url)
                captured_secrets.append("ADMIN_OK_POLICY")
                l_m2.wait_out(lambda e: e.get("text") == "ADMIN_OK_POLICY", desc="m2 receives admin msg")

                cli_json(["room", "set", rid, "--send-policy", "owner"], home=h_own, api_url=api_url)
                rc_adm_own_sp, _, _ = run_cli(["room", "send", rid, "admin blocked by owner policy"], home=h_adm, api_url=api_url)
                assert_eq(rc_adm_own_sp, 5, "admin blocked by send_policy=owner")
                cli_json(["room", "set", rid, "--send-policy", "all"], home=h_own, api_url=api_url)

                # join_policy = friends_only blocks outsider
                cli_json(["room", "set", rid, "--join-policy", "friends_only"], home=h_own, api_url=api_url)
                rc_jp_out, _, err_jp = run_cli(["room", "invite", rid, out_id], home=h_own, api_url=api_url)
                assert_true(rc_jp_out == 5 and "ERR_FRIENDS_ONLY" in err_jp, f"friends_only blocks outsider: {rc_jp_out} {err_jp}")

                # join_policy = controller_only allows MemCtrl (NOT friend of Owner!) without friendship
                cli_json(["room", "set", rid, "--join-policy", "controller_only"], home=h_own, api_url=api_url)
                rc_ctrl_out, _, _ = run_cli(["room", "invite", rid, out_id], home=h_own, api_url=api_url)
                assert_eq(rc_ctrl_out, 5, "controller_only blocks non-ctrl outsider")

                l_m1 = LineProc(["--json", "listen", "--rooms", rid], home=h_m1, api_url=api_url)
                time.sleep(0.4)
                try:
                    cli_json(["room", "invite", rid, m1_id, "--role", "member"], home=h_own, api_url=api_url)
                    ev_m1_inv = l_m1.wait_out(lambda e: e.get("type") == "room_invite" and e.get("room_id") == rid, desc="m1 ctrl invite")
                    assert_true(ev_m1_inv.get("stored") is True, "controller_only invite auto-stored without friendship")

                    # max_members = 5 is now reached (own, adm, m2, ro, m1)
                    cli_json(["room", "set", rid, "--join-policy", "invite_only"], home=h_own, api_url=api_url)
                    rc_full, _, err_full = run_cli(["room", "invite", rid, out_id], home=h_own, api_url=api_url)
                    assert_true(rc_full == 6 and "ERR_ROOM_FULL" in err_full, f"max_members full expected exit 6: {rc_full} {err_full}")

                    # slow_mode_sec = 2
                    cli_json(["room", "set", rid, "--slow-mode", "2"], home=h_adm, api_url=api_url)
                    cli_json(["room", "send", rid, "SLOW_FIRST"], home=h_m2, api_url=api_url)
                    rc_sl, _, err_sl = run_cli(["room", "send", rid, "SLOW_SECOND"], home=h_m2, api_url=api_url)
                    assert_true(rc_sl == 75 and "ERR_RATE_LIMITED" in err_sl, f"slow mode expected exit 75: {rc_sl} {err_sl}")
                    cli_json(["room", "send", rid, "ADMIN_SLOW_BYPASS_1"], home=h_adm, api_url=api_url)
                    cli_json(["room", "send", rid, "ADMIN_SLOW_BYPASS_2"], home=h_adm, api_url=api_url)
                    time.sleep(2.1)
                    cli_json(["room", "send", rid, "SLOW_AFTER_COOLDOWN"], home=h_m2, api_url=api_url)
                    cli_json(["room", "set", rid, "--slow-mode", "0"], home=h_adm, api_url=api_url)

                    # lock / unlock
                    cli_json(["room", "set", rid, "--lock"], home=h_adm, api_url=api_url)
                    rc_lk, _, err_lk = run_cli(["room", "send", rid, "blocked by lock"], home=h_m2, api_url=api_url)
                    assert_true(rc_lk == 5 and "ERR_ROOM_LOCKED" in err_lk, f"lock blocks member: {rc_lk} {err_lk}")
                    cli_json(["room", "set", rid, "--unlock"], home=h_adm, api_url=api_url)

                    # ------------------------------------------------------
                    # 5. Mute / Unmute + role toggle
                    # ------------------------------------------------------
                    print("[5/10] Testing mute / unmute and role change...")
                    cli_json(["room", "mute", rid, m2_id], home=h_adm, api_url=api_url)
                    rc_mu, _, err_mu = run_cli(["room", "send", rid, "muted send"], home=h_m2, api_url=api_url)
                    assert_true(rc_mu == 5 and "ERR_ROOM_MUTED" in err_mu, f"mute blocks send: {rc_mu} {err_mu}")
                    cli_json(["room", "unmute", rid, m2_id], home=h_adm, api_url=api_url)
                    cli_json(["room", "send", rid, "UNMUTED_OK"], home=h_m2, api_url=api_url)

                    # ------------------------------------------------------
                    # 6. Kick + automatic epoch+1 rekey
                    # ------------------------------------------------------
                    print("[6/10] Testing kick + automatic epoch=2 rekey...")
                    l_adm.drain_out()
                    l_m1.drain_out()
                    l_m2.drain_out()
                    kres = cli_json(["room", "kick", rid, m2_id], home=h_own, api_url=api_url)
                    assert_true(kres["epoch"] == 2 and kres["rekeyed"] is True, f"kick rekey response: {kres}")

                    l_adm.wait_out(lambda e: e.get("type") == "room_rekey" and e.get("epoch") == 2 and e.get("stored") is True, desc="admin stored epoch 2")
                    l_m1.wait_out(lambda e: e.get("type") == "room_rekey" and e.get("epoch") == 2 and e.get("stored") is True, desc="m1 stored epoch 2")
                    l_ro.wait_out(lambda e: e.get("type") == "room_rekey" and e.get("epoch") == 2 and e.get("stored") is True, desc="ro stored epoch 2")
                    l_m2.wait_out(lambda e: e.get("type") == "room_event" and e.get("data", {}).get("kind") == "member_kicked", desc="m2 kicked room_event")

                    msg_e2 = "SECRET_EPOCH2_AFTER_KICK"
                    captured_secrets.append(msg_e2)
                    cli_json(["room", "send", rid, msg_e2], home=h_own, api_url=api_url)
                    l_adm.wait_out(lambda e: e.get("type") == "room" and e.get("text") == msg_e2, desc="admin decrypts epoch 2")
                    l_m1.wait_out(lambda e: e.get("type") == "room" and e.get("text") == msg_e2, desc="m1 decrypts epoch 2")
                    rc_km2, _, _ = run_cli(["room", "send", rid, "kicked send"], home=h_m2, api_url=api_url)
                    assert_eq(rc_km2, 5, "kicked member cannot send")
                    time.sleep(0.25)
                    assert_true(all(e.get("text") != msg_e2 for e in l_m2.drain_out()), "kicked member never sees epoch 2 message")

                    # Re-invite m2 with updated key after kick (requires re-friend not needed since invite_only, m2 still friends with owner)
                    cli_json(["room", "invite", rid, m2_id, "--role", "member"], home=h_own, api_url=api_url)
                    l_m2.wait_out(lambda e: e.get("type") == "room_invite" and e.get("room_id") == rid and e.get("stored") is True, desc="m2 re-invited at epoch 2")

                    # ------------------------------------------------------
                    # 7. Ban / Unban + automatic epoch+1 rekey
                    # ------------------------------------------------------
                    print("[7/10] Testing ban / unban + automatic epoch=3 rekey...")
                    bres = cli_json(["room", "ban", rid, m2_id], home=h_own, api_url=api_url)
                    assert_eq(bres["epoch"], 3, "ban bumped epoch to 3")
                    l_adm.wait_out(lambda e: e.get("type") == "room_rekey" and e.get("epoch") == 3 and e.get("stored") is True, desc="admin stored epoch 3")
                    l_m1.wait_out(lambda e: e.get("type") == "room_rekey" and e.get("epoch") == 3 and e.get("stored") is True, desc="m1 stored epoch 3")
                    rc_bi, _, err_bi = run_cli(["room", "invite", rid, m2_id], home=h_own, api_url=api_url)
                    assert_true(rc_bi == 5 and "ERR_ROOM_BANNED" in err_bi, f"banned invite blocked: {rc_bi} {err_bi}")

                    cli_json(["room", "unban", rid, m2_id], home=h_own, api_url=api_url)
                    cli_json(["room", "invite", rid, m2_id, "--role", "member"], home=h_own, api_url=api_url)
                    l_m2.wait_out(lambda e: e.get("type") == "room_invite" and e.get("stored") is True, desc="m2 re-invited after unban")

                    # ------------------------------------------------------
                    # 8. Manual rotate -> epoch=4
                    # ------------------------------------------------------
                    print("[8/10] Testing manual room rotate -> epoch=4...")
                    rrot = cli_json(["room", "rotate", rid], home=h_own, api_url=api_url)
                    assert_eq(rrot["epoch"], 4, "manual rotate epoch=4")
                    l_m1.wait_out(lambda e: e.get("type") == "room_rekey" and e.get("epoch") == 4 and e.get("stored") is True, desc="m1 stored epoch 4")
                    l_m2.wait_out(lambda e: e.get("type") == "room_rekey" and e.get("epoch") == 4 and e.get("stored") is True, desc="m2 stored epoch 4")
                    msg_e4 = "SECRET_EPOCH4_MANUAL_ROTATE"
                    captured_secrets.append(msg_e4)
                    cli_json(["room", "send", rid, msg_e4], home=h_m1, api_url=api_url)
                    l_m2.wait_out(lambda e: e.get("type") == "room" and e.get("text") == msg_e4, desc="m2 decrypts epoch 4")

                    # ------------------------------------------------------
                    # 9. Leave & Transfer & Role Promotion
                    # ------------------------------------------------------
                    print("[9/10] Testing role, leave, transfer, and close...")
                    cli_json(["room", "role", rid, ro_id, "member"], home=h_own, api_url=api_url)
                    cli_json(["room", "send", rid, "RO_PROMOTED_OK"], home=h_ro, api_url=api_url)

                    rc_ol, _, _ = run_cli(["room", "leave", rid], home=h_own, api_url=api_url)
                    assert_eq(rc_ol, 6, "owner cannot leave without transfer")
                    cli_json(["room", "leave", rid], home=h_m2, api_url=api_url)
                    assert_true(not (h_m2 / "rooms" / f"{rid}.json").exists(), "m2 local room file deleted on leave")
                    rc_ml, _, _ = run_cli(["room", "send", rid, "after leave"], home=h_m2, api_url=api_url)
                    assert_true(rc_ml in (4, 5), "left member cannot send")

                    cli_json(["room", "transfer", rid, adm_id], home=h_own, api_url=api_url)
                    inf_t = cli_json(["room", "info", rid], home=h_adm, api_url=api_url)["room"]
                    assert_eq(inf_t["owner_id"], adm_id, "ownership transferred to admin")
                    assert_eq(inf_t["your_role"], "owner", "new owner role reflected")

                    # ------------------------------------------------------
                    # 10. Restart persistence check + close + zero-key/zero-plaintext audit
                    # ------------------------------------------------------
                    print("[10/10] Testing server restart persistence, room close, and zero-plaintext/key audit...")
                    local_room_file = json.loads((h_adm / "rooms" / f"{rid}.json").read_text(encoding="utf-8"))
                    captured_secrets.append(local_room_file["key"])

                    stop_server(srv)
                    srv = start_server(port, data_dir, log_dir)

                    inf_p = cli_json(["room", "info", rid], home=h_adm, api_url=api_url)["room"]
                    assert_eq(inf_p["owner_id"], adm_id, "owner persisted across restart")
                    assert_eq(inf_p["epoch"], 4, "epoch persisted across restart")
                    assert_eq(inf_p["topic"], "Encrypted Coordination", "topic persisted across restart")

                    # Old owner (now admin) cannot close; new owner closes room
                    rc_oc, _, _ = run_cli(["room", "close", rid], home=h_own, api_url=api_url)
                    assert_eq(rc_oc, 5, "former owner (now admin) cannot close")
                    cli_json(["room", "close", rid], home=h_adm, api_url=api_url)
                    assert_true(not (h_adm / "rooms" / f"{rid}.json").exists(), "owner local room file deleted on close")
                    rc_cs, _, err_cs = run_cli(["room", "send", rid, "closed"], home=h_m1, api_url=api_url)
                    assert_true(rc_cs == 5 and "ERR_ROOM_CLOSED" in err_cs, f"closed room rejects send: {rc_cs} {err_cs}")
                finally:
                    l_m1.stop()
            finally:
                for lp in (l_adm, l_m2, l_ro, l_out_all, l_out_sub):
                    lp.stop()
        finally:
            stop_server(srv)

        assert_eq(scan_files_for_substrings(data_dir, captured_secrets), [], "Room key or plaintext leaked in data_dir")
        assert_eq(scan_files_for_substrings(log_dir, captured_secrets), [], "Room key or plaintext leaked in log_dir")

    print("ALL 10 ROOM PERMISSIONS, SETTINGS, ROLES & REKEY TESTS PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
