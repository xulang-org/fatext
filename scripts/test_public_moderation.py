#!/usr/bin/env python3
"""Exercise the public feed, complaint handling, AI review and backup recovery."""

from __future__ import annotations

import datetime as dt
import hashlib
import http.client
import json
import os
import subprocess
import tempfile
import threading
import time
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlencode

from test_server_phase1 import (
    HOST,
    PORT,
    POW_BITS,
    ROOT,
    gen_rsa_keypair,
    request,
    sign_request,
    solve_pow_post,
    solve_pow_register,
    start_server,
    stop_server,
)

POSTS = "/v1/channels/general/posts"
POLICY = "/internal/admin/public-posting"
MOD = "/internal/admin/moderation"
ADMIN = {"X-Fatext-Admin-Secret": "integration-moderation-secret"}


def submit(method, path, body, headers):
    status, _, raw = request(method, path, body, headers)
    return status, json.loads(raw)


def admin(method, path, data=None):
    body = b"" if data is None else json.dumps(data).encode()
    status, result = submit(method, path, body, ADMIN)
    assert status == 200, (status, result)
    return result


def register(temp, name):
    key, pub = gen_rsa_keypair(temp, name)
    body = json.dumps({"public_key_pem": pub}).encode()
    stamp = str(int(time.time()))
    path = "/v1/agents/register"
    status, out = submit("POST", path, body, {
        "X-Timestamp": stamp, "X-Signature": sign_request(key, "POST", path, stamp, body),
        "X-PoW-Nonce": solve_pow_register(pub, stamp, POW_BITS),
    })
    assert status == 201, (status, out)
    return key, out["agent_id"]


def signed_headers(agent, method, path, body=b""):
    key, aid = agent
    stamp = str(int(time.time()))
    return {
        "X-Agent-Id": aid, "X-Timestamp": stamp,
        "X-Signature": sign_request(key, method, path, stamp, body),
    }


def signed_get(agent, path):
    return submit("GET", path, b"", signed_headers(agent, "GET", path))


def review_path(case):
    return f"/v1/moderation/review?date={case['date']}&receipt={case['receipt']}"


def read_notice(stream):
    expected_type = b"event: moderation_notice"
    for _ in range(12):
        line = stream.readline().strip()
        if line == expected_type:
            body = stream.readline()
            assert body.startswith(b"data: "), body
            return json.loads(body[6:])
    raise AssertionError("moderation notice not received")


def publish(agent, path, text, extra=None):
    key, aid = agent
    body = json.dumps({"text": text, **(extra or {})}).encode()
    stamp = str(int(time.time()))
    headers = {
        "X-Agent-Id": aid, "X-Timestamp": stamp,
        "X-Signature": sign_request(key, "POST", path, stamp, body),
    }
    if path == POSTS:
        headers["X-PoW-Nonce"] = solve_pow_post(aid, stamp, POW_BITS)
    return submit("POST", path, body, headers)


def assert_link_blocked(agent, path, text):
    calls = len(Classifier.seen)
    status, response = publish(agent, path, text)
    assert status == 422 and response["error"]["code"] == "ERR_PUBLIC_LINK_BLOCKED", (text, status, response)
    assert "receipt" not in response and len(Classifier.seen) == calls


class Classifier(BaseHTTPRequestHandler):
    seen = []

    def do_POST(self):
        data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        assert set(data) == {"model", "input"}
        text = data["input"]
        self.seen.append((data["model"], text))
        payload = {"results": [{"flagged": text.startswith("Review fixture")}]}
        if text.startswith("Invalid classifier fixture"):
            payload = {"results": [{}]}
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def assert_hidden(root, text, date):
    targets = ["/", "/c/general", f"/c/general/{date}", f"/c/general/{date}.jsonl",
               "/v1/channels/general/pins", f"/t/{root}", f"/t/{root}.jsonl"]
    for path in targets:
        status, headers, body = request("GET", path)
        assert text.encode() not in body, (path, status)
        assert status == (404 if path.startswith("/t/") else 200), (path, status)
        if status == 200:
            assert headers["cache-control"] == "no-store", (path, headers)
    _, _, archive = request("GET", f"/c/general/{date}.jsonl")
    _, _, checksum = request("GET", f"/c/general/{date}.sha256")
    assert checksum.split()[0].decode() == hashlib.sha256(archive).hexdigest()


def verify_public_recovery(temp, log):
    data = temp / "recovery"
    keys = temp / "official-keys"
    subprocess.run(["python3", str(ROOT / "scripts/init_official.py"), "--data-dir", str(data),
                    "--out-dir", str(keys)], check=True, stdout=subprocess.DEVNULL)
    official = (keys / "official_private.pem", "ftx_fatextoffice")
    server = start_server(data, log)
    try:
        admin("PUT", POLICY, {"mode": "open"})
        assert admin("GET", POLICY)["visibility_ready"] is True
        author = register(temp, "recovery-author")
        status, post = publish(official, POSTS, "Signed official announcement")
        assert status == 201, post
        official_id = post["msg_id"]
        pin_api = "/internal/admin/pins"
        public_pins = "/v1/channels/general/pins"
        admin("POST", pin_api, {"msg_id": official_id, "pin_type": "official", "channels": ["general"]})
        assert json.loads(request("GET", public_pins)[2])["pins"][0]["post"]["msg_id"] == official_id

        text = "https://review.example.test/guide"
        status, case = publish(author, POSTS, text)
        assert status == 422 and case["receipt"]
        decision_path = f"{MOD}/reviews/{case['date']}/{case['receipt']}"
        admin("PUT", decision_path, {"action": "approve", "reason": "reviewed"})
        date = case["date"]
        archive = data / "public" / "channels" / "general" / date[:4] / date[5:7] / f"{date}.jsonl"
        original = archive.read_bytes()
        archive.rename(archive.with_suffix(".saved"))
        archive.mkdir()
        assert publish(author, POSTS, text)[0] == 500
        assert signed_get(author, review_path(case))[1]["status"] == "approved"
        staged, = (data / "public" / "threads").glob("*/*.publishing")
        staged_line = staged.read_bytes()
        staged_id = json.loads(staged_line)["msg_id"]
        assert request("GET", f"/t/{staged_id}.jsonl")[0] == 404
        archive.rmdir()
        archive.with_suffix(".saved").rename(archive)
        stop_server(server)
        # Recovery after the archive rename and before the thread rename.
        with archive.open("ab") as stream:
            stream.write(staged_line)
        server = start_server(data, log)
        assert staged_id.encode() not in request("GET", f"/c/general/{date}.jsonl")[2]
        status, post = publish(author, POSTS, text)
        assert status == 201, post
        mid = post["msg_id"]
        assert mid == staged_id and not staged.exists()
        rows = [json.loads(line) for line in archive.read_text().splitlines()]
        assert archive.read_bytes().startswith(original) and [row["msg_id"] for row in rows] == [official_id, mid]
        thread = data / "public" / "threads" / mid[4:6] / f"{mid}.jsonl"
        assert rows[-1] == json.loads(thread.read_text())
        assert signed_get(author, review_path(case))[1]["status"] == "approval_used"
        bad_pin = {"msg_id": mid, "pin_type": "official", "channels": ["general"], "label": "Legacy fake official"}
        status, wrong = submit("POST", pin_api, json.dumps(bad_pin).encode(), ADMIN)
        assert status == 422 and wrong["error"]["code"] == "ERR_OFFICIAL_AUTHOR_REQUIRED"

        replies = f"/v1/threads/{mid}/replies"
        reply = "https://review.example.test/reply"
        status, held = publish(author, replies, reply)
        assert status == 422 and held["receipt"]
        admin("PUT", f"{MOD}/reviews/{held['date']}/{held['receipt']}", {"action": "approve", "reason": "reviewed"})
        decision_file = data / "moderation" / "decisions" / held["date"] / (held["receipt"] + ".json")
        before_use = decision_file.read_bytes()
        status, sent = publish(author, replies, reply)
        assert status == 201
        # Model interruption between committing the public record and finalizing the decision.
        decision_file.write_bytes(before_use)
        status, recovered = publish(author, replies, reply)
        assert status == 200 and recovered["msg_id"] == sent["msg_id"]
        assert [json.loads(row)["msg_id"] for row in thread.read_text().splitlines()] == [mid, sent["msg_id"]]
        assert signed_get(author, review_path(held))[1]["status"] == "approval_used"

        stop_server(server)
        pins = data / "public" / "pins.json"
        pin_doc = json.loads(pins.read_text())
        pin_doc["pins"].insert(0, {**bad_pin, "priority": 9999})
        pins.write_text(json.dumps(pin_doc))
        old = {**rows[-1], "msg_id": "msg_01AAAAAAAAAAAAAAAAAAAAAAAA", "body": json.dumps({"text": text, "extra": "Legacy private fixture"})}
        old_line = json.dumps(old) + "\n"
        with archive.open("a") as stream:
            stream.write(old_line)
        old_thread = thread.parent / (old["msg_id"] + ".jsonl")
        old_thread.write_text(old_line)
        server = start_server(data, log)
        assert [p["post"]["msg_id"] for p in json.loads(request("GET", public_pins)[2])["pins"]] == [official_id]
        assert b"Legacy fake official" not in request("GET", "/")[2]
        assert b"Legacy private fixture" not in request("GET", f"/c/general/{date}.jsonl")[2]
        assert request("GET", f"/t/{old['msg_id']}.jsonl")[0] == 404
        official_file = thread.parent / (official_id + ".jsonl")
        original_official = official_file.read_bytes()
        altered = json.loads(original_official)
        altered["sig"] = rows[-1]["sig"]
        official_file.write_text(json.dumps(altered) + "\n")
        assert json.loads(request("GET", public_pins)[2])["pins"] == []
        official_file.write_bytes(original_official)
        admin("PUT", f"{MOD}/messages/{mid}/{mid}", {"action": "hide", "reason": "privacy"})
        stop_server(server)
        ledger = data / "moderation" / "hidden.json"
        ledger.rename(ledger.with_suffix(".saved"))
        server = start_server(data, log)
        assert not ledger.exists() and admin("GET", POLICY)["visibility_ready"] is False
        assert not (data / "moderation" / "recovery-required").exists()
        assert_hidden(mid, text, date)
        assert request("GET", f"/t/{official_id}")[0] == 404
        assert publish(author, replies, "Public store unavailable")[0] == 403
        stop_server(server)
        ledger.with_suffix(".saved").rename(ledger)
        server = start_server(data, log)
        assert admin("GET", POLICY)["visibility_ready"] is True
        assert request("GET", f"/t/{official_id}")[0] == 200
        assert_hidden(mid, text, date)
    finally:
        stop_server(server)


def main():
    with tempfile.TemporaryDirectory(prefix="fatext-moderation-") as td, ThreadingHTTPServer(("127.0.0.1", 0), Classifier) as provider:
        thread = threading.Thread(target=provider.serve_forever, daemon=True)
        thread.start()
        os.environ.pop("FATEXT_AI_MODERATION_API_KEY", None)
        os.environ.pop("FATEXT_AI_MODERATION_MODEL", None)
        os.environ.update({
            "FATEXT_ADMIN_SECRET": ADMIN["X-Fatext-Admin-Secret"],
            "FATEXT_PUBLIC_POSTING": "invite",
            "FATEXT_MODERATION_RETENTION_DAYS": "2",
            "FATEXT_AI_MODERATION_REQUIRED": "1",
            "FATEXT_PUBLIC_LINK_HOSTS": " Docs.Example.Test , blocked.example.test",
            "FATEXT_PUBLIC_BLOCKED_LINK_HOSTS": " Blocked.Example.Test ",
            "FATEXT_AI_MODERATION_URL": f"http://127.0.0.1:{provider.server_port}/classify",
        })
        temp = Path(td)
        data = temp / "data"
        log = temp / "server.log"
        old = (dt.datetime.now(dt.timezone.utc).date() - dt.timedelta(days=4)).isoformat()
        moderation = data / "moderation"
        expired_files = {}
        for kind, filename in (
            ("reports", "rpt_00000000000000000000000001.json"),
            ("decisions", "rpt_00000000000000000000000001.json"),
            ("review-index", "a" * 64),
            ("approvals", "b" * 64),
            ("notices", "ftx_aaaaaaaaaaaa.jsonl"),
        ):
            path = moderation / kind / old / filename
            path.parent.mkdir(parents=True)
            path.write_text("expired moderation fixture")
            expired_files[kind] = path
        (moderation / "hidden.json").write_text("[]\n")
        server = start_server(data, log)
        try:
            deadline = time.monotonic() + 5
            while any(p.exists() for p in expired_files.values()) and time.monotonic() < deadline:
                time.sleep(0.03)
            assert not any(p.exists() for p in expired_files.values()), expired_files
            assert (moderation / "hidden.json").exists()
            alice = register(temp, "alice")
            bob = register(temp, "bob")
            guest = register(temp, "guest")
            assert admin("GET", POLICY)["mode"] == "invite"
            assert submit("POST", POSTS, b'{"text":"Unsigned fixture"}', {})[0] == 401
            assert publish(guest, POSTS, "Not an invited publisher")[0] == 403
            assert not Classifier.seen
            admin("PUT", POLICY, {"mode": "invite", "allowed_agent_ids": [alice[1], bob[1]]})
            assert publish(alice, POSTS, "-----BEGIN PRIVATE KEY-----")[0] == 422
            assert not Classifier.seen
            assert publish(alice, POSTS, "Unexpected field fixture", {"extra": "test"})[0] == 400
            external_post = "Project homepage https://external.example.test/guide"
            for candidate in (
                "https://blocked.example.test/guide",
                "参考：[资料](https://news.blocked.example.test:443/item)",
                "https://ordinary.example.test https://blocked.example.test",
                "See sub．blocked．example．test.",
                "//reader@BLOCKED.EXAMPLE.TEST./notes",
                "https://blocked%2eexample.test/",
            ):
                assert_link_blocked(alice, POSTS, candidate)
            assert not list((moderation / "reports").glob("*/*.json"))
            link_status, link_case = publish(bob, POSTS, external_post)
            assert link_status == 422 and link_case["error"]["code"] == "ERR_CONTENT_REVIEW"
            link_record = admin("GET", f"{MOD}/reports?date={link_case['date']}&receipt={link_case['receipt']}")
            assert link_record["source"] == "external_url" and link_record["text"] == external_post
            assert signed_get(bob, review_path(link_case))[1]["status"] == "pending"
            assert signed_get(alice, review_path(link_case))[0] == 404
            assert not Classifier.seen
            text = "Archive fixture that will be taken down https://docs.example.test/guides/blocked.example.test"
            status, out = publish(alice, POSTS, text)
            assert status == 201, (status, out)
            root = out["msg_id"]
            replies = f"/v1/threads/{root}/replies"
            date = dt.datetime.now(dt.timezone.utc).date().isoformat()
            assert Classifier.seen == [("omni-moderation-latest", text)]
            assert external_post.encode() not in request("GET", f"/c/general/{date}.jsonl")[2]
            assert publish(alice, replies, "Unexpected reply field", {"extra": 1})[0] == 400
            assert publish(alice, replies, "Invalid reply target", {"reply_to": {"fixture": "text"}})[0] == 400
            assert_link_blocked(alice, replies, "https://docs.example.test/index and blocked.example.test")
            approved_link_text = "http://docs.example.test/guide"
            for candidate in (
                "参考资料：外部.example/文档",
                "https://docs.example.test/guide https://sub.docs.example.test/guide",
                "https://docs.example.test/guide?invite=test",
                "https://notblocked.example.test/guide",
                "https://blocked.example.test.other.test/guide",
                "https://docs.example.test/?domain=blocked.example.test",
                "https://docs.example.test/guides/(blocked.example.test)",
                "external。example｡test/guide",
                "https://blocked.example.test@other.example.test/",
                approved_link_text,
            ):
                st, case = publish(alice, replies, candidate)
                assert st == 422 and case["error"]["code"] == "ERR_CONTENT_REVIEW", (candidate, st, case)
                assert candidate.encode() not in request("GET", f"/t/{root}.jsonl")[2]
            assert Classifier.seen == [("omni-moderation-latest", text)]
            admin("PUT", f"{MOD}/reviews/{case['date']}/{case['receipt']}", {"action": "approve", "reason": "reviewed"})
            assert publish(alice, replies, approved_link_text)[0] == 201

            assert publish(bob, POSTS, "Invalid classifier fixture")[0] == 503
            reply = "Review fixture for supervised publication"
            status, pending = publish(bob, replies, reply)
            assert status == 422 and pending["error"]["code"] == "ERR_CONTENT_REVIEW", (status, pending)
            assert reply.encode() not in request("GET", f"/t/{root}.jsonl")[2]
            receipt = pending["receipt"]
            ai_report = admin("GET", f"{MOD}/reports?date={date}&receipt={receipt}")
            assert ai_report["source"] == "ai" and ai_report["text"] == reply
            assert signed_get(bob, review_path(pending))[1]["status"] == "pending"
            assert signed_get(alice, review_path(pending))[0] == 404
            stream_path = "/v1/stream"
            with closing(http.client.HTTPConnection(HOST, PORT, timeout=5)) as stream_connection:
                stream_connection.request("GET", stream_path, headers=signed_headers(bob, "GET", stream_path))
                with stream_connection.getresponse() as stream:
                    assert stream.status == 200
                    decision = admin("PUT", f"{MOD}/reviews/{date}/{receipt}", {
                        "action": "approve", "reason": "false-positive",
                    })
                    assert decision["notice_recorded"] is True
                    pushed = read_notice(stream)
                    assert pushed["receipt"] == receipt and pushed["decision"]["status"] == "approved"
                    assert "text" not in pushed
            assert signed_get(bob, review_path(pending))[1]["status"] == "approved"
            approval_path = f"{MOD}/reviews/{date}/{receipt}"
            approval_action = {"action": "approve", "reason": "false-positive"}
            assert admin("PUT", approval_path, approval_action) == decision
            assert len(signed_get(bob, "/v1/moderation/notices")[1]["notices"]) == 1
            assert all(notice.get("receipt") != receipt for notice in signed_get(alice, "/v1/moderation/notices")[1]["notices"])
            changed_status, changed_case = publish(bob, replies, reply + " changed")
            assert changed_status == 422 and changed_case["receipt"] != receipt
            rejected = admin("PUT", f"{MOD}/reviews/{date}/{changed_case['receipt']}", {
                "action": "reject", "reason": "policy",
            })
            assert rejected["notice_recorded"] is True
            assert signed_get(bob, review_path(changed_case))[1]["status"] == "rejected"
            status, retry = publish(bob, replies, reply + " changed")
            assert status == 422 and retry["status"] == "rejected" and retry["receipt"] == changed_case["receipt"]
            calls_before_qs = len(Classifier.seen)
            status_qs, retry_qs = publish(bob, replies + "?bypass=1", reply + " changed")
            assert status_qs == 400 and retry_qs["error"]["code"] == "ERR_BAD_REQUEST"
            assert len(Classifier.seen) == calls_before_qs

            calls_before_replay = len(Classifier.seen)
            replay_body = json.dumps({"text": reply + " replay fixture"}).encode()
            replay_hdrs = signed_headers(bob, "POST", replies, replay_body)
            st_rep1, rep1 = submit("POST", replies, replay_body, replay_hdrs)
            assert st_rep1 == 422 and rep1["error"]["code"] == "ERR_CONTENT_REVIEW", (st_rep1, rep1)
            assert len(Classifier.seen) == calls_before_replay + 1
            st_rep2, rep2 = submit("POST", replies, replay_body, replay_hdrs)
            assert st_rep2 == 401 and rep2["error"]["code"] == "ERR_REPLAY", (st_rep2, rep2)
            assert len(Classifier.seen) == calls_before_replay + 1

            calls_before_friend = len(Classifier.seen)
            fr_body = json.dumps({"agent_id": alice[1], "note": "Review fixture friend note"}).encode()
            fr_st, _ = submit("POST", "/v1/friends/request", fr_body, signed_headers(bob, "POST", "/v1/friends/request", fr_body))
            assert fr_st == 200 and len(Classifier.seen) == calls_before_friend
            admin("PUT", POLICY, {"mode": "readonly"})
            assert publish(bob, replies, reply)[0] == 403
            admin("PUT", POLICY, {"mode": "invite"})
            calls = len(Classifier.seen)
            status, approved = publish(bob, replies, reply)
            assert status == 201 and len(Classifier.seen) == calls, (status, approved)
            rid = approved["msg_id"]
            assert signed_get(bob, review_path(pending))[1]["status"] == "approval_used"
            assert submit("PUT", approval_path, json.dumps(approval_action).encode(), ADMIN)[0] == 409
            assert signed_get(bob, review_path(pending))[1]["status"] == "approval_used"
            records = [json.loads(line) for line in request("GET", f"/t/{root}.jsonl")[2].splitlines()]
            assert [record["msg_id"] for record in records if record["text"] == reply] == [rid]
            admin("POST", "/internal/admin/pins", {"msg_id": root, "pin_type": "sponsored", "channels": ["general"]})
            assert text.encode() in request("GET", "/")[2]

            assert f"/report?thread={root}&amp;message={root}".encode() in request("GET", f"/t/{root}")[2]
            status, headers, page = request("GET", f"/report?thread={root}&message={root}")
            assert status == 200 and b"<form" in page and "form-action 'self'" in headers["content-security-policy"]
            assert b'<option value="unsafe-link">' in page
            bogus_fields = {"thread_id": root, "msg_id": "msg_01ZZZZZZZZZZZZZZZZZZZZZZZZ", "reason": "other", "details": "missing"}
            for _ in range(7):
                assert submit("POST", "/v1/reports", json.dumps(bogus_fields).encode(), {})[0] == 404
            fields = {"thread_id": root, "msg_id": root, "reason": "unsafe-link", "details": "The linked page changed."}
            status, out = submit("POST", "/v1/reports", json.dumps(fields).encode(), {})
            assert status == 201, (status, out)
            report = admin("GET", f"{MOD}/reports?date={date}&receipt={out['receipt']}")
            assert report["msg_id"] == root and report["source"] == "public" and report["reason"] == "unsafe-link"
            assert report["status_token_hash"] == hashlib.sha256(out["token"].encode()).hexdigest()
            status_path = "/v1/reports/status"
            assert submit("POST", status_path, json.dumps({**out, "token": "0" * 64}).encode(), {})[0] == 404
            assert submit("POST", status_path, json.dumps(out).encode(), {})[1]["status"] == "pending"
            admin("PUT", f"{MOD}/reports/{date}/{out['receipt']}", {"action": "dismissed", "reason": "insufficient"})
            done_status, done = submit("POST", status_path, json.dumps(out).encode(), {})
            assert done_status == 200 and done["status"] == "dismissed" and "details" not in done
            assert submit("POST", status_path, json.dumps(pending).encode(), {})[0] == 404

            signed_body = json.dumps(fields).encode()
            signed_status, signed_report = submit("POST", "/v1/reports", signed_body,
                                                   signed_headers(guest, "POST", "/v1/reports", signed_body))
            assert signed_status == 201
            signed_report_path = f"{MOD}/reports/{date}/{signed_report['receipt']}"
            disposition = {"action": "resolved", "reason": "reviewed"}
            notice_path = moderation / "notices" / date / f"{guest[1]}.jsonl"
            notice_path.mkdir()
            initial = admin("PUT", signed_report_path, disposition)
            assert initial["notice_recorded"] is False and initial["decision"]["status"] == "resolved"
            notice_path.rmdir()
            signed_result = admin("PUT", signed_report_path, disposition)
            assert signed_result["notice_recorded"] is True and signed_result["decision"] == initial["decision"]
            assert admin("PUT", signed_report_path, disposition) == signed_result
            guest_notices = signed_get(guest, "/v1/moderation/notices")[1]["notices"]
            assert len(guest_notices) == 1 and guest_notices[0]["kind"] == "report_decision"
            assert guest_notices[0]["receipt"] == signed_report["receipt"] and "details" not in guest_notices[0]
            status, _, html = request("POST", "/report", urlencode(fields).encode(), {
                "Content-Type": "application/x-www-form-urlencoded",
            })
            assert status == 201 and b"Report received." in html and b"/report/status" in html
            status, headers, status_page = request("POST", "/report/status", urlencode(out).encode(), {
                "Content-Type": "application/x-www-form-urlencoded",
            })
            assert status == 200 and b"reviewed and closed" in status_page
            assert headers["cache-control"] == "no-store" and out["token"].encode() not in status_page
            assert request("GET", f"{MOD}/reports")[0] == 403

            admin("PUT", f"{MOD}/reviews/{link_case['date']}/{link_case['receipt']}", {"action": "approve", "reason": "reviewed"})
            backup_dir = temp / "backups"
            subprocess.run(["bash", str(ROOT / "deploy/backup.sh"), str(data), str(backup_dir)], check=True)
            archive = next(backup_dir.glob("*.tar.gz"))
            admin("PUT", f"{MOD}/messages/{root}/{rid}", {"action": "hide", "reason": "privacy"})
            assert reply.encode() not in request("GET", f"/t/{root}.jsonl")[2]
            assert reply.encode() not in request("GET", f"/t/{root}")[2]
            admin("PUT", f"{MOD}/messages/{root}/{rid}", {"action": "restore", "reason": "appeal"})
            assert reply.encode() in request("GET", f"/t/{root}.jsonl")[2]
            hidden = admin("PUT", f"{MOD}/messages/{root}/{root}", {"action": "hide", "reason": "unsafe-link"})
            assert hidden["notice_recorded"] is True
            assert signed_get(alice, "/v1/moderation/notices")[1]["notices"][0]["msg_id"] == root
            assert all(item.get("msg_id") != root for item in signed_get(bob, "/v1/moderation/notices")[1]["notices"])
            assert_hidden(root, text, date)

            admin("PUT", POLICY, {"mode": "readonly"})
            calls = len(Classifier.seen)
            assert publish(bob, POSTS, "Readonly should stop before classification")[0] == 403
            assert len(Classifier.seen) == calls
            stop_server(server)
            subprocess.run(["bash", str(ROOT / "deploy/restore.sh"), str(archive), str(data)], check=True)
            model = "fixture/moderation:v2"
            os.environ["FATEXT_AI_MODERATION_MODEL"] = model
            os.environ["FATEXT_PUBLIC_BLOCKED_LINK_HOSTS"] += ",external.example.test"
            server = start_server(data, log)
            assert admin("GET", POLICY)["mode"] == "readonly"
            assert signed_get(alice, "/v1/moderation/notices")[1]["notices"][0]["kind"] == "message_hide"
            assert signed_get(bob, review_path(pending))[1]["status"] == "approval_used"
            assert submit("POST", status_path, json.dumps(out).encode(), {})[1]["status"] == "dismissed"
            assert_hidden(root, text, date)
            admin("PUT", POLICY, {"mode": "invite"})
            assert signed_get(bob, review_path(link_case))[1]["status"] == "approved"
            assert_link_blocked(bob, POSTS, external_post)
            custom_text = "公告已更新。请查看今天的说明。"
            assert publish(bob, POSTS, custom_text)[0] == 201
            assert Classifier.seen[-1] == (model, custom_text)

            stop_server(server)
            os.environ.pop("FATEXT_AI_MODERATION_URL")
            os.environ.pop("FATEXT_AI_MODERATION_REQUIRED")
            os.environ.pop("FATEXT_PUBLIC_LINK_HOSTS")
            server = start_server(data, log)
            admin("PUT", POLICY, {"mode": "open"})
            calls = len(Classifier.seen)
            assert_link_blocked(guest, POSTS, "https://external.example.test/latest")
            link_st, default_case = publish(guest, POSTS, "https://docs.example.test/guide")
            assert link_st == 422 and default_case["error"]["code"] == "ERR_CONTENT_REVIEW"
            assert len(Classifier.seen) == calls
            stop_server(server)
            fresh = temp / "fresh"
            subprocess.run(["bash", str(ROOT / "deploy/restore.sh"), str(archive), str(fresh)], check=True)
            server = start_server(fresh, log)
            assert admin("GET", POLICY)["visibility_ready"] is False
            assert_hidden(root, text, date)
            stop_server(server)
            verify_public_recovery(temp, log)
            print("Public reporting, AI moderation, visibility and recovery checks passed.")
        finally:
            stop_server(server)
            provider.shutdown()


if __name__ == "__main__":
    main()
