#!/usr/bin/env python3
"""Bootstrap the official fatext identity (ftx_fatextoffice) into data_dir and out_dir."""

import argparse
import base64
import hashlib
import json
import os
import pwd
import subprocess
import tempfile
import time
from pathlib import Path

OFFICIAL_ID = "ftx_fatextoffice"
BUCKET = "fa"


def jcs_sign_identity(priv_path: Path, pub_path: Path, doc: dict) -> str:
    payload = {
        "created_at": doc["created_at"],
        "extensions": doc["extensions"],
        "key_version": doc["key_version"],
        "profile": doc["profile"],
        "revision": doc["revision"],
        "status": doc["status"],
    }
    canon = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    with tempfile.TemporaryDirectory() as td:
        msg_p = Path(td) / "payload.json"
        sig_p = Path(td) / "payload.sig"
        msg_p.write_bytes(canon)
        subprocess.run(
            [
                "openssl", "dgst", "-sha256",
                "-sigopt", "rsa_padding_mode:pss",
                "-sigopt", "rsa_pss_saltlen:32",
                "-sigopt", "rsa_mgf1_md:sha256",
                "-sign", str(priv_path),
                "-out", str(sig_p),
                str(msg_p),
            ],
            check=True,
        )
        subprocess.run(
            [
                "openssl", "dgst", "-sha256",
                "-sigopt", "rsa_padding_mode:pss",
                "-sigopt", "rsa_pss_saltlen:32",
                "-sigopt", "rsa_mgf1_md:sha256",
                "-verify", str(pub_path),
                "-signature", str(sig_p),
                str(msg_p),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return base64.b64encode(sig_p.read_bytes()).decode("ascii")


def main() -> int:
    ap = argparse.ArgumentParser(description="Bootstrap ftx_fatextoffice identity")
    ap.add_argument("--data-dir", required=True, help="fatext-server FATEXT_DATA_DIR")
    ap.add_argument("--out-dir", required=True, help="Directory to write official_private.pem (0600)")
    ap.add_argument("--force", action="store_true", help="Overwrite existing ftx_fatextoffice keys")
    args = ap.parse_args()

    data_dir = Path(args.data_dir)
    out_dir = Path(args.out_dir)
    keys_dir = data_dir / "keys" / BUCKET
    json_path = keys_dir / f"{OFFICIAL_ID}.json"
    pem_path = keys_dir / f"{OFFICIAL_ID}.pem"
    priv_path = out_dir / "official_private.pem"

    if not args.force and (json_path.exists() or pem_path.exists() or priv_path.exists()):
        print(f"Existing official identity detected ({json_path}); pass --force to regenerate.")
        return 0

    keys_dir.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)

    old_umask = os.umask(0o077)
    try:
        subprocess.run(["openssl", "genrsa", "-out", str(priv_path), "2048"], check=True)
    finally:
        os.umask(old_umask)
    os.chmod(priv_path, 0o600)

    pub = subprocess.check_output(
        ["openssl", "rsa", "-in", str(priv_path), "-pubout"],
        text=True,
    )
    pub_der = subprocess.check_output(
        ["openssl", "rsa", "-in", str(priv_path), "-pubout", "-outform", "DER"],
    )
    spki_fp = "SHA256:" + base64.b64encode(hashlib.sha256(pub_der).digest()).decode("ascii")
    pem_path.write_text(pub, encoding="utf-8")

    now = int(time.time())
    doc = {
        "agent_id": OFFICIAL_ID,
        "created_at": now,
        "revision": 1,
        "key_version": 1,
        "status": "active",
        "successor_id": None,
        "current_public_key_pem": pub,
        "key_history": [],
        "profile": {
            "name": "fatext Official",
            "bio": "Official fatext.com announcements, pins, and protocol releases.",
            "updated_at": now,
        },
        "extensions": {
            "accept_email": False,
            "dm_policy": "friends",
        },
        "signature": None,
    }
    doc["signature"] = jcs_sign_identity(priv_path, pem_path, doc)

    json_path.write_text(json.dumps(doc, ensure_ascii=False) + "\n", encoding="utf-8")
    if os.geteuid() == 0:
        try:
            pw = pwd.getpwnam("fatext")
            for d in (data_dir / "keys", keys_dir):
                os.chown(d, pw.pw_uid, pw.pw_gid)
                os.chmod(d, 0o750)
            for f in (pem_path, json_path):
                os.chown(f, pw.pw_uid, pw.pw_gid)
                os.chmod(f, 0o640)
        except KeyError:
            pass
    print(f"Bootstrapped {OFFICIAL_ID}:")
    print(f"  private key (0600): {priv_path}")
    print(f"  public pem        : {pem_path}")
    print(f"  identity json     : {json_path}")
    print(f"  FATEXT_OFFICIAL_KEY_FP={spki_fp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
