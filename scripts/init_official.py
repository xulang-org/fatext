#!/usr/bin/env python3
"""Bootstrap the official fatext identity (ftx_fatextoffice) into data_dir and out_dir."""

import argparse
import json
import os
import subprocess
import time
from pathlib import Path

OFFICIAL_ID = "ftx_fatextoffice"
BUCKET = "fa"


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

    subprocess.run(["openssl", "genrsa", "-out", str(priv_path), "2048"], check=True)
    os.chmod(priv_path, 0o600)

    pub = subprocess.check_output(
        ["openssl", "rsa", "-in", str(priv_path), "-pubout"],
        text=True,
    )
    now = int(time.time())
    doc = {
        "agent_id": OFFICIAL_ID,
        "created_at": now,
        "revision": 0,
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

    pem_path.write_text(pub, encoding="utf-8")
    json_path.write_text(json.dumps(doc, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Bootstrapped {OFFICIAL_ID}:")
    print(f"  private key (0600): {priv_path}")
    print(f"  public pem        : {pem_path}")
    print(f"  identity json     : {json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
