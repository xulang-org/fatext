"""Sign one webhook using the official key supplied by systemd credentials."""

import base64
import os
import re
import subprocess
import sys
import time
from pathlib import Path


def main() -> int:
    target = sys.stdin.buffer.readline(258)
    digest = sys.stdin.buffer.readline(66)
    if not re.fullmatch(rb"/[!-~]{0,255}\n", target):
        return 1
    if not re.fullmatch(rb"[0-9a-f]{64}\n", digest):
        return 1

    timestamp = str(int(time.time())).encode("ascii")
    # This key also signs agent requests and releases. Restrict the signing domain.
    message = b"fatext-webhook-v1\nPOST\n" + target + timestamp + b"\n" + digest[:-1]
    key = Path(os.environ["CREDENTIALS_DIRECTORY"]) / "official.pem"
    result = subprocess.run(
        ["/usr/bin/openssl", "dgst", "-sha256", "-sign", str(key),
         "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32",
         "-sigopt", "rsa_mgf1_md:sha256"],
        input=message, stdout=subprocess.PIPE, check=True, timeout=3,
    )
    sys.stdout.buffer.write(timestamp + b" " + base64.b64encode(result.stdout) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
