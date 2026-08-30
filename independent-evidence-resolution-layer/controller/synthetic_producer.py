from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--content", required=True)
    parser.add_argument("--exit-code", type=int, default=0)
    args = parser.parse_args()
    content = args.content.encode("utf-8")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(content)
    print(json.dumps({
        "pid": os.getpid(),
        "nonce": args.nonce,
        "sha256": hashlib.sha256(content).hexdigest(),
    }, sort_keys=True, separators=(",", ":")))
    return args.exit_code


if __name__ == "__main__":
    raise SystemExit(main())

