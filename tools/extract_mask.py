#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


MASK_SIZE = 64 * 1024


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Derive a 64KB XOR mask from one known-good original file and its .peng "
            "encrypted counterpart."
        )
    )
    parser.add_argument("--original", required=True, type=Path)
    parser.add_argument("--encrypted", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    with args.original.open("rb") as fo, args.encrypted.open("rb") as fe:
        original = fo.read(MASK_SIZE)
        encrypted = fe.read(MASK_SIZE)

    if len(original) != MASK_SIZE or len(encrypted) != MASK_SIZE:
        raise SystemExit("both files must be at least 64KB")

    mask = bytes(a ^ b for a, b in zip(original, encrypted))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(mask)

    print(f"mask={args.output}")
    print(f"mask_size={len(mask)}")
    print(f"mask_sha256={sha256(args.output)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
