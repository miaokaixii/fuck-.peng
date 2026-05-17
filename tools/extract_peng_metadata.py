#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
from collections import Counter
from pathlib import Path


METADATA_SIZE = 265


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def printable_ascii(data: bytes) -> str:
    chars = []
    for b in data:
        if 32 <= b <= 126:
            chars.append(chr(b))
        else:
            chars.append(".")
    return "".join(chars)


def iter_peng_files(paths: list[Path]) -> list[Path]:
    files: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        if path.is_file():
            candidates = [path]
        elif path.is_dir():
            candidates = sorted(p for p in path.rglob("*.peng") if p.is_file())
        else:
            print(f"SKIP missing {path}")
            continue
        for candidate in candidates:
            key = str(candidate.resolve(strict=False))
            if key in seen:
                continue
            seen.add(key)
            files.append(candidate)
    return sorted(files)


def metadata_for(path: Path) -> tuple[bytes, bytes]:
    with path.open("rb") as f:
        head = f.read(METADATA_SIZE)
        if path.stat().st_size >= METADATA_SIZE:
            f.seek(-METADATA_SIZE, 2)
            tail = f.read(METADATA_SIZE)
        else:
            tail = b""
    return head, tail


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract and compare 265-byte metadata candidates from .peng files."
    )
    parser.add_argument("paths", nargs="+", type=Path, help="Files or directories to scan.")
    parser.add_argument("--csv", type=Path, help="Write detailed rows to CSV.")
    parser.add_argument(
        "--hex-bytes",
        type=int,
        default=64,
        help="Number of metadata bytes to print as hex/ascii in terminal summary.",
    )
    args = parser.parse_args()

    files = iter_peng_files(args.paths)
    rows: list[dict[str, str | int]] = []
    head_hashes: Counter[str] = Counter()
    tail_hashes: Counter[str] = Counter()

    for path in files:
        size = path.stat().st_size
        head, tail = metadata_for(path)
        head_hash = sha256_bytes(head)
        tail_hash = sha256_bytes(tail)
        head_hashes[head_hash] += 1
        tail_hashes[tail_hash] += 1
        rows.append(
            {
                "path": str(path),
                "size": size,
                "original_size_candidate": max(size - METADATA_SIZE, 0),
                "head265_sha256": head_hash,
                "tail265_sha256": tail_hash,
                "head265_hex": head.hex(),
                "tail265_hex": tail.hex(),
                "head265_ascii": printable_ascii(head),
                "tail265_ascii": printable_ascii(tail),
            }
        )

    print(f"files={len(files)}")
    print(f"unique_head265={len(head_hashes)} unique_tail265={len(tail_hashes)}")
    if head_hashes:
        value, count = head_hashes.most_common(1)[0]
        print(f"most_common_head265 count={count} sha256={value}")
    if tail_hashes:
        value, count = tail_hashes.most_common(1)[0]
        print(f"most_common_tail265 count={count} sha256={value}")

    shown = min(5, len(rows))
    for row in rows[:shown]:
        n = max(0, args.hex_bytes)
        print(f"\npath={row['path']}")
        print(f"size={row['size']} original_size_candidate={row['original_size_candidate']}")
        print(f"head265_sha256={row['head265_sha256']}")
        print(f"head265_hex_prefix={str(row['head265_hex'])[: n * 2]}")
        print(f"head265_ascii_prefix={str(row['head265_ascii'])[:n]}")
        print(f"tail265_sha256={row['tail265_sha256']}")
        print(f"tail265_hex_prefix={str(row['tail265_hex'])[: n * 2]}")
        print(f"tail265_ascii_prefix={str(row['tail265_ascii'])[:n]}")

    if args.csv:
        args.csv.parent.mkdir(parents=True, exist_ok=True)
        with args.csv.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["path"])
            writer.writeheader()
            writer.writerows(rows)
        print(f"csv={args.csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
