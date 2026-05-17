#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import shutil
from pathlib import Path


METADATA_SIZE = 265
MASK_SIZE = 64 * 1024
DEFAULT_SUFFIX = ".peng"
RANSOM_MARKER_RE = re.compile(r"(?:\.\[\[[^\]]+\]\])+$")
MAGIC_HEADERS = (
    b"\x89PNG\r\n\x1a\n",
    b"\xff\xd8\xff",
    b"%PDF-",
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"PK\x07\x08",
    b"RIFF",
    b"\x00\x00\x00\x14ftyp",
    b"\x00\x00\x00\x18ftyp",
    b"\x00\x00\x00\x1cftyp",
    b"\x00\x00\x00 ftyp",
)


def load_mask(path: Path) -> bytes:
    mask = path.read_bytes()
    if len(mask) != MASK_SIZE:
        raise ValueError(f"mask file must be exactly {MASK_SIZE} bytes: {path}")
    return mask


def xor_region(data: bytearray, mask: bytes, mask_offset: int = 0) -> None:
    for i in range(len(data)):
        data[i] ^= mask[mask_offset + i]


def xor_prefix(data: bytearray, mask: bytes) -> None:
    for i in range(min(len(data), len(mask))):
        data[i] ^= mask[i]


def looks_like_known_file(data: bytes) -> bool:
    return any(data.startswith(header) for header in MAGIC_HEADERS)


def detect_mode(encrypted: Path, mask: bytes) -> str:
    with encrypted.open("rb") as f:
        raw = f.read(METADATA_SIZE + MASK_SIZE)
    if len(raw) <= METADATA_SIZE:
        raise ValueError("file is too small to decrypt")

    head_meta_candidate = bytearray(raw[METADATA_SIZE : METADATA_SIZE + MASK_SIZE])
    xor_prefix(head_meta_candidate, mask)
    if looks_like_known_file(bytes(head_meta_candidate[:32])):
        return "small-head-meta"

    tail_meta_candidate = bytearray(raw[:MASK_SIZE])
    xor_prefix(tail_meta_candidate, mask)
    if looks_like_known_file(bytes(tail_meta_candidate[:32])):
        return "large-tail-meta"

    encrypted_size = encrypted.stat().st_size
    if encrypted_size - METADATA_SIZE >= MASK_SIZE:
        return "large-tail-meta"
    return "small-head-meta"


def default_output_path(encrypted: Path, suffix: str) -> Path:
    name = encrypted.name
    if name.endswith(suffix):
        restored = name[: -len(suffix)]
        if suffix == DEFAULT_SUFFIX:
            restored = RANSOM_MARKER_RE.sub("", restored)
        return encrypted.with_name(restored)
    return encrypted.with_name(name + ".restored")


def decrypt_large_tail_meta(encrypted: Path, output: Path, mask: bytes) -> None:
    encrypted_size = encrypted.stat().st_size
    original_size = encrypted_size - METADATA_SIZE
    if original_size < MASK_SIZE:
        raise ValueError("file is too small for large-tail-meta mode")

    regions = (0, original_size // 2, original_size - MASK_SIZE)
    output.parent.mkdir(parents=True, exist_ok=True)
    with encrypted.open("rb") as fe, output.open("wb") as fw:
        offset = 0
        remaining = original_size
        block_size = 4 * 1024 * 1024
        while remaining > 0:
            n = min(block_size, remaining)
            data = bytearray(fe.read(n))
            start = offset
            end = offset + n
            for region_start in regions:
                region_end = region_start + MASK_SIZE
                lo = max(start, region_start)
                hi = min(end, region_end)
                if lo >= hi:
                    continue
                data_start = lo - start
                mask_start = lo - region_start
                for i in range(hi - lo):
                    data[data_start + i] ^= mask[mask_start + i]
            fw.write(data)
            offset += n
            remaining -= n


def decrypt_small_head_meta(encrypted: Path, output: Path, mask: bytes) -> None:
    encrypted_size = encrypted.stat().st_size
    original_size = encrypted_size - METADATA_SIZE
    if original_size <= 0:
        raise ValueError("file is too small for small-head-meta mode")

    output.parent.mkdir(parents=True, exist_ok=True)
    with encrypted.open("rb") as fe, output.open("wb") as fw:
        fe.seek(METADATA_SIZE)
        data = bytearray(fe.read())
        xor_prefix(data, mask)
        fw.write(data)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Decrypt observed .peng partial-XOR files with a known 64KB mask."
    )
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--mask-file", type=Path)
    parser.add_argument("--victim-id", help="Victim ID, used only to locate masks/peng_mask_<id>.bin.")
    parser.add_argument("--suffix", default=DEFAULT_SUFFIX)
    parser.add_argument(
        "--mode",
        choices=("auto", "large-tail-meta", "small-head-meta"),
        default="auto",
    )
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()

    mask_file = args.mask_file
    if mask_file is None and args.victim_id:
        mask_file = Path(__file__).resolve().parents[1] / "masks" / f"peng_mask_{args.victim_id}.bin"
    if mask_file is None:
        raise SystemExit("provide --mask-file or --victim-id")

    mask = load_mask(mask_file)
    output = args.output or default_output_path(args.input, args.suffix)
    if output.exists() and not args.overwrite:
        raise SystemExit(f"output exists, use --overwrite: {output}")

    mode = detect_mode(args.input, mask) if args.mode == "auto" else args.mode
    if mode == "large-tail-meta":
        decrypt_large_tail_meta(args.input, output, mask)
    elif mode == "small-head-meta":
        decrypt_small_head_meta(args.input, output, mask)
    else:
        raise ValueError(f"unknown mode: {mode}")

    try:
        shutil.copystat(args.input, output)
    except OSError:
        pass
    print(f"output={output}")
    print(f"mode={mode}")
    print(f"mask={mask_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
