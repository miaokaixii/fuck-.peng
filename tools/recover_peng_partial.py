#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re


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


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def derive_mask(original: Path, encrypted: Path) -> bytes:
    with original.open("rb") as fo, encrypted.open("rb") as fe:
        original_head = fo.read(MASK_SIZE)
        encrypted_head = fe.read(MASK_SIZE)
    if len(original_head) != MASK_SIZE or len(encrypted_head) != MASK_SIZE:
        raise ValueError("sample files must be at least 64KB")
    return bytes(a ^ b for a, b in zip(original_head, encrypted_head))


def load_or_derive_mask(mask_file: Path | None, original: Path | None, encrypted: Path | None) -> bytes:
    if mask_file:
        mask = mask_file.read_bytes()
        if len(mask) != MASK_SIZE:
            raise ValueError(f"mask file must be exactly {MASK_SIZE} bytes")
        return mask
    if original is None or encrypted is None:
        raise ValueError("provide either --mask-file or both --sample-original and --sample-encrypted")
    return derive_mask(original, encrypted)


def xor_prefix(data: bytearray, mask: bytes) -> None:
    for i in range(min(len(data), len(mask))):
        data[i] ^= mask[i]


def looks_like_known_file(data: bytes) -> bool:
    return any(data.startswith(header) for header in MAGIC_HEADERS)


def restore_large_tail_meta(encrypted: Path, output: Path, mask: bytes) -> None:
    encrypted_size = encrypted.stat().st_size
    original_size = encrypted_size - METADATA_SIZE
    if original_size < MASK_SIZE:
        raise ValueError(f"{encrypted} is too small for large-tail-meta pattern")

    regions = (0, original_size // 2, original_size - MASK_SIZE)
    output.parent.mkdir(parents=True, exist_ok=True)

    with encrypted.open("rb") as fe, output.open("wb") as fw:
        remaining = original_size
        offset = 0
        block_size = 1024 * 1024
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


def restore_small_head_meta(encrypted: Path, output: Path, mask: bytes) -> None:
    encrypted_size = encrypted.stat().st_size
    original_size = encrypted_size - METADATA_SIZE
    if original_size <= 0:
        raise ValueError(f"{encrypted} is too small for small-head-meta pattern")

    output.parent.mkdir(parents=True, exist_ok=True)
    with encrypted.open("rb") as fe, output.open("wb") as fw:
        fe.seek(METADATA_SIZE)
        data = bytearray(fe.read())
        xor_prefix(data, mask)
        fw.write(data)


def detect_mode(encrypted: Path, mask: bytes) -> str:
    with encrypted.open("rb") as f:
        raw = f.read(METADATA_SIZE + MASK_SIZE)

    if len(raw) <= METADATA_SIZE:
        raise ValueError(f"{encrypted} is too small to detect")

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


def restore_file(encrypted: Path, output: Path, mask: bytes, mode: str) -> str:
    if mode == "auto":
        mode = detect_mode(encrypted, mask)
    if mode == "large-tail-meta":
        restore_large_tail_meta(encrypted, output, mask)
    elif mode == "small-head-meta":
        restore_small_head_meta(encrypted, output, mask)
    else:
        raise ValueError(f"unknown mode: {mode}")
    return mode


def strip_peng_name(path: Path, suffix: str) -> str:
    name = path.name
    if name.endswith(suffix):
        restored = name[: -len(suffix)]
        if suffix == DEFAULT_SUFFIX:
            restored = RANSOM_MARKER_RE.sub("", restored)
        return restored
    if name.endswith(".peng"):
        return RANSOM_MARKER_RE.sub("", name[: -len(".peng")])
    return name + ".restored"


def iter_encrypted_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    return sorted(p for p in path.rglob("*.peng") if p.is_file())


def output_path_for(encrypted: Path, input_root: Path, output_dir: Path, suffix: str) -> Path:
    if input_root.is_file():
        return output_dir / strip_peng_name(encrypted, suffix)
    rel_parent = encrypted.parent.relative_to(input_root)
    return output_dir / rel_parent / strip_peng_name(encrypted, suffix)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Recover files affected by the observed .peng partial-XOR pattern."
    )
    parser.add_argument("--sample-original", type=Path)
    parser.add_argument("--sample-encrypted", type=Path)
    parser.add_argument("--mask-file", type=Path)
    parser.add_argument("--encrypted", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--suffix", default=DEFAULT_SUFFIX)
    parser.add_argument(
        "--mode",
        choices=("auto", "large-tail-meta", "small-head-meta"),
        default="auto",
    )
    parser.add_argument("--verify-original", type=Path)
    args = parser.parse_args()

    mask = load_or_derive_mask(args.mask_file, args.sample_original, args.sample_encrypted)
    encrypted_files = iter_encrypted_files(args.encrypted)
    if not encrypted_files:
        raise SystemExit(f"no .peng files found: {args.encrypted}")

    for encrypted in encrypted_files:
        output = output_path_for(encrypted, args.encrypted, args.output_dir, args.suffix)
        used_mode = restore_file(encrypted, output, mask, args.mode)
        print(f"output={output}")
        print(f"mode={used_mode}")
        print(f"encrypted_size={encrypted.stat().st_size}")
        print(f"output_size={output.stat().st_size}")
        print(f"output_sha256={sha256(output)}")
        if args.verify_original and len(encrypted_files) == 1:
            print(f"verify_sha256={sha256(args.verify_original)}")
            print(f"match={sha256(output) == sha256(args.verify_original)}")


if __name__ == "__main__":
    main()
