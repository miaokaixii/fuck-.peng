#!/usr/bin/env python3
from __future__ import annotations

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
import os
import re
import sys
import time
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
DEFAULT_EXCLUDE_DIRS = {
    "_peng_recover_test",
    "_ova_analysis",
    "$RECYCLE.BIN",
    "$Recycle.Bin",
    ".Trash",
}


def load_mask(path: Path) -> bytes:
    mask = path.read_bytes()
    if len(mask) != MASK_SIZE:
        raise ValueError(f"mask file must be exactly {MASK_SIZE} bytes: {path}")
    return mask


def xor_prefix(data: bytearray, mask: bytes) -> None:
    for i in range(min(len(data), len(mask))):
        data[i] ^= mask[i]


def looks_like_known_file(data: bytes) -> bool:
    return any(data.startswith(header) for header in MAGIC_HEADERS)


def detect_mode(encrypted: Path, mask: bytes) -> str:
    with encrypted.open("rb") as f:
        raw = f.read(METADATA_SIZE + MASK_SIZE)

    if len(raw) <= METADATA_SIZE:
        raise ValueError("file is too small to detect")

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


def original_name(path: Path, suffix: str) -> str:
    name = path.name
    if name.endswith(suffix):
        restored = name[: -len(suffix)]
        if suffix == DEFAULT_SUFFIX:
            restored = RANSOM_MARKER_RE.sub("", restored)
        return restored
    if name.endswith(".peng"):
        return RANSOM_MARKER_RE.sub("", name[: -len(".peng")])
    return name + ".restored"


def dedupe_paths(paths: list[Path]) -> list[Path]:
    result: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        key = str(path.resolve(strict=False))
        if key in seen:
            continue
        seen.add(key)
        result.append(path)
    return result


def is_excluded(path: Path, exclude_dirs: set[str]) -> bool:
    return any(part in exclude_dirs for part in path.parts)


def iter_peng_files(paths: list[Path], exclude_dirs: set[str]) -> list[Path]:
    files: list[Path] = []
    seen: set[str] = set()
    for path in dedupe_paths(paths):
        if path.is_file() and path.name.endswith(".peng"):
            if not is_excluded(path, exclude_dirs):
                key = str(path.resolve(strict=False))
                if key not in seen:
                    seen.add(key)
                    files.append(path)
        elif path.is_dir():
            for p in path.rglob("*.peng"):
                if not p.is_file() or is_excluded(p, exclude_dirs):
                    continue
                key = str(p.resolve(strict=False))
                if key in seen:
                    continue
                seen.add(key)
                files.append(p)
        else:
            print(f"SKIP missing_or_not_peng {path}", file=sys.stderr)
    return sorted(files)


def copy_large_tail_meta(encrypted: Path, output: Path, mask: bytes) -> None:
    encrypted_size = encrypted.stat().st_size
    original_size = encrypted_size - METADATA_SIZE
    if original_size < MASK_SIZE:
        raise ValueError("file is too small for large-tail-meta")

    regions = (0, original_size // 2, original_size - MASK_SIZE)
    with encrypted.open("rb") as fe, output.open("wb") as fw:
        remaining = original_size
        offset = 0
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


def copy_small_head_meta(encrypted: Path, output: Path, mask: bytes) -> None:
    encrypted_size = encrypted.stat().st_size
    original_size = encrypted_size - METADATA_SIZE
    if original_size <= 0:
        raise ValueError("file is too small for small-head-meta")

    with encrypted.open("rb") as fe, output.open("wb") as fw:
        fe.seek(METADATA_SIZE)
        data = bytearray(fe.read())
        xor_prefix(data, mask)
        fw.write(data)


def xor_file_region_inplace(f, offset: int, length: int, mask: bytes, mask_offset: int = 0) -> None:
    f.seek(offset)
    data = bytearray(f.read(length))
    for i in range(len(data)):
        data[i] ^= mask[mask_offset + i]
    f.seek(offset)
    f.write(data)


def restore_large_tail_meta_inplace(encrypted: Path, mask: bytes) -> str:
    encrypted_size = encrypted.stat().st_size
    original_size = encrypted_size - METADATA_SIZE
    if original_size < MASK_SIZE:
        raise ValueError("file is too small for large-tail-meta inplace")

    regions = (0, original_size // 2, original_size - MASK_SIZE)
    with encrypted.open("r+b") as f:
        for region_start in regions:
            xor_file_region_inplace(f, region_start, MASK_SIZE, mask)
        f.truncate(original_size)
    return "large-tail-meta-inplace"


def restore_small_head_meta_inplace(encrypted: Path, mask: bytes) -> str:
    encrypted_size = encrypted.stat().st_size
    original_size = encrypted_size - METADATA_SIZE
    if original_size <= 0:
        raise ValueError("file is too small for small-head-meta inplace")

    block_size = 4 * 1024 * 1024
    with encrypted.open("r+b") as f:
        read_offset = METADATA_SIZE
        write_offset = 0
        first = True
        while read_offset < encrypted_size:
            f.seek(read_offset)
            data = bytearray(f.read(min(block_size, encrypted_size - read_offset)))
            if first:
                xor_prefix(data, mask)
                first = False
            f.seek(write_offset)
            f.write(data)
            read_offset += len(data)
            write_offset += len(data)
        f.truncate(original_size)
    return "small-head-meta-inplace"


def restore_one(encrypted: Path, mask: bytes, suffix: str, overwrite_target: bool) -> tuple[str, Path]:
    target = encrypted.with_name(original_name(encrypted, suffix))
    temp = encrypted.with_name(f".{target.name}.peng_recovering.tmp")

    if target.exists() and not overwrite_target:
        raise FileExistsError(f"target already exists: {target}")
    if temp.exists():
        temp.unlink()

    mode = detect_mode(encrypted, mask)
    if mode == "large-tail-meta":
        copy_large_tail_meta(encrypted, temp, mask)
    elif mode == "small-head-meta":
        copy_small_head_meta(encrypted, temp, mask)
    else:
        raise ValueError(f"unknown mode: {mode}")

    st = encrypted.stat()
    os.chmod(temp, st.st_mode & 0o777)
    os.utime(temp, (st.st_atime, st.st_mtime))

    if overwrite_target and target.exists():
        target.unlink()
    temp.replace(target)
    encrypted.unlink()
    return mode, target


def restore_one_inplace_fast(
    encrypted: Path,
    mask: bytes,
    suffix: str,
    overwrite_target: bool,
    large_threshold: int,
) -> tuple[str, Path]:
    target = encrypted.with_name(original_name(encrypted, suffix))
    if target.exists() and not overwrite_target:
        raise FileExistsError(f"target already exists: {target}")

    encrypted_size = encrypted.stat().st_size
    if encrypted_size >= large_threshold:
        mode = restore_large_tail_meta_inplace(encrypted, mask)
    else:
        mode = detect_mode(encrypted, mask)
        if mode == "large-tail-meta":
            mode = restore_large_tail_meta_inplace(encrypted, mask)
        elif mode == "small-head-meta":
            mode = restore_small_head_meta_inplace(encrypted, mask)
        else:
            raise ValueError(f"unknown mode: {mode}")

    if overwrite_target and target.exists():
        target.unlink()
    encrypted.replace(target)
    return mode, target


def restore_worker(args: tuple[str, bytes, str, bool, bool, int]) -> tuple[bool, str, str, str]:
    encrypted_s, mask, suffix, overwrite_target, inplace_fast, large_threshold = args
    encrypted = Path(encrypted_s)
    try:
        if inplace_fast:
            mode, out = restore_one_inplace_fast(
                encrypted, mask, suffix, overwrite_target, large_threshold
            )
        else:
            mode, out = restore_one(encrypted, mask, suffix, overwrite_target)
        return True, mode, encrypted_s, str(out)
    except Exception as exc:
        return False, str(exc), encrypted_s, ""


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Restore observed .peng partial-XOR files in place."
    )
    parser.add_argument("paths", nargs="+", type=Path, help="Files or directories to scan.")
    parser.add_argument("--mask-file", required=True, type=Path)
    parser.add_argument("--suffix", default=DEFAULT_SUFFIX)
    parser.add_argument("--apply", action="store_true", help="Actually restore and delete .peng files.")
    parser.add_argument(
        "--overwrite-target",
        action="store_true",
        help="Overwrite an existing restored target path if it already exists.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Parallel restore workers. Benchmark first; large media trees often work well at 16-32.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Only print summary and failures when applying.",
    )
    parser.add_argument(
        "--inplace-fast",
        action="store_true",
        help="Modify .peng files in place, then rename them. Much faster for large files.",
    )
    parser.add_argument(
        "--large-threshold",
        type=int,
        default=1024 * 1024,
        help="Files at or above this encrypted size use large-file inplace mode directly.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Only process the first N .peng files after sorting. Useful for speed tests.",
    )
    parser.add_argument(
        "--exclude-dir",
        action="append",
        default=[],
        help="Directory name to skip. Can be repeated.",
    )
    args = parser.parse_args()

    mask = load_mask(args.mask_file)
    exclude_dirs = set(DEFAULT_EXCLUDE_DIRS)
    exclude_dirs.update(args.exclude_dir)
    files = iter_peng_files(args.paths, exclude_dirs)
    if args.limit > 0:
        files = files[: args.limit]
    print(f"found={len(files)} apply={args.apply}")
    started = time.monotonic()

    ok = 0
    failed = 0
    for encrypted in files:
        target = encrypted.with_name(original_name(encrypted, args.suffix))
        if not args.apply:
            print(f"DRYRUN {encrypted} -> {target}")
            continue
    if not args.apply:
        print(f"done ok=0 failed=0 dryrun=True")
        return 0

    worker_count = max(1, args.workers)
    jobs = [
        (
            str(path),
            mask,
            args.suffix,
            args.overwrite_target,
            args.inplace_fast,
            args.large_threshold,
        )
        for path in files
    ]
    if worker_count == 1:
        iterator = map(restore_worker, jobs)
        for success, mode_or_error, encrypted, out in iterator:
            if success:
                ok += 1
                if not args.quiet:
                    print(f"OK mode={mode_or_error} {encrypted} -> {out}")
            else:
                failed += 1
                print(f"FAIL {encrypted} error={mode_or_error}", file=sys.stderr)
    else:
        with ProcessPoolExecutor(max_workers=worker_count) as pool:
            futures = [pool.submit(restore_worker, job) for job in jobs]
            for future in as_completed(futures):
                success, mode_or_error, encrypted, out = future.result()
                if success:
                    ok += 1
                    if not args.quiet:
                        print(f"OK mode={mode_or_error} {encrypted} -> {out}")
                else:
                    failed += 1
                    print(f"FAIL {encrypted} error={mode_or_error}", file=sys.stderr)

    elapsed = max(time.monotonic() - started, 0.001)
    rate = ok / elapsed
    print(f"done ok={ok} failed={failed} dryrun=False elapsed={elapsed:.2f}s rate={rate:.2f}/s")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
