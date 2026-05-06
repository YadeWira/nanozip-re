#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
from typing import List, Optional, Tuple


KNOWN_SIG = b"NanoZip 0.09 alpha"


def read_varint(data: bytes, pos: int, end: int) -> Tuple[Optional[int], int]:
    if pos >= end:
        return None, pos
    cur = data[pos]
    pos += 1
    value = cur & 0x7F
    shift = 7
    while cur & 0x80:
        if pos >= end or shift >= 63:
            return None, pos
        cur = data[pos]
        pos += 1
        value += ((cur & 0x7F) + 1) << shift
        shift += 7
    return value, pos


def read_table_span(data: bytes, pos: int) -> Tuple[Optional[int], int]:
    if pos >= len(data):
        return None, pos
    b0 = data[pos]
    if (b0 & 0x0F) != 0x01:
        return None, pos
    pos += 1
    if (b0 & 0x80) == 0:
        hi = b0 >> 4
        if hi < 2:
            return None, pos
        return hi - 2, pos
    if pos >= len(data):
        return None, pos
    b1 = data[pos]
    pos += 1
    return (b0 >> 4) + (b1 << 3) - 2, pos


def looks_like_filename_table(data: bytes, start: int, end: int) -> bool:
    p = start
    entries = 0
    while p < end:
        _, p = read_varint(data, p, end)
        if _ is None:
            return False
        try:
            z = data.index(0, p, end)
        except ValueError:
            return False
        if z <= p:
            return False
        p = z + 1
        entries += 1
    return p == end and entries > 0


def parse_legacy(path: Path) -> None:
    data = path.read_bytes()
    if len(data) < 32:
        raise ValueError("file too small")
    if data[:2] != b"\xAE\x01" or data[2 : 2 + len(KNOWN_SIG)] != KNOWN_SIG:
        raise ValueError("not NanoZip 0.09a legacy stream")

    pos = 2 + len(KNOWN_SIG)
    if data[pos : pos + 3] != b"\x1F\x0F\x09":
        raise ValueError("legacy header prefix mismatch")
    pos += 3
    checksum_byte = None
    if pos < len(data) and data[pos] in (0x05, 0x06, 0x07):
        checksum_byte = data[pos]
        pos += 1

    if pos + 3 > len(data):
        raise ValueError("truncated method bytes")
    method, p0, p1 = data[pos], data[pos + 1], data[pos + 2]
    pos += 3

    base = pos
    table_pos = None
    table_end = None
    used_skip = None
    for skip in range(9):
        q = base + skip
        span, q2 = read_table_span(data, q)
        if span is None:
            continue
        table_len = span + 2
        if table_len > len(data) - q2:
            continue
        te = q2 + table_len
        if not looks_like_filename_table(data, q2, te):
            continue
        table_pos = q2
        table_end = te
        used_skip = skip
        break

    if table_pos is None or table_end is None:
        raise ValueError("could not locate legacy filename table")

    entries: List[Tuple[int, str]] = []
    p = table_pos
    total_size = 0
    while p < table_end:
        size_u64, p = read_varint(data, p, table_end)
        if size_u64 is None:
            raise ValueError("bad varint in filename table")
        z = data.index(0, p, table_end)
        name = data[p:z].decode("utf-8", errors="replace")
        entries.append((size_u64, name))
        total_size += size_u64
        p = z + 1

    payload_start = None
    stream_data_off = None
    stream_size = None
    stream_tag = None
    for s in range(table_end, len(data)):
        tag, q = read_varint(data, s, len(data))
        if tag is None or (tag & 0x0F):
            continue
        n = tag >> 4
        if n <= len(data) - q and q + n == len(data):
            payload_start = s
            stream_data_off = q
            stream_size = n
            stream_tag = tag
            break

    print(f"file: {path}")
    print(f"size: {len(data)}")
    print(f"checksum_byte: {checksum_byte}")
    print(f"method: 0x{method:02x} p0={p0} p1={p1}")
    print(f"table_skip: {used_skip} table_pos={table_pos} table_end={table_end} table_len={table_end - table_pos}")
    print(f"entries: {len(entries)} total_size={total_size}")
    for sz, name in entries:
        print(f"  - {name} ({sz})")
    if payload_start is None:
        print("payload: not found")
        return
    print(
        "payload:"
        f" tag=0x{stream_tag:x} start={payload_start} data_off={stream_data_off} stream_bytes={stream_size}"
    )
    assert stream_data_off is not None and stream_size is not None
    stream = data[stream_data_off : stream_data_off + stream_size]
    print(f"stream_head: {stream[:32].hex()}")
    print(f"stream_tail: {stream[-32:].hex()}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Dump layout of NanoZip legacy payload stream")
    ap.add_argument("archive", type=Path, help="path to .nz archive")
    args = ap.parse_args()
    parse_legacy(args.archive)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
