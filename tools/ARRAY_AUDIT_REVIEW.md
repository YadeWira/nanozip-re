# `ghidra_array_audit.py` — the 2026-09-21 review

The audit finds places where Ghidra's guessed pointee type disagrees with the
width the code actually stores, because every element count written against such
a pointer is then off by the ratio. It exists because one of those cost this port
hours: a 1024-byte recency ring typed as 256 four-byte slots.

Run over the four decompile sets the port was written from
(`work/reports/decomp_{lzhd,lzpf,optimum}` and `optimum2_enc`), 46 files:

    A 0 | A' 2 | B 12 | B' 3 | unclassified loops 3 | pointer-wrap constants 34

**Class A — a declaration that understates the buffer — is empty.** That is the
dangerous one: it is the shape that makes a port allocate less than the original
writes.

The rest, and why each is benign here:

| where | what the tool sees | disposition |
|---|---|---|
| `FUN_080dbdd0` (5 hits) | 1- and 2-byte stores through a `uint *` | it is the library's memcpy/memmove. The port calls `std::memcpy`; no count was transcribed from it. |
| `decomp_enc.c:234,706`, `decomp_co_f8e0.c:467` (B), `decomp_enc.c:217,1754`, `decomp_co_f8e0.c:223` (B') | 2- and 4-byte stores through pointers into the parsers' node array | the node is 32 bytes and the port's layout was checked field by field against the original's in GDB (price@2, back@4, len@6, ctx@8, hist@10, dist@0xc, rep[4]@0x10) — 18 consecutive nodes agree item for item. |
| `FUN_08095d90:291` | 2-byte stores through an `undefined8 *` | the predictor's history copy. The port copies `int16_t` elements (`CopyHist`), which is the width the loop advances by. |
| `FUN_0809c700:52` | 1-byte stores through a `uint *` | the bit-count decoder's table fill, which writes bytes and advances by a byte count. The port's table is a byte table; the audio path is byte-exact against the original on every fixture and corpus. |
| `FUN_08097570:167` | a 1-byte read through a `ushort *` that advances 7 bytes | the lzpf token walker, byte-exact over both corpora. |
| `FUN_080a41d0:46`, `FUN_080a5330:212` (A') | an init loop covering less than the declaration | the tool's own note applies: one buffer used as several tables, or a deliberate partial clear. |

So: nothing to change, and the gap this tool was written for stays closed. Re-run
it (with `--selftest` first, which is what proves the checker still finds a
planted defect of each class) whenever a new decompile set is added.
