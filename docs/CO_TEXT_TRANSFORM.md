# The `-co` text transform, transcribed from the original's encoder

Everything here is read off NanoZip 0.09a's own code, not inferred from its decoder.
Eighteen of the functions involved had never been decompiled; they now live in
`~/.cache/nzre_tools/encode/decomp/tt_encoder_missing.c` (1188 lines).

`-co`, `-cO` and `-cc` share one text driver, **FUN_0808da10**; `-cd`/`-cD` use a
different and much poorer one, FUN_08064bb0, which this project already ports as
`TextDetect`. That difference is the whole reason `-co` reaches for the transform
where `-cd` does not.

## The chain, and which direction it runs

The encoder's dispatcher is **FUN_08059060** (ported as `TextPipeline`). It applies
the transforms in this order, which is the exact reverse of the decoder's:

| bit  | transform      | function      | in our tree |
|------|----------------|---------------|-------------|
| 0x01 | CR to CRLF     | FUN_08056960  | `TextCrlfEncode` |
| 0x40 | chess          | FUN_080581d0  | `TextChessEncode` |
| 0x20 | line RLE       | FUN_08058050  | `TextLineRleEncode` |
| 0x02 | insert LF      | FUN_080587f0  | missing |
| 0x04 | html           | FUN_08056080  | missing |
| 0x08 | word dictionary| FUN_08055290  | `TextDictEncode` |
| 0x10 | number         | FUN_08058580  | missing |
| 0x80 | space removal  | FUN_08055e70  | `TextParam14Encode` |

Each step re-reads the requested mask, and on success swaps the buffers, updates the
size and ORs its bit into the **applied** mask. That applied mask is the byte the
block header carries, and it can be smaller than what the detector asked for.

Two conditions ride along: bit 0x80 only runs when 0x08 actually landed, and bit 0x10
requires that 0x40 did not.

**The dictionary step ends with an inverse ASCII reorder** through DAT_08185860 when
the codec is not the CM one. That is the only piece bit 0x08 was missing here:
`TextDictEncode` followed by that inverse table reproduces the original's coded stream
byte for byte on both oracle blocks (25026 and 25714 bytes).

## The detector (FUN_0808da10's text section)

The block first has to be text at all: `ExeMetric(buf, n) / ((n >> 12) + 1)` must be
zero, and the audio and image detectors must both decline.

The analysis object is **FUN_08054b50** over only the first **n >> 3** bytes, and it is
richer than the `-cd` one:

- `hist[256]` — the byte histogram, but counting only bytes NOT covered by a repeat of
  more than three bytes. It hashes the two bytes before each position, looks up the last
  position with that hash, and when two bytes match extends the match; a match longer
  than three skips those bytes entirely.
- `n` at +0x400 — the sample size.
- `dedup` at +0x404 — how many positions the scan actually visited, starting at 1.
- two score bytes at +0x408 and +0x409 — `sum(hist[c] where traits&0x9d) * 100 / dedup`
  and the same for `traits&0x19`, both plain integer division of a 64-bit product.
- mean line length at +0x40c — the sum of gaps between line feeds over `hist[10] + 1`.

Then, **only if the text test passes**, the histogram is rebuilt over every byte of the
sample, replacing the deduplicated counts.

The eight predicates, verbatim:

| function | test |
|----------|------|
| FUN_08054e60 is-text | `s408 >= 0x58 \|\| (s408 > 0x4f && s409 > 0x4f)` |
| FUN_08054b30 insert-LF | `(meanline - 30) < 0x33` unsigned, i.e. 30..80 |
| FUN_08054e90 html | `hist['>']/3 <= hist['/'] && hist['<'] - (hist['<']>>4) <= hist['>']` |
| FUN_08054ee0 enough digits | `sum(hist['0'..'9']) >= dedup >> 5` |
| FUN_08054f10 mostly digits | `sum(hist['0'..'9']) >= (dedup >> 1) + 0x400` |
| FUN_08054f50 number part 1 | `sum(hist['0'..'9']) > 0x13` |
| FUN_08054f80 CRLF | `(n>>7) <= hist[10] <= (n>>3)` and `hist[10]` within a 64th of `hist[13]` |
| FUN_08054fe0 number part 2 | `hist[10] + hist[13] > n >> 8` |

The flag logic, in order:

1. Gate: `is-text(obj)` or the line-RLE detector on `min(n>>10, 0x400)` bytes.
2. Dictionary: `DictFits(buf, n>>1)` and then `DictFits(buf + n/2, n - n/2)`. Both true
   sets 0x08. If either fails, fall to the digit route: without `enough digits` the flags
   are zero; with it, `FUN_080550c0(buf, n>>2)` — the `-co`-only detector that counts
   nonzero integers below 256 followed by a dot, and accepts when the count exceeds
   `len >> 8` — sets 0x08 and marks the block as taking the *number route*.
3. Chess on `n>>6` bytes sets 0x40 and clears the number route. Otherwise, if line RLE
   fits both halves split at `n>>7`, then for a non-CM codec the mask is *replaced* by
   0x20, and 0x08 is cleared either way.
4. On the chess path, or whenever the mask is still non-zero: CRLF sets 0x01 and the
   insert-LF predicate sets 0x02. If the mask is still zero, the block needs `enough
   digits` to go on at all.
5. Number part 1 and part 2, with 0x40 clear, set 0x10. Html sets 0x04.

For `-co` and `-cO` the CM object is null, so the transform is attempted whenever the
mask came out non-zero. For `-cc` the number route suppresses it outright, and so does
the mostly-digits case.

## The trial gate (FUN_0808f8e0)

This is what actually decides, and it costs a compression pass:

    sample = min(n >> 3, 0x20000)
    baseline = compress(sample)            or the sample size if that fails
    candidate = compress(pipeline(sample)) + the aux-stream bytes the pipeline wrote
    apply the transform only if  baseline > candidate + (candidate >> 10)

So the transform has to beat the untransformed sample by more than about a tenth of a
percent. Measured on prefixes of one real source file: 2000 bytes asks for 0x0c and is
refused, 3000 asks 0x0a and is accepted, 15000 asks 0x18 and is refused, 20000 asks
0x1a and is accepted, 25000 asks 0x10 and is refused, 30000 asks 0x1a and is accepted —
its output being exactly the 25714 bytes of the oracle block. Sizes in between produce
no transform at all because the mask itself came out zero.

## An initialisation-order hazard that carries over

The dictionary detector reads a word-continuation table that only the dictionary
*transform* builds. On the first block a process sees, the detector therefore reads an
all-zero table, and every later block reads the real one. `-cd` already documents this;
`-co` inherits it, with the twist that the trial gate's own pipeline pass is what first
builds the table.

## Side streams

Bits 0x02 and 0x10 each write a side stream, emitted by FUN_080b8910 as a varint length
followed by the bytes, in the order the block header lists them: the flags byte, then
the 0x02 stream, then the 0x10 stream. Bit 0x08 carries none.

### insert LF (0x02)

Its parameters are hardcoded before every call: minimum 40, maximum 96, hard minimum 4.
The coded decision is simply "this byte is a line feed in the text", and **every**
line feed that passes the gate is flattened to a space — there is no search and no cost
decision. The gate needs the line length at or above the hard minimum, more than one
byte remaining, and the neighbouring characters to pass two class tables, which is why
only 12 of one block's 1022 line feeds are flattened: source lines start with
indentation, and neither space nor tab passes. The 1010 that do not still have to be
coded through the same model, so the encoder mirrors the whole model, not just the
events. Three chained interpolation stages over a 1024-entry table drive a carryless
range coder. A forward pass written this way is byte-exact against the original,
including its 31-byte side stream.

### number (0x10)

Size-preserving by construction. Every decimal digit becomes `0`; a hexadecimal run of
at least four characters with at least one hex letter and a single case becomes one `1`
per character for lowercase or one `2` for uppercase, mixed case being rejected. Decimal
digits are concatenated across `-`, `.` and `:` into one number of up to nine digits,
which is how dates, times, IP addresses and version strings compress. All the
information lives in the arithmetic side stream. Its acceptance test probes the second
half of the block and compares an entropy estimate before running the full pass, which
is why the bit is often requested and not applied.

## What is verified, and by what

- `TextDictEncode` plus the inverse reorder reproduces the original's coded stream on
  two independent oracle blocks.
- A reference forward pass for the whole of bit 0x08, written from this spec, is
  byte-exact on 127 oracle pairs totalling 16.8 MB of coded bytes, including 96 real
  corpus files and probes covering every possible byte after a word.
- The insert-LF forward pass is byte-exact on two blocks, stream and side stream.
- Twelve captured triples exercise the number transform's decimal and both hexadecimal
  paths.

Oracle pairs are captured with `NZOPT_DUMP_TT=<dir>` on archives made by the original;
`docs/../` — see the pair inventory in the project's own scratch area, and the four
rules that a forward dictionary pass gets wrong without being told:

1. A two-byte dictionary code is illegal when the byte after the word is 0x80 or above,
   because the decoder would read it as a three-byte code. The original spells the word
   out instead.
2. The one-byte tier is used only when the aliasing character is a letter with another
   letter after it.
3. When a single uppercase letter's lowercase form is itself a one-byte code, the case
   escape is unavailable and the character is escaped with the case mode cleared.
4. After an all-caps word the first following byte is written verbatim and only the
   rest of the run is pre-inverted.

The word itself is never searched for: it is always the maximal leading run of letters
in the chunk, an exact lookup, and the dictionary wins unconditionally whenever the
word's case shape can be expressed.


## Status (2026-09-09, night)

Everything above is ported and the writer uses it:

- the detector (`CoTextFlags`) matches the original's requested mask on 180 corpus
  files and the eight oracle inputs, read out of the original with GDB;
- the forward passes insert-LF, html and number are byte-exact on every oracle
  pair (6, 28 and 45 pairs, side streams included);
- the trial gate is what it says: FUN_0805d1e0 (the BWT) and FUN_0806c350 (the
  BWT bucket coder) on the sample before and after, and both are ported
  (`NzBwtTransform`, `NzBwtEncodeInput`, identical on every capture). Under -t1
  the bucket coder writes ONE bucket; the per-symbol split is the multi-threaded
  layout, not written yet;
- the number step's second-half trial uses FUN_08052ec0's estimate (context sort,
  move-to-front, optimal prefix code length), ported as `CoEntropyEstimate`;
- FUN_0808d7f0 then picks LZ or BWT for the block on a min(n >> 3, 512 KB)
  sample coded both ways with a fresh LZ engine, LZ only when strictly smaller.

## The two post-filters that run when no text transform applied

When the block took no text transform the driver attempts, in this order,
**param1** (FUN_0806e7a0) and then **param2** (FUN_0808ff20). The block header
carries them the other way round -- param2's flag and side stream first -- which
is also the order the decoder undoes them in, so the naming inverts between the
writer and the reader.

- **param2** is the u32 run collapse (`NzPostfilterParam2Encode`): six or more
  equal 32-bit words open a run, the run lengths go to an arithmetic-coded side
  stream and the sub-word tail is copied verbatim. Accepted only when
  `side + out < n - min(n >> 7, 0x800)`.
- **param1** is the encoder of `AddBytesFilter`, our decoder's delta filter
  (`NzOptimumParam1Encode`, `src/nz_optimum_param1.cpp`). It walks the block
  keeping three distinct-count models over a 512-entry window -- the raw bytes
  and the bytes delta-coded against two candidate offsets, each hashed to a
  9-bit context -- and every 100 qualifying bytes it re-evaluates. Candidate
  offsets are proposed from a 1024-entry ring of recent same-byte distances
  (1..255); the offset a mode is using is never replaced while it is in use.
  When a delta model stops beating the raw one the run is turned into a region:
  a 256-byte window slid backwards over it picks the position where the delta
  alphabet is smallest (FUN_0806e690), the region is grown backwards and
  forwards for as long as the delta stays profitable (FUN_0806e3c0), and it is
  kept only if **three independent tests agree** -- the delta alphabet is at
  least ~14 % smaller, an order-2 LZP scored through Huffman code lengths is
  cheaper on the delta, and a positional sort plus MTF run-length entropy is
  cheaper too -- and, for offsets above 0x13, only if the region is not mostly
  exact repeats at that offset (which the LZ pass would code better). Accepted
  regions are written as `(offset, start, length - 8)` triples into a bit stream
  read back by `AddBytesFilter::DecodeOne`, terminated by a zero offset. The
  whole filter is kept only when the side stream stayed under half its 0x1000
  budget, at least one region was emitted, and (over 0x3ff bytes) the filtered
  block has fewer distinct order-2.5 contexts than the original.
  See [quirks 61-63](ORIGINAL_QUIRKS.md) for what it measures wrong.

`a -co -t1 -m4m` is byte-identical to the original on the twelve text-transform
oracle inputs (three of them BWT blocks) and on **47 of 47** corpus XML/HTML/SVG
files. Not written yet: the exe filter path, image and audio blocks, the
param14/param15 passes, the stored form of a block nothing shrinks, the
multi-threaded bucket layout, and budgets above 16 MB.
