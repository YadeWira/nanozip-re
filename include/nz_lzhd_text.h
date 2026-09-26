// nz_lzhd_text.h -- the `-cd` text pipeline of the original's compressor: the
// detectors of FUN_08064bb0 (text histogram FUN_08054dc0/e60, CRLF FUN_08054f80,
// dictionary FUN_08055150, chess FUN_08058530, line-RLE FUN_08058000) and the
// driver FUN_08059060 with its transforms (CRLF FUN_08056960, chess FUN_080581d0,
// line-RLE FUN_08058050, dictionary FUN_08055290, space removal FUN_08055e70).
#pragma once
#include <cstddef>
#include <cstdint>
#include <functional>
#include <vector>

namespace nzr::lzhd_enc {

// FUN_08064bb0's text detection on a chunk: the transform bits it asks for
// (0x88 dictionary + param14, 0x40 chess, 0x20 line-RLE, 0x01 CRLF), or 0.
std::uint32_t TextDetect(const std::uint8_t* buf, std::uint32_t n, std::uint8_t* scratch);

// FUN_08059060: run the requested transforms; `buf` (n bytes, capacity 0x8000+0x100)
// and `tmp` are swapped as each transform lands. Returns the new size and the
// applied bits in `*applied`, or 0 when nothing applied or the result is not
// below `cap` (0x8040).
std::uint32_t TextPipeline(std::uint32_t bits, std::uint8_t*& buf, std::uint32_t n, std::uint8_t*& tmp,
                           std::uint32_t cap, std::uint8_t* applied, bool reorder_ascii);

// the individual transforms (exposed for tests)
std::uint32_t TextCrlfEncode(const std::uint8_t* src, std::uint32_t n, std::uint8_t* dst, std::uint32_t cap);
std::uint32_t TextLineRleEncode(std::uint8_t term, const std::uint8_t* src, std::uint32_t n, std::uint8_t* dst, std::uint32_t cap);
std::uint32_t TextParam14Encode(const std::uint8_t* src, std::uint32_t n, std::uint8_t* dst, std::uint32_t cap);
std::uint32_t TextDictEncode(const std::uint8_t* src, std::uint32_t n, std::uint8_t* dst, std::uint32_t cap);
std::uint32_t TextChessEncode(const std::uint8_t* src, std::uint32_t n, std::uint8_t* dst, std::uint32_t cap);

// The two detectors the `-co` driver shares with this one: FUN_08055150 (reached
// there through the wrapper FUN_08055280) and FUN_08057e60 (through FUN_08058000,
// which pins the terminator to 10). The chess detector FUN_08058530 is
// TextChessEncode(buf, n - 0x40, scratch, n) guarded by n >= 0x80.
bool DictFits(const std::uint8_t* p, std::uint32_t n);
bool LineRleFits(const std::uint8_t* src, std::uint32_t n);

// Quirk 56 under concurrent workers. The detector reads a word-continuation table
// that the dictionary transform fills the first time it runs in the PROCESS, so in
// the original's serial order ([1..N-1, 0], measured) a worker stream sees it
// filled exactly when an earlier worker ran the transform. Workers compressed
// concurrently each get a view of that flag: `resolve` (set by the driver)
// yields the value the worker inherits, called at the worker's first read unless
// the worker has already filled the table itself; `on_set` tells the driver the
// worker has filled it. Without a view (one thread), the process-wide flag.
struct DictTableView {
    bool resolved = true;
    bool built = false;
    bool did_set = false;
    std::function<bool()> resolve;
    std::function<void()> on_set;
};
void SetThreadDictTableView(DictTableView* view);
bool ProcessDictTablesBuilt();
void SetProcessDictTablesBuilt(bool built);

}  // namespace nzr::lzhd_enc
