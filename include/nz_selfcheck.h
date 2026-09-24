// The whole-archive self-check `a` runs on what it has just written.
//
// Both sides describe the archive's content as items (stored name, offset in the
// file, length, CRC-64): the writer one per piece it read, the reader one per
// slice or entry it decoded. A CRC-64 can be joined across pieces knowing only
// the second piece's length, so a file split across worker streams, read out of
// order, compares equal to the same file decoded whole.
#pragma once

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace nzr {
namespace selfcheck {

// CRC-64/XZ (ECMA-182, reflected; initial value and final xor all ones),
// slicing-by-8.
class Crc64 {
public:
    static constexpr std::uint64_t kPoly = 0xc96c5795d7870f42ull;
    Crc64() { v_ = ~0ull; }
    void Update(const unsigned char* p, std::size_t n) {
        const auto& t = Tables();
        std::uint64_t c = v_;
        while (n >= 8u) {
            c ^= static_cast<std::uint64_t>(p[0]) | (static_cast<std::uint64_t>(p[1]) << 8) |
                 (static_cast<std::uint64_t>(p[2]) << 16) | (static_cast<std::uint64_t>(p[3]) << 24) |
                 (static_cast<std::uint64_t>(p[4]) << 32) | (static_cast<std::uint64_t>(p[5]) << 40) |
                 (static_cast<std::uint64_t>(p[6]) << 48) | (static_cast<std::uint64_t>(p[7]) << 56);
            c = t[7][c & 0xffu] ^ t[6][(c >> 8) & 0xffu] ^ t[5][(c >> 16) & 0xffu] ^ t[4][(c >> 24) & 0xffu] ^
                t[3][(c >> 32) & 0xffu] ^ t[2][(c >> 40) & 0xffu] ^ t[1][(c >> 48) & 0xffu] ^ t[0][c >> 56];
            p += 8; n -= 8u;
        }
        while (n-- != 0u) c = t[0][(c ^ *p++) & 0xffu] ^ (c >> 8);
        v_ = c;
    }
    std::uint64_t Final() const { return ~v_; }
    static std::uint64_t Of(const unsigned char* p, std::size_t n) { Crc64 c; c.Update(p, n); return c.Final(); }
    static std::uint64_t Empty() { return 0u; }   // ~(~0) of no bytes

    // CRC of A||B from CRC(A), CRC(B) and |B| (zlib's crc32_combine, 64 bits wide).
    static std::uint64_t Combine(std::uint64_t a, std::uint64_t b, std::uint64_t len_b) {
        if (len_b == 0u) return a;
        std::uint64_t even[64], odd[64];
        odd[0] = kPoly;
        std::uint64_t row = 1u;
        for (int i = 1; i < 64; ++i) { odd[i] = row; row <<= 1; }
        Square(even, odd);   // two zero bits
        Square(odd, even);   // four zero bits
        for (;;) {
            Square(even, odd);
            if (len_b & 1u) a = Times(even, a);
            len_b >>= 1;
            if (len_b == 0u) break;
            Square(odd, even);
            if (len_b & 1u) a = Times(odd, a);
            len_b >>= 1;
            if (len_b == 0u) break;
        }
        return a ^ b;
    }

private:
    std::uint64_t v_;
    using Table = std::uint64_t[8][256];
    static const Table& Tables() {
        static const struct Holder {
            std::uint64_t t[8][256];
            Holder() {
                for (unsigned i = 0; i < 256u; ++i) {
                    std::uint64_t c = i;
                    for (int k = 0; k < 8; ++k) c = (c & 1u) ? (c >> 1) ^ kPoly : (c >> 1);
                    t[0][i] = c;
                }
                for (unsigned i = 0; i < 256u; ++i)
                    for (int s = 1; s < 8; ++s) t[s][i] = t[0][t[s - 1][i] & 0xffu] ^ (t[s - 1][i] >> 8);
            }
        } h;
        return h.t;
    }
    static std::uint64_t Times(const std::uint64_t* mat, std::uint64_t vec) {
        std::uint64_t sum = 0;
        for (int i = 0; vec != 0u; ++i, vec >>= 1) if (vec & 1u) sum ^= mat[i];
        return sum;
    }
    static void Square(std::uint64_t* sq, const std::uint64_t* mat) {
        for (int i = 0; i < 64; ++i) sq[i] = Times(mat, mat[i]);
    }
};

struct Item {
    std::string name;             // as stored in the archive
    std::uint64_t off = 0;        // where it sits inside its file
    std::uint64_t len = 0;
    std::uint64_t crc = 0;
    bool complete = true;         // reader side: every byte of it was decoded
};

// The reader's items, filled while a self-check decode runs (from the stream
// workers too, hence the lock). Off at every other time.
class Recorder {
public:
    static Recorder& Get() { static Recorder r; return r; }
    bool Active() const { return active_.load(std::memory_order_acquire); }
    void Start() { std::lock_guard<std::mutex> lk(mu_); items_.clear(); active_.store(true, std::memory_order_release); }
    std::vector<Item> Stop() {
        std::lock_guard<std::mutex> lk(mu_);
        active_.store(false, std::memory_order_release);
        std::vector<Item> out;
        out.swap(items_);
        return out;
    }
    void Add(Item it) { std::lock_guard<std::mutex> lk(mu_); if (Active()) items_.push_back(std::move(it)); }
    // Strict reading while the check runs: no fallback the original's reader
    // does not have (the lzpf dictionary guesses) may make a bad archive pass.
    bool Strict() const { return Active(); }

private:
    std::atomic<bool> active_{false};
    std::mutex mu_;
    std::vector<Item> items_;
};

// One side's items, per stored name, as runs: pieces that follow each other in
// the file are joined, pieces that overlap (the same file listed twice) stay
// apart. Two sides describe the same content exactly when their runs agree.
struct Run { std::uint64_t off, len, crc; bool operator==(const Run& o) const { return off == o.off && len == o.len && crc == o.crc; } };
inline std::map<std::string, std::vector<Run>> Runs(std::vector<Item> items) {
    std::sort(items.begin(), items.end(), [](const Item& a, const Item& b) {
        if (a.name != b.name) return a.name < b.name;
        if (a.off != b.off) return a.off < b.off;
        if (a.len != b.len) return a.len < b.len;
        return a.crc < b.crc;
    });
    std::map<std::string, std::vector<Run>> out;
    // Per name, keep a set of open runs: each item extends the first run that
    // ends exactly where it starts, or opens a new one.
    for (const Item& it : items) {
        std::vector<Run>& rs = out[it.name];
        bool joined = false;
        for (Run& r : rs) {
            if (r.off + r.len == it.off && it.len != 0u) {
                r.crc = Crc64::Combine(r.crc, it.crc, it.len);
                r.len += it.len;
                joined = true;
                break;
            }
        }
        if (!joined) rs.push_back({it.off, it.len, it.crc});
    }
    for (auto& kv : out) std::sort(kv.second.begin(), kv.second.end(), [](const Run& a, const Run& b) {
        if (a.off != b.off) return a.off < b.off;
        if (a.len != b.len) return a.len < b.len;
        return a.crc < b.crc;
    });
    return out;
}

}  // namespace selfcheck
}  // namespace nzr
