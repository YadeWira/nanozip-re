// The self-check's CRC-64 (CRC-64/XZ, reflected) folded 64 bytes at a time with
// carry-less multiplication (PCLMULQDQ), for x86 processors that have it. The
// table version in nz_selfcheck.h stays the reference and the fallback; this
// one returns a 16-byte state whose table CRC from 0 continues the same value.
//
// The fold constants are x^n mod G in the reflected domain: (x^191, x^127) step
// 16 bytes, (x^575, x^511) step 64. Found by search against the table version
// and checked on random lengths and start values (tests/encode/crc64_fold.cpp).
// -DNZ_NO_CRC64_FOLD builds the table version only.
#include "nz_selfcheck.h"

#if !defined(NZ_NO_CRC64_FOLD) && (defined(__x86_64__) || defined(__i386__)) && (defined(__GNUC__) || defined(__clang__))
#include <immintrin.h>
#define NZ_CRC64_FOLD 1
#endif

namespace nzr {
namespace selfcheck {

#ifdef NZ_CRC64_FOLD
namespace {
constexpr std::uint64_t kK1 = 0xe05dd497ca393ae4ull;   // x^191
constexpr std::uint64_t kK2 = 0xdabe95afc7875f40ull;   // x^127
constexpr std::uint64_t kK3 = 0x6ae3efbb9dd441f3ull;   // x^575
constexpr std::uint64_t kK4 = 0x081f6054a7842df4ull;   // x^511

__attribute__((target("pclmul,sse2")))
inline __m128i Fold(__m128i x, __m128i k) {   // k = {lo: constant for x.lo, hi: constant for x.hi}
    return _mm_xor_si128(_mm_clmulepi64_si128(x, k, 0x00), _mm_clmulepi64_si128(x, k, 0x11));
}
}  // namespace

__attribute__((target("pclmul,sse2")))
std::size_t Crc64Fold(std::uint64_t crc, const unsigned char* p, std::size_t n, unsigned char state[16]) {
    if (n < 64u) return 0u;
    const __m128i k12 = _mm_set_epi64x(static_cast<long long>(kK2), static_cast<long long>(kK1));
    const __m128i k34 = _mm_set_epi64x(static_cast<long long>(kK4), static_cast<long long>(kK3));
    __m128i x0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(p));
    __m128i x1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(p + 16));
    __m128i x2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(p + 32));
    __m128i x3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(p + 48));
    x0 = _mm_xor_si128(x0, _mm_set_epi64x(0, static_cast<long long>(crc)));
    std::size_t i = 64;
    for (; i + 64u <= n; i += 64u) {
        x0 = _mm_xor_si128(Fold(x0, k34), _mm_loadu_si128(reinterpret_cast<const __m128i*>(p + i)));
        x1 = _mm_xor_si128(Fold(x1, k34), _mm_loadu_si128(reinterpret_cast<const __m128i*>(p + i + 16)));
        x2 = _mm_xor_si128(Fold(x2, k34), _mm_loadu_si128(reinterpret_cast<const __m128i*>(p + i + 32)));
        x3 = _mm_xor_si128(Fold(x3, k34), _mm_loadu_si128(reinterpret_cast<const __m128i*>(p + i + 48)));
    }
    __m128i y = _mm_xor_si128(Fold(x0, k12), x1);
    y = _mm_xor_si128(Fold(y, k12), x2);
    y = _mm_xor_si128(Fold(y, k12), x3);
    for (; i + 16u <= n; i += 16u)
        y = _mm_xor_si128(Fold(y, k12), _mm_loadu_si128(reinterpret_cast<const __m128i*>(p + i)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(state), y);
    return i;
}

bool Crc64FoldAvailable() {
    static const bool ok = __builtin_cpu_supports("pclmul") && __builtin_cpu_supports("sse2");
    return ok;
}
#else
std::size_t Crc64Fold(std::uint64_t, const unsigned char*, std::size_t, unsigned char*) { return 0u; }
bool Crc64FoldAvailable() { return false; }
#endif

}  // namespace selfcheck
}  // namespace nzr
