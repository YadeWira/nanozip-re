#pragma once
// A zero-filled byte buffer that does not touch its pages to get there.
//
// `std::vector<uint8_t>(n, 0)` writes every byte, so the kernel has to back all
// n of them before the first one is used -- on a decode that reserves a ring
// or a double buffer sized for the whole stream and then touches a fraction of
// it, that zeroing was 11% of the run (`clear_page_erms`). Fresh memory from
// calloc is already zero: for a large block glibc takes it straight from mmap,
// whose pages cost nothing until they are written. The contents are exactly
// what the vector gave, so nothing that reads them can tell the difference.
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <new>

namespace nzr {

class ZeroedBytes {
 public:
    ZeroedBytes() = default;
    explicit ZeroedBytes(std::size_t n) { Reset(n); }

    // n zero bytes; whatever was held before is released.
    void Reset(std::size_t n) {
        p_.reset(n != 0u ? static_cast<std::uint8_t*>(std::calloc(n, 1u)) : nullptr);
        if (n != 0u && !p_) throw std::bad_alloc();
        n_ = n;
    }
    std::uint8_t* data() { return p_.get(); }
    const std::uint8_t* data() const { return p_.get(); }
    std::size_t size() const { return n_; }

 private:
    struct Free { void operator()(std::uint8_t* p) const { std::free(p); } };
    std::unique_ptr<std::uint8_t, Free> p_;
    std::size_t n_ = 0;
};

}  // namespace nzr
