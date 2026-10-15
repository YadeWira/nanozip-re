// nz_calloc_vec.h -- a byte vector whose memory is zeroed by the allocator, not
// written to zero.
//
// std::vector's value-initialisation writes every byte of a fresh buffer, so a
// generous capacity is resident the moment it exists: a decode stage that
// reserves twice its input and fills part of it, or a 128 MiB window of which a
// stream uses a part, cost the whole size. calloc hands out pages the kernel
// has already zeroed, so the contents are the same zeros and only what is
// written is ever touched. Default-constructing an element does nothing, which
// is correct only for a buffer built fresh at its size (or shrunk): growing one
// in place after a shrink would expose old bytes instead of zeros, and no user
// does that.
#pragma once
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <utility>
#include <vector>

namespace nz {

template <class T>
struct CallocAlloc {
    using value_type = T;
    CallocAlloc() = default;
    template <class U> CallocAlloc(const CallocAlloc<U>&) noexcept {}
    T* allocate(std::size_t n) {
        void* p = std::calloc(n ? n : 1u, sizeof(T));
        if (p == nullptr) throw std::bad_alloc();
        return static_cast<T*>(p);
    }
    void deallocate(T* p, std::size_t) noexcept { std::free(p); }
    template <class U> void construct(U*) noexcept {}
    template <class U, class... A> void construct(U* p, A&&... a) { ::new (static_cast<void*>(p)) U(std::forward<A>(a)...); }
    template <class U> bool operator==(const CallocAlloc<U>&) const noexcept { return true; }
    template <class U> bool operator!=(const CallocAlloc<U>&) const noexcept { return false; }
};
using CallocVec = std::vector<std::uint8_t, CallocAlloc<std::uint8_t>>;

}  // namespace nz
