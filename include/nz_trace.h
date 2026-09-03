// NZ_TRACE_CONSTRUCTS=1: print each distinct format construct the decoder meets,
// once per process, as "[construct] key=value" on stderr. The real-corpus sweep
// collects these lines so a release can state which constructs were exercised
// (sub-chunk kinds, image-model modes, text-transform bits, block kinds) instead
// of assuming.
#pragma once
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <set>
#include <string>

namespace nz_trace {

inline bool ConstructsOn() {
    static const bool on = (std::getenv("NZ_TRACE_CONSTRUCTS") != nullptr);
    return on;
}

inline void Construct(const char* fmt, ...) {
    if (!ConstructsOn()) return;
    char b[256];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(b, sizeof(b), fmt, ap);
    va_end(ap);
    static std::mutex m;
    static std::set<std::string> seen;
    std::lock_guard<std::mutex> g(m);
    if (seen.insert(b).second) std::fprintf(stderr, "[construct] %s\n", b);
}

}  // namespace nz_trace
