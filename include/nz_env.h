// Cached environment lookups for the trace/dump switches.
//
// The decoders test switches such as NZOPT_TRACE / NZO2_* inside per-symbol
// loops; a plain getenv() there is a linear scan of the environment on every
// symbol and showed up at 3-9 % of the whole decode in perf. NZ_ENV caches the
// answer once per call site (the environment does not change during a run).
#ifndef NZ_ENV_H
#define NZ_ENV_H
#include <cstdlib>
#define NZ_ENV(name) ([]() -> const char* { static const char* const v = std::getenv(name); return v; }())
#endif
