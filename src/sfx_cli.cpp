#include "nz_sfx/sfx_cli.hpp"
#include <vector>
#include <string>
#include <cstdlib>
#include <cstdio>
#include <thread>
#include <chrono>
#include <cstring>
#include <fstream>
#include <x86intrin.h>
#include <cpuid.h>
#if defined(_WIN32)
#include <windows.h>
#else
#include <unistd.h>
#endif
#include <ctime>

#include <algorithm>
#include <cctype>

namespace nz {
namespace recon {

namespace {

bool StartsWith(const std::string& value, const std::string& prefix) {
    return value.size() >= prefix.size() &&
           std::equal(prefix.begin(), prefix.end(), value.begin());
}

Command ParseCommand(const std::string& token) {
    if (token == "a") {
        return Command::kAdd;
    }
    if (token == "l") {
        return Command::kList;
    }
    if (token == "t") {
        return Command::kTest;
    }
    if (token == "s") {
        return Command::kSimulate;
    }
    if (token == "x") {
        return Command::kExtract;
    }
    if (token == "w32c") {
        return Command::kW32c;
    }
    if (token == "info") {
        return Command::kInfo;
    }
    if (token == "help") {
        return Command::kHelp;
    }
    return Command::kUnknown;
}

Compressor ParseCompressor(const std::string& value, bool* ok) {
    if (ok != nullptr) {
        *ok = true;
    }
    if (value == "n") {
        return Compressor::kNone;
    }
    if (value == "f") {
        return Compressor::kLzpf;
    }
    if (value == "F") {
        return Compressor::kLzpfLarge;
    }
    if (value == "d") {
        return Compressor::kLzhd;
    }
    if (value == "dp") {
        return Compressor::kLzhdParallel;
    }
    if (value == "dP") {
        return Compressor::kLzhdParallelExtra;
    }
    if (value == "D") {
        return Compressor::kLzhds;
    }
    if (value == "Dp") {
        return Compressor::kLzhdsParallel;
    }
    if (value == "DP") {
        return Compressor::kLzhdsParallelExtra;
    }
    if (value == "o") {
        return Compressor::kOptimum1;
    }
    if (value == "O") {
        return Compressor::kOptimum2;
    }
    if (value == "c") {
        return Compressor::kCm;
    }
    if (ok != nullptr) {
        *ok = false;
    }
    return Compressor::kOptimum1;
}

}  // namespace

CliOptions ParseCli(int argc, char** argv) {
    CliOptions out;
    if (argv == nullptr || argc <= 1) {
        out.show_usage = true;
        return out;
    }

    for (int i = 1; i < argc; ++i) {
        if (argv[i] != nullptr) {
            out.passthrough_args.emplace_back(argv[i]);
        }
    }

    out.command_token = argv[1] == nullptr ? "" : argv[1];
    out.command = ParseCommand(out.command_token);
    if (out.command == Command::kUnknown) {
        out.show_usage = true;
        out.unknown_command = out.command_token;
        return out;
    }

    if (out.command == Command::kHelp) {
        out.show_advanced_help = true;
        return out;
    }
    if (out.command == Command::kInfo) {
        return out;
    }

    // The original scans EVERY argument after the command for switches -- a "-y"
    // after the archive name is still a switch (measured: `x arc -y` overwrites,
    // `x arc -v -y` shows the -v header). Values must be attached (`-o out` makes
    // "out" the archive; `-x` alone is "Unknown argument: -x"), and a lone "-" is
    // rejected the same way on the decode commands. The first switch it cannot
    // parse stops the run with "Unknown argument: <switch>".
    std::vector<std::string> plain;
    for (int i = 2; i < argc; ++i) {
        const char* raw = argv[i];
        if (raw == nullptr) continue;
        const std::string token(raw);
        if (token.empty() || token[0] != '-') { plain.push_back(token); continue; }
        const std::string sw = token.substr(1);
        const auto is_digits = [](const std::string& v) {
            return std::all_of(v.begin(), v.end(), [](unsigned char ch) { return std::isdigit(ch) != 0; });
        };
        // <n>[k,m,g] with an optional decimal part ("-m1.5g" is accepted).
        const auto parse_size = [&](const std::string& v, std::uint64_t* out_bytes) {
            if (v.empty()) { *out_bytes = 0; return true; }
            std::string num = v; std::uint64_t unit = 1;
            const char last = num.back();
            if (last == 'k' || last == 'm' || last == 'g') {
                unit = (last == 'k') ? 1024ull : (last == 'm') ? 1048576ull : 1073741824ull;
                num.pop_back();
            }
            if (num.empty()) return false;
            const std::size_t dot = num.find('.');
            const std::string ip = (dot == std::string::npos) ? num : num.substr(0, dot);
            const std::string fp = (dot == std::string::npos) ? "" : num.substr(dot + 1);
            if (!is_digits(ip) || !is_digits(fp) || (ip.empty() && fp.empty())) return false;
            double val = ip.empty() ? 0.0 : static_cast<double>(std::stoull(ip));
            if (!fp.empty()) val += std::stod("0." + fp);
            *out_bytes = static_cast<std::uint64_t>(val * static_cast<double>(unit));
            return true;
        };
        bool ok = true;
        if (sw.empty())                 ok = false;
        else if (sw == "r")             out.recurse = true;
        else if (sw == "y")             out.yes_to_all = true;
        else if (sw == "v")             out.verbose = true;
        else if (sw == "sp")            out.strip_paths = true;
        else if (sw == "nt")            out.no_timestamps = true;
        else if (sw == "np")            out.no_permissions = true;
        else if (sw == "nm")            { out.no_timestamps = true; out.no_permissions = true; out.checksum = ChecksumMode::kNone; }
        else if (sw == "nofilenameext") out.no_filename_ext = true;
        else if (sw == "swapinout")     out.swapinout = true;
        else if (sw == "forceout")      out.forceout = true;
        else if (sw == "fo")            out.restore_ownership = true;
        else if (sw == "pause")         out.pause = true;
        else if (sw == "continue")      { /* accepted silently by the original */ }
        else if (sw == "forcemem")      out.deprecated_forcemem = true;
        else if (sw[0] == 'c') {
            bool cok = false;
            out.compressor = ParseCompressor(sw.substr(1), &cok);
            ok = cok;
        } else if (sw[0] == 'h') {
            const std::string v = sw.substr(1);
            if (v == "n") out.checksum = ChecksumMode::kNone;
            else if (v == "c") out.checksum = ChecksumMode::kCrc16;
            else if (v == "C") out.checksum = ChecksumMode::kCrc32;
            else if (v == "f") out.checksum = ChecksumMode::kFletcher16;
            else ok = false;
        } else if (sw[0] == 's') {
            const std::string v = sw.substr(1);
            ok = (v == "n" || v == "e" || v == "a" || v == "s");
        } else if (sw[0] == 'o') {
            out.output_path = sw.substr(1);            // may be empty: no effect
        } else if (sw[0] == 'x') {
            if (sw.size() < 2u) ok = false; else out.exclude_patterns.push_back(sw.substr(1));
        } else if (sw.compare(0, 2, "br") == 0) {
            ok = parse_size(sw.substr(2), &out.read_buffer_bytes);
        } else if (sw.compare(0, 2, "bw") == 0) {
            ok = parse_size(sw.substr(2), &out.write_buffer_bytes);
        } else if (sw[0] == 't') {
            const std::string v = sw.substr(1);
            if (!is_digits(v)) ok = false;
            else out.threads = v.empty() ? 0u : static_cast<unsigned>(std::stoul(v));
        } else if (sw[0] == 'p') {
            ok = is_digits(sw.substr(1));
        } else if (sw[0] == 'm') {
            std::uint64_t dummy = 0; ok = parse_size(sw.substr(1), &dummy);
        } else ok = false;
        if (!ok) { out.unknown_switches.push_back(token); return out; }
    }

    if (out.command == Command::kW32c) {
        // The original validates the archive name for `w32c` like any other
        // command ("Error: Archive name missing..."); only the self-extractor
        // build itself is missing here.
        if (plain.empty()) {
            out.show_usage = true;
            out.error = "archive name missing";
            return out;
        }
        out.archive_path = plain.front(); plain.erase(plain.begin());
        out.positional = plain;
        return out;
    }

    if (plain.empty()) {
        out.show_usage = true;
        out.error = "archive name missing";
        return out;
    }
    out.archive_path = plain.front();
    plain.erase(plain.begin());
    out.positional = plain;
    // -swapinout: the archive name and the first file argument change places (with
    // "*" standing in for a missing file argument -- measured "Archive: *.nz").
    if (out.swapinout) {
        std::string first = out.positional.empty() ? std::string("*") : out.positional.front();
        if (out.positional.empty()) out.positional.push_back(out.archive_path); else out.positional.front() = out.archive_path;
        out.archive_path = first;
    }
    // The original appends ".nz" to whatever archive name it is given unless the
    // name already ends in ".nz" or ".exe" (a self-extractor), case-sensitively
    // (measured: m.bin -> m.bin.nz, m.NZ -> m.NZ.nz, m.EXE -> m.EXE.nz, m.exe and
    // m.tar.nz untouched), or -nofilenameext is set. Same rule for every command.
    if (!out.no_filename_ext) {
        const std::string& a = out.archive_path;
        const auto ends = [&a](const char* suf) {
            const std::size_t n = std::strlen(suf);
            return a.size() >= n && a.compare(a.size() - n, n, suf) == 0;
        };
        if (!ends(".nz") && !ends(".exe")) out.archive_path += ".nz";
    }

    if ((out.command == Command::kAdd || out.command == Command::kSimulate) && out.positional.empty()) {
        out.show_usage = true;
        out.error = "no input files provided";
    }

    return out;
}

std::string FormatGrouped(std::uint64_t value) {
    std::string digits = std::to_string(value);
    std::string out;
    const std::size_t n = digits.size();
    for (std::size_t i = 0; i < n; ++i) {
        if (i != 0 && ((n - i) % 3u) == 0u) out.push_back(' ');
        out.push_back(digits[i]);
    }
    return out;
}

std::string FormatSizeColumn(std::uint64_t bytes) {
    // Unit steps up once the value exceeds NINE of the current unit, and the
    // printed number is rounded rather than truncated. Both measured against the
    // original -- see the header comment for the boundary samples.
    static const char* kUnits[] = {"B", "KB", "MB", "GB", "TB"};
    std::uint64_t unit = 1;
    int idx = 0;
    while (idx < 4 && bytes > 9u * unit * 1024u) { unit *= 1024u; ++idx; }
    const std::uint64_t shown = (idx == 0) ? bytes : (bytes + unit / 2u) / unit;
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%6llu %-2s",
                  static_cast<unsigned long long>(shown), kUnits[idx]);
    return std::string(buf);
}

void ClearStatusLine(std::ostream& os) {
    os << '\r' << std::string(79, ' ') << '\r';
}

namespace {

std::string ProcField(const char* path, const char* key) {
    std::ifstream in(path);
    std::string line;
    const std::size_t klen = std::strlen(key);
    while (std::getline(in, line)) {
        if (line.compare(0, klen, key) != 0) continue;
        std::size_t colon = line.find(':');
        if (colon == std::string::npos) return std::string();
        std::size_t b = line.find_first_not_of(" \t", colon + 1);
        if (b == std::string::npos) return std::string();
        std::size_t e = line.find_last_not_of(" \t");
        return line.substr(b, e - b + 1);
    }
    return std::string();
}

unsigned MeasuredMhz(const std::string& cpuinfo_mhz) {
#if defined(__i386__) || defined(__x86_64__)
    // std::chrono + sleep_for rather than clock_gettime/nanosleep: the latter
    // pair does not exist on mingw, and this measures the same thing.
    const auto t0 = std::chrono::steady_clock::now();
    const unsigned long long c0 = __rdtsc();
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    const unsigned long long c1 = __rdtsc();
    const auto t1 = std::chrono::steady_clock::now();
    const double ns = static_cast<double>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count());
    if (ns > 0.0) return static_cast<unsigned>(static_cast<double>(c1 - c0) * 1000.0 / ns);
#endif
    return cpuinfo_mhz.empty() ? 0u : (unsigned)std::strtod(cpuinfo_mhz.c_str(), nullptr);
}

// The brand string from CPUID leaves 0x80000002-4 -- what the original prints,
// on every platform (Windows has no /proc; Linux may hide /proc/cpuinfo).
std::string CpuidBrand() {
    unsigned regs[4] = {0, 0, 0, 0};
    if (!__get_cpuid(0x80000000u, &regs[0], &regs[1], &regs[2], &regs[3]) ||
        regs[0] < 0x80000004u) {
        return std::string();
    }
    char brand[49];
    brand[48] = '\0';
    for (unsigned leaf = 0; leaf < 3u; ++leaf) {
        if (!__get_cpuid(0x80000002u + leaf, &regs[0], &regs[1], &regs[2], &regs[3])) {
            return std::string();
        }
        std::memcpy(brand + leaf * 16u, regs, 16u);
    }
    std::string out(brand);
    // CPUID pads the brand string with leading blanks on many parts.
    const std::size_t first = out.find_first_not_of(' ');
    if (first == std::string::npos) return std::string();
    return out.substr(first, out.find_last_not_of(' ') - first + 1u);
}

#if defined(_WIN32)

// Physical cores and logical processors, so the "+HT" suffix means the same
// thing it does on the Linux build.
void WinCoreCounts(unsigned* physical, unsigned* logical) {
    *physical = 0u;
    *logical = 0u;
    DWORD len = 0;
    GetLogicalProcessorInformation(nullptr, &len);
    if (len != 0u) {
        std::vector<SYSTEM_LOGICAL_PROCESSOR_INFORMATION> info(
            len / sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION));
        if (GetLogicalProcessorInformation(info.data(), &len)) {
            for (const auto& e : info) {
                if (e.Relationship != RelationProcessorCore) continue;
                ++(*physical);
                ULONG_PTR mask = e.ProcessorMask;
                while (mask) { *logical += static_cast<unsigned>(mask & 1u); mask >>= 1; }
            }
        }
    }
    if (*logical == 0u) {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        *logical = static_cast<unsigned>(si.dwNumberOfProcessors);
    }
    if (*physical == 0u) *physical = *logical;
    if (*logical == 0u) { *logical = 1u; *physical = 1u; }
}
#endif  // _WIN32

}  // namespace

unsigned HostThreadCount() {
#if defined(_WIN32)
    // The original reports 16 on a 16-core/32-thread host, on Linux AND under
    // wine, where GetLogicalProcessorInformation says 32 cores of one thread
    // each -- so it takes the count from the CPU itself, not from the OS. Do the
    // same: logical processors divided by the hyper-threading ratio the CPU
    // reports (logical per package / cores per package), which is exactly what
    // the Linux path derives from `siblings` and `cpu cores`.
    unsigned physical = 0, logical = 0;
    WinCoreCounts(&physical, &logical);
    if (logical == 0u) logical = 1u;
    if (logical > 32u) logical = 32u;
    unsigned ratio = 1u;
    unsigned a = 0, b = 0, c = 0, d = 0;
    if (__get_cpuid(1u, &a, &b, &c, &d)) {
        const unsigned logical_per_pkg = (b >> 16u) & 0xffu;
        unsigned cores_per_pkg = 0;
        unsigned a4 = 0, b4 = 0, c4 = 0, d4 = 0;
        if (__get_cpuid_count(4u, 0u, &a4, &b4, &c4, &d4)) cores_per_pkg = ((a4 >> 26u) & 0x3fu) + 1u;
        if (logical_per_pkg > 0u && cores_per_pkg > 0u && logical_per_pkg > cores_per_pkg)
            ratio = logical_per_pkg / cores_per_pkg;
        else if ((d & (1u << 28)) != 0u && logical_per_pkg > 1u && cores_per_pkg == 0u)
            ratio = 2u;   // hyper-threading advertised, core count unavailable
    }
    if (ratio > 1u && logical / ratio >= 1u) logical /= ratio;
    return logical;
#else
    unsigned logical = 0;
    std::ifstream in("/proc/cpuinfo");
    std::string line;
    while (std::getline(in, line))
        if (line.compare(0, 9, "processor") == 0) ++logical;
    if (logical == 0) logical = 1;
    if (logical > 32u) logical = 32u;
    // The original reports 16 on this host, whose visible count is 32 with
    // hyper-threading -- i.e. it uses PHYSICAL cores, not logical ones.
    const std::string siblings = ProcField("/proc/cpuinfo", "siblings");
    const std::string cores    = ProcField("/proc/cpuinfo", "cpu cores");
    if (!siblings.empty() && !cores.empty() && siblings != cores && logical > 1u) logical /= 2u;
    return logical;
#endif
}

std::string HostSummaryLine() {
    // "<model>|<MHz> MHz|#<logical>[+HT]|<available>/<total> MB", the second line
    // the original prints under its banner and the only line `info` shares with it.
#if defined(_WIN32)
    unsigned physical = 0, logical_w = 0;
    WinCoreCounts(&physical, &logical_w);
    if (logical_w > 32u) logical_w = 32u;
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    unsigned long long avail_mb = 0, total_mb = 0;
    if (GlobalMemoryStatusEx(&ms)) {
        avail_mb = ms.ullAvailPhys / (1024ull * 1024ull);
        total_mb = ms.ullTotalPhys / (1024ull * 1024ull);
    }
    const std::string brand = CpuidBrand();
    char wbuf[512];
    std::snprintf(wbuf, sizeof(wbuf), "%s|%u MHz|#%u%s|%llu/%llu MB",
                  brand.empty() ? "unknown CPU" : brand.c_str(),
                  MeasuredMhz(std::string()),
                  logical_w, (logical_w > physical) ? "+HT" : "",
                  avail_mb, total_mb);
    return std::string(wbuf);
#else
    const std::string model = ProcField("/proc/cpuinfo", "model name");
    const std::string mhz = ProcField("/proc/cpuinfo", "cpu MHz");
    const std::string siblings = ProcField("/proc/cpuinfo", "siblings");
    const std::string cores = ProcField("/proc/cpuinfo", "cpu cores");

    unsigned logical = 0;
    double max_mhz = 0.0;
    {
        std::ifstream in("/proc/cpuinfo");
        std::string line;
        while (std::getline(in, line)) {
            if (line.compare(0, 9, "processor") == 0) ++logical;
            if (line.compare(0, 7, "cpu MHz") == 0) {
                const std::size_t c = line.find(':');
                if (c != std::string::npos)
                    max_mhz = std::max(max_mhz, std::strtod(line.c_str() + c + 1, nullptr));
            }
        }
    }
    // The original reports 32 on this 64-thread host. A 32-bit process sees a
    // 32-entry affinity mask, so cap it the same way -- on any machine with 32 or
    // fewer logical CPUs this is a no-op and reports the true count.
    if (logical > 32u) logical = 32u;
    // The original reports a MEASURED clock (its readings drift around 2653-2752 MHz
    // on a 2.60 GHz part), not the "cpu MHz" field -- that field is a live per-core
    // value and reads the idle floor on a quiet core. Measure the invariant TSC over
    // a short interval, which is what lands in the same place.
    (void)max_mhz;
    const bool ht = (!siblings.empty() && !cores.empty() && siblings != cores);

    // MemFree, not MemAvailable: measured against the original, which reports
    // 10261 MB on a host whose MemFree is 10507332 kB and MemAvailable 49801188 kB.
    std::uint64_t total_kb = 0, avail_kb = 0;
    {
        const std::string t = ProcField("/proc/meminfo", "MemTotal");
        const std::string a = ProcField("/proc/meminfo", "MemFree");
        if (!t.empty()) total_kb = std::strtoull(t.c_str(), nullptr, 10);
        if (!a.empty()) avail_kb = std::strtoull(a.c_str(), nullptr, 10);
    }

    // The original takes these from CPUID and the CPU count from the kernel,
    // not from /proc/cpuinfo (measured: identical line with the file unreadable).
    std::string brand = model;
    bool ht_flag = ht;
    if (brand.empty()) brand = CpuidBrand();
    if (logical == 0u) {
        const long n = ::sysconf(_SC_NPROCESSORS_ONLN);
        logical = n > 0 ? static_cast<unsigned>(n) : 1u;
        if (logical > 32u) logical = 32u;
        unsigned a = 0, b = 0, c = 0, d = 0;
        if (__get_cpuid(1u, &a, &b, &c, &d)) ht_flag = (d & (1u << 28)) != 0u;
    }
    char buf[512];
    std::snprintf(buf, sizeof(buf), "%s|%u MHz|#%u%s|%llu/%llu MB",
                  brand.empty() ? "unknown CPU" : brand.c_str(),
                  MeasuredMhz(mhz),
                  logical, ht_flag ? "+HT" : "",
                  static_cast<unsigned long long>((avail_kb + 512u) / 1024u),
                  static_cast<unsigned long long>((total_kb + 512u) / 1024u));
    return std::string(buf);
#endif
}

void PrintBanner(std::ostream& os) {
    // Layout matched to the original, which prints the product line and then the
    // host summary with no leading blank. The build tag names the platform the way
    // the original's builds do ("/Linux32" and "/Linux64" are its own strings; the
    // Windows pair follows the same pattern -- the original Windows binary is
    // packed, so its exact tag could not be read and "Win32"/"Win64" is the
    // natural reading). Leading CR and BOTH lines go to stderr in the original --
    // everything else it prints goes to stdout, so piping stdout gives you just
    // the data. Measured by capturing the two streams separately.
#if defined(_WIN32)
    const char* tag = (sizeof(void*) == 8) ? "Win64" : "Win32";
#else
    const char* tag = (sizeof(void*) == 8) ? "Linux64" : "Linux32";
#endif
    // The original emits the whole thing in one write(2) -- the CR, the product
    // line, its newline and the host summary with no trailing newline -- then a
    // separate write of the closing "\n" (measured: a 145-byte write followed by a
    // 1-byte write on stderr). std::cerr is unit-buffered, so each `<<` would be
    // its own syscall; build the block and write it once to match.
    std::string block = "\rNanoZip 0.09 alpha/";
    block += tag;
    block += "  (C) 2008-2011 Sami Runsas  www.nanozip.net\n";
    block += HostSummaryLine();
    os.write(block.data(), static_cast<std::streamsize>(block.size()));
    os << '\n';
}

void PrintUsage(const char* program_name, std::ostream& os) {
    const char* prog = (program_name != nullptr) ? program_name : "nz_recon";
    os << "\nusage: " << prog << " <command> [-<opt_1>...-<opt_n>] <archive_file> <files...>\n";
    os << "e.g. " << prog << " a -cO -m1.2g backup document1.txt document2.txt\n\n";

    os << " commands:\n";
    os << "  a       add files to archive\n";
    os << "  l       list contents of archive\n";
    os << "  t       test archive, decompress without writing output\n";
    os << "  s       simulate compression without writing output\n";
    os << "  x       extract files from archive\n";
    os << "  w32c    create self-extracting archive (windows 32-bit console)\n";
    os << "  info    information about host system\n";
    os << "  help    show advanced options\n\n";

    os << " compression specific options (must be set at compression time):\n";
    os << "  c<n,f,F,         compressor: none, nz_lzpf, nz_lzpf_large,\n";
    os << "    d,dp,dP        nz_lzhd, nz_lzhd_parallel, nz_lzhd_parallel_extra,\n";
    os << "    D,Dp,DP        nz_lzhds, nz_lzhds_parallel, nz_lzhds_parallel_extra,\n";
    os << "    o,O,c>         nz_optimum1 (default), nz_optimum2, nz_cm\n";
    os << "                   (use parallel compressor on multicore platform only)\n";
    os << "  p<0...n>         number of compressors to run in parallel\n";
    os << "                   (default: 0=auto/smart config based on -c, -t and files)\n";
    os << "  m<0...n>[k,m,g]  memory use (approximate limit) (default: 512m)\n";
    os << "  s<n,e,a,s>       sort files before compression by: nothing,\n";
    os << "                   extension (default), name, size\n\n";

    os << " general options:\n";
    os << "  -                stop scanning switches\n";
    os << "  r                recurse subdirectories\n";
    os << "  t<0...n>         number of threads (default: 0=autodetect)\n";
    os << "  br<0...n>[k,m,g] read-ahead buffer size (default: auto)\n";
    os << "  bw<0...n>[k,m,g] write-behind buffer size (default: auto)\n";
    os << "  h<n,c,C,f>       checksum: none, crc16, crc32, fletcher16 (default)\n";
    os << "  nt               do not store timestamps\n";
    os << "  np               do not store permissions\n";
    os << "  nm               do not store metadata or redundancy (equals -nt -np -hn)\n";
    os << "  sp               strip paths from files\n";
    os << "  o<path>          output path\n";
    os << "  y                yes to all queries\n";
    os << "  v                verbose\n";
    os << "  x<file>          exclude file(s)\n";
}

void PrintAdvancedHelp(std::ostream& os) {
    os << "\nThe following options may be useful for people running benchmarks:\n\n";
    os << " -swapinout        swap archive name with source filename\n";
    os << " -forceout         replace filenames inside archive with a source filename\n";
    os << " -nofilenameext    do not add .nz extension to archive filename\n\n";
    os << "Unix specific options:\n\n";
    os << " -fo               re/store file ownership (user & group)\n\n";
    os << "Miscellaneous options:\n\n";
    os << " -pause            pause before quitting\n";
}

const char* CommandToString(Command command) {
    switch (command) {
        case Command::kAdd:
            return "a";
        case Command::kList:
            return "l";
        case Command::kTest:
            return "t";
        case Command::kSimulate:
            return "s";
        case Command::kExtract:
            return "x";
        case Command::kW32c:
            return "w32c";
        case Command::kInfo:
            return "info";
        case Command::kHelp:
            return "help";
        case Command::kUnknown:
        default:
            return "unknown";
    }
}

const char* CompressorToString(Compressor compressor) {
    switch (compressor) {
        case Compressor::kNone:
            return "none";
        case Compressor::kLzpf:
            return "nz_lzpf";
        case Compressor::kLzpfLarge:
            return "nz_lzpf_large";
        case Compressor::kLzhd:
            return "nz_lzhd";
        case Compressor::kLzhdParallel:
            return "nz_lzhd_parallel";
        case Compressor::kLzhdParallelExtra:
            return "nz_lzhd_parallel_extra";
        case Compressor::kLzhds:
            return "nz_lzhds";
        case Compressor::kLzhdsParallel:
            return "nz_lzhds_parallel";
        case Compressor::kLzhdsParallelExtra:
            return "nz_lzhds_parallel_extra";
        case Compressor::kOptimum1:
            return "nz_optimum1";
        case Compressor::kOptimum2:
            return "nz_optimum2";
        case Compressor::kCm:
            return "nz_cm";
        default:
            return "unknown";
    }
}

}  // namespace recon
}  // namespace nz
