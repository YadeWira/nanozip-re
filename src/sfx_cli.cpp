#include "nz_sfx/sfx_cli.hpp"
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <x86intrin.h>
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

    bool parse_switches = true;
    int i = 2;
    for (; i < argc; ++i) {
        const char* raw = argv[i];
        if (raw == nullptr) {
            continue;
        }

        const std::string token(raw);
        if (!parse_switches || token.empty() || token[0] != '-') {
            break;
        }

        if (token == "-") {
            parse_switches = false;
            continue;
        }

        const std::string sw = token.substr(1);
        if (sw.empty()) {
            continue;
        }

        if (sw == "r") {
            out.recurse = true;
            continue;
        }
        if (sw == "y") {
            out.yes_to_all = true;
            continue;
        }
        if (sw == "v") {
            out.verbose = true;
            continue;
        }
        if (sw == "sp") {
            out.strip_paths = true;
            continue;
        }
        if (sw == "nt") {
            out.no_timestamps = true;
            continue;
        }
        if (sw == "np") {
            out.no_permissions = true;
            continue;
        }
        if (sw == "nm") {
            out.no_timestamps = true;
            out.no_permissions = true;
            out.checksum = ChecksumMode::kNone;
            continue;
        }
        if (sw == "nofilenameext") {
            out.no_filename_ext = true;
            continue;
        }

        if (StartsWith(sw, "c")) {
            bool ok = false;
            const std::string suffix = sw.substr(1);
            out.compressor = ParseCompressor(suffix, &ok);
            if (!ok) {
                out.unknown_switches.push_back(token);
            }
            continue;
        }

        if (StartsWith(sw, "h")) {
            const std::string suffix = sw.substr(1);
            if (suffix == "n") {
                out.checksum = ChecksumMode::kNone;
            } else if (suffix == "c") {
                out.checksum = ChecksumMode::kCrc16;
            } else if (suffix == "C") {
                out.checksum = ChecksumMode::kCrc32;
            } else if (suffix == "f") {
                out.checksum = ChecksumMode::kFletcher16;
            } else {
                out.unknown_switches.push_back(token);
            }
            continue;
        }

        if (StartsWith(sw, "o")) {
            const std::string suffix = sw.substr(1);
            if (suffix.empty()) {
                if (i + 1 < argc && argv[i + 1] != nullptr) {
                    ++i;
                    out.output_path = argv[i];
                } else {
                    out.error = "missing value for -o<path>";
                    out.show_usage = true;
                    return out;
                }
            } else {
                out.output_path = suffix;
            }
            continue;
        }

        if (StartsWith(sw, "x")) {
            const std::string suffix = sw.substr(1);
            if (suffix.empty()) {
                if (i + 1 < argc && argv[i + 1] != nullptr) {
                    ++i;
                    out.exclude_patterns.emplace_back(argv[i]);
                } else {
                    out.error = "missing value for -x<file>";
                    out.show_usage = true;
                    return out;
                }
            } else {
                out.exclude_patterns.push_back(suffix);
            }
            continue;
        }

        // Parsed but ignored (kept for CLI compatibility).
        if (StartsWith(sw, "m") || StartsWith(sw, "p") || StartsWith(sw, "t") ||
            StartsWith(sw, "br") || StartsWith(sw, "bw") || StartsWith(sw, "s") ||
            sw == "fo" || sw == "pause" || sw == "swapinout" || sw == "forceout") {
            continue;
        }

        out.unknown_switches.push_back(token);
    }

    if (out.command == Command::kW32c) {
        // `w32c` requires archive in original NanoZip. We keep parser permissive.
        if (i < argc && argv[i] != nullptr) {
            out.archive_path = argv[i++];
        }
        for (; i < argc; ++i) {
            if (argv[i] != nullptr) {
                out.positional.emplace_back(argv[i]);
            }
        }
        return out;
    }

    if (i >= argc || argv[i] == nullptr) {
        out.show_usage = true;
        out.error = "archive name missing";
        return out;
    }

    out.archive_path = argv[i++];
    for (; i < argc; ++i) {
        if (argv[i] != nullptr) {
            out.positional.emplace_back(argv[i]);
        }
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
    struct timespec t0, t1;
    if (clock_gettime(CLOCK_MONOTONIC, &t0) == 0) {
        const unsigned long long c0 = __rdtsc();
        struct timespec req{0, 2000000};   // 2 ms
        nanosleep(&req, nullptr);
        const unsigned long long c1 = __rdtsc();
        if (clock_gettime(CLOCK_MONOTONIC, &t1) == 0) {
            const double ns = (double)(t1.tv_sec - t0.tv_sec) * 1e9 +
                              (double)(t1.tv_nsec - t0.tv_nsec);
            if (ns > 0.0) return (unsigned)((double)(c1 - c0) * 1000.0 / ns);
        }
    }
#endif
    return cpuinfo_mhz.empty() ? 0u : (unsigned)std::strtod(cpuinfo_mhz.c_str(), nullptr);
}

}  // namespace

unsigned HostThreadCount() {
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
}

std::string HostSummaryLine() {
    // "<model>|<MHz> MHz|#<logical>[+HT]|<available>/<total> MB", the second line
    // the original prints under its banner and the only line `info` shares with it.
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

    char buf[512];
    std::snprintf(buf, sizeof(buf), "%s|%u MHz|#%u%s|%llu/%llu MB",
                  model.empty() ? "unknown CPU" : model.c_str(),
                  MeasuredMhz(mhz),
                  logical, ht ? "+HT" : "",
                  static_cast<unsigned long long>((avail_kb + 512u) / 1024u),
                  static_cast<unsigned long long>((total_kb + 512u) / 1024u));
    return std::string(buf);
}

void PrintBanner(std::ostream& os) {
    // Layout matched to the original, which prints the product line and then the
    // host summary with no leading blank. The build tag stays "/Reconstruction"
    // (the original says "/Linux32"): everything else is 1:1, but the binary
    // should not claim to BE nanozip.
    // Leading CR and BOTH lines go to stderr in the original -- everything else it
    // prints goes to stdout, so piping stdout gives you just the data. Measured by
    // capturing the two streams separately.
    os << "\rNanoZip 0.09 alpha/Reconstruction  (C) 2008-2011 Sami Runsas  www.nanozip.net\n";
    os << HostSummaryLine() << '\n';
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
