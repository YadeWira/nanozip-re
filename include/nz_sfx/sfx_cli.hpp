#pragma once

#include <ostream>
#include <cstdint>
#include <string>
#include <vector>

namespace nz {
namespace recon {

enum class Command {
    kUnknown,
    kAdd,
    kList,
    kTest,
    kSimulate,
    kExtract,
    kW32c,
    kInfo,
    kHelp
};

enum class Compressor {
    kNone,
    kLzpf,
    kLzpfLarge,
    kLzhd,
    kLzhdParallel,
    kLzhdParallelExtra,
    kLzhds,
    kLzhdsParallel,
    kLzhdsParallelExtra,
    kOptimum1,
    kOptimum2,
    kCm
};

enum class ChecksumMode {
    kNone,
    kCrc16,
    kCrc32,
    kFletcher16,
    kFletcher32
};

struct CliOptions {
    bool show_usage = false;
    bool show_advanced_help = false;

    Command command = Command::kUnknown;
    std::string command_token;

    std::string archive_path;
    std::vector<std::string> positional;

    Compressor compressor = Compressor::kOptimum1;
    ChecksumMode checksum = ChecksumMode::kFletcher16;

    bool recurse = false;
    bool verbose = false;
    bool yes_to_all = false;
    bool strip_paths = false;
    bool no_timestamps = false;
    bool no_permissions = false;
    bool no_filename_ext = false;

    std::string output_path;
    std::vector<std::string> exclude_patterns;

    // -t<n>: thread count to report (0 = auto); -br/-bw: IO buffer sizes in bytes
    // (0 = auto, not shown); -swapinout / -forceout: the benchmark helpers.
    unsigned threads = 0;
    std::uint64_t read_buffer_bytes = 0;
    std::uint64_t write_buffer_bytes = 0;
    bool swapinout = false;
    bool forceout = false;

    std::vector<std::string> unknown_switches;
    std::vector<std::string> passthrough_args;

    std::string unknown_command;
    std::string error;
};

CliOptions ParseCli(int argc, char** argv);
void PrintBanner(std::ostream& os);

// ---- console formatting, matched to the original nz's own output ----
//
// The original writes its status lines over one another with a 79-space clear,
// and formats every byte count with a SPACE as the thousands separator. Both are
// reproduced here so `nz_recon`'s output can be diffed against `nz`'s directly.

// "9 000", "2 546 000" -- space-separated groups of three, as the original prints
// every byte count.
std::string FormatGrouped(std::uint64_t value);

// The size column of `l`: `%6llu %-2s`, with the unit stepping up as soon as the
// value exceeds NINE of the current unit (measured against the original: 9216 B
// prints as bytes, 9300 as "9 KB"; 9437184 -- exactly 9 MB -- prints as
// "9216 KB", 9500000 as "9 MB"), and the number itself ROUNDED, not truncated:
// (bytes + unit/2) / unit.
std::string FormatSizeColumn(std::uint64_t bytes);

// `\r` + 79 spaces + `\r`: the original's line-clear before each status line.
void ClearStatusLine(std::ostream& os);

// The banner's second line: "<cpu model>|<MHz> MHz|#<n>[+HT]|<avail>/<total> MB".
std::string HostSummaryLine();

// The thread count the original reports (and the `#N` in the host line): the number
// of logical CPUs, capped at 32 the way a 32-bit process's affinity mask caps it.
unsigned HostThreadCount();
void PrintUsage(const char* program_name, std::ostream& os);
void PrintAdvancedHelp(std::ostream& os);

const char* CommandToString(Command command);
const char* CompressorToString(Compressor compressor);

}  // namespace recon
}  // namespace nz
