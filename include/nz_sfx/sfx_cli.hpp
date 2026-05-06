#pragma once

#include <ostream>
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

    std::vector<std::string> unknown_switches;
    std::vector<std::string> passthrough_args;

    std::string unknown_command;
    std::string error;
};

CliOptions ParseCli(int argc, char** argv);
void PrintBanner(std::ostream& os);
void PrintUsage(const char* program_name, std::ostream& os);
void PrintAdvancedHelp(std::ostream& os);

const char* CommandToString(Command command);
const char* CompressorToString(Compressor compressor);

}  // namespace recon
}  // namespace nz
