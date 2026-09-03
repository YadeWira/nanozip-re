#pragma once

#include "nz_sfx/sfx_cli.hpp"

#include <cstdint>
#include <ostream>
#include <string>
#include <vector>

namespace nz {
namespace recon {

enum class ArchiveOpenError {
    kNone,
    kCannotOpen,
    kNotNanoZip,
    kIncompatibleVersion,
    kUnsupportedFormat,
    kCorrupt
};

struct ArchiveHeaderInfo {
    std::uint8_t version_major = 0;
    std::uint8_t version_minor = 9;
    std::string signature;

    bool reconstructed_layout = false;
    std::uint8_t recon_format_major = 1;
    std::uint8_t recon_format_minor = 0;

    Compressor compressor = Compressor::kNone;
    ChecksumMode checksum = ChecksumMode::kFletcher16;
    bool has_timestamps = true;
    bool has_permissions = true;
};

struct ArchiveEntry {
    std::string path;
    std::uint64_t original_size = 0;
    std::uint64_t stored_size = 0;
    std::uint32_t permissions = 0644;
    std::int64_t mtime_unix = 0;
    std::uint32_t checksum = 0;
    std::uint8_t method = 0;
};

struct ArchiveContext {
    std::string archive_path;
    ArchiveHeaderInfo header;
    std::vector<ArchiveEntry> entries;
    std::uint64_t data_offset = 0;
};

ArchiveOpenError OpenArchive(
    const std::string& archive_path,
    ArchiveContext* out_context,
    std::string* out_error_message);

int RunAdd(const CliOptions& options, std::ostream& os);
int RunSimulate(const CliOptions& options, std::ostream& os);
int RunList(const CliOptions& options, std::ostream& os);
int RunExtractOrTest(const CliOptions& options, bool test_mode, std::ostream& os);
int RunInfo(std::ostream& os);


}  // namespace recon
}  // namespace nz
