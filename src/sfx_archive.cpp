#include "nz_sfx/sfx_archive.hpp"
#include "lzpf_arith.h"
#include "nz_cm.h"
#include "nz_lzhd.h"
#include "nz_cd_tokens.h"
#include "nz_lzhds.h"
#include "nz_optimum_lz.h"
#include "nz_optimum2_lz.h"
#include "nz_text_transform.h"
#include "nz_postfilter.h"
#include "nz_bwt.h"
#include "nz_audio.h"
#include "nz_exefilter.h"
#include "nz_texttransform_num.h"

#include <algorithm>
#include <array>
#include <set>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <ios>
#include <iostream>
#include <limits>
#include <map>
#include <numeric>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_set>
#include <vector>

#if defined(__unix__) || defined(__APPLE__)
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <utime.h>
#endif

namespace nz {
namespace recon {

namespace fs = std::filesystem;

namespace {

constexpr std::array<unsigned char, 2> kMagicPrefix = {0xae, 0x01};
constexpr const char* kKnownSignaturePrefix = "NanoZip ";
constexpr const char* kKnownSignature = "NanoZip 0.09 alpha";
constexpr std::size_t kKnownSignatureBytes = 18;
constexpr unsigned kSupportedMajor = 0;
constexpr unsigned kSupportedMinor = 9;

constexpr std::array<char, 4> kReconMarker = {'N', 'Z', 'R', '1'};
constexpr std::uint8_t kReconFormatMajor = 1;
constexpr std::uint8_t kReconFormatMinor = 0;

constexpr std::uint8_t kFlagHasTimestamps = 1u << 0;
constexpr std::uint8_t kFlagHasPermissions = 1u << 1;

constexpr std::size_t kBufferSize = 1u << 20;

struct SourceFile {
    fs::path source_path;
    std::string archive_name;
    std::uint64_t size = 0;
    std::uint32_t permissions = 0644;
    std::int64_t mtime_unix = 0;
    std::uint32_t checksum = 0;
};

bool ParseVersionFromSignature(const std::string& signature, unsigned* major, unsigned* minor) {
    if (major == nullptr || minor == nullptr) {
        return false;
    }
    if (signature.rfind(kKnownSignaturePrefix, 0) != 0) {
        return false;
    }

    const std::size_t start = std::char_traits<char>::length(kKnownSignaturePrefix);
    std::size_t i = start;
    if (i >= signature.size() || !std::isdigit(static_cast<unsigned char>(signature[i]))) {
        return false;
    }

    unsigned maj = 0;
    while (i < signature.size() && std::isdigit(static_cast<unsigned char>(signature[i]))) {
        maj = (maj * 10u) + static_cast<unsigned>(signature[i] - '0');
        ++i;
    }

    if (i >= signature.size() || signature[i] != '.') {
        return false;
    }
    ++i;

    if (i >= signature.size() || !std::isdigit(static_cast<unsigned char>(signature[i]))) {
        return false;
    }

    unsigned min = 0;
    while (i < signature.size() && std::isdigit(static_cast<unsigned char>(signature[i]))) {
        min = (min * 10u) + static_cast<unsigned>(signature[i] - '0');
        ++i;
    }

    *major = maj;
    *minor = min;
    return true;
}

template <typename T>
void WriteLE(std::ostream& out, T value) {
    using U = std::make_unsigned_t<T>;
    U v = static_cast<U>(value);
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        const unsigned char b = static_cast<unsigned char>((v >> (i * 8u)) & static_cast<U>(0xffu));
        out.put(static_cast<char>(b));
    }
}

template <typename T>
bool ReadLE(std::istream& in, T* out) {
    if (out == nullptr) {
        return false;
    }
    using U = std::make_unsigned_t<T>;
    U v = 0;
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        const int ch = in.get();
        if (ch == EOF) {
            return false;
        }
        v |= (static_cast<U>(static_cast<unsigned char>(ch)) << (i * 8u));
    }
    *out = static_cast<T>(v);
    return true;
}

std::uint32_t UpdateCrc32(std::uint32_t crc, const unsigned char* data, std::size_t size) {
    static std::array<std::uint32_t, 256> table = [] {
        std::array<std::uint32_t, 256> t{};
        for (std::uint32_t i = 0; i < t.size(); ++i) {
            std::uint32_t x = i;
            for (unsigned bit = 0; bit < 8; ++bit) {
                const bool one = (x & 1u) != 0;
                x >>= 1u;
                if (one) {
                    x ^= 0xedb88320u;
                }
            }
            t[i] = x;
        }
        return t;
    }();

    std::uint32_t x = crc;
    for (std::size_t i = 0; i < size; ++i) {
        x = (x >> 8u) ^ table[(x ^ data[i]) & 0xffu];
    }
    return x;
}

std::uint32_t UpdateCrc16(std::uint32_t crc, const unsigned char* data, std::size_t size) {
    std::uint32_t x = crc;
    for (std::size_t i = 0; i < size; ++i) {
        x ^= static_cast<std::uint32_t>(data[i]);
        for (unsigned bit = 0; bit < 8; ++bit) {
            if ((x & 1u) != 0u) {
                x = (x >> 1u) ^ 0xa001u;
            } else {
                x >>= 1u;
            }
        }
    }
    return x & 0xffffu;
}

void UpdateFletcher16(std::uint32_t* s1, std::uint32_t* s2, const unsigned char* data, std::size_t size) {
    if (s1 == nullptr || s2 == nullptr) {
        return;
    }
    std::uint32_t a = *s1;
    std::uint32_t b = *s2;
    for (std::size_t i = 0; i < size; ++i) {
        a = (a + data[i]) % 255u;
        b = (b + a) % 255u;
    }
    *s1 = a;
    *s2 = b;
}

void Fletcher32Step(std::uint32_t* s1, std::uint32_t* s2, std::uint32_t word) {
    if (s1 == nullptr || s2 == nullptr) {
        return;
    }
    std::uint32_t a = *s1;
    std::uint32_t b = *s2;
    a = (a + (word & 0xffffu)) % 0xffffu;
    b = (b + a) % 0xffffu;
    *s1 = a;
    *s2 = b;
}

void UpdateFletcher32(
    std::uint32_t* s1,
    std::uint32_t* s2,
    std::uint8_t* pending_lo_byte,
    bool* has_pending_lo_byte,
    const unsigned char* data,
    std::size_t size) {
    if (s1 == nullptr || s2 == nullptr || pending_lo_byte == nullptr || has_pending_lo_byte == nullptr) {
        return;
    }

    std::size_t i = 0;
    if (*has_pending_lo_byte) {
        if (size > 0) {
            const std::uint32_t w =
                static_cast<std::uint32_t>(*pending_lo_byte) |
                (static_cast<std::uint32_t>(data[0]) << 8u);
            Fletcher32Step(s1, s2, w);
            *has_pending_lo_byte = false;
            *pending_lo_byte = 0;
            i = 1;
        } else {
            return;
        }
    }

    while (i + 1 < size) {
        const std::uint32_t w =
            static_cast<std::uint32_t>(data[i]) |
            (static_cast<std::uint32_t>(data[i + 1u]) << 8u);
        Fletcher32Step(s1, s2, w);
        i += 2u;
    }

    if (i < size) {
        *pending_lo_byte = data[i];
        *has_pending_lo_byte = true;
    }
}

std::uint32_t FinalizeFletcher32(
    std::uint32_t s1,
    std::uint32_t s2,
    std::uint8_t pending_lo_byte,
    bool has_pending_lo_byte) {
    if (has_pending_lo_byte) {
        const std::uint32_t w = static_cast<std::uint32_t>(pending_lo_byte);
        s1 = (s1 + (w & 0xffffu)) % 0xffffu;
        s2 = (s2 + s1) % 0xffffu;
    }
    if (s1 == 0u) {
        s1 = 0xffffu;
    }
    if (s2 == 0u) {
        s2 = 0xffffu;
    }
    return ((s1 & 0xffffu) << 16u) | (s2 & 0xffffu);
}

bool ComputeFileChecksum(const fs::path& path, ChecksumMode mode, std::uint32_t* out_checksum) {
    if (out_checksum == nullptr) {
        return false;
    }
    if (mode == ChecksumMode::kNone) {
        *out_checksum = 0;
        return true;
    }

    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return false;
    }

    std::vector<unsigned char> buffer(kBufferSize);
    std::uint32_t c16 = 0xffffu;
    std::uint32_t c32 = 0xffffffffu;
    std::uint32_t f1 = 0;
    std::uint32_t f2 = 0;
    std::uint8_t f32_pending = 0;
    bool f32_has_pending = false;

    while (input) {
        input.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
        const std::streamsize got = input.gcount();
        if (got <= 0) {
            break;
        }
        const std::size_t n = static_cast<std::size_t>(got);

        switch (mode) {
            case ChecksumMode::kCrc16:
                c16 = UpdateCrc16(c16, buffer.data(), n);
                break;
            case ChecksumMode::kCrc32:
                c32 = UpdateCrc32(c32, buffer.data(), n);
                break;
            case ChecksumMode::kFletcher16:
                UpdateFletcher16(&f1, &f2, buffer.data(), n);
                break;
            case ChecksumMode::kFletcher32:
                UpdateFletcher32(&f1, &f2, &f32_pending, &f32_has_pending, buffer.data(), n);
                break;
            case ChecksumMode::kNone:
                break;
        }
    }

    if (input.bad()) {
        return false;
    }

    switch (mode) {
        case ChecksumMode::kNone:
            *out_checksum = 0;
            break;
        case ChecksumMode::kCrc16:
            *out_checksum = (c16 ^ 0xffffu) & 0xffffu;
            break;
        case ChecksumMode::kCrc32:
            *out_checksum = c32 ^ 0xffffffffu;
            break;
        case ChecksumMode::kFletcher16:
            *out_checksum = ((f2 & 0xffu) << 8u) | (f1 & 0xffu);
            break;
        case ChecksumMode::kFletcher32:
            *out_checksum = FinalizeFletcher32(f1, f2, f32_pending, f32_has_pending);
            break;
    }
    return true;
}

bool WildcardMatch(const std::string& pattern, const std::string& text) {
    const std::size_t p_len = pattern.size();
    const std::size_t t_len = text.size();
    std::vector<int> memo((p_len + 1u) * (t_len + 1u), -1);

    const auto idx = [t_len](std::size_t p, std::size_t t) {
        return p * (t_len + 1u) + t;
    };

    std::function<bool(std::size_t, std::size_t)> rec = [&](std::size_t p, std::size_t t) -> bool {
        int& slot = memo[idx(p, t)];
        if (slot != -1) {
            return slot != 0;
        }

        bool ok = false;
        if (p == p_len) {
            ok = (t == t_len);
        } else if (pattern[p] == '*') {
            ok = rec(p + 1u, t) || (t < t_len && rec(p, t + 1u));
        } else if (pattern[p] == '?') {
            ok = (t < t_len) && rec(p + 1u, t + 1u);
        } else {
            ok = (t < t_len && pattern[p] == text[t]) && rec(p + 1u, t + 1u);
        }

        slot = ok ? 1 : 0;
        return ok;
    };

    return rec(0, 0);
}

bool MatchesAnyPattern(const std::string& name, const std::vector<std::string>& patterns) {
    if (patterns.empty()) {
        return true;
    }
    for (const std::string& pat : patterns) {
        if (WildcardMatch(pat, name)) {
            return true;
        }
    }
    return false;
}

bool IsExcluded(const std::string& name, const std::vector<std::string>& exclude_patterns) {
    for (const std::string& pat : exclude_patterns) {
        if (WildcardMatch(pat, name)) {
            return true;
        }
    }
    return false;
}

std::string NormalizeArchiveName(const fs::path& source, bool strip_paths) {
    if (strip_paths) {
        return source.filename().generic_string();
    }

    std::error_code ec;
    fs::path rel = source;
    const fs::path cwd = fs::current_path(ec);
    if (!ec) {
        fs::path tentative = fs::relative(source, cwd, ec);
        if (!ec && !tentative.empty()) {
            rel = tentative;
        }
    }

    fs::path clean;
    for (const auto& part : rel) {
        const std::string piece = part.generic_string();
        if (piece.empty() || piece == "." || piece == "..") {
            continue;
        }
        clean /= part;
    }

    if (clean.empty()) {
        clean = source.filename();
    }

    std::string out = clean.generic_string();
    if (out.empty()) {
        out = source.filename().generic_string();
    }
    return out;
}

std::uint32_t PermissionsToMode(fs::perms p) {
    std::uint32_t mode = 0;
    if ((p & fs::perms::owner_read) != fs::perms::none) {
        mode |= 0400u;
    }
    if ((p & fs::perms::owner_write) != fs::perms::none) {
        mode |= 0200u;
    }
    if ((p & fs::perms::owner_exec) != fs::perms::none) {
        mode |= 0100u;
    }
    if ((p & fs::perms::group_read) != fs::perms::none) {
        mode |= 0040u;
    }
    if ((p & fs::perms::group_write) != fs::perms::none) {
        mode |= 0020u;
    }
    if ((p & fs::perms::group_exec) != fs::perms::none) {
        mode |= 0010u;
    }
    if ((p & fs::perms::others_read) != fs::perms::none) {
        mode |= 0004u;
    }
    if ((p & fs::perms::others_write) != fs::perms::none) {
        mode |= 0002u;
    }
    if ((p & fs::perms::others_exec) != fs::perms::none) {
        mode |= 0001u;
    }
    return mode;
}

fs::perms ModeToPermissions(std::uint32_t mode) {
    fs::perms p = fs::perms::none;
    if ((mode & 0400u) != 0u) {
        p |= fs::perms::owner_read;
    }
    if ((mode & 0200u) != 0u) {
        p |= fs::perms::owner_write;
    }
    if ((mode & 0100u) != 0u) {
        p |= fs::perms::owner_exec;
    }
    if ((mode & 0040u) != 0u) {
        p |= fs::perms::group_read;
    }
    if ((mode & 0020u) != 0u) {
        p |= fs::perms::group_write;
    }
    if ((mode & 0010u) != 0u) {
        p |= fs::perms::group_exec;
    }
    if ((mode & 0004u) != 0u) {
        p |= fs::perms::others_read;
    }
    if ((mode & 0002u) != 0u) {
        p |= fs::perms::others_write;
    }
    if ((mode & 0001u) != 0u) {
        p |= fs::perms::others_exec;
    }
    return p;
}

std::int64_t FileTimeToUnix(const fs::file_time_type& t) {
    namespace ch = std::chrono;
    const auto now_ft = fs::file_time_type::clock::now();
    const auto now_sys = ch::system_clock::now();
    const auto sys_tp = ch::time_point_cast<ch::system_clock::duration>(t - now_ft + now_sys);
    return ch::duration_cast<ch::seconds>(sys_tp.time_since_epoch()).count();
}

fs::file_time_type UnixToFileTime(std::int64_t unix_seconds) {
    namespace ch = std::chrono;
    const auto sys_tp = ch::system_clock::time_point{} + ch::seconds(unix_seconds);
    const auto now_ft = fs::file_time_type::clock::now();
    const auto now_sys = ch::system_clock::now();
    return ch::time_point_cast<fs::file_time_type::duration>(sys_tp - now_sys + now_ft);
}

// Create an extracted file exactly the way the original does: a single
// open(O_WRONLY|O_CREAT|O_TRUNC) whose mode argument is the mode stored in the
// archive, and no chmod afterwards.  That distinction is observable -- the
// kernel applies the umask and drops S_ISUID/S_ISGID at creation, so an archived
// 04755 lands as 0755, while a post-hoc chmod would restore the setuid bit the
// original does not.  An archive with no permission record (which is also what
// -np and an all-0600 input produce) uses the original's own default of 0600.
bool WriteExtractedFile(const fs::path& path, const unsigned char* data, std::size_t n,
                        std::uint32_t mode) {
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC,
                          static_cast<mode_t>(mode & 07777u));
    if (fd < 0) {
        return false;
    }
    std::size_t written = 0;
    while (written < n) {
        const ssize_t w = ::write(fd, data + written, n - written);
        if (w <= 0) {
            ::close(fd);
            return false;
        }
        written += static_cast<std::size_t>(w);
    }
    return ::close(fd) == 0;
}

bool ApplyExtractedMetadata(
    const fs::path& path,
    bool has_permissions,
    std::uint32_t permissions,
    bool has_mtime,
    std::int64_t mtime_unix,
    std::string* out_warning) {
    bool ok = true;
    std::ostringstream warnings;

    std::error_code ec;
    if (has_permissions && permissions != 0u) {
        fs::permissions(path, ModeToPermissions(permissions), fs::perm_options::replace, ec);
        if (ec) {
            ok = false;
            warnings << "cannot apply permissions to " << path.string() << ": " << ec.message();
            ec.clear();
        }
    }
    if (has_mtime && mtime_unix > 0) {
        fs::last_write_time(path, UnixToFileTime(mtime_unix), ec);
        if (ec) {
            if (!warnings.str().empty()) {
                warnings << "; ";
            }
            ok = false;
            warnings << "cannot apply mtime to " << path.string() << ": " << ec.message();
        }
    }

    if (out_warning != nullptr) {
        *out_warning = warnings.str();
    }
    return ok;
}

std::string MakeUniqueName(const std::string& base, std::unordered_set<std::string>* used) {
    if (used == nullptr) {
        return base;
    }
    if (used->insert(base).second) {
        return base;
    }

    fs::path p(base);
    const std::string stem = p.stem().string();
    const std::string ext = p.extension().string();

    for (unsigned i = 2; i < 1000000u; ++i) {
        std::ostringstream oss;
        oss << stem << '_' << i << ext;
        const std::string candidate = oss.str();
        if (used->insert(candidate).second) {
            return candidate;
        }
    }
    return base;
}

bool CollectRawFiles(
    const CliOptions& options,
    std::vector<fs::path>* out_files,
    std::vector<std::string>* warnings,
    std::string* error) {
    if (out_files == nullptr || warnings == nullptr || error == nullptr) {
        return false;
    }

    out_files->clear();
    warnings->clear();
    error->clear();

    for (const std::string& arg : options.positional) {
        const fs::path input(arg);
        std::error_code ec;
        const fs::file_status st = fs::status(input, ec);
        if (ec || st.type() == fs::file_type::not_found) {
            warnings->push_back("missing input: " + arg);
            continue;
        }

        if (fs::is_regular_file(st)) {
            out_files->push_back(input);
            continue;
        }

        if (fs::is_directory(st)) {
            if (!options.recurse) {
                warnings->push_back("skipping directory (use -r): " + arg);
                continue;
            }

            fs::recursive_directory_iterator it(input, fs::directory_options::skip_permission_denied, ec);
            fs::recursive_directory_iterator end;
            if (ec) {
                warnings->push_back("cannot recurse directory: " + arg);
                continue;
            }

            for (; it != end; it.increment(ec)) {
                if (ec) {
                    ec.clear();
                    continue;
                }
                const auto& entry = *it;
                const fs::path p = entry.path();
                std::error_code ec2;
                if (entry.is_regular_file(ec2) && !ec2) {
                    out_files->push_back(p);
                }
            }
            continue;
        }

        warnings->push_back("unsupported input type: " + arg);
    }

    if (out_files->empty()) {
        *error = "no usable input files";
        return false;
    }
    return true;
}

bool BuildSourceList(
    const CliOptions& options,
    std::vector<SourceFile>* out_sources,
    std::vector<std::string>* warnings,
    std::string* error,
    bool need_checksum) {
    if (out_sources == nullptr || warnings == nullptr || error == nullptr) {
        return false;
    }

    std::vector<fs::path> files;
    if (!CollectRawFiles(options, &files, warnings, error)) {
        return false;
    }

    std::unordered_set<std::string> used_names;
    out_sources->clear();

    for (const fs::path& file : files) {
        const std::string as_rel = file.generic_string();
        if (IsExcluded(as_rel, options.exclude_patterns)) {
            continue;
        }

        std::string archive_name = NormalizeArchiveName(file, options.strip_paths);
        if (archive_name.empty()) {
            warnings->push_back("skipping empty archive path: " + file.string());
            continue;
        }
        if (IsExcluded(archive_name, options.exclude_patterns)) {
            continue;
        }

        archive_name = MakeUniqueName(archive_name, &used_names);

        std::error_code ec;
        const std::uint64_t size = fs::file_size(file, ec);
        if (ec) {
            warnings->push_back("cannot stat size: " + file.string());
            continue;
        }

        SourceFile src;
        src.source_path = file;
        src.archive_name = archive_name;
        src.size = size;

        if (!options.no_permissions) {
            const fs::file_status st = fs::status(file, ec);
            if (!ec) {
                src.permissions = PermissionsToMode(st.permissions());
            }
        } else {
            src.permissions = 0;
        }

        if (!options.no_timestamps) {
            const fs::file_time_type ft = fs::last_write_time(file, ec);
            if (!ec) {
                src.mtime_unix = FileTimeToUnix(ft);
            }
        } else {
            src.mtime_unix = 0;
        }

        if (need_checksum) {
            std::uint32_t checksum = 0;
            if (!ComputeFileChecksum(file, options.checksum, &checksum)) {
                warnings->push_back("cannot checksum file: " + file.string());
                continue;
            }
            src.checksum = checksum;
        }

        out_sources->push_back(src);
    }

    if (out_sources->empty()) {
        *error = "no files left after filters/excludes";
        return false;
    }

    return true;
}

std::string FormatChecksum(ChecksumMode mode, std::uint32_t checksum) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    // The original always prints 8 hex digits, narrow modes included
    // (a crc16 of 0x3935 lists as "00003935").
    if (mode == ChecksumMode::kCrc16 || mode == ChecksumMode::kFletcher16) {
        oss << std::setw(8) << (checksum & 0xffffu);
    } else if (mode == ChecksumMode::kNone) {
        oss << "----";
    } else {
        oss << std::setw(8) << checksum;
    }
    return oss.str();
}

std::string FormatMode(std::uint32_t mode) {
    if (mode == 0) {
        return "----";
    }
    std::ostringstream oss;
    oss << std::oct << std::setfill('0') << std::setw(4) << (mode & 07777u);
    return oss.str();
}

std::string FormatMtime(std::int64_t unix_seconds) {
    if (unix_seconds <= 0) {
        return "---- --- -- --:--:--";
    }

    const std::time_t t = static_cast<std::time_t>(unix_seconds);
    std::tm tmv{};
#if defined(_WIN32)
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif

    char buf[64] = {0};
    if (std::strftime(buf, sizeof(buf), "%Y-%b-%d %H:%M:%S", &tmv) == 0) {
        return "---- --- -- --:--:--";
    }
    return buf;
}

// The archive stores a file's mtime as its epoch MINUS the writer's local UTC
// offset -- the writer converts local->UTC a second time. Measured: a file whose
// mtime is 1788282000 (12:00:00 local, -0500) is stored as 1788300000, and the
// original lists it back as "12:00:00". Adding the offset recovers the true epoch,
// after which plain localtime reproduces the original's output.
// A legacy archive stores a file's mtime as its LOCAL wall clock reinterpreted
// as UTC, so the value has to be shifted back by the zone offset both to print
// it and to restore it.  Getting this wrong is invisible in a listing that is
// only compared against itself: it shows up as a whole-hours skew against the
// original.
std::int64_t LegacyStoredMtimeToUnix(std::int64_t stored) {
    if (stored <= 0) return stored;
    const std::time_t t = static_cast<std::time_t>(stored);
    std::tm tmv{};
#if defined(_WIN32)
    localtime_s(&tmv, &t);
    const long off = -_timezone;
#else
    localtime_r(&t, &tmv);
    const long off = tmv.tm_gmtoff;
#endif
    return stored + static_cast<std::int64_t>(off);
}

std::string FormatMtimeStored(std::int64_t stored) {
    if (stored <= 0) return FormatMtime(stored);
    return FormatMtime(LegacyStoredMtimeToUnix(stored));
}

// The original restores a timestamp with utime(), which takes whole seconds and
// leaves the access time at "now".  Going through std::filesystem instead lands
// a fractional nanosecond part that a byte-exact tree comparison catches.
bool SetExtractedMtime(const fs::path& path, std::int64_t stored) {
    const std::int64_t real = LegacyStoredMtimeToUnix(stored);
    if (real <= 0) return true;
    struct utimbuf tb;
    tb.actime = std::time(nullptr);
    tb.modtime = static_cast<std::time_t>(real);
    return ::utime(path.c_str(), &tb) == 0;
}

std::string HumanBytes(std::uint64_t bytes) {
    static const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    double x = static_cast<double>(bytes);
    std::size_t u = 0;
    while (x >= 1024.0 && u + 1 < (sizeof(units) / sizeof(units[0]))) {
        x /= 1024.0;
        ++u;
    }

    std::ostringstream oss;
    if (u == 0) {
        oss << static_cast<std::uint64_t>(x) << ' ' << units[u];
    } else {
        oss << std::fixed << std::setprecision(2) << x << ' ' << units[u];
    }
    return oss.str();
}

fs::path ResolveArchivePath(const CliOptions& options) {
    fs::path out(options.archive_path);
    if (!options.no_filename_ext && out.extension() != ".nz") {
        out += ".nz";
    }
    return out;
}

bool CopyFileData(std::istream& in, std::ostream* out, std::uint64_t size, std::uint32_t* out_checksum, ChecksumMode mode) {
    std::vector<unsigned char> buffer(kBufferSize);

    std::uint64_t left = size;
    std::uint32_t c16 = 0xffffu;
    std::uint32_t c32 = 0xffffffffu;
    std::uint32_t f1 = 0;
    std::uint32_t f2 = 0;
    std::uint8_t f32_pending = 0;
    bool f32_has_pending = false;

    while (left > 0) {
        const std::size_t chunk = static_cast<std::size_t>(std::min<std::uint64_t>(left, buffer.size()));
        in.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(chunk));
        const std::streamsize got = in.gcount();
        if (got <= 0) {
            return false;
        }
        if (out != nullptr) {
            out->write(reinterpret_cast<const char*>(buffer.data()), got);
            if (!*out) {
                return false;
            }
        }

        const std::size_t n = static_cast<std::size_t>(got);
        switch (mode) {
            case ChecksumMode::kCrc16:
                c16 = UpdateCrc16(c16, buffer.data(), n);
                break;
            case ChecksumMode::kCrc32:
                c32 = UpdateCrc32(c32, buffer.data(), n);
                break;
            case ChecksumMode::kFletcher16:
                UpdateFletcher16(&f1, &f2, buffer.data(), n);
                break;
            case ChecksumMode::kFletcher32:
                UpdateFletcher32(&f1, &f2, &f32_pending, &f32_has_pending, buffer.data(), n);
                break;
            case ChecksumMode::kNone:
                break;
        }

        left -= static_cast<std::uint64_t>(n);
    }

    if (out_checksum != nullptr) {
        switch (mode) {
            case ChecksumMode::kNone:
                *out_checksum = 0;
                break;
            case ChecksumMode::kCrc16:
                *out_checksum = (c16 ^ 0xffffu) & 0xffffu;
                break;
            case ChecksumMode::kCrc32:
                *out_checksum = c32 ^ 0xffffffffu;
                break;
            case ChecksumMode::kFletcher16:
                *out_checksum = ((f2 & 0xffu) << 8u) | (f1 & 0xffu);
                break;
            case ChecksumMode::kFletcher32:
                *out_checksum = FinalizeFletcher32(f1, f2, f32_pending, f32_has_pending);
                break;
        }
    }

    return true;
}

bool SkipBytes(std::istream& in, std::uint64_t size) {
    if (size == 0) {
        return true;
    }

    const std::streamoff as_off = static_cast<std::streamoff>(size);
    in.seekg(as_off, std::ios::cur);
    if (in.good()) {
        return true;
    }

    in.clear();
    std::vector<char> buffer(64 * 1024);
    std::uint64_t left = size;
    while (left > 0) {
        const std::size_t chunk = static_cast<std::size_t>(std::min<std::uint64_t>(left, buffer.size()));
        in.read(buffer.data(), static_cast<std::streamsize>(chunk));
        const std::streamsize got = in.gcount();
        if (got <= 0) {
            return false;
        }
        left -= static_cast<std::uint64_t>(got);
    }
    return true;
}

fs::path SanitizeExtractPath(const std::string& name) {
    fs::path p(name);
    if (p.is_absolute()) {
        return {};
    }

    fs::path out;
    for (const auto& part : p) {
        const std::string x = part.generic_string();
        if (x.empty() || x == ".") {
            continue;
        }
        if (x == "..") {
            return {};
        }
        out /= part;
    }
    return out;
}

std::string ShellQuote(const std::string& raw) {
    std::string out;
    out.reserve(raw.size() + 2);
    out.push_back('\'');
    for (char c : raw) {
        if (c == '\'') {
            out += "'\\''";
        } else {
            out.push_back(c);
        }
    }
    out.push_back('\'');
    return out;
}

std::string GdbQuote(const std::string& raw) {
    std::string out;
    out.reserve(raw.size() + 2);
    out.push_back('"');
    for (char c : raw) {
        if (c == '\\' || c == '"') {
            out.push_back('\\');
        }
        out.push_back(c);
    }
    out.push_back('"');
    return out;
}

bool IsEnvEnabled(const char* name) {
    if (name == nullptr) {
        return false;
    }
    const char* value = std::getenv(name);
    if (value == nullptr) {
        return false;
    }
    std::string s(value);
    for (char& c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    if (s.empty() || s == "0" || s == "false" || s == "no" || s == "off") {
        return false;
    }
    return true;
}

bool IsExecutableFile(const fs::path& path) {
    std::error_code ec;
    if (!fs::exists(path, ec) || ec) {
        return false;
    }
    if (fs::is_directory(path, ec) || ec) {
        return false;
    }
#if defined(__unix__) || defined(__APPLE__)
    return ::access(path.c_str(), X_OK) == 0;
#else
    return true;
#endif
}

// When NZ_NO_BRIDGE is set (to anything other than "0"), the reconstruction
// must decode/compress entirely natively: every legacy-binary fallback is
// disabled and a missing native path becomes a hard error instead of a silent
// shell-out. This is the measurement tool for "true" native coverage — see the
// extract-bridge false-positive note in HANDOFF_IA.txt §12.
bool LegacyBridgeDisabled() {
    const char* env = std::getenv("NZ_NO_BRIDGE");
    return env != nullptr && env[0] != '\0' && !(env[0] == '0' && env[1] == '\0');
}

fs::path FindLegacyBackend32() {
    if (LegacyBridgeDisabled()) {
        return {};
    }
    if (const char* env = std::getenv("NZ_LEGACY_BRIDGE_BACKEND")) {
        fs::path p(env);
        std::error_code ec;
        if (fs::is_directory(p, ec) && !ec) {
            const fs::path nested = p / "nz";
            if (IsExecutableFile(nested)) {
                return nested;
            }
        } else if (IsExecutableFile(p)) {
            return p;
        }
    }

    if (const char* env = std::getenv("NZ_LEGACY_BACKEND")) {
        fs::path p(env);
        std::error_code ec;
        if (fs::is_directory(p, ec) && !ec) {
            const fs::path nested = p / "nz";
            if (IsExecutableFile(nested)) {
                return nested;
            }
        } else if (IsExecutableFile(p) && p.string().find("linux32") != std::string::npos) {
            return p;
        }
    }

    std::error_code ec;
    fs::path cur = fs::current_path(ec);
    if (ec) {
        return {};
    }

    static constexpr std::array<const char*, 2> kRelativeCandidates = {
        "work/linux32/nz",
        "linux32/nz",
    };

    for (int depth = 0; depth < 8; ++depth) {
        for (const char* rel : kRelativeCandidates) {
            const fs::path candidate = cur / rel;
            if (IsExecutableFile(candidate)) {
                return candidate;
            }
        }
        if (!cur.has_parent_path()) {
            break;
        }
        fs::path parent = cur.parent_path();
        if (parent == cur) {
            break;
        }
        cur = parent;
    }
    return {};
}

fs::path FindExecutableInPath(const std::string& name) {
    const char* env = std::getenv("PATH");
    if (env == nullptr || *env == '\0') {
        return {};
    }

    std::string path_value(env);
    std::size_t start = 0;
    while (start <= path_value.size()) {
        const std::size_t end = path_value.find(':', start);
        const std::string token =
            (end == std::string::npos) ? path_value.substr(start) : path_value.substr(start, end - start);
        const fs::path dir = token.empty() ? fs::current_path() : fs::path(token);
        const fs::path candidate = dir / name;
        if (IsExecutableFile(candidate)) {
            return candidate;
        }
        if (end == std::string::npos) {
            break;
        }
        start = end + 1u;
    }
    return {};
}

std::string MakeTempPath(const char* prefix, const char* suffix) {
    std::error_code ec;
    fs::path tmp = fs::temp_directory_path(ec);
    if (ec || tmp.empty()) {
        tmp = fs::current_path(ec);
        if (ec || tmp.empty()) {
            tmp = ".";
        }
    }
    const auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
#if defined(__unix__) || defined(__APPLE__)
    const long pid = static_cast<long>(::getpid());
#else
    const long pid = 0;
#endif
    std::ostringstream oss;
    oss << prefix << '_' << pid << '_' << now << suffix;
    return (tmp / oss.str()).string();
}

fs::path FindLegacyBackend() {
    if (LegacyBridgeDisabled()) {
        return {};
    }
    if (const char* env = std::getenv("NZ_LEGACY_BACKEND")) {
        fs::path p(env);
        std::error_code ec;
        if (fs::is_directory(p, ec) && !ec) {
            const fs::path nested = p / "nz";
            if (IsExecutableFile(nested)) {
                return nested;
            }
        } else if (IsExecutableFile(p)) {
            return p;
        }
    }

    std::error_code ec;
    fs::path cur = fs::current_path(ec);
    if (ec) {
        return {};
    }

    static constexpr std::array<const char*, 4> kRelativeCandidates = {
        "work/linux64/nz",
        "work/linux32/nz",
        "linux64/nz",
        "linux32/nz",
    };

    for (int depth = 0; depth < 8; ++depth) {
        for (const char* rel : kRelativeCandidates) {
            const fs::path candidate = cur / rel;
            if (IsExecutableFile(candidate)) {
                return candidate;
            }
        }

        if (!cur.has_parent_path()) {
            break;
        }
        fs::path parent = cur.parent_path();
        if (parent == cur) {
            break;
        }
        cur = parent;
    }

    const fs::path path_nz = FindExecutableInPath("nz");
    if (!path_nz.empty()) {
        return path_nz;
    }

    return {};
}

int RunLegacyWithSystem(const fs::path& backend, const std::vector<std::string>& passthrough_args) {
    std::string cmd = ShellQuote(backend.string());
    for (const std::string& arg : passthrough_args) {
        cmd.push_back(' ');
        cmd += ShellQuote(arg);
    }

    const int raw = std::system(cmd.c_str());
#if defined(__unix__) || defined(__APPLE__)
    if (raw == -1) {
        return 1;
    }
    if (WIFEXITED(raw)) {
        return WEXITSTATUS(raw);
    }
    return 1;
#else
    return raw;
#endif
}

int RunLegacyWithSystemQuiet(const fs::path& backend, const std::vector<std::string>& passthrough_args) {
    std::string cmd = ShellQuote(backend.string());
    for (const std::string& arg : passthrough_args) {
        cmd.push_back(' ');
        cmd += ShellQuote(arg);
    }
    cmd += " >/dev/null 2>&1";

    const int raw = std::system(cmd.c_str());
#if defined(__unix__) || defined(__APPLE__)
    if (raw == -1) {
        return 1;
    }
    if (WIFEXITED(raw)) {
        return WEXITSTATUS(raw);
    }
    return 1;
#else
    return raw;
#endif
}

std::string ParseProcValue(const char* path, const char* key_prefix) {
    std::ifstream input(path);
    if (!input) {
        return {};
    }

    std::string line;
    const std::string prefix(key_prefix);
    while (std::getline(input, line)) {
        if (line.rfind(prefix, 0) == 0) {
            std::string value = line.substr(prefix.size());
            while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) {
                value.erase(value.begin());
            }
            return value;
        }
    }
    return {};
}

struct LegacyCnEntry {
    std::string path;
    std::uint64_t size = 0;
    std::uint32_t checksum = 0;
    bool has_checksum = false;
    // Set when the archive stores checksums but this file has none of its own:
    // a parallel (-pN) container splits a big file across streams and each
    // stream checksums only its slice, so no whole-file value exists. The
    // original lists such a file as "n/a"; verifying the file against a slice
    // checksum would fail every time.
    bool checksum_na = false;
    std::uint32_t permissions = 0;
    bool has_permissions = false;
    std::int64_t mtime_unix = 0;
    bool has_mtime = false;
};

enum class LegacyPayloadMode {
    kUnknown,
    kStore,
    kLiteralOnly,
    kCompressed
};

struct LegacyCnContext {
    std::string archive_path;
    ChecksumMode checksum_mode = ChecksumMode::kNone;
    bool checksum_verification_supported = true;
    std::uint8_t legacy_method = 0;
    std::uint8_t legacy_method_p0 = 0;
    std::uint8_t legacy_method_p1 = 0;
    // CM decoder params (method==0x4b, p0==7): extracted from the two extra
    // bytes that precede the filename table span in -cc archives.
    int cm_a_bits = 28;
    int cm_b_bits = 25;
    std::uint32_t cm_window_size = 1024u * 1024u;
    bool native_payload_supported = false;
    LegacyPayloadMode payload_mode = LegacyPayloadMode::kUnknown;
    std::vector<LegacyCnEntry> entries;
    std::uint64_t data_offset = 0;
    std::uint64_t total_data_size = 0;
    std::vector<unsigned char> data;
};

constexpr int kLegacyNeedCompat = -100;

bool TryDecodeLegacyWithGdbBridge(
    const LegacyCnContext& legacy,
    std::vector<unsigned char>* out_data,
    std::string* out_error_message) {
    if (out_data == nullptr) {
        return false;
    }
    out_data->clear();

    if (legacy.legacy_method != 0x2bu &&
        legacy.legacy_method != 0x3bu &&
        legacy.legacy_method != 0x4bu) {
        return false;
    }
    if (legacy.total_data_size == 0u) {
        return false;
    }
    if (std::getenv("NZ_DISABLE_GDB_BRIDGE") != nullptr) {
        return false;
    }

    std::string bp_condition;
    switch (legacy.legacy_method_p0) {
        case 1u:  // nz_lzpf
        case 2u:  // nz_lzpf_large
            bp_condition = "(*(unsigned int*)$esp)>=0x08097570 && (*(unsigned int*)$esp)<0x08097e20";
            break;
        case 5u:  // nz_optimum1
        case 6u:  // nz_optimum2
        case 7u:  // nz_cm
            // Observed stable output callback site for payload chunks.
            bp_condition = "(*(unsigned int*)$esp)==0x08095981";
            break;
        default:
            return false;
    }

    const fs::path backend32 = FindLegacyBackend32();
    if (backend32.empty()) {
        if (out_error_message != nullptr) {
            *out_error_message = "linux32 legacy backend not found for gdb bridge";
        }
        return false;
    }

    const std::string out_bin = MakeTempPath("nzre_legacy_bridge", ".bin");
    const std::string gdb_script = MakeTempPath("nzre_legacy_bridge", ".gdb");

    {
        std::ofstream g(gdb_script, std::ios::binary | std::ios::trunc);
        if (!g) {
            if (out_error_message != nullptr) {
                *out_error_message = "cannot create temporary gdb script";
            }
            return false;
        }
        g << "set pagination off\n";
        g << "set confirm off\n";
        g << "file " << GdbQuote(backend32.string()) << '\n';
        g << "shell rm -f " << ShellQuote(out_bin) << '\n';
        g << "b *0x080dbdd0 if " << bp_condition << '\n';
        g << "commands\n";
        g << "silent\n";
        g << "set $p=*(unsigned int*)($esp+8)\n";
        g << "set $n=*(unsigned int*)($esp+12)\n";
        g << "if $n>0\n";
        g << "append binary memory " << out_bin << " $p $p+$n\n";
        g << "end\n";
        g << "continue\n";
        g << "end\n";
        g << "run t " << GdbQuote(legacy.archive_path) << '\n';
        g << "quit\n";
    }

    std::string cmd = "gdb -q --batch -x ";
    cmd += ShellQuote(gdb_script);
    cmd += " >/dev/null 2>&1";
    const int raw = std::system(cmd.c_str());
#if defined(__unix__) || defined(__APPLE__)
    if (raw == -1 || !WIFEXITED(raw) || WEXITSTATUS(raw) != 0) {
#else
    if (raw != 0) {
#endif
        std::error_code ec_rm;
        fs::remove(gdb_script, ec_rm);
        fs::remove(out_bin, ec_rm);
        if (out_error_message != nullptr) {
            *out_error_message = "gdb bridge execution failed";
        }
        return false;
    }

    std::ifstream input(out_bin, std::ios::binary);
    if (!input) {
        std::error_code ec_rm;
        fs::remove(gdb_script, ec_rm);
        fs::remove(out_bin, ec_rm);
        if (out_error_message != nullptr) {
            *out_error_message = "gdb bridge did not produce payload dump";
        }
        return false;
    }
    std::vector<unsigned char> bytes(
        (std::istreambuf_iterator<char>(input)),
        std::istreambuf_iterator<char>());

    std::error_code ec_rm;
    fs::remove(gdb_script, ec_rm);
    fs::remove(out_bin, ec_rm);

    if (bytes.size() < legacy.total_data_size) {
        if (out_error_message != nullptr) {
            std::ostringstream oss;
            oss << "gdb bridge produced " << bytes.size() << " bytes, expected " << legacy.total_data_size;
            *out_error_message = oss.str();
        }
        return false;
    }
    if (bytes.size() > legacy.total_data_size) {
        bytes.resize(static_cast<std::size_t>(legacy.total_data_size));
    }

    *out_data = std::move(bytes);
    if (out_error_message != nullptr) {
        out_error_message->clear();
    }
    return true;
}

bool TryDecodeLegacyWithExtractBridge(
    const LegacyCnContext& legacy,
    std::vector<unsigned char>* out_data,
    std::string* out_error_message) {
    if (out_data == nullptr) {
        return false;
    }
    out_data->clear();

    if (legacy.entries.empty() || legacy.total_data_size == 0u) {
        return false;
    }
    if (std::getenv("NZ_DISABLE_EXTRACT_BRIDGE") != nullptr) {
        return false;
    }

    const fs::path backend = FindLegacyBackend();
    if (backend.empty()) {
        if (out_error_message != nullptr) {
            *out_error_message = LegacyBridgeDisabled()
                ? "native decoder missing for this stream and NZ_NO_BRIDGE is set "
                  "(refusing to shell out to the original binary)"
                : "legacy backend not found for extract bridge";
        }
        return false;
    }

    const fs::path tmp_root = MakeTempPath("nzre_extract_bridge", "");
    std::error_code ec;
    fs::create_directories(tmp_root, ec);
    if (ec) {
        if (out_error_message != nullptr) {
            *out_error_message = "cannot create temporary extract-bridge directory";
        }
        return false;
    }

    const std::vector<std::string> args = {
        "x",
        "-y",
        std::string("-o") + tmp_root.string(),
        legacy.archive_path
    };
    const int rc = RunLegacyWithSystemQuiet(backend, args);
    if (rc != 0) {
        fs::remove_all(tmp_root, ec);
        if (out_error_message != nullptr) {
            std::ostringstream oss;
            oss << "extract bridge failed with backend rc=" << rc;
            *out_error_message = oss.str();
        }
        return false;
    }

    std::vector<unsigned char> decoded;
    decoded.reserve(static_cast<std::size_t>(legacy.total_data_size));
    for (const LegacyCnEntry& entry : legacy.entries) {
        const fs::path rel = SanitizeExtractPath(entry.path);
        if (rel.empty()) {
            fs::remove_all(tmp_root, ec);
            if (out_error_message != nullptr) {
                *out_error_message = "extract bridge found unsafe archive path";
            }
            return false;
        }

        const fs::path extracted = tmp_root / rel;
        std::ifstream in(extracted, std::ios::binary);
        if (!in) {
            fs::remove_all(tmp_root, ec);
            if (out_error_message != nullptr) {
                *out_error_message = "extract bridge missing extracted entry";
            }
            return false;
        }

        std::vector<unsigned char> chunk(
            (std::istreambuf_iterator<char>(in)),
            std::istreambuf_iterator<char>());
        if (chunk.size() != entry.size) {
            fs::remove_all(tmp_root, ec);
            if (out_error_message != nullptr) {
                *out_error_message = "extract bridge entry size mismatch";
            }
            return false;
        }
        decoded.insert(decoded.end(), chunk.begin(), chunk.end());
    }

    fs::remove_all(tmp_root, ec);

    if (decoded.size() != legacy.total_data_size) {
        if (out_error_message != nullptr) {
            std::ostringstream oss;
            oss << "extract bridge produced " << decoded.size() << " bytes, expected " << legacy.total_data_size;
            *out_error_message = oss.str();
        }
        return false;
    }

    *out_data = std::move(decoded);
    if (out_error_message != nullptr) {
        out_error_message->clear();
    }
    return true;
}

std::uint32_t ComputeBufferChecksum(ChecksumMode mode, const unsigned char* data, std::size_t size) {
    switch (mode) {
        case ChecksumMode::kNone:
            return 0;
        case ChecksumMode::kCrc16:
            return (UpdateCrc16(0xffffu, data, size) ^ 0xffffu) & 0xffffu;
        case ChecksumMode::kCrc32:
            return UpdateCrc32(0xffffffffu, data, size) ^ 0xffffffffu;
        case ChecksumMode::kFletcher16: {
            std::uint32_t s1 = 0;
            std::uint32_t s2 = 0;
            UpdateFletcher16(&s1, &s2, data, size);
            return ((s2 & 0xffu) << 8u) | (s1 & 0xffu);
        }
        case ChecksumMode::kFletcher32: {
            std::uint32_t s1 = 0;
            std::uint32_t s2 = 0;
            std::uint8_t pending = 0;
            bool has_pending = false;
            UpdateFletcher32(&s1, &s2, &pending, &has_pending, data, size);
            return FinalizeFletcher32(s1, s2, pending, has_pending);
        }
    }
    return 0;
}

bool ReadLegacyVarint(
    const std::vector<unsigned char>& bytes,
    std::size_t* io_pos,
    std::size_t end,
    std::uint64_t* out_value) {
    if (io_pos == nullptr || out_value == nullptr || *io_pos >= end) {
        return false;
    }

    std::size_t pos = *io_pos;
    unsigned char cur = bytes[pos++];
    std::uint64_t value = static_cast<std::uint64_t>(cur & 0x7fu);
    unsigned shift = 7;

    while ((cur & 0x80u) != 0u) {
        if (pos >= end || shift >= 63u) {
            return false;
        }
        cur = bytes[pos++];
        value += (static_cast<std::uint64_t>((cur & 0x7fu) + 1u) << shift);
        shift += 7u;
    }

    *io_pos = pos;
    *out_value = value;
    return true;
}

void WriteLegacyVarint(std::uint64_t value, std::vector<unsigned char>* out_bytes) {
    if (out_bytes == nullptr) {
        return;
    }

    const unsigned char first = static_cast<unsigned char>(value & 0x7fu);
    std::uint64_t q = value >> 7u;
    if (q == 0u) {
        out_bytes->push_back(first);
        return;
    }

    out_bytes->push_back(static_cast<unsigned char>(first | 0x80u));
    while (q != 0u) {
        const std::uint64_t y = q - 1u;
        const unsigned char chunk = static_cast<unsigned char>(y & 0x7fu);
        q = y >> 7u;
        if (q != 0u) {
            out_bytes->push_back(static_cast<unsigned char>(chunk | 0x80u));
        } else {
            out_bytes->push_back(chunk);
        }
    }
}

std::uint32_t ReadU32LE(const unsigned char* p);
// Per-file attributes carried by the container's metadata records.  A legacy
// archive is a flat sequence of [varint (size<<4)|type][payload] records, and
// the files are handed to the compressor in BLOCKS: each block contributes a
// type-1 filename table followed by the type-2/type-4 records for exactly that
// table's files, while the type-5/6/7 checksum records form one running list
// across the whole archive (a block emits the checksums of the files its data
// record completes, which is why a block's checksum count need not match its
// own table).  Validated against the original linux32 binary on 40+ synthesised
// archives (1..200 files, single- and multi-block, every checksum mode,
// -nt/-np, setuid/sticky modes).
//
//   type 2  timestamps  [u32le mtime of the record's first file] then a zigzag
//                       bounded-varint delta per further file, until the record
//                       ends.  Absent with -nt.
//   type 4  permissions a sequence of u16le values V, each covering a run of
//                       consecutive files:
//                         V <  0x1000  ->  one file, mode = V
//                         V >= 0x1000  ->  run of ((V >> 9) - 6) files,
//                                          mode = V & 0x1ff
//                       The ranges are disjoint because the encoder only
//                       collapses a run when mode < 0x200, which is also why a
//                       repeated setuid/sticky mode is written once per file.
//                       Max run is 121, so 200 equal modes encode as 121 + 79.
//                       The record is absent with -np and also when every mode
//                       is 0600 -- such an archive is byte-identical to the -np
//                       one, so absence means "no permissions stored", not
//                       "default permissions", and the original then drops the
//                       perm column from `l` and creates files with mode 0600.
//   type 5/7 checksums  u32le per file  (5 = fletcher, 7 = crc32)
//   type 6  checksums   u16le per file  (crc16).  Absent with -hn.
//
// Returns true only when every record parsed AND each attribute that appears at
// all covers exactly one value per entry.  It never guesses: on false nothing
// is written, so callers fall back to the older per-shape heuristics and, more
// importantly, no half-parsed checksum can be mistaken for a real one.
bool ApplyLegacyAttributeRecords(
    const std::vector<unsigned char>& bytes,
    const std::vector<std::array<std::size_t, 4>>& records,  // {stream, type, begin, end}
    const std::map<unsigned, std::vector<std::size_t>>& stream_named,
    const std::set<std::string>& split_paths,
    std::vector<LegacyCnEntry>* entries) {
    if (entries == nullptr || entries->empty()) {
        return false;
    }

    // Per stream: the values decoded so far, one slot per file that stream's
    // tables named, consumed in that order.
    struct StreamAcc {
        std::vector<std::int64_t> mtimes;
        std::vector<std::uint32_t> perms;
        std::vector<std::uint32_t> checksums;
    };
    std::map<unsigned, StreamAcc> acc;

    for (const auto& rec : records) {
        const unsigned sid = static_cast<unsigned>(rec[0]);
        const unsigned rtype = static_cast<unsigned>(rec[1]);
        const std::size_t rbegin = rec[2];
        const std::size_t rend = rec[3];
        if (rbegin > rend || rend > bytes.size()) return false;
        const std::size_t rsize = rend - rbegin;

        const auto named_it = stream_named.find(sid);
        if (named_it == stream_named.end()) return false;
        const std::size_t n = named_it->second.size();
        StreamAcc& a = acc[sid];

        switch (rtype) {
            case 2u: {
                if (rsize < 4u) return false;
                std::size_t p = rbegin;
                std::int64_t cur = static_cast<std::int64_t>(ReadU32LE(bytes.data() + p));
                p += 4u;
                if (a.mtimes.size() >= n) return false;
                a.mtimes.push_back(cur);
                while (p < rend) {
                    std::uint64_t z = 0u;
                    if (!ReadLegacyVarint(bytes, &p, rend, &z)) return false;
                    cur += static_cast<std::int64_t>(z >> 1u) ^ -static_cast<std::int64_t>(z & 1u);
                    if (a.mtimes.size() >= n) return false;
                    a.mtimes.push_back(cur);
                }
                if (p != rend) return false;
                break;
            }
            case 4u: {
                if ((rsize % 2u) != 0u) return false;
                for (std::size_t p = rbegin; p + 1u < rend; p += 2u) {
                    const std::uint32_t v = static_cast<std::uint32_t>(bytes[p]) |
                                            (static_cast<std::uint32_t>(bytes[p + 1u]) << 8u);
                    std::uint32_t mode = v;
                    std::size_t run = 1u;
                    if (v >= 0x1000u) {
                        const std::uint32_t coded = v >> 9u;
                        if (coded < 8u) return false;
                        run = static_cast<std::size_t>(coded - 6u);
                        mode = v & 0x1ffu;
                    }
                    if (run > n - a.perms.size()) return false;
                    a.perms.insert(a.perms.end(), run, mode);
                }
                break;
            }
            case 5u:
            case 6u:
            case 7u: {
                const std::size_t width = (rtype == 6u) ? 2u : 4u;
                if (rsize == 0u || (rsize % width) != 0u) return false;
                if (a.checksums.size() + rsize / width > n) return false;
                for (std::size_t p = rbegin; p < rend; p += width) {
                    a.checksums.push_back(
                        (width == 2u)
                            ? (static_cast<std::uint32_t>(bytes[p]) |
                               (static_cast<std::uint32_t>(bytes[p + 1u]) << 8u))
                            : ReadU32LE(bytes.data() + p));
                }
                break;
            }
            default:
                return false;
        }
    }

    bool any = false;
    for (const auto& kv : acc) {
        const auto named_it = stream_named.find(kv.first);
        if (named_it == stream_named.end()) return false;
        const std::size_t n = named_it->second.size();
        const StreamAcc& a = kv.second;
        // Partial coverage means the layout was not the one described above;
        // treat it as not understood rather than filling some files and not
        // others.
        if ((!a.mtimes.empty() && a.mtimes.size() != n) ||
            (!a.perms.empty() && a.perms.size() != n) ||
            (!a.checksums.empty() && a.checksums.size() != n)) {
            return false;
        }
        if (!a.mtimes.empty() || !a.perms.empty() || !a.checksums.empty()) any = true;
    }
    if (!any) return false;

    for (const auto& kv : acc) {
        const std::vector<std::size_t>& named = stream_named.find(kv.first)->second;
        const StreamAcc& a = kv.second;
        for (std::size_t i = 0; i < named.size(); ++i) {
            LegacyCnEntry& e = (*entries)[named[i]];
            if (!a.mtimes.empty()) { e.mtime_unix = a.mtimes[i]; e.has_mtime = true; }
            if (!a.perms.empty()) { e.permissions = a.perms[i]; e.has_permissions = true; }
            if (!a.checksums.empty()) {
                if (split_paths.count(e.path) != 0u) {
                    e.checksum_na = true;  // slice checksum, not this file's
                } else {
                    e.checksum = a.checksums[i];
                    e.has_checksum = true;
                }
            }
        }
    }
    return true;
}

struct LegacyCnContext;
static bool TryDecodeLegacyCm(const LegacyCnContext& legacy,
                              std::vector<unsigned char>* out_data,
                              std::string* out_error_message);

// One stream of a parallel (-pN) container.
struct LegacyParallelStream {
    // Block-record payload ranges for this stream, in order. Usually one, but
    // concatenated when a stream spans several type-0 chunks.
    std::vector<std::pair<std::size_t, std::size_t>> chunks;
    std::uint64_t osz = 0, ooff = 0;      // this slice's size and output offset
    ChecksumMode cmode = ChecksumMode::kNone;
    std::uint32_t cval = 0;               // checksum OF THE SLICE, not the file
    bool hasoff = false, hassz = false;
};

// Detect and parse a parallel container. The encoder splits the input into one
// slice per worker and gives each its own record set, tagged with a stream id
// in the type-15 extension: type-1 = slice size, type-10 = u32 output offset,
// type-5/6/7 = slice checksum, type-0 = its compressed (or, for -cn, raw) data.
// Streams appear in arbitrary order and are tiled by their offsets.
//
// Detected by the record right after the version chunk being an extended one.
// Returns false when the archive is not parallel or the record walk breaks.
bool ParseLegacyParallelStreams(
    const std::vector<unsigned char>& bytes,
    std::map<unsigned, LegacyParallelStream>* out_streams) {
    if (out_streams == nullptr) return false;
    out_streams->clear();

    std::size_t magic = bytes.size();
    for (std::size_t q = 0; q + 4u <= bytes.size(); ++q) {
        if (bytes[q] == 0x1fu && bytes[q + 1u] == 0x0fu && bytes[q + 2u] == 0x09u) {
            magic = q;
            break;
        }
    }
    if (magic == bytes.size() || bytes[magic + 3u] != 0x0fu) return false;

    std::size_t p = magic + 3u;
    for (int guard = 0; guard < 8192 && p < bytes.size(); ++guard) {
        std::uint64_t r = 0;
        if (!ReadLegacyVarint(bytes, &p, bytes.size(), &r)) return false;
        unsigned ct = static_cast<unsigned>(r) & 0x0fu;
        unsigned sid = 0u;
        std::size_t csz = static_cast<std::size_t>(r >> 4u);
        if (ct == 15u) {
            if (p >= bytes.size()) return false;
            unsigned ext = bytes[p++];
            if (ext >= 0xf8u) {
                if (p >= bytes.size()) return false;
                ext = (ext & 7u) + 8u * static_cast<unsigned>(bytes[p++]) + 248u;
            }
            ct = ext & 0x0fu;
            sid = ext >> 4u;
            if (sid == 0u) ct += 15u;
        }
        if (csz > bytes.size() - p) return false;
        LegacyParallelStream& st = (*out_streams)[sid];
        if (ct == 1u && csz >= 2u) {
            std::size_t tp = p;
            std::uint64_t v = 0;
            if (ReadLegacyVarint(bytes, &tp, p + csz, &v)) { st.osz = v; st.hassz = true; }
        } else if (ct == 10u && csz >= 4u) {
            st.ooff = ReadU32LE(bytes.data() + p);
            st.hasoff = true;
        } else if (ct == 5u && csz == 4u) {
            st.cmode = ChecksumMode::kFletcher32; st.cval = ReadU32LE(bytes.data() + p);
        } else if (ct == 7u && csz == 4u) {
            st.cmode = ChecksumMode::kCrc32; st.cval = ReadU32LE(bytes.data() + p);
        } else if (ct == 6u && csz == 2u) {
            st.cmode = ChecksumMode::kCrc16;
            st.cval = static_cast<std::uint32_t>(bytes[p]) |
                      (static_cast<std::uint32_t>(bytes[p + 1u]) << 8u);
        } else if (ct == 0u && csz > 0u) {
            st.chunks.emplace_back(p, csz);
        }
        p += csz;
    }
    return !out_streams->empty();
}

// Assemble a parallel STORE (-cn) payload: each stream's data record holds its
// slice verbatim, so the whole file is the slices tiled by their offsets. Every
// slice is checked against its own checksum, so a wrong layout cannot produce
// output.
bool TryAssembleParallelStore(
    const std::vector<unsigned char>& bytes,
    std::uint64_t total_size,
    std::vector<unsigned char>* out) {
    if (out == nullptr || total_size == 0u ||
        total_size > static_cast<std::uint64_t>(bytes.size())) {
        return false;
    }
    std::map<unsigned, LegacyParallelStream> streams;
    if (!ParseLegacyParallelStreams(bytes, &streams)) return false;

    std::vector<unsigned char> assembled(static_cast<std::size_t>(total_size), 0);
    std::uint64_t covered = 0;
    for (const auto& kv : streams) {
        const LegacyParallelStream& st = kv.second;
        if (st.chunks.empty()) continue;
        if (!st.hasoff || !st.hassz || st.cmode == ChecksumMode::kNone) return false;
        if (st.ooff > total_size || st.osz > total_size - st.ooff) return false;

        std::vector<unsigned char> slice;
        slice.reserve(static_cast<std::size_t>(st.osz));
        for (const auto& c : st.chunks) {
            slice.insert(slice.end(),
                         bytes.begin() + static_cast<std::ptrdiff_t>(c.first),
                         bytes.begin() + static_cast<std::ptrdiff_t>(c.first + c.second));
        }
        if (slice.size() != st.osz) return false;
        if (ComputeBufferChecksum(st.cmode, slice.data(), slice.size()) != st.cval) return false;
        std::memcpy(assembled.data() + static_cast<std::size_t>(st.ooff),
                    slice.data(), slice.size());
        covered += st.osz;
    }
    if (covered != total_size) return false;
    *out = std::move(assembled);
    return true;
}

// Walk a multi-block "stored" (-cn, method_p0==0) payload. NanoZip splits a
// large stored file into several blocks: each block is [varint (len<<4)|0]
// [len raw bytes], and every block except the last is followed by a per-block
// checksum trailer (one tag byte + checksum_bytes). Single-block stores (the
// common case) are handled by the simpler tail scan; this covers files large
// enough to split (e.g. a 215 KB source file -> 196608 + 18566). On success
// *out holds the concatenated raw payload (exactly `total` bytes) and the walk
// consumes the buffer up to EOF, which makes the starting offset unambiguous.
bool TryAssembleStoredBlocks(
    const std::vector<unsigned char>& bytes,
    std::size_t first_prefix,
    std::uint64_t total,
    std::size_t trailer_bytes,
    std::vector<unsigned char>* out) {
    if (out == nullptr || first_prefix > bytes.size() || total == 0u) {
        return false;
    }
    std::vector<unsigned char> buf;
    buf.reserve(static_cast<std::size_t>(total));
    std::size_t p = first_prefix;
    std::uint64_t acc = 0;
    while (acc < total) {
        std::size_t q = p;
        std::uint64_t tag = 0;
        if (!ReadLegacyVarint(bytes, &q, bytes.size(), &tag)) {
            return false;
        }
        if ((tag & 0x0fu) != 0u) {
            return false;  // stored blocks always carry flags == 0
        }
        const std::uint64_t len = tag >> 4u;
        if (len == 0u || len > total - acc ||
            static_cast<std::uint64_t>(bytes.size() - q) < len) {
            return false;
        }
        const std::size_t ln = static_cast<std::size_t>(len);
        buf.insert(buf.end(), bytes.begin() + static_cast<std::ptrdiff_t>(q),
                   bytes.begin() + static_cast<std::ptrdiff_t>(q + ln));
        acc += len;
        p = q + ln;
        if (acc < total) {
            if (trailer_bytes > bytes.size() - p) {
                return false;
            }
            p += trailer_bytes;  // skip the inter-block checksum trailer
        }
    }
    if (acc != total || p != bytes.size()) {
        return false;
    }
    *out = std::move(buf);
    return true;
}

bool ReadLegacyTableSpan(
    const std::vector<unsigned char>& bytes,
    std::size_t* io_pos,
    std::uint64_t* out_span) {
    if (io_pos == nullptr || out_span == nullptr || *io_pos >= bytes.size()) {
        return false;
    }

    const unsigned char b0 = bytes[*io_pos];
    if ((b0 & 0x0fu) != 0x01u) {
        return false;
    }
    *io_pos += 1u;

    if ((b0 & 0x80u) == 0u) {
        const unsigned hi = static_cast<unsigned>(b0 >> 4u);
        if (hi < 2u) {
            return false;
        }
        *out_span = static_cast<std::uint64_t>(hi - 2u);
        return true;
    }

    if (*io_pos >= bytes.size()) {
        return false;
    }
    const unsigned char b1 = bytes[*io_pos];
    *io_pos += 1u;
    *out_span = static_cast<std::uint64_t>(b0 >> 4u) + (static_cast<std::uint64_t>(b1) << 3u) - 2u;
    return true;
}

bool IsLikelyLegacyPathByte(unsigned char c) {
    // Legacy filenames are path-like text; reject control chars while allowing UTF-8 bytes.
    return c >= 0x20u && c != 0x7fu;
}

bool LooksLikeLegacyFilenameTable(
    const std::vector<unsigned char>& bytes,
    std::size_t table_start,
    std::size_t table_end) {
    if (table_start >= table_end || table_end > bytes.size()) {
        return false;
    }
    std::size_t p = table_start;
    std::size_t entry_count = 0;
    while (p < table_end) {
        std::uint64_t file_size = 0;
        if (!ReadLegacyVarint(bytes, &p, table_end, &file_size)) {
            return false;
        }
        const auto nul_it = std::find(bytes.begin() + static_cast<std::ptrdiff_t>(p),
                                      bytes.begin() + static_cast<std::ptrdiff_t>(table_end),
                                      static_cast<unsigned char>(0));
        if (nul_it == bytes.begin() + static_cast<std::ptrdiff_t>(table_end)) {
            return false;
        }
        const std::size_t name_end = static_cast<std::size_t>(std::distance(bytes.begin(), nul_it));
        if (name_end <= p) {
            return false;
        }
        for (std::size_t i = p; i < name_end; ++i) {
            if (!IsLikelyLegacyPathByte(bytes[i])) {
                return false;
            }
        }
        p = name_end + 1u;
        ++entry_count;
    }
    return p == table_end && entry_count > 0;
}

bool ReadLegacyTableSpanFlexible(
    const std::vector<unsigned char>& bytes,
    std::size_t* io_pos,
    std::uint64_t* out_span) {
    if (io_pos == nullptr || out_span == nullptr || *io_pos >= bytes.size()) {
        return false;
    }

    const std::size_t base = *io_pos;
    // Some legacy families carry one or two extra parameter bytes before filename-table span.
    for (std::size_t skip = 0; skip <= 8u && base + skip < bytes.size(); ++skip) {
        std::size_t p = base + skip;
        std::uint64_t span = 0;
        if (!ReadLegacyTableSpan(bytes, &p, &span)) {
            continue;
        }
        const std::uint64_t table_len_u64 = span + 2u;
        if (table_len_u64 > static_cast<std::uint64_t>(bytes.size() - p)) {
            continue;
        }
        const std::size_t table_end = p + static_cast<std::size_t>(table_len_u64);
        if (!LooksLikeLegacyFilenameTable(bytes, p, table_end)) {
            continue;
        }
        *io_pos = p;
        *out_span = span;
        return true;
    }
    return false;
}

bool WriteLegacyTableSpan(std::uint64_t span, std::vector<unsigned char>* out_bytes) {
    if (out_bytes == nullptr) {
        return false;
    }

    // 1-byte form: (hi << 4) | 0x01, where span = hi - 2 and hi in [2,7].
    if (span <= 5u) {
        const unsigned char hi = static_cast<unsigned char>(span + 2u);
        out_bytes->push_back(static_cast<unsigned char>((hi << 4u) | 0x01u));
        return true;
    }

    // 2-byte form accepted by parser:
    // span = (b0 >> 4) + (b1 << 3) - 2, with high bit of b0 set.
    const std::uint64_t x = span + 2u;
    const std::uint64_t hi = (x & 0x07u) + 0x08u;  // 8..15, keeps MSB set on b0.
    if (x < hi) {
        return false;
    }
    const std::uint64_t b1 = (x - hi) >> 3u;
    if (b1 > 0xffu) {
        return false;
    }

    const unsigned char b0 = static_cast<unsigned char>((hi << 4u) | 0x01u);
    out_bytes->push_back(b0);
    out_bytes->push_back(static_cast<unsigned char>(b1));
    return true;
}

std::uint32_t ReadU32LE(const unsigned char* p) {
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8u) |
           (static_cast<std::uint32_t>(p[2]) << 16u) |
           (static_cast<std::uint32_t>(p[3]) << 24u);
}

void AppendU32LE(std::uint32_t value, std::vector<unsigned char>* out_bytes) {
    if (out_bytes == nullptr) {
        return;
    }
    out_bytes->push_back(static_cast<unsigned char>(value & 0xffu));
    out_bytes->push_back(static_cast<unsigned char>((value >> 8u) & 0xffu));
    out_bytes->push_back(static_cast<unsigned char>((value >> 16u) & 0xffu));
    out_bytes->push_back(static_cast<unsigned char>((value >> 24u) & 0xffu));
}

bool InverseBwt(
    const unsigned char* last_column,
    std::size_t size,
    std::size_t primary_index,
    std::vector<unsigned char>* out_data) {
    if (last_column == nullptr || out_data == nullptr) {
        return false;
    }
    out_data->clear();

    if (size == 0u) {
        return primary_index == 0u;
    }
    if (primary_index >= size) {
        return false;
    }

    std::array<std::uint32_t, 256> counts{};
    for (std::size_t i = 0; i < size; ++i) {
        ++counts[last_column[i]];
    }

    std::array<std::uint32_t, 256> starts{};
    std::uint32_t acc = 0;
    for (std::size_t c = 0; c < starts.size(); ++c) {
        starts[c] = acc;
        acc += counts[c];
    }

    std::array<std::uint32_t, 256> seen{};
    std::vector<std::uint32_t> rank(size, 0u);
    for (std::size_t i = 0; i < size; ++i) {
        const unsigned char c = last_column[i];
        ++seen[c];
        rank[i] = seen[c];
    }

    out_data->resize(size);
    std::size_t row = primary_index;
    for (std::size_t k = size; k > 0u; --k) {
        const unsigned char c = last_column[row];
        (*out_data)[k - 1u] = c;
        row = static_cast<std::size_t>(starts[c] + rank[row] - 1u);
        if (k > 1u && row >= size) {
            out_data->clear();
            return false;
        }
    }
    return true;
}

bool ForwardBwt(
    const std::vector<unsigned char>& input,
    std::vector<unsigned char>* out_last_column,
    std::uint32_t* out_primary_index) {
    if (out_last_column == nullptr || out_primary_index == nullptr) {
        return false;
    }

    out_last_column->clear();
    *out_primary_index = 0u;

    const std::size_t n = input.size();
    if (n == 0u) {
        return true;
    }
    if (n > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max())) {
        return false;
    }

    std::vector<std::size_t> suffixes(n, 0u);
    std::iota(suffixes.begin(), suffixes.end(), 0u);

    const auto cmp = [&input, n](std::size_t a, std::size_t b) -> bool {
        if (a == b) {
            return false;
        }
        for (std::size_t k = 0; k < n; ++k) {
            const unsigned char ca = input[(a + k) % n];
            const unsigned char cb = input[(b + k) % n];
            if (ca != cb) {
                return ca < cb;
            }
        }
        return false;
    };
    std::sort(suffixes.begin(), suffixes.end(), cmp);

    out_last_column->resize(n);
    bool primary_found = false;
    for (std::size_t rank = 0; rank < n; ++rank) {
        const std::size_t start = suffixes[rank];
        if (start == 0u) {
            *out_primary_index = static_cast<std::uint32_t>(rank);
            primary_found = true;
        }
        (*out_last_column)[rank] = input[(start + n - 1u) % n];
    }

    return primary_found;
}

// C++ port of the NanoZip 0.09a `-co`/`-cO` prefilter decoder (orig 0x0809a250 +
// core 0x080acb90). Produces the BWT last-column buffer from the archive's
// prefilter substream. Validated byte-for-byte against emulator ground truth.
struct LegacyPrefilterRangeCoder {
    const unsigned char* src_cur = nullptr;
    const unsigned char* src_end = nullptr;
    std::uint32_t high = 0xFFFFFFFFu;
    std::uint32_t low = 0;
    std::uint32_t code = 0;
    std::array<std::uint16_t, 32> probs{};

    void Init(const unsigned char* begin, const unsigned char* end) {
        src_cur = begin;
        src_end = end;
        high = 0xFFFFFFFFu;
        low = 0;
        code = 0;
        probs.fill(static_cast<std::uint16_t>(0x8000u));
        for (int i = 0; i < 4; ++i) {
            const std::uint8_t b = (src_cur < src_end) ? *src_cur++ : 0u;
            code = (code << 8u) | b;
        }
    }

    void Renormalize() {
        while (((high ^ low) & 0xFF000000u) == 0u) {
            const std::uint8_t b = (src_cur < src_end) ? *src_cur++ : 0u;
            code = (code << 8u) | b;
            low <<= 8u;
            high = (high << 8u) | 0xFFu;
        }
    }

    int DecodeBit(int prob_idx) {
        const std::uint32_t prob = probs[prob_idx];
        const std::uint32_t range_size = high - low;
        const std::uint32_t bound = low + ((range_size >> 12u) * (prob >> 4u));
        int bit;
        if (code <= bound) {
            bit = 1;
            high = bound;
        } else {
            bit = 0;
            low = bound + 1u;
        }
        const std::uint32_t delta = (((static_cast<std::uint32_t>(bit) << 16u) - prob + 0x80u) & 0xFFFFFFFFu) >> 8u;
        probs[prob_idx] = static_cast<std::uint16_t>((prob + delta) & 0xFFFFu);
        Renormalize();
        return bit;
    }

    int DecodeBitRaw() {
        const std::uint32_t range_size = high - low;
        const std::uint32_t bound = low + ((range_size >> 12u) << 11u);
        int bit;
        if (code <= bound) {
            bit = 1;
            high = bound;
        } else {
            bit = 0;
            low = bound + 1u;
        }
        Renormalize();
        return bit;
    }

    std::uint32_t DecodeRunExtra(int run_len) {
        const int limit = (run_len == 0) ? 1 : (1 << (run_len < 4 ? run_len : 4));
        std::uint32_t value_acc = (run_len != 0) ? 1u : 0u;
        int tree_idx = 1;
        while (true) {
            const int bit = DecodeBit(tree_idx + limit);
            tree_idx = (tree_idx << 1) | bit;
            value_acc = (value_acc << 1) | static_cast<std::uint32_t>(bit);
            if (tree_idx >= limit) {
                break;
            }
        }
        const int max_v = run_len > 1 ? run_len : 1;
        if (max_v <= 4) {
            return value_acc;
        }
        const int k = run_len - 4;
        std::uint32_t base = value_acc << k;
        std::uint32_t raw = 0;
        for (int i = 0; i < k; ++i) {
            raw = (raw << 1) | static_cast<std::uint32_t>(DecodeBitRaw());
        }
        return base + raw;
    }
};

bool DecodeLegacyPrefilterStream(
    const unsigned char* src,
    std::size_t byte_copy_count,
    LegacyPrefilterRangeCoder& rc,
    std::size_t expected_out_size,
    std::vector<unsigned char>* out_data) {
    if (src == nullptr || out_data == nullptr) {
        return false;
    }
    out_data->clear();
    out_data->reserve(expected_out_size);

    std::size_t p = 0;
    std::size_t n = byte_copy_count;
    std::uint32_t edx = 0;

    while (n > 0u) {
        bool re_enter = false;
        while (n > 0u) {
            edx = (edx << 8u) & 0xFFFFu;
            const std::uint8_t dl = src[p++];
            --n;
            edx = (edx & 0xFF00u) | dl;
            out_data->push_back(dl);
            const std::uint8_t dh = static_cast<std::uint8_t>((edx >> 8u) & 0xFFu);
            if (dl != dh) {
                continue;
            }
            if (n == 0u) {
                break;
            }
            const std::uint8_t dl2 = src[p++];
            --n;
            edx = (edx & 0xFF00u) | dl2;
            out_data->push_back(dl2);
            if (dl2 != dh) {
                continue;
            }
            if (n == 0u) {
                break;
            }
            const std::uint8_t run_byte = dh;
            int iters = 0;
            while (n > 0u) {
                ++iters;
                --n;
                const std::uint8_t cur = src[p++];
                if (cur != run_byte) {
                    --p;
                    ++n;
                    break;
                }
            }
            const int run_len = iters - 1;
            if (run_len > 30) {
                return false;
            }
            const std::uint32_t extra = rc.DecodeRunExtra(run_len);
            if (out_data->size() + extra > expected_out_size + 16u) {
                return false;
            }
            for (std::uint32_t i = 0; i < extra; ++i) {
                out_data->push_back(run_byte);
            }
            edx = run_byte;
            re_enter = true;
            break;
        }
        if (!re_enter) {
            break;
        }
    }
    return true;
}

bool LoadSourcesRawData(
    const std::vector<SourceFile>& sources,
    std::vector<unsigned char>* out_data,
    std::string* out_error_message) {
    if (out_data == nullptr) {
        if (out_error_message != nullptr) {
            *out_error_message = "internal error: null raw-data output";
        }
        return false;
    }
    out_data->clear();

    std::uint64_t total = 0u;
    for (const SourceFile& src : sources) {
        if (src.size > (std::numeric_limits<std::uint64_t>::max() - total)) {
            if (out_error_message != nullptr) {
                *out_error_message = "input size overflow while loading source data";
            }
            return false;
        }
        total += src.size;
    }
    if (total > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        if (out_error_message != nullptr) {
            *out_error_message = "input too large for in-memory native encoder path";
        }
        return false;
    }

    out_data->reserve(static_cast<std::size_t>(total));
    std::vector<char> buffer(kBufferSize);
    for (const SourceFile& src : sources) {
        std::ifstream in(src.source_path, std::ios::binary);
        if (!in) {
            if (out_error_message != nullptr) {
                *out_error_message = "cannot read input file: " + src.source_path.string();
            }
            return false;
        }
        while (in) {
            in.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
            const std::streamsize got = in.gcount();
            if (got <= 0) {
                break;
            }
            const std::size_t old_size = out_data->size();
            const std::size_t add = static_cast<std::size_t>(got);
            if (add > std::numeric_limits<std::size_t>::max() - old_size) {
                if (out_error_message != nullptr) {
                    *out_error_message = "input too large for in-memory native encoder path";
                }
                return false;
            }
            out_data->resize(old_size + add);
            std::memcpy(out_data->data() + static_cast<std::ptrdiff_t>(old_size), buffer.data(), add);
        }
        if (in.bad()) {
            if (out_error_message != nullptr) {
                *out_error_message = "cannot read input file: " + src.source_path.string();
            }
            return false;
        }
    }

    return true;
}

bool WriteSourcesRawData(
    const std::vector<SourceFile>& sources,
    std::ostream* out,
    std::string* out_error_message) {
    if (out == nullptr) {
        if (out_error_message != nullptr) {
            *out_error_message = "internal error: null output stream";
        }
        return false;
    }

    std::vector<char> buffer(kBufferSize);
    for (const SourceFile& src : sources) {
        std::ifstream in(src.source_path, std::ios::binary);
        if (!in) {
            if (out_error_message != nullptr) {
                *out_error_message = "cannot read input file: " + src.source_path.string();
            }
            return false;
        }
        while (in) {
            in.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
            const std::streamsize got = in.gcount();
            if (got <= 0) {
                break;
            }
            out->write(buffer.data(), got);
            if (!*out) {
                if (out_error_message != nullptr) {
                    *out_error_message = "write failure while building archive";
                }
                return false;
            }
        }
        if (in.bad()) {
            if (out_error_message != nullptr) {
                *out_error_message = "cannot read input file: " + src.source_path.string();
            }
            return false;
        }
    }
    return true;
}

std::uint8_t LegacyChecksumTag(ChecksumMode mode) {
    switch (mode) {
        case ChecksumMode::kCrc16:
            return 0x26u;
        case ChecksumMode::kCrc32:
            return 0x47u;
        case ChecksumMode::kFletcher16:
        case ChecksumMode::kFletcher32:
            return 0x45u;
        case ChecksumMode::kNone:
        default:
            return 0u;
    }
}

ChecksumMode LegacyNormalizeChecksumModeForCompression(ChecksumMode requested) {
    // In legacy headers, 0x05 maps to NanoZip's Fletcher32 variant even for CLI -hf.
    if (requested == ChecksumMode::kFletcher16) {
        return ChecksumMode::kFletcher32;
    }
    return requested;
}

std::uint8_t LegacyChecksumHeaderByte(ChecksumMode mode) {
    switch (mode) {
        case ChecksumMode::kFletcher32:
            return 0x05u;
        case ChecksumMode::kCrc16:
            return 0x06u;
        case ChecksumMode::kCrc32:
            return 0x07u;
        case ChecksumMode::kNone:
        case ChecksumMode::kFletcher16:
        default:
            return 0u;
    }
}

std::size_t LegacyChecksumBytesPerFile(ChecksumMode mode) {
    switch (mode) {
        case ChecksumMode::kCrc16:
            return 2u;
        case ChecksumMode::kCrc32:
        case ChecksumMode::kFletcher16:
        case ChecksumMode::kFletcher32:
            return 4u;
        case ChecksumMode::kNone:
        default:
            return 0u;
    }
}

bool BuildLegacyChecksumBytes(
    const std::vector<SourceFile>& sources,
    ChecksumMode mode,
    std::vector<unsigned char>* out_bytes,
    std::string* out_error_message) {
    if (out_bytes == nullptr) {
        if (out_error_message != nullptr) {
            *out_error_message = "internal error: null checksum output";
        }
        return false;
    }

    out_bytes->clear();
    const std::size_t bytes_per_file = LegacyChecksumBytesPerFile(mode);
    if (bytes_per_file == 0u || sources.empty()) {
        return true;
    }

    for (const SourceFile& src : sources) {
        std::uint32_t checksum = 0;
        if (!ComputeFileChecksum(src.source_path, mode, &checksum)) {
            if (out_error_message != nullptr) {
                *out_error_message = "cannot checksum file: " + src.source_path.string();
            }
            return false;
        }

        if (bytes_per_file == 2u) {
            out_bytes->push_back(static_cast<unsigned char>(checksum & 0xffu));
            out_bytes->push_back(static_cast<unsigned char>((checksum >> 8u) & 0xffu));
        } else {
            out_bytes->push_back(static_cast<unsigned char>(checksum & 0xffu));
            out_bytes->push_back(static_cast<unsigned char>((checksum >> 8u) & 0xffu));
            out_bytes->push_back(static_cast<unsigned char>((checksum >> 16u) & 0xffu));
            out_bytes->push_back(static_cast<unsigned char>((checksum >> 24u) & 0xffu));
        }
    }
    return true;
}

// The bare compressor name the original prints in its banner. LegacyCompressorLabel
// below appends a diagnostic "[legacy m=..,p0=..,p1=..]" suffix that the original has
// no equivalent of, so the banner uses this instead.

std::string LegacyCompressorLabel(std::uint8_t method, std::uint8_t method_p0, std::uint8_t method_p1) {
    std::string base = "unknown";
    if (method == 0x2bu || method == 0x3bu || method == 0x4bu) {
        switch (method_p0) {
            case 0u:
                base = "none";
                break;
            case 1u:
                base = "nz_lzpf";
                break;
            case 2u:
                base = "nz_lzpf_large";
                break;
            case 3u:
                base = "nz_lzhd";
                break;
            case 4u:
                base = "nz_lzhds";
                break;
            case 5u:
                base = "nz_optimum1";
                break;
            case 6u:
                base = "nz_optimum2";
                break;
            case 7u:
                base = "nz_cm";
                break;
            default:
                base = "unknown";
                break;
        }
    }

    std::ostringstream oss;
    oss << base << " [legacy m=" << static_cast<unsigned>(method)
        << ",p0=" << static_cast<unsigned>(method_p0)
        << ",p1=" << static_cast<unsigned>(method_p1) << "]";
    return oss.str();
}

std::string LegacyCompressorName(std::uint8_t method, std::uint8_t method_p0) {
    const std::string full = LegacyCompressorLabel(method, method_p0, 0u);
    const std::size_t br = full.find(" [");
    return (br == std::string::npos) ? full : full.substr(0, br);
}


const char* LegacyPayloadModeLabel(LegacyPayloadMode mode) {
    switch (mode) {
        case LegacyPayloadMode::kStore:
            return "store";
        case LegacyPayloadMode::kLiteralOnly:
            return "literal-only";
        case LegacyPayloadMode::kCompressed:
            return "compressed";
        case LegacyPayloadMode::kUnknown:
        default:
            return "unknown";
    }
}

// Decode one nz_lzpf member: a chain of [stream] segments beginning at
// `first_block_pos` (the first lzpf block header — for the single-stream layout
// this is just past the leading stream tag; for a parallel-container type-0
// chunk it is the chunk start), the first segment spanning `first_stream_len`
// bytes, producing `total` output bytes. The true sliding-window dict capacity
// is not recoverable from the header, so this tries each candidate capacity and
// returns the first decode for which verify(decoded) is true. Returns true and
// fills *out on success; returns false (out untouched) otherwise. This is the
// shared core behind both single-stream and parallel-container lzpf decode.
template <typename Verify>
bool DecodeLzpfMember(
    const std::vector<unsigned char>& bytes,
    std::size_t first_block_pos,
    std::size_t first_stream_len,
    std::uint64_t total,
    bool is_variant_b,
    unsigned method_p1,
    Verify&& verify,
    std::vector<unsigned char>* out) {
    if (first_block_pos + first_stream_len > bytes.size()) return false;
    // NZOPT_TRACE_LZPF=1 dumps one line per lzpf block (mode, size, prefilter
    // header fields) plus the decline point — the fastest way to tell whether a
    // failing member even reaches the stereo prefilter path.
    const bool trace_lzpf = (std::getenv("NZOPT_TRACE_LZPF") != nullptr);
    auto decode_lzpf_header = [&](std::size_t& pos, std::uint32_t& out_uvar9) -> bool {
        if (pos >= bytes.size()) return false;
        std::uint8_t b0 = bytes[pos++];
        std::uint32_t v = static_cast<std::uint32_t>(b0) ^ (b0 & 0x80u);
        if ((b0 & 0x80u) != 0u) {
            if (pos >= bytes.size()) return false;
            std::uint8_t b1 = bytes[pos++];
            v = (static_cast<std::uint32_t>(b1) ^ (b1 & 0x80u)) * 0x80u + 0x80u + v;
            if ((b1 & 0x80u) != 0u) {
                if (pos >= bytes.size()) return false;
                std::uint8_t b2 = bytes[pos++];
                v = static_cast<std::uint32_t>(b2) * 0x4000u + 0x4000u + v;
            }
        }
        out_uvar9 = v;
        return true;
    };

    const std::size_t window_left_pad = 4u;
    // The dict capacity is always a multiple of 64 KiB, but the multiplier the
    // encoder chose is not recoverable from the header. GDB across many archives
    // shows it is one of: ceil/floor(total / 64 KiB)·64 KiB (parallel slices),
    // ceil/floor(total / 128 KiB)·128 KiB (large single-stream members), or
    // (p1+1)·64 KiB (small single-stream members). We try each and keep the
    // first whose decode passes verify(); a wrong capacity only matters once a
    // window wrap occurs, which the checksum rejects.
    std::vector<std::size_t> cap_candidates;
    {
        const std::size_t t = static_cast<std::size_t>(total);
        const std::size_t u64 = t / 0x10000u;
        const std::size_t u128 = t / 0x20000u;
        const std::size_t cands[] = {
            ((t + 0xffffu) / 0x10000u) * 0x10000u,  // ceil 64 KiB
            u64 * 0x10000u,                          // floor 64 KiB
            (u128 + 1u) * 0x20000u,                  // ceil 128 KiB
            u128 * 0x20000u,                         // floor 128 KiB
            (static_cast<std::size_t>(method_p1) + 1u) * 0x10000u,
        };
        for (std::size_t c : cands) {
            if (c == 0u) continue;
            bool dup = false;
            for (std::size_t e : cap_candidates) if (e == c) { dup = true; break; }
            if (!dup) cap_candidates.push_back(c);
        }
    }
    const std::size_t window_wrap_threshold = 0x8000u;  // 32 KiB
    const std::size_t window_tail_slack = 0x8000u;      // FUN_080b6bb0 memset reach
    const std::size_t window_initial_cursor = 4u;

    for (const std::size_t window_capacity : cap_candidates) {
        std::size_t stream_data_end = first_block_pos + first_stream_len;
        std::vector<std::uint8_t> window_alloc(
            window_left_pad + window_capacity + window_tail_slack, 0);
        std::uint8_t* const window = window_alloc.data() + window_left_pad;
        std::vector<unsigned char> decoded(static_cast<std::size_t>(total), 0);
        std::vector<std::int32_t> hash_table(
            is_variant_b ? std::size_t{0x1000000u} : std::size_t{8192u}, std::int32_t{3});
        std::vector<std::uint8_t> byte_buffer_b(
            is_variant_b ? std::size_t{0x2000u} : std::size_t{0u}, 0);
        std::size_t window_cursor = window_initial_cursor;
        std::size_t total_written = 0;
        std::size_t input_pos = first_block_pos;
        bool decode_ok = true;
        std::size_t blk_idx = 0;
        // The prefilter state object (FUN_080b1600). -cf configures order01 = 4,
        // -cF order01 = 8, both with nstages = 1 -- GDB-measured immediates at the
        // two callers. -cd/-cD use nstages = 3 (and -cD order01 = 32), which is why
        // this is now an explicit context rather than two loose predictors.
        nzr::lzpf::PrefilterContext pf_ctx;
        pf_ctx.Configure(is_variant_b ? 8u : 4u, 1u);
        nzr::lzpf::LmsObject pf_lms_ch1{};
        nzr::lzpf::LmsObject pf_lms_ch2{};
        pf_lms_ch1.Init();
        pf_lms_ch2.Init();
        while (total_written < total) {
            if (input_pos >= stream_data_end) {
                if (input_pos != stream_data_end) { decode_ok = false; break; }
                // Consume any inter-stream checksum record (tag 0x45/0x47/0x26
                // + width) before the next stream tag.
                while (input_pos < bytes.size()) {
                    const std::uint8_t tb = bytes[input_pos];
                    std::size_t tw;
                    if      (tb == 0x45u) tw = 4u;
                    else if (tb == 0x47u) tw = 4u;
                    else if (tb == 0x26u) tw = 2u;
                    else break;
                    if (input_pos + 1u + tw > bytes.size()) break;
                    input_pos += 1u + tw;
                }
                std::uint64_t next_tag = 0;
                if (!ReadLegacyVarint(bytes, &input_pos, bytes.size(), &next_tag) ||
                    (next_tag & 0x0fu) != 0u) { decode_ok = false; break; }
                const std::uint64_t next_bytes = next_tag >> 4u;
                if (next_bytes == 0u ||
                    next_bytes > static_cast<std::uint64_t>(bytes.size() - input_pos)) {
                    decode_ok = false; break;
                }
                stream_data_end = input_pos + static_cast<std::size_t>(next_bytes);
            }
            std::uint32_t uvar9 = 0;
            if (!decode_lzpf_header(input_pos, uvar9)) { decode_ok = false; break; }
            const bool mode_prefilter = ((uvar9 & 7u) == 4u);
            const bool mode_literal = !mode_prefilter && ((uvar9 & 2u) == 0u);
            const bool mode_lz77_side = !mode_prefilter && (uvar9 & 2u) && (uvar9 & 1u);
            // Raw-bytecode LZ77 (FUN_08097570: (uVar9 & 2) set, (uVar9 & 1) clear):
            // the LZ77 opcode stream is the input bytes directly — no u16 count,
            // no arith side stream. The dispatcher consumes opcodes until the
            // block output is produced and reports how many input bytes it read.
            const bool mode_lz77_raw = !mode_prefilter && (uvar9 & 2u) && !(uvar9 & 1u);
            // Sliding-window wrap (legacy FUN_080b6bb0): zero [cursor, cap+0x8000)
            // then reset the cursor to 0 when fewer than 32 KiB remain.
            if (window_capacity - window_cursor < window_wrap_threshold) {
                std::memset(window + window_cursor, 0,
                            window_capacity + window_tail_slack - window_cursor);
                window_cursor = 0;
            }
            if (mode_prefilter) {
                const std::uint32_t uvar18 = (uvar9 >> 3u) & 1u;
                if (uvar18 != 0u) { decode_ok = false; break; }
                std::uint64_t block_out_size = uvar9 >> 4u;
                if (block_out_size == 0u) block_out_size = 0x8000u;
                if (block_out_size > 0x8001u) { decode_ok = false; break; }
                if (total_written + block_out_size > total) { decode_ok = false; break; }
                const std::size_t block_start_in_window = window_cursor;
                const std::size_t avail_in = stream_data_end - input_pos;
                const std::uint8_t pf_hdr = bytes[input_pos];
                const std::uint32_t pf_channels = (pf_hdr >> 1u) % 3u;
                const bool is_stereo_pf = (pf_channels != 0u);
                const std::size_t pf_consumed = nzr::lzpf::DecodePrefilterStream(
                    bytes.data() + input_pos, avail_in,
                    window + block_start_in_window,
                    static_cast<std::size_t>(block_out_size),
                    is_stereo_pf, &pf_ctx,
                    is_stereo_pf ? &pf_lms_ch1 : nullptr,
                    is_stereo_pf ? &pf_lms_ch2 : nullptr);
                if (trace_lzpf) {
                    const std::uint32_t c1 = (pf_hdr >> 1u) / 3u;
                    const std::uint32_t wq = c1 / 5u;
                    const std::uint32_t wr = c1 - wq * 5u;
                    const unsigned sw = wr ? (unsigned)((((wr - 1u) >> 1u) + 1u) + 1u) : 1u;
                    const unsigned en = wr ? (unsigned)((wr - 1u) & 1u) : 0u;
                    fprintf(stderr,
                            "[lzpf] blk#%zu pf out=%llu hdr=%02x ch=%u fa=%u sw=%u end=%u "
                            "pfx=%u consumed=%zu\n",
                            blk_idx, (unsigned long long)block_out_size,
                            (unsigned)pf_hdr, pf_channels, (unsigned)(pf_hdr & 1u),
                            sw, en, wq, pf_consumed);
                }
                ++blk_idx;
                if (pf_consumed == 0) { decode_ok = false; break; }
                input_pos += pf_consumed;
                window_cursor += static_cast<std::size_t>(block_out_size);
                std::memcpy(decoded.data() + total_written, window + block_start_in_window,
                            static_cast<std::size_t>(block_out_size));
                // Backfill hash_table for the prefilter block's window bytes.
                // The real dispatcher FUN_08097570 calls FUN_080b6d90 at the end
                // of the prefilter branch too, not just after literal blocks --
                // and a prefilter block DOES publish window content that a later
                // LZ77 block can match into. Without this, those matches read the
                // table's untouched init value and the LZ block decodes wrong
                // (summer.php: blocks 0-2 byte-exact, first divergence 951 bytes
                // into block 3, the first lz-side block after a prefilter block).
                // A prefilter block has (uvar9 & 7) == 4, so uvar9 & 1 == 0 --
                // the SPARSE variant (every 101 bytes, stopping 100 short of the
                // block end), matching the literal path's own uvar9&1 == 0 case.
                {
                    const std::size_t bstart = block_start_in_window;
                    const std::size_t bend = block_start_in_window + static_cast<std::size_t>(block_out_size);
                    const std::size_t hstop = (bend > 100u) ? (bend - 100u) : bstart;
                    for (std::size_t hp = bstart; hp < hstop; hp += 101u) {
                        std::uint32_t hw;
                        std::memcpy(&hw, window + hp - (is_variant_b ? 3u : 2u), 4);
                        const std::uint32_t h = is_variant_b ? (hw & 0xffffffu) : (hw & 0x1fffu);
                        hash_table[h] = static_cast<std::int32_t>(hp);
                    }
                    if (is_variant_b) {
                        std::memset(byte_buffer_b.data(), 0, byte_buffer_b.size());
                    }
                }
                total_written += static_cast<std::size_t>(block_out_size);
                continue;
            }
            if (!mode_literal && !mode_lz77_side && !mode_lz77_raw) { decode_ok = false; break; }
            if (trace_lzpf) {
                fprintf(stderr, "[lzpf] blk#%zu %s uvar9=%u out=%llu\n", blk_idx,
                        mode_literal ? "lit" : (mode_lz77_side ? "lz-side" : "lz-raw"),
                        uvar9, (unsigned long long)(uvar9 >> 3u));
            }
            ++blk_idx;
            // Any non-prefilter block (literal or LZ77) resets the whole audio-model
            // context (both per-channel LPC predictors AND both LMS objects) -- confirmed
            // by GDB against the real binary (FUN_08095d90 breakpoint, st_2ch24b48000_
            // scifi.wav): the per-channel predictor object's address is stable across all
            // 16 prefilter-block calls in the stream (same param_1 pointer throughout, so
            // state is never reallocated), yet its entering state (predicted_value +
            // factors[4]) is exactly zero for every prefilter block immediately preceded
            // by a literal block, and non-zero (carried forward) for every prefilter block
            // immediately preceded by ANOTHER prefilter block with no literal in between --
            // a 16-for-16 exact match across this fixture's block sequence. FUN_080b1950
            // (the model-init routine) resets both LPC (6 channel slots, FUN_080bdac0 x6)
            // and LMS (FUN_080be670 + FUN_080beb60) together as a single primitive, which
            // is the natural candidate for what actually fires here; LMS reset piggybacks
            // on that same evidence (no fixture in this corpus ever has lms_enable=1 to
            // test it directly, but leaving LMS state stale while LPC resets would be an
            // odd asymmetry the real binary's bundled reset function does not exhibit).
            pf_ctx.ResetAll();
            pf_lms_ch1.Init();
            pf_lms_ch2.Init();
            std::uint64_t block_out_size = uvar9 >> 3u;
            if (block_out_size == 0u) block_out_size = 0x8000u;
            if (block_out_size > 0x8001u) { decode_ok = false; break; }
            if (total_written + block_out_size > total) { decode_ok = false; break; }
            // Exe un-transform (uvar9 bit 2). The real dispatcher
            // FUN_08097570 does, for every NON-prefilter block:
            //     if ((uVar9 & 4) != 0)
            //         FUN_080c0540(param_3, *param_4, param_3, param_1[0x4018], -1);
            //     param_1[0x4018] += *param_4;
            // i.e. the same x86 E8/E9 call/jmp address filter the -cd path
            // already runs for its own chunk flag &4 (NzCdExeUnfilter), driven
            // by a running output-position counter seeded at 4. This path never
            // applied it at all, so every E8/E9 displacement in an executable
            // was left in the encoder's absolute form -- e.g. batnball.exe kept
            // 0x00000410 where the file has 0x0000000b.
            //
            // Critically it filters the OUTPUT COPY ONLY: the window keeps the
            // unfiltered bytes, because later matches reference the unfiltered
            // window (the real code copies window -> param_3 first and filters
            // param_3 in place). Filtering the window would corrupt them.
            // The prefilter branch (uvar9 & 7) == 4 is NOT covered: it has its
            // own position-counter update in the original and never reaches
            // this branch.
            auto apply_exe_filter = [&](std::size_t out_off, std::size_t n) {
                if ((uvar9 & 4u) == 0u) return;
                nzr::cd::NzCdExeUnfilter(decoded.data() + out_off, static_cast<std::uint32_t>(n),
                                static_cast<std::uint32_t>(out_off + 4u));
            };
            if (mode_literal) {
                if (input_pos + block_out_size > stream_data_end) { decode_ok = false; break; }
                const std::size_t block_start_in_window = window_cursor;
                std::memcpy(window + block_start_in_window, bytes.data() + input_pos,
                            static_cast<std::size_t>(block_out_size));
                std::memcpy(decoded.data() + total_written, bytes.data() + input_pos,
                            static_cast<std::size_t>(block_out_size));
                window_cursor += static_cast<std::size_t>(block_out_size);
                // Backfill hash_table for the literal bytes just written
                // (legacy FUN_080b6d90 / FUN_080b6cf0, called after every
                // literal block — NOT called for LZ77 blocks, which insert
                // per-opcode inline instead). Without this, later blocks that
                // reference a hash bucket only ever touched during a literal
                // run read the table's untouched init value (3) instead of a
                // real offset, corrupting f6/f8/medium-match copies.
                // (uvar9 & 1) selects: 0 -> sparse (every 101 bytes, stopping
                // 100 bytes short of the block end), 1 -> dense (every byte).
                {
                    const std::size_t bstart = block_start_in_window;
                    const std::size_t bend = block_start_in_window + static_cast<std::size_t>(block_out_size);
                    const std::size_t step = (uvar9 & 1u) ? 1u : 101u;
                    const std::size_t hstop = (uvar9 & 1u) ? bend : (bend > 100u ? bend - 100u : bstart);
                    for (std::size_t pos = bstart; pos < hstop; pos += step) {
                        // memcpy rather than a uint32_t* cast: `pos` walks the
                        // window byte by byte, so these loads are unaligned and
                        // the cast form is UB (UBSan flags it). Same instruction
                        // on x86, defined everywhere.
                        std::uint32_t hw;
                        std::memcpy(&hw, window + pos - (is_variant_b ? 3u : 2u), 4);
                        const std::uint32_t h = is_variant_b ? (hw & 0xffffffu) : (hw & 0x1fffu);
                        hash_table[h] = static_cast<std::int32_t>(pos);
                    }
                    // Variant B additionally resets the entire byte_buffer_8k
                    // side-table to 0 after every literal block (legacy
                    // FUN_080b6c20, called unconditionally from the tail of
                    // both FUN_080b6d90/FUN_080b6cf0's variant-B branch).
                    if (is_variant_b) {
                        std::memset(byte_buffer_b.data(), 0, byte_buffer_b.size());
                    }
                }
                apply_exe_filter(total_written, static_cast<std::size_t>(block_out_size));
                input_pos += static_cast<std::size_t>(block_out_size);
                total_written += static_cast<std::size_t>(block_out_size);
                continue;
            }
            // Obtain the LZ77 opcode bytecode: either arith-decoded from a
            // [u16 count][arith] side stream, or the raw input bytes directly.
            const std::uint8_t* bc_ptr = nullptr;
            std::size_t bc_len = 0;
            std::vector<std::uint8_t> bytecode;  // owns arith-decoded bytes
            std::size_t* raw_consumed_ptr = nullptr;
            std::size_t raw_consumed = 0;
            if (mode_lz77_side) {
                if (input_pos + 2u > stream_data_end) { decode_ok = false; break; }
                const std::uint16_t side_count =
                    static_cast<std::uint16_t>(bytes[input_pos]) |
                    (static_cast<std::uint16_t>(bytes[input_pos + 1u]) << 8u);
                input_pos += 2u;
                const std::size_t arith_size = stream_data_end - input_pos;
                bytecode.assign(side_count + 16u, 0);
                const std::size_t consumed = nzr::lzpf::DecodeArithBuffer(
                    bytes.data() + input_pos, arith_size,
                    bytecode.data(), side_count, /*max_len=*/12);
                if (consumed == 0 || consumed > arith_size) { decode_ok = false; break; }
                input_pos += consumed;
                bc_ptr = bytecode.data();
                bc_len = side_count;
            } else {  // mode_lz77_raw
                bc_ptr = bytes.data() + input_pos;
                bc_len = stream_data_end - input_pos;
                raw_consumed_ptr = &raw_consumed;
            }
            const std::size_t block_start_in_window = window_cursor;
            std::int32_t last_lz_dest = -1;
            const bool dispatch_ok = is_variant_b
                ? nzr::lzpf::DecodeLz77VariantB(
                      bc_ptr, bc_len, window, window_capacity,
                      &window_cursor, static_cast<std::size_t>(block_out_size),
                      hash_table.data(), byte_buffer_b.data(), &last_lz_dest, raw_consumed_ptr)
                : nzr::lzpf::DecodeLz77VariantA(
                      bc_ptr, bc_len, window, window_capacity,
                      &window_cursor, static_cast<std::size_t>(block_out_size),
                      hash_table.data(), &last_lz_dest, raw_consumed_ptr);
            if (!dispatch_ok) { decode_ok = false; break; }
            if (mode_lz77_raw) input_pos += raw_consumed;
            if (window_cursor != block_start_in_window + block_out_size) { decode_ok = false; break; }
            std::memcpy(decoded.data() + total_written, window + block_start_in_window,
                        static_cast<std::size_t>(block_out_size));
            apply_exe_filter(total_written, static_cast<std::size_t>(block_out_size));
            total_written += static_cast<std::size_t>(block_out_size);
        }
        if (trace_lzpf) {
            if (const char* dp = std::getenv("NZOPT_DUMP_LZPF")) {
                char path[512];
                snprintf(path, sizeof(path), "%s.cap%zu", dp, window_capacity);
                if (FILE* fp = fopen(path, "wb")) {
                    fwrite(decoded.data(), 1, total_written, fp);
                    fclose(fp);
                }
            }
            fprintf(stderr, "[lzpf] cap=%zu blocks=%zu ok=%d written=%zu/%llu verify=%d\n",
                    window_capacity, blk_idx, (int)decode_ok, total_written,
                    (unsigned long long)total,
                    (decode_ok && total_written == total) ? (int)verify(decoded) : -1);
        }
        if (decode_ok && total_written == total && verify(decoded)) {
            *out = std::move(decoded);
            return true;
        }
    }
    return false;
}

// Forward declaration: defined further below (near TryDecodeLegacyOptimum,
// which it was extracted from), but also needed here by the -co parallel-
// container branch inside TryParseLegacyCnArchive. Templated on the decoder
// type since it now also serves -cO's NzOptimum2LzDecoder (single-container
// path only, in TryDecodeLegacyOptimum) -- the parallel-container branch
// below only ever instantiates it with NzOptimumLzDecoder (-co parallel
// containers only; -cO parallel containers remain out of scope).
template <typename OptimumDecoder>
static bool DecodeOptimumBlockSequence(
    const unsigned char* raw,
    std::size_t blocks_begin,
    std::size_t blocks_end,
    std::uint64_t total_size_hint,
    OptimumDecoder& dec,
    nzr::audio::NzAudioPred& audio,
    NzExeFilter& exe,
    std::vector<unsigned char>* out_data);

bool TryParseLegacyCnArchive(
    const std::string& archive_path,
    LegacyCnContext* out_context,
    std::string* out_error_message) {
    if (out_context == nullptr) {
        return false;
    }

    std::ifstream input(archive_path, std::ios::binary);
    if (!input) {
        if (out_error_message != nullptr) {
            *out_error_message = "Cannot open archive!";
        }
        return false;
    }

    std::vector<unsigned char> bytes(
        (std::istreambuf_iterator<char>(input)),
        std::istreambuf_iterator<char>());
    if (bytes.size() < 24u) {
        if (out_error_message != nullptr) {
            *out_error_message = "Data corrupted while reading headers!";
        }
        return false;
    }

    if (bytes[0] != kMagicPrefix[0] || bytes[1] != kMagicPrefix[1]) {
        if (out_error_message != nullptr) {
            *out_error_message = "File is not a NanoZip archive.";
        }
        return false;
    }
    if (std::memcmp(bytes.data() + 2, kKnownSignature, kKnownSignatureBytes) != 0) {
        if (out_error_message != nullptr) {
            *out_error_message = "File is not a NanoZip archive.";
        }
        return false;
    }

    std::size_t pos = 2u + kKnownSignatureBytes;
    if (pos + 3u > bytes.size() || bytes[pos] != 0x1fu || bytes[pos + 1u] != 0x0fu || bytes[pos + 2u] != 0x09u) {
        if (out_error_message != nullptr) {
            *out_error_message = "Legacy header prefix is not recognized.";
        }
        return false;
    }
    pos += 3u;

    // Scan chunk-tagged records to extract checksum mode, codec params, and
    // filename-table span.  NZ serialises the header as a sequence of
    // [varint (size<<4)|type] [size-byte payload] chunks.  When the initial
    // lower nibble of the varint is 15, one extra byte follows the varint to
    // encode the real type and a stream ID.
    //
    // Single-stream archives:
    //   [type-5 size-0 checksum] [type-11 size-2..4 codec] [type-1 size-N table]
    //
    // Parallel archives (-p10 etc.) have one type-5/type-11/type-1 record per
    // parallel stream.  Each per-stream type-1 table contains the PARTIAL
    // (per-stream) uncompressed size for each logical file; the true total is
    // the sum across all streams.  We scan all chunks to accumulate totals.
    ChecksumMode checksum_mode = ChecksumMode::kNone;
    bool checksum_verification_supported = true;
    unsigned char method = 0u, method_p0 = 0u, method_p1 = 0u;
    int cm_a_bits = 28, cm_b_bits = 25;
    std::uint32_t cm_window_size = 1024u * 1024u;
    std::size_t table_start = 0u, table_end = 0u;
    bool found_codec = false, found_table = false;
    // Every filename table, in record order, tagged with its stream id. A
    // multi-file archive hands its files to the compressor in blocks and emits
    // one table per block, so reading only the first loses every file after the
    // first block; a parallel container additionally puts some files ONLY in a
    // non-main stream's table.
    std::vector<std::array<std::size_t, 3>> all_tables;  // {stream, begin, end}
    // Per-file attribute records ({stream, type, begin, end}), in record order.
    std::vector<std::array<std::size_t, 4>> attr_records;
    // Start of the first main-stream type-0 record == end of the leading
    // metadata run (the offset the single-file path uses as payload_start).
    std::size_t first_data_record = 0u;
    bool found_first_data = false;
    // Every main-stream data record, as [record_begin, record_end). In a
    // multi-block archive the next block's table/mtime/perm/checksum records sit
    // BETWEEN two data records, so the payload is not one contiguous run.
    std::vector<std::pair<std::size_t, std::size_t>> data_records;
    // Any record belonging to a non-zero stream => parallel (-pN) container,
    // which has its own framing and must not be spliced.
    bool has_parallel_streams = false;
    // Accumulated file sizes across all per-stream type-1 tables.
    std::map<std::string, std::uint64_t> size_accum;
    // Which streams' tables mention each path; more than one means the file is
    // split across parallel streams and has no whole-file checksum.
    std::map<std::string, std::set<unsigned>> path_streams;

    for (int guard = 0; guard < 1024 && pos < bytes.size(); ++guard) {
        const std::size_t record_begin = pos;
        std::uint64_t r64 = 0u;
        if (!ReadLegacyVarint(bytes, &pos, bytes.size(), &r64)) break;
        auto r = static_cast<std::uint32_t>(r64);
        unsigned ctype   = r & 0x0fu;
        unsigned cstream = 0u;
        std::size_t csize = static_cast<std::size_t>(r >> 4u);

        if (ctype == 15u) {
            if (pos >= bytes.size()) break;
            unsigned ext = static_cast<unsigned>(bytes[pos++]);
            if (ext >= 0xf8u) {
                if (pos >= bytes.size()) break;
                ext = (ext & 7u) + 8u * static_cast<unsigned>(bytes[pos++]) + 248u;
            }
            ctype   = ext & 0x0fu;
            cstream = ext >> 4u;
            if (cstream == 0u) ctype += 15u;
        }

        if (pos + csize > bytes.size()) break;
        const bool is_main = (cstream == 0u);

        // Checksum indicator: zero-payload main-stream chunk.
        // Direct (single-stream): type 5/6/7.
        // Extended (multi-stream): type 20/21/22 = 15+5/6/7 with stream=0.
        if (is_main && csize == 0u) {
            if      (ctype == 5u || ctype == 20u) checksum_mode = ChecksumMode::kFletcher32;
            else if (ctype == 6u || ctype == 21u) checksum_mode = ChecksumMode::kCrc16;
            else if (ctype == 7u || ctype == 22u) checksum_mode = ChecksumMode::kCrc32;
        }

        // Per-file attribute records, and the first main-stream data record.
        if (found_codec) {
            if (csize > 0u && (ctype == 2u || ctype == 4u || ctype == 5u ||
                               ctype == 6u || ctype == 7u)) {
                attr_records.push_back({static_cast<std::size_t>(cstream),
                                        static_cast<std::size_t>(ctype), pos, pos + csize});
            } else if (ctype == 0u && is_main) {
                if (!found_first_data) {
                    first_data_record = record_begin;
                    found_first_data = true;
                }
                data_records.push_back({record_begin, pos + csize});
            }
        }
        if (!is_main) {
            has_parallel_streams = true;
        }

        // Codec params: type 11, main stream.  Payload: [p0] [p1] [extras...].
        // method byte = (csize<<4)|11 = 0x2b (lzpf/lzhd), 0x3b (optimum), 0x4b (cm).
        if (!found_codec && ctype == 11u && is_main && csize >= 1u) {
            method    = static_cast<unsigned char>((csize << 4u) | 11u);
            method_p0 = bytes[pos];
            method_p1 = (csize >= 2u) ? bytes[pos + 1u] : 0u;
            // CM (p0=7, size>=4): payload[2]=B (unused), payload[3]=CD.
            if (method == 0x4bu && method_p0 == 7u && csize >= 4u) {
                const unsigned char cd_byte = bytes[pos + 3u];
                cm_a_bits = static_cast<int>((cd_byte >> 4u) + 20u);
                cm_b_bits = static_cast<int>((cd_byte & 0x0fu) + 18u);
                const unsigned xp1 = static_cast<unsigned>(method_p1) + 1u;
                unsigned m = xp1 & 0x0fu;
                const unsigned s = xp1 >> 4u;
                if (s) m = (m + 16u) << (s - 1u);
                cm_window_size = m << 16u;
            }
            pos += csize;
            found_codec = true;
        }
        // Filename table: type 1 (any stream).  Accumulate per-filename sizes.
        // For the main-stream chunk, also record table_start/table_end.
        // Do NOT break early — parallel archives have type-1 chunks from every stream.
        else if (ctype == 1u && csize >= 2u) {
            // Accumulate sizes from this stream's table.
            std::size_t tp = pos, tend = pos + csize;
            while (tp < tend) {
                std::uint64_t fsize = 0u;
                if (!ReadLegacyVarint(bytes, &tp, tend, &fsize)) break;
                const auto nul_it = std::find(
                    bytes.begin() + static_cast<std::ptrdiff_t>(tp),
                    bytes.begin() + static_cast<std::ptrdiff_t>(tend),
                    static_cast<unsigned char>(0));
                if (nul_it == bytes.begin() + static_cast<std::ptrdiff_t>(tend)) break;
                std::string fname(
                    bytes.begin() + static_cast<std::ptrdiff_t>(tp), nul_it);
                size_accum[fname] += fsize;
                path_streams[fname].insert(cstream);
                tp = static_cast<std::size_t>(
                    std::distance(bytes.begin(), nul_it)) + 1u;
            }
            // Record the first main-stream type-1 chunk as the canonical table,
            // and keep every one of them for the entry build.
            if (found_codec) {
                if (is_main && !found_table) {
                    table_start = pos;
                    table_end   = pos + csize;
                    found_table = true;
                }
                all_tables.push_back({static_cast<std::size_t>(cstream), pos, pos + csize});
            }
            pos += csize;
        }
        else {
            pos += csize;
        }
    }

    if (!found_codec || !found_table) {
        if (out_error_message != nullptr) {
            *out_error_message =
                found_codec ? "Legacy filename table encoding is not recognized."
                            : "Legacy stream family is not recognized.";
        }
        return false;
    }

    if (method != 0x2bu && method != 0x3bu && method != 0x4bu) {
        if (out_error_message != nullptr) {
            *out_error_message = "Legacy stream family is not recognized.";
        }
        return false;
    }
    const bool native_store_payload = (method_p0 == 0u);

    if (table_end > bytes.size()) {
        if (out_error_message != nullptr) {
            *out_error_message = "Data corrupted while reading headers!";
        }
        return false;
    }

    std::vector<LegacyCnEntry> entries;
    std::uint64_t total_data_size = 0;
    // Walk every main-stream filename table, in order. A single-block archive
    // has exactly one; a multi-block one has a table per block and its later
    // files live only in the later tables. A parallel (-pN) container repeats a
    // filename across streams, so a path already seen is skipped rather than
    // duplicated -- its true size is restored from size_accum below.
    std::map<std::string, std::size_t> path_index;
    // Per stream, the entry indices its own tables name, in order: that stream's
    // attribute records cover exactly those, in exactly that order.
    std::map<unsigned, std::vector<std::size_t>> stream_named;
    for (const auto& table_span : all_tables) {
    const unsigned table_stream = static_cast<unsigned>(table_span[0]);
    std::size_t p = table_span[1];
    const std::size_t table_end = table_span[2];
    while (p < table_end) {
        std::uint64_t file_size = 0;
        if (!ReadLegacyVarint(bytes, &p, table_end, &file_size)) {
            if (out_error_message != nullptr) {
                *out_error_message = "Data corrupted while reading headers!";
            }
            return false;
        }

        const auto nul_it = std::find(bytes.begin() + static_cast<std::ptrdiff_t>(p),
                                      bytes.begin() + static_cast<std::ptrdiff_t>(table_end),
                                      static_cast<unsigned char>(0));
        if (nul_it == bytes.begin() + static_cast<std::ptrdiff_t>(table_end)) {
            if (out_error_message != nullptr) {
                *out_error_message = "Data corrupted while reading headers!";
            }
            return false;
        }

        const std::size_t name_end = static_cast<std::size_t>(std::distance(bytes.begin(), nul_it));
        LegacyCnEntry e;
        e.path.assign(reinterpret_cast<const char*>(bytes.data() + p), name_end - p);
        e.size = file_size;

        p = name_end + 1u;
        if (file_size > (std::numeric_limits<std::uint64_t>::max() - total_data_size)) {
            if (out_error_message != nullptr) {
                *out_error_message = "Data corrupted while reading headers!";
            }
            return false;
        }
        {
            const auto known = path_index.find(e.path);
            if (known != path_index.end()) {
                // Same file, another stream's slice (or another block's table).
                stream_named[table_stream].push_back(known->second);
                continue;
            }
        }
        path_index.emplace(e.path, entries.size());
        stream_named[table_stream].push_back(entries.size());
        total_data_size += file_size;
        if (native_store_payload && total_data_size > bytes.size()) {
            if (out_error_message != nullptr) {
                *out_error_message = "Data corrupted while reading headers!";
            }
            return false;
        }
        entries.push_back(std::move(e));
    }

    if (p != table_end) {
        if (out_error_message != nullptr) {
            *out_error_message = "Data corrupted while reading headers!";
        }
        return false;
    }
    }  // for each filename table

    if (entries.empty()) {
        if (out_error_message != nullptr) {
            *out_error_message = "Data corrupted while reading headers!";
        }
        return false;
    }

    // Parallel archives (-pN): each stream emits its own type-1 table with the
    // PARTIAL uncompressed size for that stream's portion of each file.  The
    // size_accum map holds the sum across all streams for each filename.
    // Override per-entry sizes from the main-stream table with the totals.
    if (!size_accum.empty()) {
        for (auto& e : entries) {
            auto it = size_accum.find(e.path);
            if (it != size_accum.end() && it->second != e.size) {
                total_data_size -= e.size;
                e.size = it->second;
                total_data_size += e.size;
            }
        }
    }

    // Multi-block compressed archives write one filename table per block.
    // Scan forward past the first table for additional table_span+table pairs.
    //
    // The probe walks raw bytes looking for a [table_span][filename_table]
    // shape. Compressed payload bytes are statistically noisy and can spoof
    // that shape. We require scanner-added entry paths to be pure ASCII
    // printable (0x20-0x7E) AND either contain a '/' separator OR be at
    // least 6 characters with an extension dot. This rejects short random
    // ASCII bursts that frequently appear inside compressed streams while
    // still accepting real archive paths (which always include the source
    // directory prefix in legacy `a` invocations).
    auto path_looks_like_real_legacy_entry = [](const std::string& s) {
        if (s.empty() || s.size() > 1024u) {
            return false;
        }
        // Legacy `nz a` strips leading '/' from inputs, so absolute paths
        // never appear in real archives. Reject them outright — they are a
        // common shape for random-byte spoofs that happen to start with '/'.
        if (s.front() == '/') {
            return false;
        }
        // First byte must be alphanumeric, '.', '_', or '-' — anything else
        // (punctuation, symbols) is overwhelmingly a spoof in random bytes.
        const unsigned char first = static_cast<unsigned char>(s.front());
        const bool first_ok =
            (first >= '0' && first <= '9') ||
            (first >= 'A' && first <= 'Z') ||
            (first >= 'a' && first <= 'z') ||
            first == '.' || first == '_' || first == '-';
        if (!first_ok) {
            return false;
        }
        bool has_slash = false;
        bool has_dot = false;
        for (unsigned char c : s) {
            if (c < 0x20u || c > 0x7eu) {
                return false;
            }
            if (c == '/') {
                has_slash = true;
            } else if (c == '.') {
                has_dot = true;
            }
        }
        if (has_slash) {
            return true;
        }
        // No slash: require length >= 6 AND a dot (typical "name.ext" shape).
        return s.size() >= 6u && has_dot;
    };
    bool multiblock_scanner_added_entries = false;
    // Skip the heuristic multi-block table scanner for parallel (-pN) archives:
    // size_accum already gives the true per-file size by summing every
    // stream's own type-1 table (see above), so total_data_size is already
    // correct here. The scanner's [table_span][filename_table] shape probe is
    // explicitly documented as spoofable by noisy compressed bytes (see
    // comment above `path_looks_like_real_legacy_entry`); running it anyway
    // on a parallel container's many per-stream compressed chunks measurably
    // produces false-positive phantom entries that corrupt total_data_size
    // (observed: a 9 MB tar under -cf falsely gained a phantom 114-byte entry).
    if (!native_store_payload && size_accum.empty()) {
        std::size_t scan_pos = table_end;
        while (scan_pos < bytes.size()) {
            bool found_additional = false;
            for (std::size_t probe = scan_pos; probe + 1u < bytes.size(); ++probe) {
                const unsigned char bp = bytes[probe];
                if ((bp & 0x0fu) != 0x01u) {
                    continue;
                }
                std::size_t tp = probe;
                std::uint64_t tspan = 0;
                if (!ReadLegacyTableSpan(bytes, &tp, &tspan)) {
                    continue;
                }
                const std::uint64_t tlen = tspan + 2u;
                if (tlen < 4u || tlen > static_cast<std::uint64_t>(bytes.size() - tp)) {
                    continue;
                }
                const std::size_t tend = tp + static_cast<std::size_t>(tlen);
                if (!LooksLikeLegacyFilenameTable(bytes, tp, tend)) {
                    continue;
                }
                // Validate each entry: file_size must be non-zero.
                // We are inside the !native_store_payload branch, so sizes are
                // decompressed lengths and may exceed the compressed archive size.
                std::size_t vp = tp;
                std::vector<LegacyCnEntry> add_entries;
                bool valid = true;
                while (vp < tend) {
                    std::uint64_t fs = 0;
                    if (!ReadLegacyVarint(bytes, &vp, tend, &fs) || fs == 0u) {
                        valid = false;
                        break;
                    }
                    const auto nul_it = std::find(
                        bytes.begin() + static_cast<std::ptrdiff_t>(vp),
                        bytes.begin() + static_cast<std::ptrdiff_t>(tend),
                        static_cast<unsigned char>(0));
                    if (nul_it == bytes.begin() + static_cast<std::ptrdiff_t>(tend)) {
                        valid = false;
                        break;
                    }
                    const std::size_t ne = static_cast<std::size_t>(
                        std::distance(bytes.begin(), nul_it));
                    LegacyCnEntry ae;
                    ae.path.assign(reinterpret_cast<const char*>(bytes.data() + vp), ne - vp);
                    ae.size = fs;
                    if (!path_looks_like_real_legacy_entry(ae.path)) {
                        valid = false;
                        break;
                    }
                    if (fs > (std::numeric_limits<std::uint64_t>::max() - total_data_size)) {
                        valid = false;
                        break;
                    }
                    add_entries.push_back(std::move(ae));
                    vp = ne + 1u;
                }
                if (!valid || vp != tend || add_entries.empty()) {
                    continue;
                }
                for (LegacyCnEntry& ae : add_entries) {
                    total_data_size += ae.size;
                    entries.push_back(std::move(ae));
                }
                multiblock_scanner_added_entries = true;
                scan_pos = tend;
                found_additional = true;
                break;
            }
            if (!found_additional) {
                break;
            }
        }
    }

    std::uint64_t data_offset_u64 = 0;
    std::size_t metadata_begin = table_end;
    std::size_t metadata_end = bytes.size();
    std::size_t payload_start = bytes.size();

    // Preferred path: walk the metadata run as the record sequence it actually
    // is (see ParseLegacyMetadataRun). This is the only path that reads
    // per-entry checksums for MULTI-file archives -- without them the per-entry
    // verification in RunLegacyCnExtractOrTest is skipped, which used to let a
    // wrong decode be written out silently. When the walk does not fully
    // understand the run we fall through to the older per-shape heuristics.
    std::set<std::string> split_paths;
    for (const auto& kv : path_streams) {
        if (kv.second.size() > 1u) split_paths.insert(kv.first);
    }
    const bool metadata_run_parsed =
        ApplyLegacyAttributeRecords(bytes, attr_records, stream_named, split_paths, &entries);
    const std::size_t run_metadata_end = first_data_record;

    // For stored payloads (-cn) that split across several blocks, the raw file
    // bytes are not a contiguous tail of the archive, so we assemble them here.
    bool store_multiblock = false;
    std::vector<unsigned char> store_blocks_buffer;

    if (native_store_payload) {
        data_offset_u64 = static_cast<std::uint64_t>(bytes.size()) - total_data_size;
        if (data_offset_u64 < table_end) {
            if (out_error_message != nullptr) {
                *out_error_message = "Data corrupted while reading headers!";
            }
            return false;
        }
        const std::size_t data_offset = static_cast<std::size_t>(data_offset_u64);

        // Find stream-prefix varint immediately before payload.
        const std::uint64_t expected_stream_len_tag = total_data_size << 4u;
        std::size_t prefix_start = data_offset;
        bool prefix_found = false;
        const std::size_t scan_begin = (data_offset > 16u) ? (data_offset - 16u) : table_end;
        for (std::size_t s = scan_begin; s < data_offset; ++s) {
            std::size_t q = s;
            std::uint64_t tag = 0;
            if (!ReadLegacyVarint(bytes, &q, data_offset, &tag)) {
                continue;
            }
            if (q == data_offset && tag == expected_stream_len_tag) {
                prefix_start = s;
                prefix_found = true;
                break;
            }
        }
        if (!prefix_found && entries.size() == 1u &&  // see the offset note below
            TryAssembleParallelStore(bytes, total_data_size, &store_blocks_buffer)) {
            // Parallel (-pN) store: the slices are raw and scattered between the
            // per-stream record sets, so neither the tail scan nor the block
            // chain finds them. Every slice was checksum-verified.
            store_multiblock = true;
            metadata_end = table_end;
            payload_start = table_end;
            prefix_found = true;
        }
        if (!prefix_found) {
            // Multi-block store: walk [varint len<<4|0][raw][checksum trailer]
            // from the first block prefix (just past the per-file metadata) and
            // assemble the raw payload. The trailer width follows checksum_mode
            // (one tag byte + checksum bytes; none when checksums are disabled).
            const std::size_t store_checksum_bytes =
                (checksum_mode == ChecksumMode::kCrc16) ? 2u :
                (checksum_mode == ChecksumMode::kNone) ? 0u : 4u;
            const std::size_t store_trailer_bytes =
                (checksum_mode == ChecksumMode::kNone) ? 0u : (1u + store_checksum_bytes);
            for (std::size_t s = table_end; s <= data_offset; ++s) {
                if (TryAssembleStoredBlocks(bytes, s, total_data_size,
                                            store_trailer_bytes, &store_blocks_buffer)) {
                    store_multiblock = true;
                    metadata_end = s;
                    payload_start = s;
                    break;
                }
            }
            if (!store_multiblock) {
                if (out_error_message != nullptr) {
                    *out_error_message = "Legacy stream prefix is not recognized.";
                }
                return false;
            }
        } else {
            metadata_end = prefix_start;
            payload_start = data_offset;
        }
        if (!store_multiblock) {

        // Parse checksums from the end of metadata.  Only needed when the
        // record walk above did not already provide them.
        const std::size_t checksum_bytes_per_file = metadata_run_parsed ? 0u :
            (checksum_mode == ChecksumMode::kCrc16) ? 2u :
            (checksum_mode == ChecksumMode::kNone) ? 0u : 4u;

        if (checksum_bytes_per_file > 0u) {
            const std::size_t checksum_data_bytes = entries.size() * checksum_bytes_per_file;
            if (metadata_end >= metadata_begin + checksum_data_bytes) {
                std::size_t checksum_data_start = metadata_end - checksum_data_bytes;
                bool has_tag = false;
                if (entries.size() == 1u && checksum_data_start > metadata_begin) {
                    const std::uint8_t expected_tag = LegacyChecksumTag(checksum_mode);
                    if (bytes[checksum_data_start - 1u] == expected_tag) {
                        checksum_data_start -= 1u;
                        has_tag = true;
                    }
                }

                std::size_t cp = checksum_data_start + (has_tag ? 1u : 0u);
                if (cp + checksum_data_bytes <= metadata_end) {
                    for (std::size_t i = 0; i < entries.size(); ++i) {
                        std::uint32_t v = 0;
                        if (checksum_bytes_per_file == 2u) {
                            v = static_cast<std::uint32_t>(bytes[cp]) |
                                (static_cast<std::uint32_t>(bytes[cp + 1u]) << 8u);
                        } else {
                            v = ReadU32LE(bytes.data() + cp);
                        }
                        entries[i].checksum = v;
                        entries[i].has_checksum = true;
                        cp += checksum_bytes_per_file;
                    }
                    metadata_end = checksum_data_start;
                }
            }
        }
        }  // if (!store_multiblock)
    }

    // Dumps the front metadata run, which is where the entry tags (mtime 0x42,
    // permissions 0x24, checksum 0x45/0x47/0x26) are expected to sit contiguously.
    if (getenv("NZOPT_TRACE_META")) {
        fprintf(stderr, "[META] entries=%zu metadata=[%zu,%zu) cksum_mode=%d bytes=",
                entries.size(), metadata_begin, metadata_end, (int)checksum_mode);
        for (std::size_t k = metadata_begin; k < metadata_end && k < metadata_begin + 32u; ++k)
            fprintf(stderr, "%02x ", bytes[k]);
        fprintf(stderr, "\n");
    }
    // Best-effort metadata extraction (single-file path is the most reliable).
    if (metadata_run_parsed) {
        // Attributes already filled from the record run. For single-file
        // compressed families the old path also derived payload_start from the
        // end of the metadata records; run_metadata_end is that same offset
        // (the type-0 record header), just located by parsing instead of by
        // tag sniffing.
        if (!native_store_payload && found_first_data) {
            payload_start = run_metadata_end;
        }
    } else if (entries.size() == 1u && metadata_end > metadata_begin) {
        std::size_t mp = metadata_begin;
        if (metadata_end >= mp + 5u && bytes[mp] == 0x42u) {
            entries[0].mtime_unix = static_cast<std::int64_t>(ReadU32LE(bytes.data() + mp + 1u));
            entries[0].has_mtime = true;
            mp += 5u;
        }
        if (metadata_end >= mp + 3u && bytes[mp] == 0x24u) {
            if (bytes[mp + 1u] == 0xb4u && bytes[mp + 2u] == 0x01u) {
                entries[0].permissions = 0664u;
            } else {
                entries[0].permissions = 0644u;
            }
            entries[0].has_permissions = true;
            mp += 3u;
        }
        if (!entries[0].has_checksum && checksum_mode != ChecksumMode::kNone && metadata_end > mp) {
            const std::uint8_t tag = bytes[mp];
            if ((tag == 0x45u || tag == 0x47u) && metadata_end >= mp + 5u) {
                entries[0].checksum = ReadU32LE(bytes.data() + mp + 1u);
                entries[0].has_checksum = true;
                mp += 5u;
            } else if (tag == 0x26u && metadata_end >= mp + 3u) {
                entries[0].checksum = static_cast<std::uint32_t>(bytes[mp + 1u]) |
                                      (static_cast<std::uint32_t>(bytes[mp + 2u]) << 8u);
                entries[0].has_checksum = true;
                mp += 3u;
            }
        }
        if (!native_store_payload) {
            payload_start = mp;
        }
    } else if (metadata_end > metadata_begin) {
        // Multi-file legacy metadata is still partially unknown; expose conservative defaults.
        const bool has_timestamp_tag = ((bytes[metadata_begin] & 0x0fu) == 0x02u);
        const bool has_perm_tag = std::find(bytes.begin() + static_cast<std::ptrdiff_t>(metadata_begin),
                                            bytes.begin() + static_cast<std::ptrdiff_t>(metadata_end),
                                            static_cast<unsigned char>(0x24u)) !=
                                  bytes.begin() + static_cast<std::ptrdiff_t>(metadata_end);
        for (LegacyCnEntry& e : entries) {
            if (has_perm_tag) {
                e.permissions = 0664u;
                e.has_permissions = true;
            }
            if (has_timestamp_tag && metadata_begin + 5u <= metadata_end) {
                e.mtime_unix = static_cast<std::int64_t>(ReadU32LE(bytes.data() + metadata_begin + 1u));
                e.has_mtime = true;
            }
        }
    }

    if (!native_store_payload && payload_start == bytes.size() && metadata_begin < bytes.size()) {
        // For compressed legacy families, locate the first [stream_tag][...]
        // varint that follows the per-file metadata trailer.
        //
        // Limit the search window: the stream prefix sits immediately after
        // the per-file metadata trailer, which is at most a few dozen bytes
        // (timestamps, perms, optional checksums for N entries). Without
        // this cap, random compressed bytes deep in the payload sometimes
        // decode as a stream-length tag matching EOF, putting payload_start
        // past the real start and making the checksum-trailer reader pull
        // garbage.
        //
        // Single-block (single-file) archives have stream_bytes == EOF
        // distance, so we prefer that match. Multi-block archives chain
        // multiple sub-streams, so the first block's prefix won't match
        // EOF — fall back to the first plausible stream-tag varint.
        const std::size_t kMaxMetadataTrailerBytes = 256u;
        const std::size_t search_end =
            std::min(bytes.size(), metadata_begin + kMaxMetadataTrailerBytes);
        std::size_t fallback_start = bytes.size();
        for (std::size_t s = metadata_begin; s < search_end; ++s) {
            std::size_t q = s;
            std::uint64_t tag = 0;
            if (!ReadLegacyVarint(bytes, &q, bytes.size(), &tag)) {
                continue;
            }
            if ((tag & 0x0fu) != 0u) {
                continue;
            }
            const std::uint64_t stream_bytes = tag >> 4u;
            if (stream_bytes == 0u ||
                stream_bytes > static_cast<std::uint64_t>(bytes.size() - q)) {
                continue;
            }
            if (q + static_cast<std::size_t>(stream_bytes) == bytes.size()) {
                payload_start = s;
                fallback_start = bytes.size();
                break;
            }
            if (fallback_start == bytes.size()) {
                fallback_start = s;
            }
        }
        if (payload_start == bytes.size() && fallback_start != bytes.size()) {
            payload_start = fallback_start;
        }
    }

    // Multi-file archives — including ones that fit in a single filename
    // table — scatter per-block checksums between compressed sub-streams.
    // The "contiguous trailer of N*4 bytes before payload_start" heuristic
    // reads neighboring metadata or compressed bytes as if they were
    // checksums and rejects correctly extracted data on mismatch. Better
    // to show 00000000 than to falsely fail extraction.
    //
    // ParseLegacyMetadataRun does not guess: it only reports success when the
    // whole record run parsed and the checksum record covered exactly one
    // value per entry. When it did, the values are the real ones and the
    // per-entry verification must run — that verification is what stops a
    // wrong multi-file decode from being written out silently.
    if (!metadata_run_parsed && (multiblock_scanner_added_entries || entries.size() > 1u)) {
        checksum_verification_supported = false;
    }
    // Skip this fallback for single-file archives — the tagged scan above
    // (0x45/0x47/0x26) is authoritative there. The unguarded "trailer at
    // payload_start" read picks up perm/mtime bytes as a fake checksum on
    // methods like cc/co that don't emit one.
    // Also skip for multi-file (handled by has_checksum=false above).
    if (false &&
        !native_store_payload &&
        !multiblock_scanner_added_entries &&
        entries.size() > 1u &&
        checksum_mode != ChecksumMode::kNone &&
        payload_start < bytes.size() &&
        payload_start > metadata_begin) {
        const std::size_t checksum_bytes_per_file = LegacyChecksumBytesPerFile(checksum_mode);
        if (checksum_bytes_per_file > 0u) {
            const std::size_t checksum_data_bytes = entries.size() * checksum_bytes_per_file;
            if (payload_start >= metadata_begin + checksum_data_bytes) {
                std::size_t checksum_data_start = payload_start - checksum_data_bytes;
                bool has_tag = false;
                if (entries.size() == 1u && checksum_data_start > metadata_begin) {
                    const std::uint8_t expected_tag = LegacyChecksumTag(checksum_mode);
                    if (bytes[checksum_data_start - 1u] == expected_tag) {
                        checksum_data_start -= 1u;
                        has_tag = true;
                    }
                }

                std::size_t cp = checksum_data_start + (has_tag ? 1u : 0u);
                if (cp + checksum_data_bytes <= payload_start) {
                    std::vector<std::uint32_t> candidate_values;
                    candidate_values.reserve(entries.size());
                    bool plausible = true;
                    std::size_t scan_cp = cp;
                    for (std::size_t i = 0; i < entries.size(); ++i) {
                        std::uint32_t v = 0;
                        if (checksum_bytes_per_file == 2u) {
                            v = static_cast<std::uint32_t>(bytes[scan_cp]) |
                                (static_cast<std::uint32_t>(bytes[scan_cp + 1u]) << 8u);
                        } else {
                            v = ReadU32LE(bytes.data() + scan_cp);
                        }
                        // Fletcher32 never finalizes with either half at zero
                        // (both s1 and s2 are clamped to 0xffff before packing).
                        if (checksum_mode == ChecksumMode::kFletcher32 &&
                            ((v & 0xffff0000u) == 0u || (v & 0x0000ffffu) == 0u)) {
                            plausible = false;
                            break;
                        }
                        candidate_values.push_back(v);
                        scan_cp += checksum_bytes_per_file;
                    }
                    if (plausible) {
                        for (std::size_t i = 0; i < entries.size(); ++i) {
                            entries[i].checksum = candidate_values[i];
                            entries[i].has_checksum = true;
                        }
                    }
                }
            }
        }
    }

    bool native_literal_payload = false;
    std::size_t literal_data_offset = 0;
    std::size_t literal_data_size = 0;
    bool literal_data_owned = false;
    std::vector<unsigned char> literal_data_buffer;
    const auto validate_literal_candidate = [&](std::size_t offset) -> bool {
        if (offset > bytes.size()) {
            return false;
        }
        if (total_data_size > static_cast<std::uint64_t>(bytes.size() - offset)) {
            return false;
        }
        std::size_t cursor = offset;
        for (const LegacyCnEntry& e : entries) {
            if (e.size > static_cast<std::uint64_t>(bytes.size() - cursor)) {
                return false;
            }
            cursor += static_cast<std::size_t>(e.size);
        }
        return cursor == offset + static_cast<std::size_t>(total_data_size);
    };
    const auto validate_literal_candidate_with_checksums = [&](std::size_t offset) -> bool {
        if (!validate_literal_candidate(offset)) {
            return false;
        }
        if (!checksum_verification_supported) {
            return true;
        }

        std::size_t cursor = offset;
        for (const LegacyCnEntry& e : entries) {
            if (e.size > static_cast<std::uint64_t>(bytes.size() - cursor)) {
                return false;
            }

            const std::size_t n = static_cast<std::size_t>(e.size);
            if (e.has_checksum) {
                const std::uint32_t got = ComputeBufferChecksum(checksum_mode, bytes.data() + cursor, n);
                if (got != e.checksum) {
                    return false;
                }
            }
            cursor += n;
        }

        return true;
    };
    const auto validate_decoded_candidate = [&](const std::vector<unsigned char>& candidate) -> bool {
        if (candidate.size() != static_cast<std::size_t>(total_data_size))
            return false;
        std::size_t cursor = 0;
        for (const LegacyCnEntry& e : entries) {
            if (e.size > static_cast<std::uint64_t>(candidate.size() - cursor))
                return false;
            const std::size_t n = static_cast<std::size_t>(e.size);
            if (e.has_checksum && checksum_verification_supported) {
                const std::uint32_t got = ComputeBufferChecksum(checksum_mode, candidate.data() + cursor, n);
                if (got != e.checksum)
                    return false;
            }
            cursor += n;
        }
        return cursor == candidate.size();
    };

    // A multi-block archive interleaves the next block's table/mtime/perm/
    // checksum records BETWEEN its data records, so the raw tail is not a valid
    // stream chain -- a chain walker reaching the end of one member lands on a
    // filename table. Splice the main-stream data records back together once,
    // for both the chain decoders and ctx.data. Left empty when the records are
    // already adjacent (every single-block archive and every contiguous chain)
    // and for parallel containers, which have their own framing.
    std::vector<unsigned char> spliced_data;
    {
        bool data_contiguous = true;
        for (std::size_t i = 1; i < data_records.size(); ++i) {
            if (data_records[i].first != data_records[i - 1u].second) {
                data_contiguous = false;
                break;
            }
        }
        if (!data_contiguous && !has_parallel_streams) {
            for (const auto& dr : data_records) {
                spliced_data.insert(spliced_data.end(),
                                    bytes.begin() + static_cast<std::ptrdiff_t>(dr.first),
                                    bytes.begin() + static_cast<std::ptrdiff_t>(dr.second));
            }
        }
    }

    if (!native_store_payload && !entries.empty() && payload_start <= bytes.size()) {
                // Parallel multi-stream container (header flag byte 0x0f, used by
                // the multi-threaded encoder for inputs >~8 MB). The output is cut
                // into N independent nz_lzpf streams; each is serialised as a group
                // of chunk records keyed by a stream id:
                //   type-1  = slice output size      (varint, first field)
                //   type-10 = slice output offset    (u32 LE, first 4 of 8 bytes)
                //   type-5/7/6 = slice checksum       (Fletcher32 / crc32 / crc16)
                //   type-0  = the compressed lzpf stream (block headers, no tag)
                // We decode each type-0 stream into its slice (verifying it against
                // the slice checksum, which also selects the dict capacity), place
                // it at its offset, and require the slices to tile the whole output
                // exactly. Every byte is checksum-verified, so a wrong decode is
                // rejected rather than emitted.
                if (!native_literal_payload &&
                    method == 0x2bu &&
                    (method_p0 == 1u || method_p0 == 2u)) {
                    std::size_t magic = bytes.size();
                    for (std::size_t q = 0; q + 4u <= bytes.size(); ++q) {
                        if (bytes[q] == 0x1fu && bytes[q + 1u] == 0x0fu && bytes[q + 2u] == 0x09u) {
                            magic = q; break;
                        }
                    }
                    // A parallel container's type-10 offset is the slice's
                    // offset WITHIN ITS FILE, not within the output: in a
                    // two-file archive both files have a slice at offset 0, and
                    // one stream can carry slices of two different files. These
                    // paths tile straight into the whole output, which is only
                    // the same thing when the archive holds ONE file. Tiling a
                    // multi-file one would overlap the files, and the per-entry
                    // check cannot catch it -- a file split across streams has
                    // no whole-file checksum to verify against. So decline.
                    if (magic != bytes.size() && bytes[magic + 3u] == 0x0fu &&
                        entries.size() == 1u) {
                        const bool is_variant_b = (method_p0 == 2u);
                        struct PStream {
                            // A stream's compressed payload may be split across
                            // several type-0 chunks (one per ~1 MB output sub-
                            // stream); they form one logical lzpf stream and are
                            // concatenated before decode.
                            std::vector<std::pair<std::size_t, std::size_t>> chunks;
                            std::uint64_t osz = 0, ooff = 0;
                            ChecksumMode cmode = ChecksumMode::kNone;
                            std::uint32_t cval = 0;
                            bool hasoff = false, hassz = false;
                        };
                        std::map<unsigned, PStream> ps;
                        std::size_t p = magic + 3u;
                        bool parse_ok = true;
                        for (int guard = 0; guard < 8192 && p < bytes.size(); ++guard) {
                            std::uint64_t r = 0;
                            if (!ReadLegacyVarint(bytes, &p, bytes.size(), &r)) { parse_ok = false; break; }
                            unsigned ct = static_cast<unsigned>(r) & 0x0fu;
                            unsigned sid = 0u;
                            std::size_t csz = static_cast<std::size_t>(r >> 4u);
                            if (ct == 15u) {
                                if (p >= bytes.size()) { parse_ok = false; break; }
                                unsigned ext = bytes[p++];
                                if (ext >= 0xf8u) {
                                    if (p >= bytes.size()) { parse_ok = false; break; }
                                    ext = (ext & 7u) + 8u * static_cast<unsigned>(bytes[p++]) + 248u;
                                }
                                ct = ext & 0x0fu;
                                sid = ext >> 4u;
                                if (sid == 0u) ct += 15u;
                            }
                            if (p + csz > bytes.size()) { parse_ok = false; break; }
                            PStream& s = ps[sid];
                            if (ct == 1u && csz >= 2u) {
                                std::size_t tp = p; std::uint64_t v = 0;
                                if (ReadLegacyVarint(bytes, &tp, p + csz, &v)) { s.osz = v; s.hassz = true; }
                            } else if (ct == 10u && csz >= 4u) {
                                s.ooff = static_cast<std::uint32_t>(bytes[p]) |
                                         (static_cast<std::uint32_t>(bytes[p + 1u]) << 8u) |
                                         (static_cast<std::uint32_t>(bytes[p + 2u]) << 16u) |
                                         (static_cast<std::uint32_t>(bytes[p + 3u]) << 24u);
                                s.hasoff = true;
                            } else if (ct == 5u && csz == 4u) {
                                s.cmode = ChecksumMode::kFletcher32;
                                s.cval = static_cast<std::uint32_t>(bytes[p]) |
                                         (static_cast<std::uint32_t>(bytes[p + 1u]) << 8u) |
                                         (static_cast<std::uint32_t>(bytes[p + 2u]) << 16u) |
                                         (static_cast<std::uint32_t>(bytes[p + 3u]) << 24u);
                            } else if (ct == 7u && csz == 4u) {
                                s.cmode = ChecksumMode::kCrc32;
                                s.cval = static_cast<std::uint32_t>(bytes[p]) |
                                         (static_cast<std::uint32_t>(bytes[p + 1u]) << 8u) |
                                         (static_cast<std::uint32_t>(bytes[p + 2u]) << 16u) |
                                         (static_cast<std::uint32_t>(bytes[p + 3u]) << 24u);
                            } else if (ct == 6u && csz == 2u) {
                                s.cmode = ChecksumMode::kCrc16;
                                s.cval = static_cast<std::uint32_t>(bytes[p]) |
                                         (static_cast<std::uint32_t>(bytes[p + 1u]) << 8u);
                            } else if (ct == 0u && csz > 0u) {
                                s.chunks.emplace_back(p, csz);
                            }
                            p += csz;
                        }
                        std::vector<unsigned char> assembled(
                            static_cast<std::size_t>(total_data_size), 0);
                        bool all_ok = parse_ok && !ps.empty();
                        std::uint64_t covered = 0;
                        for (auto& kv : ps) {
                            PStream& s = kv.second;
                            if (s.chunks.empty()) continue;
                            if (!s.hasoff || !s.hassz || s.cmode == ChecksumMode::kNone ||
                                s.ooff + s.osz > total_data_size) { all_ok = false; break; }
                            // Concatenate this stream's type-0 chunks into one
                            // contiguous lzpf payload (blocks continue seamlessly
                            // across chunk boundaries, sharing the dict state).
                            std::vector<unsigned char> payload;
                            std::size_t plen = 0;
                            for (const auto& c : s.chunks) plen += c.second;
                            payload.reserve(plen);
                            for (const auto& c : s.chunks)
                                payload.insert(payload.end(), bytes.begin() + static_cast<std::ptrdiff_t>(c.first),
                                               bytes.begin() + static_cast<std::ptrdiff_t>(c.first + c.second));
                            const ChecksumMode cm = s.cmode;
                            const std::uint32_t cv = s.cval;
                            auto slice_verify = [&](const std::vector<unsigned char>& dec) -> bool {
                                return ComputeBufferChecksum(cm, dec.data(), dec.size()) == cv;
                            };
                            std::vector<unsigned char> slice;
                            if (!DecodeLzpfMember(payload, 0u, payload.size(), s.osz,
                                                  is_variant_b, method_p1, slice_verify, &slice)) {
                                all_ok = false; break;
                            }
                            std::memcpy(assembled.data() + static_cast<std::size_t>(s.ooff),
                                        slice.data(), slice.size());
                            covered += s.osz;
                        }
                        if (all_ok && covered == total_data_size &&
                            validate_decoded_candidate(assembled)) {
                            native_literal_payload = true;
                            literal_data_offset = 0u;
                            literal_data_size = assembled.size();
                            literal_data_owned = true;
                            literal_data_buffer = std::move(assembled);
                        }
                    }
                }

                // `-cd/-cD` parallel multi-stream container (same header flag
                // byte 0x0f / same chunk-record scheme as the -cf/-cF parallel
                // container above, used by the multi-threaded encoder for
                // inputs >~8 MB). The stream-descriptor parsing loop below is
                // byte-for-byte identical to the -cf/-cF branch (shared
                // infrastructure, not lzpf-specific); only the per-stream
                // downstream decode differs: each of a stream's type-0 chunk
                // records is one raw nz_cd (DecLZ) block (unlike -cf/-cF's
                // lzpf bitstream, a -cd stream's chunks are NOT continuous and
                // need no concatenation), decoded with NzCdDecodeStream one
                // chunk at a time into a FRESH per-stream ring (confirmed:
                // each parallel-encoder thread owned its own nz_cd instance /
                // ring, unlike the single-container case in
                // TryDecodeLegacyLzhd which shares one ring across the whole
                // archive). The ring is sized round(slice_osz/0x10000)*0x10000
                // (min 0x10000), matching the single-container formula but
                // applied per-slice. Every slice is checksum-verified before
                // being placed into the assembled output, so a wrong decode
                // is rejected rather than emitted.
                if (!native_literal_payload &&
                    method == 0x2bu &&
                    (method_p0 == 3u || method_p0 == 4u)) {
                    std::size_t magic = bytes.size();
                    for (std::size_t q = 0; q + 4u <= bytes.size(); ++q) {
                        if (bytes[q] == 0x1fu && bytes[q + 1u] == 0x0fu && bytes[q + 2u] == 0x09u) {
                            magic = q; break;
                        }
                    }
                    // A parallel container's type-10 offset is the slice's
                    // offset WITHIN ITS FILE, not within the output: in a
                    // two-file archive both files have a slice at offset 0, and
                    // one stream can carry slices of two different files. These
                    // paths tile straight into the whole output, which is only
                    // the same thing when the archive holds ONE file. Tiling a
                    // multi-file one would overlap the files, and the per-entry
                    // check cannot catch it -- a file split across streams has
                    // no whole-file checksum to verify against. So decline.
                    if (magic != bytes.size() && bytes[magic + 3u] == 0x0fu &&
                        entries.size() == 1u) {
                        struct PCdStream {
                            // Each entry is one raw nz_cd block: (offset, size)
                            // into `bytes`, decoded in order into the slice.
                            std::vector<std::pair<std::size_t, std::size_t>> chunks;
                            std::uint64_t osz = 0, ooff = 0;
                            ChecksumMode cmode = ChecksumMode::kNone;
                            std::uint32_t cval = 0;
                            bool hasoff = false, hassz = false;
                        };
                        std::map<unsigned, PCdStream> ps;
                        std::size_t p = magic + 3u;
                        bool parse_ok = true;
                        for (int guard = 0; guard < 8192 && p < bytes.size(); ++guard) {
                            std::uint64_t r = 0;
                            if (!ReadLegacyVarint(bytes, &p, bytes.size(), &r)) { parse_ok = false; break; }
                            unsigned ct = static_cast<unsigned>(r) & 0x0fu;
                            unsigned sid = 0u;
                            std::size_t csz = static_cast<std::size_t>(r >> 4u);
                            if (ct == 15u) {
                                if (p >= bytes.size()) { parse_ok = false; break; }
                                unsigned ext = bytes[p++];
                                if (ext >= 0xf8u) {
                                    if (p >= bytes.size()) { parse_ok = false; break; }
                                    ext = (ext & 7u) + 8u * static_cast<unsigned>(bytes[p++]) + 248u;
                                }
                                ct = ext & 0x0fu;
                                sid = ext >> 4u;
                                if (sid == 0u) ct += 15u;
                            }
                            if (p + csz > bytes.size()) { parse_ok = false; break; }
                            PCdStream& s = ps[sid];
                            if (ct == 1u && csz >= 2u) {
                                std::size_t tp = p; std::uint64_t v = 0;
                                if (ReadLegacyVarint(bytes, &tp, p + csz, &v)) { s.osz = v; s.hassz = true; }
                            } else if (ct == 10u && csz >= 4u) {
                                s.ooff = static_cast<std::uint32_t>(bytes[p]) |
                                         (static_cast<std::uint32_t>(bytes[p + 1u]) << 8u) |
                                         (static_cast<std::uint32_t>(bytes[p + 2u]) << 16u) |
                                         (static_cast<std::uint32_t>(bytes[p + 3u]) << 24u);
                                s.hasoff = true;
                            } else if (ct == 5u && csz == 4u) {
                                s.cmode = ChecksumMode::kFletcher32;
                                s.cval = static_cast<std::uint32_t>(bytes[p]) |
                                         (static_cast<std::uint32_t>(bytes[p + 1u]) << 8u) |
                                         (static_cast<std::uint32_t>(bytes[p + 2u]) << 16u) |
                                         (static_cast<std::uint32_t>(bytes[p + 3u]) << 24u);
                            } else if (ct == 7u && csz == 4u) {
                                s.cmode = ChecksumMode::kCrc32;
                                s.cval = static_cast<std::uint32_t>(bytes[p]) |
                                         (static_cast<std::uint32_t>(bytes[p + 1u]) << 8u) |
                                         (static_cast<std::uint32_t>(bytes[p + 2u]) << 16u) |
                                         (static_cast<std::uint32_t>(bytes[p + 3u]) << 24u);
                            } else if (ct == 6u && csz == 2u) {
                                s.cmode = ChecksumMode::kCrc16;
                                s.cval = static_cast<std::uint32_t>(bytes[p]) |
                                         (static_cast<std::uint32_t>(bytes[p + 1u]) << 8u);
                            } else if (ct == 0u && csz > 0u) {
                                s.chunks.emplace_back(p, csz);
                            }
                            p += csz;
                        }
                        std::vector<unsigned char> assembled(
                            static_cast<std::size_t>(total_data_size), 0);
                        bool all_ok = parse_ok && !ps.empty();
                        std::uint64_t covered = 0;
                        static constexpr std::size_t kCdWindowPad = 16u;
                        for (auto& kv : ps) {
                            PCdStream& s = kv.second;
                            if (s.chunks.empty()) continue;
                            if (!s.hasoff || !s.hassz || s.cmode == ChecksumMode::kNone ||
                                s.ooff + s.osz > total_data_size) { all_ok = false; break; }

                            const std::size_t slice_total = static_cast<std::size_t>(s.osz);
                            std::vector<unsigned char> slice_buf(kCdWindowPad + slice_total, 0u);
                            unsigned char* const slice_window = slice_buf.data() + kCdWindowPad;

                            // Fresh, independent per-stream ring (hypothesis:
                            // each parallel-encoder thread had its own nz_cd
                            // instance), sized to this stream's own slice
                            // output via the same round(slice/0x10000)*0x10000
                            // formula used for the single-container case.
                            std::uint32_t sring_units = static_cast<std::uint32_t>(
                                (static_cast<std::uint64_t>(slice_total) + 0x8000u) / 0x10000u);
                            if (sring_units == 0u) sring_units = 1u;
                            const std::uint32_t sring_size = sring_units * 0x10000u;
                            std::vector<std::uint8_t> sring(sring_size, 0u);
                            std::uint32_t sring_pos = 0u;

                            // `-cD` parallel streams: each thread owned its own
                            // nz_lzhds instance (same "fresh per-stream ring"
                            // hypothesis as above), so the MTF-context table is
                            // fresh per slice too, not shared across streams.
                            const bool s_is_lzhds = (method_p0 == 4u);
                            std::vector<std::uint8_t> s_lzhds_ctx;
                            std::uint32_t s_lzhds_ctx_index = 0u;
                            std::uint8_t* s_lzhds_ctx_ptr = nullptr;
                            if (s_is_lzhds) {
                                s_lzhds_ctx.assign(nzr::cd::kLzhdsCtxTableSize, 0u);
                                nzr::cd::NzLzhdsInitCtxTable(s_lzhds_ctx.data());
                                s_lzhds_ctx_ptr = s_lzhds_ctx.data();
                            }

                            // Each type-0 chunk record IS one raw nz_cd
                            // (DecLZ) block already delimited by the outer
                            // record parser above (its `csz` is exactly the
                            // compressed byte length, no embedded stream_tag
                            // inside it) -- unlike the -cf/-cF lzpf payload,
                            // whose bitstream is continuous across chunk
                            // boundaries and must be concatenated before a
                            // single decode call. Here each chunk maps 1:1 to
                            // one NzCdDecodeStream() call, threading the
                            // per-stream ring + output cursor across chunks,
                            // exactly like TryDecodeLegacyLzhd's per-stream_tag
                            // loop in the single-container case.
                            std::size_t pwritten = 0u;
                            bool sok = true;
                            for (const auto& c : s.chunks) {
                                if (pwritten >= slice_total) break;
                                const std::uint8_t* blk_in = bytes.data() + c.first;
                                const std::uint32_t blk_in_size = static_cast<std::uint32_t>(c.second);
                                const std::uint32_t blk_cap = static_cast<std::uint32_t>(slice_total - pwritten);
                                std::uint32_t produced = nzr::cd::NzCdDecodeStream(
                                    blk_in, blk_in_size, slice_window + pwritten, blk_cap,
                                    sring.data(), sring_size, &sring_pos,
                                    static_cast<std::uint32_t>(pwritten),
                                    s_is_lzhds, s_lzhds_ctx_ptr, &s_lzhds_ctx_index);
                                if (produced == 0u) { sok = false; break; }
                                pwritten += produced;
                            }
                            if (!sok || pwritten != slice_total) { all_ok = false; break; }
                            if (ComputeBufferChecksum(s.cmode, slice_window, slice_total) != s.cval) {
                                all_ok = false; break;
                            }
                            std::memcpy(assembled.data() + static_cast<std::size_t>(s.ooff),
                                        slice_window, slice_total);
                            covered += s.osz;
                        }
                        if (all_ok && covered == total_data_size &&
                            validate_decoded_candidate(assembled)) {
                            native_literal_payload = true;
                            literal_data_offset = 0u;
                            literal_data_size = assembled.size();
                            literal_data_owned = true;
                            literal_data_buffer = std::move(assembled);
                        }
                    }
                }

                // `-co`/`-cO` (nz_optimum1/nz_optimum2, method_p0==5 or 6)
                // parallel multi-stream container (same header flag 0x0f /
                // same generic chunk-record scheme as the -cf/-cF and -cd/-cD
                // parallel branches above; shared infrastructure, not
                // codec-specific). Empirically confirmed for -co (real
                // 8-15MB archives, GDB-free -- just byte inspection + the
                // checksum gate as arbiter; -cO's parallel envelope is
                // identical, only the per-stream engine differs): each
                // stream's type-0 chunk(s) contain the SAME "sequence of
                // block records" body that TryDecodeLegacyOptimum's
                // single-container path decodes after its own leading
                // stream_tag varint -- i.e. a chunk begins directly with a
                // block's payload_size (u32 LE), NOT with another stream_tag,
                // and (unlike -cd/-cD, where a chunk is exactly one block) a
                // single chunk here can itself contain several back-to-back
                // block records. Each parallel stream gets its own FRESH
                // decoder instance (mirrors -cd/-cD's "each encoder thread
                // owned its own subengine instance" finding), but all
                // streams share the archive-wide window capacity derived
                // from method_p1 -- there is only one such byte in the whole
                // container header, so every stream almost certainly used
                // the same ring size; a wrong guess here would simply make
                // DecodeOptimumBlockSequence fail or the per-slice checksum
                // mismatch, so it's safe to try. The decoder TYPE (-co's
                // NzOptimumLzDecoder vs -cO's NzOptimum2LzDecoder) is fixed
                // for the whole archive (method_p0 doesn't vary per stream),
                // so it's selected once via a type-erased closure rather
                // than duplicating this whole loop per type.
                // Parallel (-pN) `-cc`: each stream is an INDEPENDENT CM decode
                // of its own slice -- feeding all four streams' chunks to one
                // decoder (which is what the flat chunk walk does, since it just
                // skips the records it does not know) shares state across slices
                // that never shared it. Rebuild each stream's chunks as a normal
                // record chain, decode it with a fresh context, and tile by the
                // type-10 offsets. Every slice is checked against its own
                // checksum, so a wrong layout cannot produce output.
                if (!native_literal_payload && method == 0x4bu && method_p0 == 7u &&
                    entries.size() == 1u) {  // see the offset note above
                    std::map<unsigned, LegacyParallelStream> pstreams;
                    if (ParseLegacyParallelStreams(bytes, &pstreams) && pstreams.size() > 1u) {
                        std::vector<unsigned char> assembled(
                            static_cast<std::size_t>(total_data_size), 0);
                        bool all_ok = true;
                        std::uint64_t covered = 0;
                        for (const auto& kv : pstreams) {
                            const LegacyParallelStream& st = kv.second;
                            if (st.chunks.empty()) continue;
                            if (!st.hasoff || !st.hassz || st.cmode == ChecksumMode::kNone ||
                                st.ooff > total_data_size ||
                                st.osz > total_data_size - st.ooff) { all_ok = false; break; }

                            LegacyCnContext sub;
                            sub.legacy_method = method;
                            sub.legacy_method_p0 = method_p0;
                            sub.legacy_method_p1 = method_p1;
                            sub.cm_a_bits = cm_a_bits;
                            sub.cm_b_bits = cm_b_bits;
                            sub.cm_window_size = cm_window_size;
                            sub.total_data_size = st.osz;
                            for (const auto& c : st.chunks) {
                                WriteLegacyVarint(static_cast<std::uint64_t>(c.second) << 4u,
                                                  &sub.data);
                                sub.data.insert(
                                    sub.data.end(),
                                    bytes.begin() + static_cast<std::ptrdiff_t>(c.first),
                                    bytes.begin() + static_cast<std::ptrdiff_t>(c.first + c.second));
                            }
                            std::vector<unsigned char> slice;
                            std::string sub_err;
                            if (!TryDecodeLegacyCm(sub, &slice, &sub_err) ||
                                slice.size() != st.osz ||
                                ComputeBufferChecksum(st.cmode, slice.data(), slice.size()) != st.cval) {
                                all_ok = false;
                                break;
                            }
                            std::memcpy(assembled.data() + static_cast<std::size_t>(st.ooff),
                                        slice.data(), slice.size());
                            covered += st.osz;
                        }
                        if (all_ok && covered == total_data_size &&
                            validate_decoded_candidate(assembled)) {
                            native_literal_payload = true;
                            literal_data_offset = 0u;
                            literal_data_size = assembled.size();
                            literal_data_owned = true;
                            literal_data_buffer = std::move(assembled);
                        }
                    }
                }

                if (!native_literal_payload &&
                    method == 0x3bu &&
                    (method_p0 == 5u || method_p0 == 6u)) {
                    std::size_t magic = bytes.size();
                    for (std::size_t q = 0; q + 4u <= bytes.size(); ++q) {
                        if (bytes[q] == 0x1fu && bytes[q + 1u] == 0x0fu && bytes[q + 2u] == 0x09u) {
                            magic = q; break;
                        }
                    }
                    // A parallel container's type-10 offset is the slice's
                    // offset WITHIN ITS FILE, not within the output: in a
                    // two-file archive both files have a slice at offset 0, and
                    // one stream can carry slices of two different files. These
                    // paths tile straight into the whole output, which is only
                    // the same thing when the archive holds ONE file. Tiling a
                    // multi-file one would overlap the files, and the per-entry
                    // check cannot catch it -- a file split across streams has
                    // no whole-file checksum to verify against. So decline.
                    if (magic != bytes.size() && bytes[magic + 3u] == 0x0fu &&
                        entries.size() == 1u) {
                        struct POptStream {
                            // Each entry is one contiguous block-record range
                            // (offset, size) into `bytes`; usually just one,
                            // but concatenated in order if a stream is ever
                            // split across more than one type-0 chunk.
                            std::vector<std::pair<std::size_t, std::size_t>> chunks;
                            std::uint64_t osz = 0, ooff = 0;
                            ChecksumMode cmode = ChecksumMode::kNone;
                            std::uint32_t cval = 0;
                            bool hasoff = false, hassz = false;
                        };
                        std::map<unsigned, POptStream> ps;
                        std::size_t p = magic + 3u;
                        bool parse_ok = true;
                        for (int guard = 0; guard < 8192 && p < bytes.size(); ++guard) {
                            std::uint64_t r = 0;
                            if (!ReadLegacyVarint(bytes, &p, bytes.size(), &r)) { parse_ok = false; break; }
                            unsigned ct = static_cast<unsigned>(r) & 0x0fu;
                            unsigned sid = 0u;
                            std::size_t csz = static_cast<std::size_t>(r >> 4u);
                            if (ct == 15u) {
                                if (p >= bytes.size()) { parse_ok = false; break; }
                                unsigned ext = bytes[p++];
                                if (ext >= 0xf8u) {
                                    if (p >= bytes.size()) { parse_ok = false; break; }
                                    ext = (ext & 7u) + 8u * static_cast<unsigned>(bytes[p++]) + 248u;
                                }
                                ct = ext & 0x0fu;
                                sid = ext >> 4u;
                                if (sid == 0u) ct += 15u;
                            }
                            if (p + csz > bytes.size()) { parse_ok = false; break; }
                            POptStream& s = ps[sid];
                            if (ct == 1u && csz >= 2u) {
                                std::size_t tp = p; std::uint64_t v = 0;
                                if (ReadLegacyVarint(bytes, &tp, p + csz, &v)) { s.osz = v; s.hassz = true; }
                            } else if (ct == 10u && csz >= 4u) {
                                s.ooff = static_cast<std::uint32_t>(bytes[p]) |
                                         (static_cast<std::uint32_t>(bytes[p + 1u]) << 8u) |
                                         (static_cast<std::uint32_t>(bytes[p + 2u]) << 16u) |
                                         (static_cast<std::uint32_t>(bytes[p + 3u]) << 24u);
                                s.hasoff = true;
                            } else if (ct == 5u && csz == 4u) {
                                s.cmode = ChecksumMode::kFletcher32;
                                s.cval = static_cast<std::uint32_t>(bytes[p]) |
                                         (static_cast<std::uint32_t>(bytes[p + 1u]) << 8u) |
                                         (static_cast<std::uint32_t>(bytes[p + 2u]) << 16u) |
                                         (static_cast<std::uint32_t>(bytes[p + 3u]) << 24u);
                            } else if (ct == 7u && csz == 4u) {
                                s.cmode = ChecksumMode::kCrc32;
                                s.cval = static_cast<std::uint32_t>(bytes[p]) |
                                         (static_cast<std::uint32_t>(bytes[p + 1u]) << 8u) |
                                         (static_cast<std::uint32_t>(bytes[p + 2u]) << 16u) |
                                         (static_cast<std::uint32_t>(bytes[p + 3u]) << 24u);
                            } else if (ct == 6u && csz == 2u) {
                                s.cmode = ChecksumMode::kCrc16;
                                s.cval = static_cast<std::uint32_t>(bytes[p]) |
                                         (static_cast<std::uint32_t>(bytes[p + 1u]) << 8u);
                            } else if (ct == 0u && csz > 0u) {
                                s.chunks.emplace_back(p, csz);
                            }
                            p += csz;
                        }
                        const std::uint32_t popt_window_capacity =
                            nzr::optimum::NzOptimumLzWindowSizeFromP1(method_p1);
                        // Type-erased "decode one block-record range" closure: the
                        // decoder TYPE is fixed for the whole archive (method_p0
                        // doesn't vary per stream), so pick it once here rather
                        // than duplicating the per-stream loop body per type.
                        std::function<bool(const unsigned char*, std::size_t, std::size_t,
                                            std::uint64_t, std::vector<unsigned char>*)> decode_seq;
                        if (method_p0 == 5u) {
                            decode_seq = [popt_window_capacity](
                                const unsigned char* raw, std::size_t b, std::size_t e,
                                std::uint64_t hint, std::vector<unsigned char>* out) {
                                nzr::optimum::NzOptimumLzDecoder sdec(popt_window_capacity);
                                nzr::audio::NzAudioPred saud;
                                NzExeFilter sexe;
                                return DecodeOptimumBlockSequence(raw, b, e, hint, sdec, saud, sexe, out);
                            };
                        } else {
                            decode_seq = [popt_window_capacity](
                                const unsigned char* raw, std::size_t b, std::size_t e,
                                std::uint64_t hint, std::vector<unsigned char>* out) {
                                nzr::optimum2::NzOptimum2LzDecoder sdec(popt_window_capacity);
                                nzr::audio::NzAudioPred saud;
                                NzExeFilter sexe;
                                return DecodeOptimumBlockSequence(raw, b, e, hint, sdec, saud, sexe, out);
                            };
                        }
                        std::vector<unsigned char> assembled(
                            static_cast<std::size_t>(total_data_size), 0);
                        bool all_ok = parse_ok && !ps.empty() && popt_window_capacity != 0u;
                        std::uint64_t covered = 0;
                        for (auto& kv : ps) {
                            if (!all_ok) break;
                            POptStream& s = kv.second;
                            if (s.chunks.empty()) continue;
                            if (!s.hasoff || !s.hassz || s.cmode == ChecksumMode::kNone ||
                                s.ooff + s.osz > total_data_size) { all_ok = false; break; }

                            std::vector<unsigned char> slice;
                            slice.reserve(static_cast<std::size_t>(s.osz));
                            bool sok = true;
                            if (s.chunks.size() == 1u) {
                                const auto& c = s.chunks.front();
                                sok = decode_seq(
                                    bytes.data(), c.first, c.first + c.second,
                                    s.osz, &slice);
                            } else {
                                // Defensive path: not observed in practice
                                // (every real -co/-cO parallel archive fixture
                                // so far emits exactly one type-0 chunk per
                                // stream), but concatenate in order and decode
                                // as one contiguous block-record range, same
                                // shape as -cf/-cF's lzpf payload handling.
                                std::vector<unsigned char> concat;
                                std::size_t clen = 0;
                                for (const auto& c : s.chunks) clen += c.second;
                                concat.reserve(clen);
                                for (const auto& c : s.chunks)
                                    concat.insert(concat.end(),
                                                  bytes.begin() + static_cast<std::ptrdiff_t>(c.first),
                                                  bytes.begin() + static_cast<std::ptrdiff_t>(c.first + c.second));
                                sok = decode_seq(concat.data(), 0u, concat.size(), s.osz, &slice);
                            }
                            if (!sok || slice.size() != s.osz) { all_ok = false; break; }
                            if (ComputeBufferChecksum(s.cmode, slice.data(), slice.size()) != s.cval) {
                                all_ok = false; break;
                            }
                            std::memcpy(assembled.data() + static_cast<std::size_t>(s.ooff),
                                        slice.data(), slice.size());
                            covered += s.osz;
                        }
                        if (all_ok && covered == total_data_size &&
                            validate_decoded_candidate(assembled)) {
                            native_literal_payload = true;
                            literal_data_offset = 0u;
                            literal_data_size = assembled.size();
                            literal_data_owned = true;
                            literal_data_buffer = std::move(assembled);
                        }
                    }
                }

        std::size_t sp = payload_start;
        std::uint64_t stream_tag = 0;
        if (ReadLegacyVarint(bytes, &sp, bytes.size(), &stream_tag) &&
            (stream_tag & 0x0fu) == 0u) {
            const std::uint64_t stream_bytes = stream_tag >> 4u;
            // Multi-stream chains (e.g., -cf/-cF p1=15 big files) put more
            // stream tags after the first stream's payload. The LZ77+arith
            // path handles the chain itself; literal/BWT paths still
            // require the strict single-stream layout via inner checks.
            if (stream_bytes <= static_cast<std::uint64_t>(bytes.size() - sp)) {
                // `-cf/-cF` literal-only substream:
                // [stream_tag][bitlen_tag][raw_payload]
                if (method == 0x2bu &&
                    (method_p0 == 1u || method_p0 == 2u) &&
                    method_p1 == 0u) {
                    std::size_t bp = sp;
                    std::uint64_t bitlen_tag = 0;
                    if (ReadLegacyVarint(bytes, &bp, bytes.size(), &bitlen_tag) &&
                        total_data_size <= (std::numeric_limits<std::uint64_t>::max() - 1u) / 8u) {
                        const std::uint64_t expected_bits = total_data_size * 8u;
                        const bool bitlen_match = (bitlen_tag == expected_bits || bitlen_tag == expected_bits + 1u);
                        if (bitlen_match &&
                            total_data_size <= static_cast<std::uint64_t>(bytes.size() - bp) &&
                            bp + static_cast<std::size_t>(total_data_size) == bytes.size() &&
                            validate_literal_candidate_with_checksums(bp)) {
                            native_literal_payload = true;
                            literal_data_offset = bp;
                            literal_data_size = static_cast<std::size_t>(total_data_size);
                        }
                    }
                }

                // `-cf/-cF` LZ77 bytecode + arith side-stream substream
                // (the common path for compressible inputs).
                //
                // Block layout (per-block):
                //   [varint uVar9]              — header. uVar9 = (out_size << 3) | flags.
                //                                  uVar9 & 7 == 3 → LZ77 bytecode mode,
                //                                  uVar9 & 1 == 1 → has arith side-stream.
                //   [u16 LE side_stream_count]  — number of bytecode bytes in side-stream output.
                //   [arith-coded side-stream]   — input to nzr::lzpf::DecodeArithBuffer.
                //
                // The decoded side-stream IS the LZ77 bytecode opcode stream
                // consumed by nzr::lzpf::DecodeLz77VariantA. For multi-block
                // archives (large inputs) we loop until we've produced
                // total_data_size output bytes. method_p1 != 0 indicates the
                // legacy parallel-encoder layout — same per-block format
                // applies, just more blocks.
                // method_p0 == 1 → nz_lzpf (variant A, 13-bit hash).
                // method_p0 == 2 → nz_lzpf_large (variant B, 24-bit hash,
                // opcode 0xf5 with secondary 8 KiB byte buffer). Both ported
                // natively (task #26). Variant B allocates a 64 MiB hash table
                // lazily — costly but matches legacy `nz_lzpf_large`.


                if (!native_literal_payload &&
                    method == 0x2bu &&
                    (method_p0 == 1u || method_p0 == 2u) &&
                    sp + static_cast<std::size_t>(stream_bytes) <= bytes.size()) {
                    const bool is_variant_b = (method_p0 == 2u);
                    // Verifier: the member's whole-output checksum, embedded as
                    // [tag][value] (the per-file checksum). For members that also
                    // carry a per-entry checksum, validate_decoded_candidate has
                    // already verified the bytes, so the embedded scan is skipped.
                    bool entries_have_checksum = false;
                    if (checksum_verification_supported) {
                        for (const LegacyCnEntry& e : entries)
                            if (e.has_checksum) { entries_have_checksum = true; break; }
                    }
                    auto member_verify = [&](const std::vector<unsigned char>& dec) -> bool {
                        const bool vdc = validate_decoded_candidate(dec);
                        if (getenv("NZOPT_TRACE_LZPF")) {
                            fprintf(stderr, "[lzpf] member_verify: size=%zu vdc=%d entries=%zu have_cksum=%d mode=%d\n",
                                    dec.size(), (int)vdc, entries.size(), (int)entries_have_checksum, (int)checksum_mode);
                            std::size_t cur = 0;
                            for (const LegacyCnEntry& e : entries) {
                                if (e.size > (std::uint64_t)(dec.size() - cur)) break;
                                const std::uint32_t got = ComputeBufferChecksum(checksum_mode, dec.data() + cur, (std::size_t)e.size);
                                fprintf(stderr, "[lzpf]   entry sz=%llu has_cksum=%d stored=%08x got=%08x %s\n",
                                        (unsigned long long)e.size, (int)e.has_checksum, e.checksum, got,
                                        (e.has_checksum && got != e.checksum) ? "MISMATCH" : "");
                                cur += (std::size_t)e.size;
                            }
                        }
                        if (!vdc) return false;
                        if (entries_have_checksum) return true;
                        std::uint8_t tag = 0; std::size_t cw = 0;
                        switch (checksum_mode) {
                            case ChecksumMode::kFletcher32: tag = 0x45u; cw = 4u; break;
                            case ChecksumMode::kFletcher16: tag = 0x45u; cw = 2u; break;
                            case ChecksumMode::kCrc32:      tag = 0x47u; cw = 4u; break;
                            case ChecksumMode::kCrc16:      tag = 0x26u; cw = 2u; break;
                            case ChecksumMode::kNone:       return false;
                        }
                        const std::uint32_t c = ComputeBufferChecksum(checksum_mode, dec.data(), dec.size());
                        std::array<std::uint8_t, 5> pat{};
                        pat[0] = tag;
                        for (std::size_t k = 0; k < cw; ++k)
                            pat[1u + k] = static_cast<std::uint8_t>((c >> (8u * k)) & 0xffu);
                        const std::size_t patlen = 1u + cw;
                        for (std::size_t q = 0; q + patlen <= bytes.size(); ++q)
                            if (std::memcmp(bytes.data() + q, pat.data(), patlen) == 0) return true;
                        return false;
                    };
                    std::vector<unsigned char> member_out;
                    // payload_start IS data_records[0].first, so the same parse
                    // applies to the spliced buffer from its own start.
                    const bool use_splice = !spliced_data.empty();
                    const std::vector<unsigned char>& chain_src =
                        use_splice ? spliced_data : bytes;
                    const std::size_t chain_sp = use_splice ? (sp - payload_start) : sp;
                    if (DecodeLzpfMember(chain_src, chain_sp, static_cast<std::size_t>(stream_bytes),
                                         total_data_size, is_variant_b, method_p1,
                                         member_verify, &member_out)) {
                        native_literal_payload = true;
                        literal_data_offset = 0u;
                        literal_data_size = member_out.size();
                        literal_data_owned = true;
                        literal_data_buffer = std::move(member_out);
                    }
                }

                // `-cd/-cD` literal-only substream:
                // [stream_tag][unknown_varint][0x00][raw_payload]
                if (!native_literal_payload &&
                    method == 0x2bu &&
                    (method_p0 == 3u || method_p0 == 4u) &&
                    method_p1 == 0u) {
                    std::size_t bp = sp;
                    std::uint64_t unused_tag = 0;
                    if (ReadLegacyVarint(bytes, &bp, bytes.size(), &unused_tag) &&
                        bp < bytes.size() && bytes[bp] == 0x00u) {
                        ++bp;
                        if (total_data_size <= static_cast<std::uint64_t>(bytes.size() - bp) &&
                            bp + static_cast<std::size_t>(total_data_size) == bytes.size() &&
                            validate_literal_candidate_with_checksums(bp)) {
                            native_literal_payload = true;
                            literal_data_offset = bp;
                            literal_data_size = static_cast<std::size_t>(total_data_size);
                        }
                    }
                }

                // `-co/-cO` observed BWT-wrapper substreams:
                // - variant A: [stream_tag][u32 raw_size][bwt_last(raw_size)][u24 primary_be][trailer]
                // - variant B: [stream_tag][u32 raw_size][bwt_last(raw_size)][16-byte trailer], where
                //   primary index is encoded as little-endian u24 at trailer+5.
                if (!native_literal_payload &&
                    method == 0x3bu &&
                    (method_p0 == 5u || method_p0 == 6u) &&
                    method_p1 == 0u &&
                    stream_bytes >= 7u &&
                    sp + 7u <= bytes.size()) {
                    const std::uint32_t raw_size = ReadU32LE(bytes.data() + sp);
                    if (raw_size == total_data_size &&
                        stream_bytes >= 4u + static_cast<std::uint64_t>(raw_size) + 3u &&
                        sp + 4u + static_cast<std::size_t>(raw_size) + 3u <= bytes.size()) {
                        const unsigned char* const bwt_last = bytes.data() + sp + 4u;
                        const std::size_t trailer_off = sp + 4u + static_cast<std::size_t>(raw_size);
                        const auto try_bwt_primary = [&](std::uint32_t primary_index) -> bool {
                            std::vector<unsigned char> decoded;
                            if (!InverseBwt(
                                    bwt_last,
                                    static_cast<std::size_t>(raw_size),
                                    static_cast<std::size_t>(primary_index),
                                    &decoded)) {
                                return false;
                            }
                            if (!validate_decoded_candidate(decoded)) {
                                return false;
                            }
                            native_literal_payload = true;
                            literal_data_offset = 0u;
                            literal_data_size = decoded.size();
                            literal_data_owned = true;
                            literal_data_buffer = std::move(decoded);
                            return true;
                        };

                        // Variant A (legacy samples with direct BE u24 right after bwt_last).
                        const std::uint32_t primary_be =
                            (static_cast<std::uint32_t>(bytes[trailer_off]) << 16u) |
                            (static_cast<std::uint32_t>(bytes[trailer_off + 1u]) << 8u) |
                            static_cast<std::uint32_t>(bytes[trailer_off + 2u]);
                        (void)try_bwt_primary(primary_be);

                        // Variant B (observed in bigger single-file streams): 16-byte trailer,
                        // primary index at trailer offset +5 as LE u24.
                        if (!native_literal_payload &&
                            stream_bytes >= 4u + static_cast<std::uint64_t>(raw_size) + 16u &&
                            trailer_off + 16u <= bytes.size()) {
                            const std::uint32_t primary_tail_le =
                                static_cast<std::uint32_t>(bytes[trailer_off + 5u]) |
                                (static_cast<std::uint32_t>(bytes[trailer_off + 6u]) << 8u) |
                                (static_cast<std::uint32_t>(bytes[trailer_off + 7u]) << 16u);
                            (void)try_bwt_primary(primary_tail_le);
                        }
                    }
                }

                // `-co/-cO` prefilter-compressed BWT substream:
                // [stream_tag][u32 pf_input_size][pf_input_size bytes prefilter_data][22-byte trailer]
                // trailer layout (first 13 bytes significant, last 9 are zero padding):
                //   00 01 [u32 bwt_size] 03 [u32 checksum] 00 [u24 primary_le]
                // Decoder consumes (pf_input_size - 11) bytes via core byte-copy + RC run-extra.
                if (!native_literal_payload &&
                    method == 0x3bu &&
                    (method_p0 == 5u || method_p0 == 6u) &&
                    method_p1 == 0u &&
                    stream_bytes >= 4u + 11u + 22u &&
                    sp + 4u <= bytes.size()) {
                    const std::uint32_t pf_input_size = ReadU32LE(bytes.data() + sp);
                    const std::size_t pf_off = sp + 4u;
                    if (pf_input_size >= 12u &&
                        stream_bytes >= 4u + static_cast<std::uint64_t>(pf_input_size) + 22u &&
                        pf_off + static_cast<std::size_t>(pf_input_size) + 22u <= bytes.size()) {
                        const std::size_t trailer_off = pf_off + static_cast<std::size_t>(pf_input_size);
                        const std::uint32_t bwt_size_from_trailer = ReadU32LE(bytes.data() + trailer_off + 2u);
                        const std::uint32_t primary_from_trailer =
                            static_cast<std::uint32_t>(bytes[trailer_off + 11u]) |
                            (static_cast<std::uint32_t>(bytes[trailer_off + 12u]) << 8u) |
                            (static_cast<std::uint32_t>(bytes[trailer_off + 13u]) << 16u);
                        if (bwt_size_from_trailer >= total_data_size &&
                            bwt_size_from_trailer <= total_data_size + 64u * 1024u) {
                            LegacyPrefilterRangeCoder rc;
                            rc.Init(bytes.data() + pf_off, bytes.data() + pf_off + 1u);
                            const std::size_t byte_copy_count =
                                static_cast<std::size_t>(pf_input_size) - 11u;
                            std::vector<unsigned char> bwt_last;
                            if (DecodeLegacyPrefilterStream(
                                    bytes.data() + pf_off + 1u,
                                    byte_copy_count,
                                    rc,
                                    static_cast<std::size_t>(bwt_size_from_trailer),
                                    &bwt_last) &&
                                bwt_last.size() == bwt_size_from_trailer) {
                                std::vector<unsigned char> decoded;
                                if (InverseBwt(
                                        bwt_last.data(),
                                        bwt_last.size(),
                                        static_cast<std::size_t>(primary_from_trailer),
                                        &decoded) &&
                                    validate_decoded_candidate(decoded)) {
                                    native_literal_payload = true;
                                    literal_data_offset = 0u;
                                    literal_data_size = decoded.size();
                                    literal_data_owned = true;
                                    literal_data_buffer = std::move(decoded);
                                }
                            }
                        }
                    }
                }

                // `-co/-cO` observed raw-wrapper substream on incompressible inputs:
                // [stream_tag][u32 raw_size][raw_payload][trailer]
                if (!native_literal_payload &&
                    method == 0x3bu &&
                    (method_p0 == 5u || method_p0 == 6u) &&
                    method_p1 == 0u &&
                    stream_bytes >= 4u + total_data_size &&
                    sp + 4u <= bytes.size()) {
                    const std::uint32_t raw_size = ReadU32LE(bytes.data() + sp);
                    const std::size_t bp = sp + 4u;
                    if (raw_size == total_data_size && validate_literal_candidate_with_checksums(bp)) {
                        native_literal_payload = true;
                        literal_data_offset = bp;
                        literal_data_size = static_cast<std::size_t>(total_data_size);
                    }
                }

                // `-cc` observed literal-wrapper substream on incompressible inputs:
                // [stream_tag][u32 raw_size][raw_payload][trailer]
                if (!native_literal_payload &&
                    method == 0x4bu &&
                    method_p0 == 7u &&
                    stream_bytes >= 4u + total_data_size &&
                    sp + 4u <= bytes.size()) {
                    const std::uint32_t raw_size = ReadU32LE(bytes.data() + sp);
                    const std::size_t bp = sp + 4u;
                    if (raw_size == total_data_size && validate_literal_candidate_with_checksums(bp)) {
                        native_literal_payload = true;
                        literal_data_offset = bp;
                        literal_data_size = static_cast<std::size_t>(total_data_size);
                    }
                }
            }
        }
    }

    if (native_literal_payload && literal_data_size == 0u) {
        literal_data_size = static_cast<std::size_t>(total_data_size);
    }

    // Zero-byte payload fast path: every compressor serialises an empty file
    // identically (no data bytes), so we can satisfy the request natively
    // without falling through to the bridge (which segfaults in the legacy
    // backend on some builds when asked to decompress nothing).
    if (!native_store_payload && !native_literal_payload && total_data_size == 0u) {
        native_literal_payload = true;
        literal_data_offset = 0u;
        literal_data_size = 0u;
        literal_data_owned = true;
        literal_data_buffer.clear();
    }

    LegacyCnContext ctx;
    ctx.archive_path = archive_path;
    ctx.checksum_mode = checksum_mode;
    ctx.checksum_verification_supported = checksum_verification_supported;
    ctx.legacy_method = method;
    ctx.legacy_method_p0 = method_p0;
    ctx.legacy_method_p1 = method_p1;
    ctx.cm_a_bits = cm_a_bits;
    ctx.cm_b_bits = cm_b_bits;
    ctx.cm_window_size = cm_window_size;
    ctx.native_payload_supported = native_store_payload || native_literal_payload;
    if (native_store_payload) {
        ctx.payload_mode = LegacyPayloadMode::kStore;
    } else if (native_literal_payload) {
        ctx.payload_mode = LegacyPayloadMode::kLiteralOnly;
    } else if (payload_start < bytes.size()) {
        ctx.payload_mode = LegacyPayloadMode::kCompressed;
    } else {
        ctx.payload_mode = LegacyPayloadMode::kUnknown;
    }
    ctx.entries = std::move(entries);
    ctx.data_offset = (native_store_payload && !store_multiblock) ? data_offset_u64 : 0u;
    ctx.total_data_size = total_data_size;
    if (native_store_payload) {
        if (store_multiblock) {
            // Raw payload was reassembled from multiple stored blocks.
            ctx.data = std::move(store_blocks_buffer);
        } else {
            const std::size_t data_offset = static_cast<std::size_t>(data_offset_u64);
            ctx.data.assign(bytes.begin() + static_cast<std::ptrdiff_t>(data_offset), bytes.end());
        }
    } else if (native_literal_payload) {
        if (literal_data_owned) {
            ctx.data_offset = 0u;
            ctx.data = std::move(literal_data_buffer);
        } else {
            ctx.data_offset = static_cast<std::uint64_t>(literal_data_offset);
            ctx.data.assign(
                bytes.begin() + static_cast<std::ptrdiff_t>(literal_data_offset),
                bytes.begin() + static_cast<std::ptrdiff_t>(literal_data_offset + literal_data_size));
        }
    } else if (ctx.payload_mode == LegacyPayloadMode::kCompressed &&
               ((method == 0x4bu && method_p0 == 7u) ||
                (method == 0x2bu && (method_p0 == 3u || method_p0 == 4u)) ||
                (method == 0x3bu && (method_p0 == 5u || method_p0 == 6u))) &&
               payload_start < bytes.size()) {
        // Store the raw compressed stream so the native decoders can parse the
        // stream_tag + block directly:
        //  - 0x4b p0=7  -> TryDecodeLegacyCm (CM)
        //  - 0x2b p0=3/4 -> TryDecodeLegacyLzhd (the real coroutine token-LZ, now
        //    ported as NzCdDecodeBlock; the old "virtual-stream framing crashes a
        //    flat DecLZ" note is obsolete — pure-LZ -cd decodes byte-exact).
        //  - 0x3b p0=5 (-co, nz_optimum1) -> TryDecodeLegacyOptimum, backed by
        //    NzOptimumLzDecoder (FUN_0809e600 port).
        //  - 0x3b p0=6 (-cO, nz_optimum2) -> TryDecodeLegacyOptimum, backed by
        //    NzOptimum2LzDecoder (FUN_080a5d90 port) -- single-container only;
        //    parallel-container -cO (flag 0x0f) and decr_param==0 (BWT) still
        //    bridge (see nz_optimum2_lz.h for scope).
        if (!spliced_data.empty()) {
            ctx.data = std::move(spliced_data);
        } else {
            ctx.data.assign(bytes.begin() + static_cast<std::ptrdiff_t>(payload_start),
                            bytes.end());
        }
    }

    *out_context = std::move(ctx);
    if (out_error_message != nullptr) {
        out_error_message->clear();
    }
    return true;
}

int RunLegacyCnList(const CliOptions& options, const LegacyCnContext& legacy, std::ostream& os) {
    const bool has_checksum = legacy.checksum_mode != ChecksumMode::kNone;
    // The original drops a whole column when the archive carries no such
    // record: -hn removes the checksum, -nt the timestamp, -np the permission
    // column -- and so does a permission record that the encoder omitted
    // because every entry was mode 0600 (such an archive is byte-identical to
    // the -np one).
    bool has_perm = false;
    bool has_date = false;
    for (const LegacyCnEntry& e : legacy.entries) {
        if (e.has_permissions) has_perm = true;
        if (e.has_mtime) has_date = true;
    }
    // Layout matched to the original: archive name, column header, one row per
    // entry, total. It prints no compressor or payload line here.
    os << "Archive: " << legacy.archive_path << '\n';
    if (has_checksum) {
        os << "checksum ";
    }
    if (has_perm) {
        os << "perm ";
    }
    if (has_date) {
        os << "yyyy-mmm-dd hh:mm:ss";
    }
    os << "     size  file\n";

    std::uint64_t total_size = 0;
    std::size_t total_files = 0;
    for (const LegacyCnEntry& e : legacy.entries) {
        if (!MatchesAnyPattern(e.path, options.positional)) {
            continue;
        }

        if (has_checksum) {
            if (e.checksum_na) {
                os << "     n/a ";
            } else {
                const std::uint32_t shown = e.has_checksum ? e.checksum : 0;
                os << std::setw(8) << std::left
                   << FormatChecksum(legacy.checksum_mode, shown) << ' ';
            }
        }
        if (has_perm) {
            os << std::setw(4) << std::right << FormatMode(e.permissions) << ' ';
        }
        if (has_date) {
            os << FormatMtimeStored(e.mtime_unix);
        }
        os << FormatSizeColumn(e.size) << "  " << e.path << '\n';

        total_size += e.size;
        ++total_files;
    }

    os << "Total of " << total_files << " files, " << FormatGrouped(total_size) << " bytes.\n";
    return 0;
}

// Decode -cd/-cD (nz_lzhd) compressed payload natively using the ported DecLZ
// decoder.
//
// Block format (from strace of nz binary): the archive parser reads each type-0
// chunk as a unit of exactly chunk.size bytes.  The chunk body is the raw DecLZ
// bitstream — no Header struct, no payload_size/decr_param prefix.  The
// stream_tag varint encodes (compressed_bytes << 4) | 0, identical to the
// type-0 chunk varint.  Multi-file archives have one type-0 chunk per logical
// block; each chunk is decoded independently and the outputs are concatenated
// in file-table order.
static bool TryDecodeLegacyLzhd(
    const LegacyCnContext& legacy,
    std::vector<unsigned char>* out_data,
    std::string* out_error_message) {
    if (out_data == nullptr) return false;
    out_data->clear();

    if (getenv("NZOPT_TRACE_CD")) {
        fprintf(stderr, "[LZHD] enter: method=0x%x p0=%u p1=%u total=%llu data=%zu\n",
                legacy.legacy_method, legacy.legacy_method_p0, legacy.legacy_method_p1,
                (unsigned long long)legacy.total_data_size, legacy.data.size());
    }
    if (legacy.legacy_method != 0x2bu ||
        (legacy.legacy_method_p0 != 3u && legacy.legacy_method_p0 != 4u)) {
        if (getenv("NZOPT_TRACE_CD")) fprintf(stderr, "[LZHD] reject: method/p0 gate\n");
        return false;
    }
    if (legacy.data.empty()) {
        if (getenv("NZOPT_TRACE_CD")) fprintf(stderr, "[LZHD] reject: empty data\n");
        return false;
    }

    const auto* raw = legacy.data.data();
    const std::size_t raw_len = legacy.data.size();

    // Pre-allocate full output with 16-byte zero prefix for safe history reads
    // (DecLZ reads cur_ptr[-5] etc. from the first byte).
    static constexpr std::size_t kWindowPad = 16u;
    const std::size_t total_out = static_cast<std::size_t>(legacy.total_data_size);
    std::vector<unsigned char> buf(kWindowPad + total_out, 0u);
    unsigned char* const window_base = buf.data() + kWindowPad;

    std::size_t pos = 0u;
    std::size_t written = 0u;
    bool ok = true;

    // The cross-stream LZ window is a single per-archive ring (the binary's window
    // object persists across streams). GDB on FUN_08099050 (obj+0x978) shows the ring
    // size = round(total_output / 0x10000) * 0x10000 (min 0x10000): the encoder sizes
    // the window to hold the whole COMPACT recon, so the ring cursor (obj+0x980)
    // advances monotonically and NEVER wraps for real archives (verified across
    // text50/source.cpp/big_code/repeat_3M = 1/3/19/46 * 64 KB). Large files split the
    // output into 1 MB streams that reference each other through this shared ring, so
    // it is allocated ONCE and `ring_pos` threads across stream iterations. (The old
    // (method_p1+1)*0x10000 lzpf rule under-sized the ring for large files and forced
    // a wrap the binary never does.)
    std::uint32_t ring_units = static_cast<std::uint32_t>(
        (static_cast<std::uint64_t>(total_out) + 0x8000u) / 0x10000u);
    if (ring_units == 0u) ring_units = 1u;
    const std::uint32_t ring_size = ring_units * 0x10000u;
    std::vector<std::uint8_t> ring(ring_size, 0u);
    std::uint32_t ring_pos = 0u;

    // `-cD` (method_p0==4, nz_lzhds) selects the per-context MTF+adaptive-
    // predictor literal model (nz_lzhds.h) instead of `-cd`'s raw literal copy.
    // The context table is per-archive persistent state (like `ring`): init
    // once here, then thread across every stream/chunk in this archive.
    const bool is_lzhds = (legacy.legacy_method_p0 == 4u);

    // Prefilter sub-chunk state ((nibble & 0xc) == 0xc). ONE object for the whole
    // archive, matching the real codec object's single instance at obj+0x40: state
    // persists across adjacent prefilter chunks and every LZ chunk resets it
    // (both rules measured; see nz_cd_tokens.cpp). -cd configures order01 = 8,
    // -cD order01 = 32, both nstages = 3 (GDB-measured immediates).
    nzr::lzpf::PrefilterContext cd_pf_ctx;
    cd_pf_ctx.Configure(is_lzhds ? 32u : 8u, 3u);
    nzr::lzpf::LmsObject cd_pf_lms1{}, cd_pf_lms2{};
    cd_pf_lms1.Init();
    cd_pf_lms2.Init();

    std::vector<std::uint8_t> lzhds_ctx;
    std::uint32_t lzhds_ctx_index = 0u;
    std::uint8_t* lzhds_ctx_ptr = nullptr;
    if (is_lzhds) {
        lzhds_ctx.assign(nzr::cd::kLzhdsCtxTableSize, 0u);
        nzr::cd::NzLzhdsInitCtxTable(lzhds_ctx.data());
        lzhds_ctx_ptr = lzhds_ctx.data();
    }

    // Each type-0 chunk is one stream: stream_tag varint followed by
    // stream_bytes bytes of raw DecLZ compressed data.
    while (pos < raw_len && written < total_out) {
        // Read stream_tag (ParseChunk-style biased varint).
        std::uint64_t stream_tag = 0u;
        {
            unsigned shift = 7u;
            unsigned char c = raw[pos++];
            stream_tag = static_cast<std::uint64_t>(c & 0x7fu);
            while ((c & 0x80u) != 0u) {
                if (pos >= raw_len || shift >= 63u) {
                    ok = false; break;
                }
                c = raw[pos++];
                stream_tag += (static_cast<std::uint64_t>((c & 0x7fu) + 1u) << shift);
                shift += 7u;
            }
            if (!ok) break;
        }
        if ((stream_tag & 0x0fu) != 0u) { ok = false; break; }
        const std::uint64_t stream_bytes = stream_tag >> 4u;
        if (stream_bytes == 0u || stream_bytes > raw_len - pos) { ok = false; break; }

        const std::uint8_t* block_in  = raw + pos;
        const std::uint32_t block_in_size = static_cast<std::uint32_t>(stream_bytes);
        pos += static_cast<std::size_t>(stream_bytes);

        // Native -cd LZ block decode (NzCdDecodeBlock): loops the block's 32 KB
        // chunks into the contiguous output. Handles pure-LZ -cd (recon output ==
        // file). Blocks whose chunks carry a tt08/param14/CM/BWT post-filter
        // produce fewer bytes here; the size-mismatch check below rejects them so
        // they fall back to the bridge until those stages are wired.
        const std::uint32_t block_cap = static_cast<std::uint32_t>(total_out - written);
        std::uint32_t produced = nzr::cd::NzCdDecodeStream(
            block_in, block_in_size, window_base + written, block_cap,
            ring.data(), ring_size, &ring_pos, static_cast<std::uint32_t>(written),
            is_lzhds, lzhds_ctx_ptr, &lzhds_ctx_index,
            &cd_pf_ctx, &cd_pf_lms1, &cd_pf_lms2);
        if (getenv("NZOPT_TRACE_CD")) {
            fprintf(stderr, "[LZHD] stream: in=%u cap=%u produced=%u written=%zu/%zu\n",
                    block_in_size, block_cap, produced, written + produced, (size_t)total_out);
        }
        if (produced == 0u) { ok = false; break; }
        written += produced;
    }

    if (!ok) {
        if (getenv("NZOPT_TRACE_CD")) fprintf(stderr, "[LZHD] reject: malformed block stream (written=%zu/%zu)\n", written, (size_t)total_out);
        if (out_error_message) *out_error_message = "lzhd: malformed block stream";
        return false;
    }
    if (const char* dp = getenv("NZOPT_DUMP_PRECHECK")) {
        // Dump before BOTH the size check and the checksum gate, so a short
        // decode is diffable too (its prefix is still meaningful) -- not just a
        // full-size wrong-bytes one.
        FILE* f = fopen(dp, "wb");
        if (f) { fwrite(window_base, 1, written, f); fclose(f); }
        fprintf(stderr, "[LZHD] dumped %zu of %zu bytes to %s\n", written, (size_t)total_out, dp);
    }
    if (written != total_out) {
        if (getenv("NZOPT_TRACE_CD")) fprintf(stderr, "[LZHD] reject: size mismatch written=%zu total=%zu\n", written, (size_t)total_out);
        if (out_error_message) *out_error_message = "lzhd: output size mismatch";
        return false;
    }
    // Verify the decoded output against the archive's stored per-file checksum(s).
    // The native -cd ring model is byte-exact for the common case but has a residual
    // edge (multi-stream ring wrap under heavy repetition). Rejecting a checksum
    // mismatch here makes the caller fall through to the bridge so the user still
    // gets byte-exact output (no silent corruption, no double-decode of correct
    // files), and turns NZ_NO_BRIDGE native-only into a provable correctness signal.
    // Skipped only when the archive carries no usable checksum.
    if (legacy.checksum_verification_supported &&
        legacy.checksum_mode != ChecksumMode::kNone &&
        !legacy.entries.empty()) {
        std::size_t cursor = 0;
        for (const LegacyCnEntry& e : legacy.entries) {
            const std::size_t n = static_cast<std::size_t>(e.size);
            if (cursor + n > total_out) break;
            if (e.has_checksum) {
                const std::uint32_t got =
                    ComputeBufferChecksum(legacy.checksum_mode, window_base + cursor, n);
                if (got != e.checksum) {
                    if (out_error_message) *out_error_message = "lzhd: checksum mismatch";
                    return false;
                }
            }
            cursor += n;
        }
    }
    out_data->assign(window_base, window_base + total_out);
    return true;
}

// Decode -cc (nz_cm) compressed payload natively using the ported CM decoder.
// Parses the stream_tag varint + one or more per-block headers (payload_size,
// decr_param, param6, size18, staged_checksum_count, param2..dece_param) that
// immediately follow it, and feeds each block to CM_Decode.
static bool TryDecodeLegacyCm(
    const LegacyCnContext& legacy,
    std::vector<unsigned char>* out_data,
    std::string* out_error_message) {
    if (out_data == nullptr) return false;
    out_data->clear();

    if (legacy.legacy_method != 0x4bu || legacy.legacy_method_p0 != 7u) return false;
    if (legacy.data.empty()) return false;

    const auto* raw = legacy.data.data();
    const std::size_t raw_len = legacy.data.size();

    // Create the CM decoder once; its state persists across all data chunks.
    NzCmDecoder* cm = NzCmCreate(legacy.cm_a_bits, legacy.cm_b_bits, legacy.cm_window_size);
    // One audio predictor for the whole entry, matching the reference's single
    // global. Reset rules are applied per block below.
    nzr::audio::NzAudioPred aud;
    // Inter-channel stage selector, from the decoder object's flag byte in the
    // real binary (GDB-read at FUN_080a5330's entry): -cO 0x03, -cc 0x0f,
    // -co 0x13. Only bit 4 is consulted; see NzAudioPred::SetContextFlags.
    aud.SetContextFlags(0x0fu);      // -cc
    aud.SetPlaneOrders(384u, 16u, 8u);
    aud.SetStereoParam(16u);
    // One exe filter for the whole entry. Its recent-target caches and base
    // persist across a RUN of consecutive dece blocks and reset as soon as a
    // block without dece intervenes -- see nz_exefilter.h. The reference's
    // per-block temporary is wrong on 22 of 88 real dece archives.
    NzExeFilter exe;
    if (!cm) {
        if (out_error_message) *out_error_message = "cm: allocation failed";
        return false;
    }
    out_data->reserve(static_cast<std::size_t>(legacy.total_data_size));
    bool ok = true;
    std::size_t pos = 0;

    // Set when a type-5/6/7 checksum record turns up mid-stream rather than in the
    // front metadata run (see the chunk_type != 0 branch below).
    std::uint32_t inline_checksum = 0;
    bool inline_checksum_seen = false;

    // Outer loop over consecutive type-0 data chunks. Large -cc archives split the
    // payload into multiple chunks; the CM state carries across them (a block with
    // decr_param != 1 does not reset). Each chunk header is a biased varint
    // (size<<4)|type; non-type-0 chunks (metadata) between data chunks are skipped.
    while (ok && pos < raw_len &&
           out_data->size() < static_cast<std::size_t>(legacy.total_data_size)) {
        std::uint64_t stream_tag = 0;
        {
            unsigned shift = 7;
            unsigned char c = raw[pos++];
            stream_tag = static_cast<std::uint64_t>(c & 0x7fu);
            while ((c & 0x80u) != 0u) {
                if (pos >= raw_len || shift >= 63u) { ok = false; break; }
                c = raw[pos++];
                stream_tag += (static_cast<std::uint64_t>((c & 0x7fu) + 1u) << shift);
                shift += 7u;
            }
        }
        if (!ok) break;
        std::uint32_t chunk_type = static_cast<std::uint32_t>(stream_tag & 0x0fu);
        std::uint64_t chunk_size = stream_tag >> 4u;
        if (chunk_type == 15u) {  // extended stream-id form
            if (pos >= raw_len) { ok = false; break; }
            unsigned r = raw[pos++];
            if (r >= 0xf8u) {
                if (pos >= raw_len) { ok = false; break; }
                r = (r & 7u) + 8u * raw[pos++] + 248u;
            }
            chunk_type = r & 0x0fu;
            if ((r >> 4) == 0u) chunk_type += 15u;
        }
        if (chunk_size > raw_len - pos) { ok = false; break; }
        if (chunk_type != 0u) {
            // Metadata chunk between data chunks. One of these can be the entry's
            // CHECKSUM: it is a type-5 record, and it does NOT have to sit in the
            // contiguous metadata run at the front of the archive. A large -cc
            // archive emits an EMPTY type-5 placeholder up front and the real
            // 4-byte one after its first data chunk, which the front-of-archive
            // tag scan in TryParseLegacyCnArchive cannot see -- so the entry came
            // out with has_checksum == false and the gate below declined a decode
            // that was in fact byte-exact. Pick it up here instead.
            if ((chunk_type == 5u || chunk_type == 6u || chunk_type == 7u) &&
                !inline_checksum_seen) {
                if (chunk_size == 4u) {
                    inline_checksum = static_cast<std::uint32_t>(raw[pos]) |
                                      (static_cast<std::uint32_t>(raw[pos + 1]) << 8u) |
                                      (static_cast<std::uint32_t>(raw[pos + 2]) << 16u) |
                                      (static_cast<std::uint32_t>(raw[pos + 3]) << 24u);
                    inline_checksum_seen = true;
                } else if (chunk_size == 2u) {
                    inline_checksum = static_cast<std::uint32_t>(raw[pos]) |
                                      (static_cast<std::uint32_t>(raw[pos + 1]) << 8u);
                    inline_checksum_seen = true;
                }
                if (inline_checksum_seen && getenv("NZOPT_TRACE_TDO")) {
                    fprintf(stderr, "[TDCC] inline type-%u checksum record: 0x%08x\n",
                            chunk_type, inline_checksum);
                }
            }
            pos += static_cast<std::size_t>(chunk_size);
            continue;
        }
        const std::size_t stream_end = pos + static_cast<std::size_t>(chunk_size);

        while (pos < stream_end) {
        if (pos + 4u > stream_end) { ok = false; break; }
        const std::uint32_t payload_size =
            static_cast<std::uint32_t>(raw[pos]) |
            (static_cast<std::uint32_t>(raw[pos+1]) << 8u) |
            (static_cast<std::uint32_t>(raw[pos+2]) << 16u) |
            (static_cast<std::uint32_t>(raw[pos+3]) << 24u);
        pos += 4u;
        if (payload_size > stream_end - pos) { ok = false; break; }
        const std::uint8_t* payload = raw + pos;
        pos += payload_size;

        if (pos >= stream_end) { ok = false; break; }
        const std::uint8_t decr_param = raw[pos++];

        // decr_param 2 (audio) and 3 both use the TRUNCATED header that stops
        // right after size18 -- no staged-checksum count and none of the
        // param2/param1/param16/tt/dece fields (reference Header::Parse
        // early-returns for both). Reading them with the ordinary layout takes
        // mode2_type for param6 and then walks into the following record.
        if (decr_param == 2u || decr_param == 3u) {
            std::uint8_t mode2_type = 0;
            if (decr_param == 2u) {
                if (pos >= stream_end) { ok = false; break; }
                mode2_type = raw[pos++];
            }
            if (pos + 4u > stream_end) { ok = false; break; }
            const std::uint32_t alt_out_size =
                static_cast<std::uint32_t>(raw[pos]) |
                (static_cast<std::uint32_t>(raw[pos+1]) << 8u) |
                (static_cast<std::uint32_t>(raw[pos+2]) << 16u) |
                (static_cast<std::uint32_t>(raw[pos+3]) << 24u);
            pos += 4u;
            if (getenv("NZOPT_TRACE_TDO")) {
                fprintf(stderr, "[TDCC] block payload_size=%u decr_param=%u mode2_type=%u out_size=%u pos=%zu stream_end=%zu\n",
                        payload_size, decr_param, mode2_type, alt_out_size, pos, stream_end);
            }
            if (alt_out_size >
                static_cast<std::uint32_t>(legacy.total_data_size) -
                static_cast<std::uint32_t>(out_data->size())) { ok = false; break; }

            if (decr_param == 2u) {
                if (alt_out_size == 0u) continue;
                // An audio block resets the predictor only when mode2_type is set.
                if (const char* adp = getenv("NZOPT_DUMP_AUDIO")) {
                    FILE* f = fopen(adp, "wb");
                    if (f) { fwrite(payload, 1, payload_size, f); fclose(f); }
                    fprintf(stderr, "[TDCC] dumped audio payload (%u bytes, out_size=%u) to %s\n",
                            payload_size, alt_out_size, adp);
                }
                if (mode2_type) aud.Reset();
                std::vector<std::uint8_t> abuf(alt_out_size);
                const bool aok = aud.Decode(payload, payload_size, abuf.data(), alt_out_size);
                if (getenv("NZOPT_TRACE_TDO")) {
                    fprintf(stderr, "[TDCC] audio Decode(payload_size=%u out_size=%u) -> %d\n",
                            payload_size, alt_out_size, aok ? 1 : 0);
                }
                if (!aok) { ok = false; break; }
                // NOTE: the reference does not feed audio output through the CM
                // model. Our stored-block path does feed it (an empirically
                // established deviation -- see the long comment below), so if a
                // decr_param==0 CM block ever turns up after an audio block and
                // decodes wrong, this is the first place to look.
                out_data->insert(out_data->end(), abuf.begin(), abuf.end());
                continue;
            }

            // decr_param == 3: an ordinary CM block that must NOT reset the
            // model, carrying no post-filters at all.
            aud.Reset();
            if (alt_out_size == 0u) continue;
            std::vector<std::uint8_t> work3(alt_out_size);
            NzCmDecode(cm, payload, payload_size, work3.data(), alt_out_size);
            out_data->insert(out_data->end(), work3.begin(), work3.end());
            continue;
        }
        // Every non-audio block resets the audio predictor.
        aud.Reset();

        if (pos >= stream_end) { ok = false; break; }
        const std::uint8_t param6 = raw[pos++];

        std::uint32_t out_size = 0;
        if (param6) {
            if (pos + 4u > stream_end) { ok = false; break; }
            out_size =
                static_cast<std::uint32_t>(raw[pos]) |
                (static_cast<std::uint32_t>(raw[pos+1]) << 8u) |
                (static_cast<std::uint32_t>(raw[pos+2]) << 16u) |
                (static_cast<std::uint32_t>(raw[pos+3]) << 24u);
            pos += 4u;
        }

        // Skip staged checksums.
        if (pos >= stream_end) { ok = false; break; }
        const std::uint8_t staged_count = raw[pos++];
        if (pos + staged_count > stream_end) { ok = false; break; }
        pos += staged_count;

        // Read param2 flag + vector.
        if (pos >= stream_end) { ok = false; break; }
        const std::uint8_t param2_flag = raw[pos++];
        std::vector<std::uint8_t> param2_data;
        if (param2_flag) {
            if (pos + 4u > stream_end) { ok = false; break; }
            std::uint32_t vlen =
                static_cast<std::uint32_t>(raw[pos]) |
                (static_cast<std::uint32_t>(raw[pos+1]) << 8u) |
                (static_cast<std::uint32_t>(raw[pos+2]) << 16u) |
                (static_cast<std::uint32_t>(raw[pos+3]) << 24u);
            pos += 4u;
            if (pos + vlen > stream_end) { ok = false; break; }
            param2_data.assign(raw + pos, raw + pos + vlen);
            pos += vlen;
        }
        // Read param1 flag + vector.
        if (pos >= stream_end) { ok = false; break; }
        const std::uint8_t param1_flag = raw[pos++];
        std::vector<std::uint8_t> param1_data;
        if (param1_flag) {
            if (pos + 4u > stream_end) { ok = false; break; }
            std::uint32_t vlen =
                static_cast<std::uint32_t>(raw[pos]) |
                (static_cast<std::uint32_t>(raw[pos+1]) << 8u) |
                (static_cast<std::uint32_t>(raw[pos+2]) << 16u) |
                (static_cast<std::uint32_t>(raw[pos+3]) << 24u);
            pos += 4u;
            if (pos + vlen > stream_end) { ok = false; break; }
            param1_data.assign(raw + pos, raw + pos + vlen);
            pos += vlen;
        }
        // Skip param16.
        if (pos + 1u > stream_end) { ok = false; break; }
        pos++;
        // Read texttransformer_enabled.
        if (pos >= stream_end) { ok = false; break; }
        const std::uint8_t tt_enabled = raw[pos++];
        std::uint8_t tt_flags = 0;
        std::vector<std::uint8_t> tt2_data, tt16_data;
        if (tt_enabled) {
            if (pos >= stream_end) { ok = false; break; }
            tt_flags = raw[pos++];
            // Header.Parse order: tt2_data (if &2) then tt16_data (if &16).
            auto read_varint_str = [&](std::vector<std::uint8_t>& dst) -> bool {
                if (pos >= stream_end) return false;
                std::uint32_t n = 0, sh = 0;
                unsigned char vc;
                do {
                    if (pos >= stream_end) return false;
                    vc = raw[pos++];
                    n |= static_cast<std::uint32_t>(vc & 0x7fu) << sh;
                    sh += 7u;
                } while (vc & 0x80u);
                if (pos + n > stream_end) return false;
                dst.assign(raw + pos, raw + pos + n);
                pos += n;
                return true;
            };
            if ((tt_flags & 2u) && !read_varint_str(tt2_data)) { ok = false; break; }
            if ((tt_flags & 16u) && !read_varint_str(tt16_data)) { ok = false; break; }
        }
        // Read dece_param + its side stream.
        if (pos >= stream_end) { ok = false; break; }
        std::vector<std::uint8_t> dece_data;
        const std::uint8_t dece_param = raw[pos++];
        if (dece_param) {
            if (pos + 4u > stream_end) { ok = false; break; }
            std::uint32_t vlen =
                static_cast<std::uint32_t>(raw[pos]) |
                (static_cast<std::uint32_t>(raw[pos+1]) << 8u) |
                (static_cast<std::uint32_t>(raw[pos+2]) << 16u) |
                (static_cast<std::uint32_t>(raw[pos+3]) << 24u);
            pos += 4u;
            if (pos + vlen > stream_end) { ok = false; break; }
            dece_data.assign(raw + pos, raw + pos + vlen);
            pos += vlen;
        }

        // param6 == 0 marks a STORED block: the CM could not compress (e.g. high-
        // entropy / incompressible data), so the payload bytes are the raw output
        // verbatim. (The reference decoder rejects these with param6 != 1; the
        // linux32 binary stores them.)
        //
        // The CM model observes every byte of the decompressed *output* stream in
        // position order, not just the bytes it actually entropy-codes: its rolling
        // byte-history window/hash context (used for LZP-style match prediction)
        // must stay in sync with the true output position even across a stored
        // span, or a later decr_param==0 ("don't reset") CM block will decode
        // correctly for a while (its bit-level predictions are still individually
        // plausible) and then desync once the stale context finally drives a wrong
        // decision -- confirmed via a differential trace against an independently
        // built copy of the reference NZ_CM.cpp: feeding the stored bytes through
        // CM_Input_Bit (no entropy coding, model-update only) between two CM_Decode
        // calls made the second block's output round-trip byte-exact through
        // param2, where omitting the feed produced the same corruption this port
        // was producing. Feed the model here so any subsequent CM block sees the
        // context an unbroken pass over the file would have produced.
        if (!param6 || out_size == 0u) {
            for (std::uint32_t i = 0; i < payload_size; ++i) {
                NzCmFeedByte(cm, payload[i]);
            }
            out_data->insert(out_data->end(), payload, payload + payload_size);
            continue;
        }

        if (decr_param == 1u) NzCmReset(cm);

        // Reference DecodeFromStream pipeline (post CM decode):
        //   CM -> param2 (RLE u32 expand) -> param1 (AddBytes) -> text-transform
        //   -> dece (exe filter).  Decode CM into a working buffer, then apply the
        //   filters that are present in order. Filters not yet ported decline so
        //   the caller can fall back to the extract bridge.
        std::vector<std::uint8_t> work(out_size);
        NzCmDecode(cm, payload, payload_size, work.data(), out_size);
        std::uint32_t cur_size = out_size;

        const std::size_t prev_size = out_data->size();
        const std::uint32_t remaining =
            static_cast<std::uint32_t>(legacy.total_data_size) -
            static_cast<std::uint32_t>(prev_size);

        if (getenv("NZOPT_TRACE_TDO")) {
            fprintf(stderr, "[TDCC] pre-filters: decr_param=%u param6=%u param2_flag=%u param1_flag=%u "
                            "tt_enabled=%u tt_flags=%u out_size=%u pos=%zu stream_end=%zu\n",
                    decr_param, param6, param2_flag, param1_flag, tt_enabled, tt_flags, out_size, pos, stream_end);
        }
        // param2: u32-wise RLE expansion driven by the param2 side stream.
        if (param2_flag) {
            std::vector<std::uint8_t> exp(remaining);
            std::uint32_t esz = remaining;
            const bool p2ok = NzBwtRleDecodeU32(param2_data.data(),
                                   static_cast<std::uint32_t>(param2_data.size()),
                                   work.data(), cur_size, exp.data(), &esz);
            if (getenv("NZOPT_TRACE_TDO")) {
                fprintf(stderr, "[TDCC] param2: data.size=%zu cur_size=%u -> ok=%d esz=%u\n",
                        param2_data.size(), cur_size, p2ok ? 1 : 0, esz);
            }
            if (!p2ok || esz == 0u) { ok = false; break; }
            exp.resize(esz);
            work.swap(exp);
            cur_size = esz;
        }

        // param1: AddBytesFilter (delta filter, output size == input size).
        if (param1_flag) {
            std::vector<std::uint8_t> tbuf(cur_size);
            const bool p1ok = NzAddBytesFilter(param1_data.data(),
                                  static_cast<std::uint32_t>(param1_data.size()),
                                  work.data(), cur_size, tbuf.data());
            if (getenv("NZOPT_TRACE_TDO")) {
                fprintf(stderr, "[TDCC] param1: data.size=%zu cur_size=%u -> ok=%d\n",
                        param1_data.size(), cur_size, p1ok ? 1 : 0);
            }
            if (!p1ok) { ok = false; break; }
            work.swap(tbuf);
            // cur_size unchanged
        }

        // Text transforms, applied in reference order: 0x10 (number transform),
        // then 0x08 (dictionary), then 0x02 (insert-LF). Other bits
        // (0x80/0x04/0x20/0x40/0x01) not yet ported -> decline so the caller
        // can bridge.
        if (tt_enabled && (tt_flags & ~(0x10u | 0x08u | 0x04u | 0x02u | 0x20u | 0x01u))) { ok = false; break; }
        if (tt_enabled && (tt_flags & 0x10u)) {
            std::vector<std::uint8_t> tbuf(remaining);
            const std::uint32_t n = NzTextTransformNumber(
                tt16_data.data(), static_cast<std::uint32_t>(tt16_data.size()),
                work.data(), cur_size, tbuf.data(), remaining);
            if (n == 0) { ok = false; break; }
            tbuf.resize(n);
            work.swap(tbuf);
            cur_size = n;
        }
        if (tt_enabled && (tt_flags & 0x08u)) {
            // word-dict encoded; expand with dictionary transform.
            //
            // NzTextTransformDict's CopyDictEntWithCase (like the reference
            // TransformText_1_Dictionary it's ported from) writes a fixed
            // 8 or 16 bytes per multi-byte dict word starting at the word's
            // logical output position, even when the word itself is shorter
            // -- the reference relies on caller-provided output slack to
            // absorb that intentional over-write (bytes beyond the word's
            // true length get overwritten by the next characters anyway).
            // Found live via ASan while validating tt_flags&0x02 real-archive
            // fixtures: a short (~3-byte) final dict word landing at the
            // exact tail of a tight `remaining`-sized buffer over-wrote past
            // the vector's allocation, corrupting the heap allocator
            // (glibc "double free or corruption" on free). +16 bytes of
            // slack is more than the max possible per-word overshoot (7
            // bytes) and costs nothing since the buffer is resized down
            // immediately after.
            std::vector<std::uint8_t> tbuf(remaining + 16u);
            const std::uint32_t expanded = NzTextTransformDict(
                work.data(), cur_size, tbuf.data(), remaining);
            if (expanded == 0) { ok = false; break; }
            tbuf.resize(expanded);
            work.swap(tbuf);
            cur_size = expanded;
        }
        if (tt_enabled && (tt_flags & 0x04u)) {
            // HTML closing-tag restoration (NzTextTransformHtml). Reference
            // order puts 0x04 after the 0x08 dictionary and before 0x02.
            std::vector<std::uint8_t> tbuf(remaining);
            const std::uint32_t n = NzTextTransformHtml(work.data(), cur_size, tbuf.data(), remaining);
            if (n == 0) { ok = false; break; }
            tbuf.resize(n);
            work.swap(tbuf);
            cur_size = n;
        }
        if (tt_enabled && (tt_flags & 0x02u)) {
            // Insert-LF transform (NzTextTransformInsertLf, ported from
            // TransformText_3_InsertLF). Byte-count-preserving pure byte
            // post-filter driven by the tt2_data side stream.
            std::vector<std::uint8_t> tbuf(remaining);
            const std::uint32_t n = NzTextTransformInsertLf(
                tt2_data.data(), static_cast<std::uint32_t>(tt2_data.size()),
                work.data(), cur_size, tbuf.data(), remaining);
            if (n == 0) { ok = false; break; }
            tbuf.resize(n);
            work.swap(tbuf);
            cur_size = n;
        }

        if (tt_enabled && (tt_flags & 0x20u)) {
            // Escape+run-length repeat transform, the same codec-agnostic
            // function the optimum path already uses and has verified against
            // real archives. NOT verified for -cc specifically: no -cc archive
            // in a 60-file real corpus sets this bit, so there is no repro to
            // check. Wiring it can only help -- the reference applies 0x20
            // identically regardless of codec (no reorder_ascii_ dependency),
            // and a wrong result is caught by the entry checksum and declines
            // exactly as it does today.
            std::vector<std::uint8_t> tbuf(remaining);
            const std::uint32_t n = NzTextTransformRle(work.data(), cur_size, tbuf.data(), remaining);
            if (n == 0) { ok = false; break; }
            tbuf.resize(n);
            work.swap(tbuf);
            cur_size = n;
        }
        if (tt_enabled && (tt_flags & 0x01u)) {
            // CR/CRLF restoration -- LAST in the reference's chain (after 0x20
            // and 0x40). One byte of slack: the reference's output budget is
            // out_cap + 1 and it writes that extra byte before noticing the
            // overrun (see NzTextTransformCrToCrLf's header comment).
            std::vector<std::uint8_t> tbuf(static_cast<std::size_t>(remaining) + 1u);
            const std::uint32_t n = NzTextTransformCrToCrLf(work.data(), cur_size, tbuf.data(), remaining);
            if (n == 0) { ok = false; break; }
            tbuf.resize(n);
            work.swap(tbuf);
            cur_size = n;
        }

        if (dece_param) {
            // dece: x86 CALL/JMP address un-relativiser -- the LAST step of the
            // post-filter chain (reference DecodeFromStream: param2 -> param1 ->
            // text transforms -> dece). Output GROWS (4 bytes per restored
            // displacement, 3 more per add-esp), and since dece is last its
            // result IS the block final output, so `remaining` is the right cap.
            std::vector<std::uint8_t> tbuf(remaining);
            std::uint32_t n = 0;
            const bool dok = exe.Decode(dece_data.data(),
                                 static_cast<std::uint32_t>(dece_data.size()),
                                 work.data(), cur_size, tbuf.data(), remaining, &n);
            if (getenv("NZOPT_TRACE_TDO")) {
                fprintf(stderr, "[TDCC] dece: param=%u data=%zu in=%u -> %d out=%u\n",
                        dece_param, dece_data.size(), cur_size, dok ? 1 : 0, n);
            }
            if (!dok || n == 0u) { ok = false; break; }
            tbuf.resize(n); work.swap(tbuf); cur_size = n;
        } else {
            // No dece on this block: it breaks any run in progress.
            exe.Reset();
        }

        out_data->insert(out_data->end(), work.begin(), work.begin() + cur_size);
        }
    }

    NzCmDestroy(cm);

    if (getenv("NZOPT_TRACE_TDO")) {
        fprintf(stderr, "[TDCC] loop end: ok=%d pos=%zu raw_len=%zu out_data.size=%zu total_data_size=%llu\n",
                ok ? 1 : 0, pos, raw_len, out_data->size(),
                static_cast<unsigned long long>(legacy.total_data_size));
    }
    if (!ok) {
        out_data->clear();
        if (out_error_message) *out_error_message = "cm: malformed block stream";
        return false;
    }
    if (out_data->size() != static_cast<std::size_t>(legacy.total_data_size)) {
        out_data->clear();
        if (out_error_message) *out_error_message = "cm: output size mismatch";
        return false;
    }

    // Checksum self-verify, mirroring the sibling TryDecodeLegacyLzhd and
    if (const char* dp = getenv("NZOPT_DUMP_PRECHECK")) {
        FILE* f = fopen(dp, "wb");
        if (f) { fwrite(out_data->data(), 1, out_data->size(), f); fclose(f); }
        fprintf(stderr, "[TDCC] dumped pre-checksum output (%zu bytes) to %s\n", out_data->size(), dp);
    }

    // TryDecodeLegacyOptimum gates: a stored per-file checksum mismatch means
    // "decline and let the caller fall back to the bridge", never "emit it
    // anyway".
    //
    // This gate was missing until a real-world corpus sweep found the hole it
    // left. The caller's own CM handling cross-checks native output against a
    // bridge decode, but ONLY when a bridge is actually available -- with
    // NZ_NO_BRIDGE=1 (or simply no legacy binary present, which is this
    // project's whole goal) it took `cm_native_ok` at face value and emitted
    // whatever this function returned. Sweeping 56 real files x 8 methods
    // surfaced one archive (a ~10 MB game-data blob under -cc) where this
    // function returns true with 394113 wrong bytes, so the extractor wrote a
    // silently corrupt file instead of declining. Output size alone is not a
    // correctness signal for CM: the block framing can parse cleanly and the
    // sizes can add up exactly while the entropy-decoded content diverges.
    //
    // The underlying CM divergence on that archive is a separate, still-open
    // bug; this gate is what makes it a clean decline rather than corruption.
    if (legacy.checksum_verification_supported &&
        legacy.checksum_mode != ChecksumMode::kNone &&
        !legacy.entries.empty()) {
        std::size_t cursor = 0;
        if (getenv("NZOPT_TRACE_TDO")) {
            fprintf(stderr, "[TDCC] checksum gate: mode=%d entries=%zu outsize=%zu\n",
                    (int)legacy.checksum_mode, legacy.entries.size(), out_data->size());
        }
        for (const LegacyCnEntry& e : legacy.entries) {
            const std::size_t n = static_cast<std::size_t>(e.size);
            if (cursor + n > out_data->size()) break;
            if (getenv("NZOPT_TRACE_TDO")) {
                fprintf(stderr, "[TDCC]   entry: size=%zu has_cksum=%d cursor=%zu outsize=%zu\n",
                        n, (int)e.has_checksum, cursor, out_data->size());
            }
            std::uint32_t expected = e.checksum;
            if (!e.has_checksum) {
                // Fall back to a checksum record found mid-stream. Only for the
                // single-entry case: with several entries there is no way to tell
                // from here which entry a mid-stream record belongs to.
                if (!inline_checksum_seen || legacy.entries.size() != 1u) {
                    out_data->clear();
                    if (out_error_message) *out_error_message = "cm: entry missing checksum, declining";
                    return false;
                }
                expected = inline_checksum;
            }
            const std::uint32_t got =
                ComputeBufferChecksum(legacy.checksum_mode, out_data->data() + cursor, n);
            if (getenv("NZOPT_TRACE_TDO")) {
                fprintf(stderr, "[TDCC]   entry n=%zu expected=0x%08x computed=0x%08x %s\n",
                        n, expected, got, got == expected ? "OK" : "MISMATCH");
            }
            if (got != expected) {
                out_data->clear();
                if (out_error_message) *out_error_message = "cm: checksum mismatch";
                return false;
            }
            cursor += n;
        }
    }
    return true;
}

// Decode -co (nz_optimum1, method_p0==5) natively via NzOptimumLzDecoder
// (src/nz_optimum_lz.cpp, a byte-exact transcription of the real linux32/nz
// binary's FUN_0809e600) or -cO (nz_optimum2, method_p0==6) via
// NzOptimum2LzDecoder (src/nz_optimum2_lz.cpp, a byte-exact transcription of
// FUN_080a5d90) -- see include/nz_optimum_lz.h, include/nz_optimum2_lz.h, and
// work/reports/decomp_optimum/optimum_lz_core_ARCHITECTURE.md for the full RE
// provenance. This function's outer block-header framing (payload_size u32,
// decr_param, param6, size18, staged, params, tt, dece -- the same flat
// framing -cc uses) was already confirmed correct in an earlier session (the
// field walk lands exactly on stream_end/EOF for every fixture tried); what
// changed is the decr_param==1 payload decoder itself: it used to call
// NzLzhdDecode() (a port of the community reference's DecLZ), which live GDB
// tracing proved is never reached by the real binary for -co/-cO content.
// -co's real per-block LZ/CM core is FUN_0809e600, validated byte-exact
// against 4 isolated golden vectors (matchfix_co/bigdist_co/smalldist_co/
// hientropy_co -- see tests/test_optimum_lz.cpp) covering literal runs,
// small/large-distance matches (slots 0-18), rep-offset reuse, and a
// high-entropy literal stress segment. -cO's real per-block core is
// FUN_080a5d90 (a materially richer 8-input literal-mixer plus a rolling
// LZP-style secondary predictor -- the backbone is a byte-identical-formula
// scale-up of -co's own), validated byte-exact against 2 isolated golden
// vectors (aaa200_cO/hientropy_cO -- see tests/test_optimum2_lz.cpp)
// covering the same shapes as -co's own vectors plus all three of -cO's
// distance-tier footer-bit schedules (including tier3, only reachable with
// slot>6 / distance>=129).
//
// Scope: SINGLE-CONTAINER only (archive header flag 0x05 for -co, 0x06 for
// -cO) -- one decoder instance is constructed per call (i.e. per container
// stream) and threaded across every decr_param==1 block in this stream's
// sequence, matching the real binary's per-stream-persistent ring/adaptive-
// table state. Parallel-container -cO (flag 0x0f) remains out of scope and
// is declined here so it keeps routing to the bridge (parallel-container
// -co IS handled, but by a separate code path in TryParseLegacyCnArchive, not
// this function -- see its own comments). decr_param==0 (BWT) blocks are also
// not yet ported (either engine) and decline.
//
// Safety: every candidate is checksum-gated below (mirroring -cd/-cD/-cc's
// own self-verify pattern) before being trusted by the caller; any mismatch,
// malformed framing, or DecodeBlock-reported inconsistency cleanly declines
// (returns false) so RunLegacyCnExtractOrTest falls through to the bridge --
// never a partial/corrupt native result.
// Decode a sequence of -co (nz_optimum1) block records occupying
// [blocks_begin, blocks_end) within `raw` -- NO leading stream_tag (callers
// that have one, e.g. the single-container path below, must consume it
// first and pass just the block-sequence body that follows). Appends
// decoded bytes to *out_data, which may already contain bytes from a prior
// call against the same stream/decoder (e.g. a parallel stream whose data
// is split across more than one type-0 chunk record). `total_size_hint` is
// this stream's ultimate total decoded size -- used only to size the
// "remaining" scratch buffers the post-filters need; it does not by itself
// decide when decoding stops (the caller controls that via `blocks_end`).
// `dec` must already be constructed with this stream's window capacity and
// must be threaded across every call belonging to the same stream: its
// ring and every adaptive probability table persist across block
// boundaries (only the range coder and 4 rep-offsets reset per block).
// Templated on the per-engine decoder type so the exact same block-record
// framing/post-filter loop serves both -co (NzOptimumLzDecoder) and -cO
// (NzOptimum2LzDecoder) -- both expose the identical
// `bool DecodeBlock(in, in_len, out, out_size)` signature (see
// nz_optimum_lz.h / nz_optimum2_lz.h), differing only in which real-binary
// function ports the actual per-block LZ/CM engine.
template <typename OptimumDecoder>
static bool DecodeOptimumBlockSequence(
    const unsigned char* raw,
    std::size_t blocks_begin,
    std::size_t blocks_end,
    std::uint64_t total_size_hint,
    OptimumDecoder& dec,
    nzr::audio::NzAudioPred& audio,
    NzExeFilter& exe,
    std::vector<unsigned char>* out_data) {
    std::size_t pos = blocks_begin;
    const std::size_t stream_end = blocks_end;
    bool ok = true;

    while (pos < stream_end) {
        if (pos + 4u > stream_end) { ok = false; break; }
        const std::uint32_t payload_size =
            static_cast<std::uint32_t>(raw[pos]) |
            (static_cast<std::uint32_t>(raw[pos+1]) << 8u) |
            (static_cast<std::uint32_t>(raw[pos+2]) << 16u) |
            (static_cast<std::uint32_t>(raw[pos+3]) << 24u);
        pos += 4u;
        if (payload_size > stream_end - pos) { ok = false; break; }
        const std::uint8_t* payload = raw + pos;
        pos += payload_size;

        if (pos >= stream_end) { ok = false; break; }
        const std::uint8_t decr_param = raw[pos++];

        // decr_param 2 (audio) and 3 use a TRUNCATED header that stops right
        // after size18: no staged-checksum count, and none of the param2 /
        // param1 / param16 / text-transform / dece fields an ordinary block
        // carries (reference Header::Parse, which early-returns for both).
        // Parsing them with the ordinary layout reads mode2_type as param6 and
        // then walks off into the next record -- which is exactly why every
        // audio-bearing archive used to die before its first block trace.
        if (decr_param == 2u || decr_param == 3u) {
            std::uint8_t mode2_type = 0;
            if (decr_param == 2u) {
                if (pos >= stream_end) { ok = false; break; }
                mode2_type = raw[pos++];
            }
            if (pos + 4u > stream_end) { ok = false; break; }
            const std::uint32_t audio_out_size =
                static_cast<std::uint32_t>(raw[pos]) |
                (static_cast<std::uint32_t>(raw[pos+1]) << 8u) |
                (static_cast<std::uint32_t>(raw[pos+2]) << 16u) |
                (static_cast<std::uint32_t>(raw[pos+3]) << 24u);
            pos += 4u;
            if (getenv("NZOPT_TRACE_TDO")) {
                fprintf(stderr, "[TDO] block payload_size=%u decr_param=%u mode2_type=%u out_size=%u pos=%zu stream_end=%zu\n",
                        payload_size, decr_param, mode2_type, audio_out_size, pos, stream_end);
            }
            // decr_param == 3 is a CM-only shape: the reference dispatches it
            // to CM_Decode without a reset, and returns false for every
            // non-CM codec -- which is what the optimum family is.
            if (decr_param == 3u) { ok = false; break; }
            if (audio_out_size == 0u) continue;
            if (audio_out_size > total_size_hint - out_data->size()) { ok = false; break; }
            // An audio block resets the predictor only when mode2_type is set.
            if (const char* adp = getenv("NZOPT_DUMP_AUDIO")) {
                FILE* f = fopen(adp, "wb");
                if (f) { fwrite(payload, 1, payload_size, f); fclose(f); }
                fprintf(stderr, "[TDO] dumped audio payload (%u bytes, out_size=%u, mode2=%u) to %s\n",
                        payload_size, audio_out_size, mode2_type, adp);
            }
            if (mode2_type) audio.Reset();
            std::vector<std::uint8_t> abuf(audio_out_size);
            const bool aok = audio.Decode(payload, payload_size, abuf.data(), audio_out_size);
            if (getenv("NZOPT_TRACE_TDO")) {
                fprintf(stderr, "[TDO] audio Decode(payload_size=%u out_size=%u) -> %d\n",
                        payload_size, audio_out_size, aok ? 1 : 0);
            }
            if (!aok) { ok = false; break; }
            out_data->insert(out_data->end(), abuf.begin(), abuf.end());
            continue;
        }
        // Every non-audio block resets the audio predictor (reference
        // DecodeFromStream calls audio_pred->Reset() on the way past the
        // decr_param == 2 branch), so its state never carries across one.
        audio.Reset();

        if (pos >= stream_end) { ok = false; break; }
        const std::uint8_t param6 = raw[pos++];
        std::uint32_t out_size = 0;
        if (param6) {
            if (pos + 4u > stream_end) { ok = false; break; }
            out_size = static_cast<std::uint32_t>(raw[pos]) |
                (static_cast<std::uint32_t>(raw[pos+1]) << 8u) |
                (static_cast<std::uint32_t>(raw[pos+2]) << 16u) |
                (static_cast<std::uint32_t>(raw[pos+3]) << 24u);
            pos += 4u;
        }
        if (pos >= stream_end) { ok = false; break; }
        const std::uint8_t staged_count = raw[pos++];
        if (pos + staged_count > stream_end) { ok = false; break; }
        pos += staged_count;
        if (getenv("NZOPT_TRACE_TDO")) {
            fprintf(stderr, "[TDO] block payload_size=%u decr_param=%u param6=%u out_size=%u staged_count=%u pos=%zu stream_end=%zu\n",
                    payload_size, decr_param, param6, out_size, staged_count, pos, stream_end);
        }

        // BWT-only header fields. Per the reference Header::Parse, a non-CM
        // block with decr_param == 0 carries param7 (only when param6 is set),
        // the inverse-BWT start position, and params 14/15 -- all absent from
        // the decr_param == 1 (LZ) layout, which goes straight to param2.
        std::uint8_t bwt_param7 = 0;
        std::uint32_t bwt_start_pos = 0;
        std::uint8_t param14_flag = 0, param15_flag = 0;
        std::vector<std::uint8_t> param14_data, param15_data;
        auto read_u32vec = [&](std::vector<std::uint8_t>& dst) -> bool {
            if (pos + 4u > stream_end) return false;
            const std::uint32_t vlen = static_cast<std::uint32_t>(raw[pos]) |
                (static_cast<std::uint32_t>(raw[pos+1]) << 8u) |
                (static_cast<std::uint32_t>(raw[pos+2]) << 16u) |
                (static_cast<std::uint32_t>(raw[pos+3]) << 24u);
            pos += 4u;
            if (vlen > stream_end - pos) return false;
            dst.assign(raw + pos, raw + pos + vlen);
            pos += vlen;
            return true;
        };
        if (decr_param == 0u) {
            if (param6) {
                if (pos >= stream_end) { ok = false; break; }
                bwt_param7 = raw[pos++];
            }
            if (pos + 4u > stream_end) { ok = false; break; }
            bwt_start_pos = static_cast<std::uint32_t>(raw[pos]) |
                (static_cast<std::uint32_t>(raw[pos+1]) << 8u) |
                (static_cast<std::uint32_t>(raw[pos+2]) << 16u) |
                (static_cast<std::uint32_t>(raw[pos+3]) << 24u);
            pos += 4u;
            if (pos >= stream_end) { ok = false; break; }
            param14_flag = raw[pos++];
            if (param14_flag && !read_u32vec(param14_data)) { ok = false; break; }
            if (pos >= stream_end) { ok = false; break; }
            param15_flag = raw[pos++];
            if (param15_flag && !read_u32vec(param15_data)) { ok = false; break; }
            if (getenv("NZOPT_TRACE_TDO")) {
                fprintf(stderr, "[TDO] BWT hdr: param7=%u bwt_start_pos=%u param14=%u (%zu bytes) param15=%u (%zu bytes) pos=%zu\n",
                        bwt_param7, bwt_start_pos, param14_flag, param14_data.size(),
                        param15_flag, param15_data.size(), pos);
            }
        }

        if (pos >= stream_end) { ok = false; break; }
        const std::uint8_t param2_flag = raw[pos++];
        std::vector<std::uint8_t> param2_data;
        if (param2_flag) {
            if (pos + 4u > stream_end) { ok = false; break; }
            std::uint32_t vlen = static_cast<std::uint32_t>(raw[pos]) |
                (static_cast<std::uint32_t>(raw[pos+1]) << 8u) |
                (static_cast<std::uint32_t>(raw[pos+2]) << 16u) |
                (static_cast<std::uint32_t>(raw[pos+3]) << 24u);
            pos += 4u;
            if (pos + vlen > stream_end) { ok = false; break; }
            param2_data.assign(raw + pos, raw + pos + vlen);
            pos += vlen;
        }
        if (pos >= stream_end) { ok = false; break; }
        const std::uint8_t param1_flag = raw[pos++];
        std::vector<std::uint8_t> param1_data;
        if (param1_flag) {
            if (pos + 4u > stream_end) { ok = false; break; }
            std::uint32_t vlen = static_cast<std::uint32_t>(raw[pos]) |
                (static_cast<std::uint32_t>(raw[pos+1]) << 8u) |
                (static_cast<std::uint32_t>(raw[pos+2]) << 16u) |
                (static_cast<std::uint32_t>(raw[pos+3]) << 24u);
            pos += 4u;
            if (pos + vlen > stream_end) { ok = false; break; }
            param1_data.assign(raw + pos, raw + pos + vlen);
            pos += vlen;
        }
        if (pos + 1u > stream_end) { ok = false; break; }
        pos++;  // param16
        if (pos >= stream_end) { ok = false; break; }
        const std::uint8_t tt_enabled = raw[pos++];
        std::uint8_t tt_flags = 0;
        std::vector<std::uint8_t> tt16_data, tt2_data;
        if (tt_enabled) {
            if (pos >= stream_end) { ok = false; break; }
            tt_flags = raw[pos++];
            auto read_varint_str = [&](std::vector<std::uint8_t>& dst) -> bool {
                if (pos >= stream_end) return false;
                std::uint32_t n = 0, sh = 0; unsigned char vc;
                do {
                    if (pos >= stream_end) return false;
                    vc = raw[pos++];
                    n |= static_cast<std::uint32_t>(vc & 0x7fu) << sh; sh += 7u;
                } while (vc & 0x80u);
                if (pos + n > stream_end) return false;
                dst.assign(raw + pos, raw + pos + n); pos += n; return true;
            };
            if ((tt_flags & 2u) && !read_varint_str(tt2_data)) { ok = false; break; }
            if ((tt_flags & 16u) && !read_varint_str(tt16_data)) { ok = false; break; }
        }
        if (getenv("NZOPT_TRACE_TDO")) {
            fprintf(stderr, "[TDO] param2_flag=%u param1_flag=%u tt_enabled=%u tt_flags=%u tt16_data.size=%zu pos=%zu stream_end=%zu\n",
                    param2_flag, param1_flag, tt_enabled, tt_flags, tt16_data.size(), pos, stream_end);
        }
        if (pos >= stream_end) { ok = false; break; }
        std::vector<std::uint8_t> dece_data;
        const std::uint8_t dece_param = raw[pos++];
        if (dece_param) {
            if (pos + 4u > stream_end) { ok = false; break; }
            std::uint32_t vlen = static_cast<std::uint32_t>(raw[pos]) |
                (static_cast<std::uint32_t>(raw[pos+1]) << 8u) |
                (static_cast<std::uint32_t>(raw[pos+2]) << 16u) |
                (static_cast<std::uint32_t>(raw[pos+3]) << 24u);
            pos += 4u;
            if (vlen > stream_end - pos) { ok = false; break; }
            dece_data.assign(raw + pos, raw + pos + vlen);
            pos += vlen;
        }
        if (getenv("NZOPT_TRACE_TDO")) {
            fprintf(stderr, "[TDO] dece_param=%u pos=%zu stream_end=%zu param6=%u out_size=%u\n",
                    dece_param, pos, stream_end, param6, out_size);
        }

        // param6 == 0 means "this block has no compressed layer": the encoder
        // found the data incompressible, so there is no size18 field at all and
        // the block expands to exactly its own payload size. That holds for BOTH
        // block kinds the optimum family emits, which is visible in the
        // reference's own dispatch (NZ.cpp:997-1004): the decr_param == 0 branch
        // does `size = payload_size; memcpy(...)` and only applies the entropy
        // layer `if (header.param6)`. The decr_param == 1 branch reads
        // `size = header.size18` unconditionally -- but size18 is only ever
        // assigned under `if (param6)` and `Header` has no constructor, so with
        // param6 == 0 the reference is reading an UNINITIALISED field. It is UB
        // there, not a specification; the payload-size reading is what the real
        // binary does, and it is what makes the sizes add up (PowerPacker.pp:
        // 40492 total - 20091 from its two BWT blocks = 20401 = exactly this
        // block's payload size).
        //
        // Treating only the BWT kind as storable made a stored LZ block hit the
        // `continue` below: the block was skipped ENTIRELY while the sequence
        // reported success, so the stream came up short and the whole file was
        // declined with a misleading "decode failed".
        const bool stored_block = ((decr_param == 0u || decr_param == 1u) && param6 == 0u);
        const bool bwt_raw = (decr_param == 0u && param6 == 0u);
        if (!stored_block && (!param6 || out_size == 0u)) continue;

        if (const char* dpp = getenv("NZOPT_DUMP_PAYLOAD")) {
            FILE* f = fopen(dpp, "wb");
            fwrite(payload, 1, payload_size, f);
            fclose(f);
            fprintf(stderr, "[TDO] dumped payload (%u bytes) to %s, out_size=%u\n",
                    payload_size, dpp, out_size);
        }

        std::vector<std::uint8_t> work;
        std::uint32_t cur_size = 0;
        if (decr_param == 0u) {
            if (bwt_raw) {
                work.assign(payload, payload + payload_size);
                cur_size = payload_size;
            } else {
                // param6 == 1: the BWT output is entropy-coded (256
                // per-leading-symbol MTF/arith buckets). size18 is its size.
                work.resize(out_size);
                const bool bdi_ok = NzBwtDecodeInput(payload, payload_size, out_size, work.data());
                if (getenv("NZOPT_TRACE_TDO")) {
                    fprintf(stderr, "[TDO] BWT DecodeInput(payload_size=%u out_size=%u) -> %d\n",
                            payload_size, out_size, bdi_ok ? 1 : 0);
                }
                if (!bdi_ok) { ok = false; break; }
                cur_size = out_size;
            }
            const bool bwt_ok = NzBwtUntransform(work.data(), cur_size, bwt_start_pos);
            if (getenv("NZOPT_TRACE_TDO")) {
                fprintf(stderr, "[TDO] BWT raw untransform(size=%u bwt_start_pos=%u) -> %d\n",
                        cur_size, bwt_start_pos, bwt_ok ? 1 : 0);
            }
            if (!bwt_ok) { ok = false; break; }

            // params 14/15 run here: after the inverse BWT, before the shared
            // param2/param1/text-transform/dece chain (reference
            // DecodeFromStream lines 1009-1017).
            if (param14_flag) {
                // Output can grow: the transform expands LZ matches. Cap at
                // whatever this entry still has left to produce.
                const std::uint32_t cap =
                    static_cast<std::uint32_t>(total_size_hint) -
                    static_cast<std::uint32_t>(out_data->size());
                std::vector<std::uint8_t> t14(cap);
                std::uint32_t n14 = 0;
                const bool p14ok = NzBwtParam14(param14_data.data(),
                                       static_cast<std::uint32_t>(param14_data.size()),
                                       work.data(), cur_size, t14.data(), cap, &n14);
                if (getenv("NZOPT_TRACE_TDO")) {
                    fprintf(stderr, "[TDO] param14: data=%zu in=%u -> %d out=%u\n",
                            param14_data.size(), cur_size, p14ok ? 1 : 0, n14);
                }
                if (!p14ok || n14 == 0u) { ok = false; break; }
                t14.resize(n14); work.swap(t14); cur_size = n14;
            }
            if (param15_flag) {
                // param15 matches are ABSOLUTE offsets into the whole
                // accumulated output stream, so the window has to be
                // "everything decoded so far, with this block's current bytes
                // at the end". Splice this block onto out_data, run the
                // transform against that, then roll out_data back -- the
                // block's own result is appended by the shared tail below.
                const std::size_t prev = out_data->size();
                out_data->insert(out_data->end(), work.begin(), work.begin() + cur_size);
                const std::uint32_t cap =
                    static_cast<std::uint32_t>(total_size_hint) -
                    static_cast<std::uint32_t>(prev);
                std::vector<std::uint8_t> t15(cap);
                std::uint32_t n15 = 0;
                const bool p15ok = NzBwtParam15(param15_data.data(),
                                       static_cast<std::uint32_t>(param15_data.size()),
                                       out_data->data() + prev, cur_size,
                                       out_data->data(), out_data->size(),
                                       t15.data(), cap, &n15);
                out_data->resize(prev);
                if (getenv("NZOPT_TRACE_TDO")) {
                    fprintf(stderr, "[TDO] param15: data=%zu in=%u -> %d out=%u\n",
                            param15_data.size(), cur_size, p15ok ? 1 : 0, n15);
                }
                if (!p15ok || n15 == 0u) { ok = false; break; }
                t15.resize(n15); work.swap(t15); cur_size = n15;
            }

            // The window is the shared accumulated-block buffer in the
            // original, advanced by every block that writes into it -- a BWT
            // block included (reference: mem->data += size, right after
            // params 14/15 and before the post-filter chain). This port's ring
            // is otherwise only written by DecodeBlock, so feed it here or a
            // later LZ block whose match reaches back into this BWT output
            // reads stale ring bytes and fails.
            dec.FeedWindow(work.data(), cur_size);
        } else {
            // Decode this block's LZ/CM payload via the persistent per-stream
            // decoder. A false return means the bitstream produced a malformed
            // dispatch bit, an out-of-window match, or any other detected
            // inconsistency -- decline cleanly rather than trust a partially-
            // written buffer (DecodeBlock never touches `work` before it is
            // sure).
            if (stored_block) {
                // Stored LZ block: the payload IS the block output. It still has
                // to go through the window, exactly as the BWT branch above does
                // -- the original advances its shared accumulated-block buffer
                // for every block, so a later LZ block whose match reaches back
                // into this one must find these bytes there.
                work.assign(payload, payload + payload_size);
                cur_size = payload_size;
                dec.FeedWindow(work.data(), cur_size);
                if (getenv("NZOPT_TRACE_TDO")) {
                    fprintf(stderr, "[TDO] stored LZ block: payload_size=%u (param6=0, no size18)\n",
                            payload_size);
                }
            } else {
            work.resize(out_size);
            const bool decode_block_ok = dec.DecodeBlock(payload, payload_size, work.data(), out_size);
            if (getenv("NZOPT_TRACE_TDO")) {
                fprintf(stderr, "[TDO] DecodeBlock(payload_size=%u out_size=%u) -> %d\n",
                        payload_size, out_size, decode_block_ok ? 1 : 0);
            }
            if (!decode_block_ok) {
                ok = false; break;
            }
            cur_size = out_size;
            }
        }

        const std::size_t prev_size = out_data->size();
        const std::uint32_t remaining =
            static_cast<std::uint32_t>(total_size_hint) -
            static_cast<std::uint32_t>(prev_size);

        if (param2_flag) {
            std::vector<std::uint8_t> exp(remaining);
            std::uint32_t esz = remaining;
            if (!NzBwtRleDecodeU32(param2_data.data(),
                                   static_cast<std::uint32_t>(param2_data.size()),
                                   work.data(), cur_size, exp.data(), &esz)
                || esz == 0u) { ok = false; break; }
            exp.resize(esz); work.swap(exp); cur_size = esz;
        }
        // param1: AddBytesFilter (delta filter, output size == input size).
        // Same NzAddBytesFilter already used by -cc's TryDecodeLegacyCm --
        // shared post-filter, not codec-specific (the "not yet ported" gate
        // here was just never wired for the optimum family until now).
        if (param1_flag) {
            std::vector<std::uint8_t> tbuf(cur_size);
            const bool p1ok = NzAddBytesFilter(param1_data.data(),
                                  static_cast<std::uint32_t>(param1_data.size()),
                                  work.data(), cur_size, tbuf.data());
            if (getenv("NZOPT_TRACE_TDO")) {
                fprintf(stderr, "[TDO] param1: data.size=%zu cur_size=%u -> %d\n",
                        param1_data.size(), cur_size, p1ok ? 1 : 0);
            }
            if (!p1ok) { ok = false; break; }
            work.swap(tbuf);
            // cur_size unchanged
        }
        // Reference bit order (TextTransformer::TransformText): 0x80, 0x10,
        // 0x08, 4, 2, 0x20, 0x40, 1. Only 0x10/0x08/0x02/0x20 are ported so
        // far; any other bit set (0x80/4/0x40/1) declines cleanly.
        if (tt_enabled && (tt_flags & ~(0x10u | 0x08u | 0x04u | 0x02u | 0x20u | 0x01u))) { ok = false; break; }
        if (tt_enabled && (tt_flags & 0x10u)) {
            std::vector<std::uint8_t> tbuf(remaining + (1u << 16));
            const std::uint32_t n = NzTextTransformNumber(
                tt16_data.data(), static_cast<std::uint32_t>(tt16_data.size()),
                work.data(), cur_size, tbuf.data(), remaining + (1u << 16));
            if (n == 0) { ok = false; break; }
            tbuf.resize(n); work.swap(tbuf); cur_size = n;
        }
        if (tt_enabled && (tt_flags & 0x08u)) {
            // Non-CM codecs (optimum/lzhd, decparams type != 7) reorder the ASCII
            // alphabet before the dictionary transform (TextTransformer ctor sets
            // reorder_ascii_ = type != 7). Apply kReorderAscii in place first.
            static const std::uint8_t kReorderAscii[256] = {
                0,1,2,3,4,5,6,7,8,9,34,11,12,13,14,15, 16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,
                39,38,10,35,36,37,32,44,40,41,42,43,46,58,47,45, 48,49,50,51,52,53,54,55,56,57,33,59,60,61,62,63,
                64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79, 80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,
                96,115,107,122,110,109,112,118,100,120,99,106,108,114,103,104, 102,116,98,119,105,121,113,101,97,117,111,123,124,125,126,127,
                128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143, 144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159,
                160,161,162,163,164,165,166,167,168,169,170,171,172,173,174,175, 176,177,178,179,180,181,182,183,184,185,186,187,188,189,190,191,
                192,193,194,195,196,197,198,199,200,201,202,203,204,205,206,207, 208,209,210,211,212,213,214,215,216,217,218,219,220,221,222,223,
                224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239, 240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255
            };
            for (std::uint32_t i = 0; i < cur_size; ++i) work[i] = kReorderAscii[work[i]];
            // +16 bytes of slack: see the matching comment at the -cc
            // NzTextTransformDict call site above (CopyDictEntWithCase's
            // intentional fixed-width over-write needs caller-provided
            // headroom past the logical output size).
            std::vector<std::uint8_t> tbuf(remaining + 16u);
            const std::uint32_t n = NzTextTransformDict(work.data(), cur_size, tbuf.data(), remaining);
            if (n == 0) { ok = false; break; }
            tbuf.resize(n); work.swap(tbuf); cur_size = n;
        }
        if (tt_enabled && (tt_flags & 0x04u)) {
            // HTML closing-tag restoration (NzTextTransformHtml). Reference
            // order puts 0x04 after the 0x08 dictionary and before 0x02.
            std::vector<std::uint8_t> tbuf(remaining);
            const std::uint32_t n = NzTextTransformHtml(work.data(), cur_size, tbuf.data(), remaining);
            if (n == 0) { ok = false; break; }
            tbuf.resize(n); work.swap(tbuf); cur_size = n;
        }
        if (tt_enabled && (tt_flags & 0x02u)) {
            // Insert-LF transform (NzTextTransformInsertLf, ported from
            // TransformText_3_InsertLF -- see include/nz_text_transform.h).
            // Byte-count-preserving pure byte post-filter driven by the
            // tt2_data side stream (its own embedded arithmetic decoder,
            // independent of the CM/LZ entropy coder).
            std::vector<std::uint8_t> tbuf(remaining);
            const std::uint32_t n = NzTextTransformInsertLf(
                tt2_data.data(), static_cast<std::uint32_t>(tt2_data.size()),
                work.data(), cur_size, tbuf.data(), remaining);
            if (n == 0) { ok = false; break; }
            tbuf.resize(n); work.swap(tbuf); cur_size = n;
        }
        if (tt_enabled && (tt_flags & 0x20u)) {
            // Escape+run-length repeat transform (NzTextTransformRle, ported
            // from TransformText_4 -- see include/nz_text_transform.h). Pure
            // byte post-filter, no side-channel data, order-independent of
            // the entropy coder (verified against real -co archives whose
            // literal payload didn't warrant the word dictionary).
            std::vector<std::uint8_t> tbuf(remaining);
            const std::uint32_t n = NzTextTransformRle(work.data(), cur_size, tbuf.data(), remaining);
            if (n == 0) { ok = false; break; }
            tbuf.resize(n); work.swap(tbuf); cur_size = n;
        }
        if (tt_enabled && (tt_flags & 0x01u)) {
            // CR/CRLF restoration -- LAST in the reference's chain (after 0x20
            // and 0x40). One byte of slack: the reference's output budget is
            // out_cap + 1 and it writes that extra byte before noticing the
            // overrun (see NzTextTransformCrToCrLf's header comment).
            std::vector<std::uint8_t> tbuf(static_cast<std::size_t>(remaining) + 1u);
            const std::uint32_t n = NzTextTransformCrToCrLf(work.data(), cur_size, tbuf.data(), remaining);
            if (n == 0) { ok = false; break; }
            tbuf.resize(n); work.swap(tbuf); cur_size = n;
        }
        if (dece_param) {
            // dece: x86 CALL/JMP address un-relativiser -- the LAST step of the
            // post-filter chain (reference DecodeFromStream: param2 -> param1 ->
            // text transforms -> dece). Output GROWS (4 bytes per restored
            // displacement, 3 more per add-esp), and since dece is last its
            // result IS the block final output, so `remaining` is the right cap.
            std::vector<std::uint8_t> tbuf(remaining);
            std::uint32_t n = 0;
            const bool dok = exe.Decode(dece_data.data(),
                                 static_cast<std::uint32_t>(dece_data.size()),
                                 work.data(), cur_size, tbuf.data(), remaining, &n);
            if (getenv("NZOPT_TRACE_TDO")) {
                fprintf(stderr, "[TDO] dece: param=%u data=%zu in=%u -> %d out=%u\n",
                        dece_param, dece_data.size(), cur_size, dok ? 1 : 0, n);
            }
            if (!dok || n == 0u) { ok = false; break; }
            tbuf.resize(n); work.swap(tbuf); cur_size = n;
        } else {
            // No dece on this block: it breaks any run in progress.
            exe.Reset();
        }

        out_data->insert(out_data->end(), work.begin(), work.begin() + cur_size);
        if (getenv("NZOPT_TRACE_TDO")) {
            fprintf(stderr, "[TDO] after postfilters: cur_size=%u total_out_data=%zu total_data_size=%llu param2_flag=%u param1_flag=%u tt_enabled=%u tt_flags=%u dece_param=%u\n",
                    cur_size, out_data->size(), (unsigned long long)total_size_hint,
                    param2_flag, param1_flag, tt_enabled, tt_flags, dece_param);
        }
    }

    return ok;
}

static bool TryDecodeLegacyOptimum(
    const LegacyCnContext& legacy,
    std::vector<unsigned char>* out_data,
    std::string* out_error_message) {
    if (out_data == nullptr) return false;
    out_data->clear();

    if (legacy.legacy_method != 0x3bu ||
        (legacy.legacy_method_p0 != 5u && legacy.legacy_method_p0 != 6u))
        return false;
    if (legacy.data.empty()) return false;

    const auto* raw = legacy.data.data();
    const std::size_t raw_len = legacy.data.size();

    // Read one top-level `stream_tag` varint: (stream_bytes<<4)|0, giving the
    // byte range of one segment's block-record sequence. Real single-
    // container -co/-cO archives can contain MORE THAN ONE of these back to
    // back, directly concatenated with no separator/checksum record between
    // them (unlike -cf/-cd's own chain mode, which has an inter-segment
    // whole-output checksum) -- confirmed empirically on a real 60 KB .doc
    // file whose first segment only covered 10229 of the entry's 60416
    // declared output bytes: the very next byte was a second, independently
    // valid `stream_tag` varint (low nibble 0, in-bounds stream_bytes)
    // immediately following the first segment's end. An earlier RE session's
    // "chain mode doesn't exist for -co" conclusion was apparently reached
    // from insufficient (large-synthetic-file-only) fixtures.
    auto read_stream_tag = [raw, raw_len](std::size_t* p, std::uint64_t* out_tag) -> bool {
        unsigned shift = 7;
        if (*p >= raw_len) return false;
        unsigned char c = raw[(*p)++];
        std::uint64_t tag = static_cast<std::uint64_t>(c & 0x7fu);
        while ((c & 0x80u) != 0u) {
            if (*p >= raw_len || shift >= 63u) return false;
            c = raw[(*p)++];
            tag += (static_cast<std::uint64_t>((c & 0x7fu) + 1u) << shift);
            shift += 7u;
        }
        *out_tag = tag;
        return true;
    };

    // One persistent decoder for this whole (single-container) entry: its
    // ring/dictionary window and every adaptive probability table carry over
    // from one decr_param==1 block to the next -- INCLUDING across chain
    // segments, exactly like the real binary's per-container-stream
    // subengine object (there is only one such object for the whole entry,
    // not one per segment).
    const std::uint32_t window_capacity =
        nzr::optimum::NzOptimumLzWindowSizeFromP1(legacy.legacy_method_p1);
    if (window_capacity == 0u) return false;
    if (getenv("NZOPT_TRACE_TDO")) {
        fprintf(stderr, "[TDO] method_p1=%u window_capacity=%u total_data_size=%llu\n",
                legacy.legacy_method_p1, window_capacity,
                (unsigned long long)legacy.total_data_size);
    }
    out_data->reserve(static_cast<std::size_t>(legacy.total_data_size));
    // method_p0==5 -> -co (nz_optimum1, NzOptimumLzDecoder / FUN_0809e600);
    // method_p0==6 -> -cO (nz_optimum2, NzOptimum2LzDecoder / FUN_080a5d90).
    // Both share the exact same block-record framing/post-filter loop
    // (DecodeOptimumBlockSequence, templated on the decoder type) and the
    // same window-size-from-method_p1 formula -- only the per-block LZ/CM
    // engine construction differs. The decoder type is fixed for the whole
    // entry, so select it once via a small closure (mirrors the
    // parallel-container branch's own pattern below) rather than
    // duplicating the chain loop per type.
    const std::uint64_t total_size_hint = legacy.total_data_size;
    // One audio predictor per archive entry, shared across every chain
    // segment: the reference keeps a single global for the whole decode, and
    // its state is meant to survive from one segment's last block into the
    // next segment's first (subject to the per-block reset rule inside
    // DecodeOptimumBlockSequence).
    auto aud = std::make_shared<nzr::audio::NzAudioPred>();
    // Same flag byte as at the -cc site above: -co (p0 5) is the one codec of
    // the three whose bit 4 is SET, so it is the one that runs FUN_08096e20
    // (the LMS) instead of FUN_08096160 -- and reads two 3-bit shifts biased
    // +7 rather than two 4-bit shifts biased +0x10.
    aud->SetContextFlags(legacy.legacy_method_p0 == 5u ? 0x13u : 0x03u);
    if (legacy.legacy_method_p0 == 5u) { aud->SetPlaneOrders(64u, 8u, 8u); aud->SetStereoParam(4u); aud->SetBitcountVariantB(true); }   // -co
    else                               { aud->SetPlaneOrders(96u, 8u, 8u); aud->SetStereoParam(8u); }   // -cO
    // One exe filter per entry, same run/reset semantics as -cc above.
    auto exe = std::make_shared<NzExeFilter>();
    std::function<bool(std::size_t, std::size_t, std::vector<unsigned char>*)> decode_seq;
    if (legacy.legacy_method_p0 == 5u) {
        auto dec = std::make_shared<nzr::optimum::NzOptimumLzDecoder>(window_capacity);
        decode_seq = [raw, dec, aud, exe, total_size_hint](std::size_t b, std::size_t e, std::vector<unsigned char>* out) {
            return DecodeOptimumBlockSequence(raw, b, e, total_size_hint, *dec, *aud, *exe, out);
        };
    } else {
        auto dec = std::make_shared<nzr::optimum2::NzOptimum2LzDecoder>(window_capacity);
        decode_seq = [raw, dec, aud, exe, total_size_hint](std::size_t b, std::size_t e, std::vector<unsigned char>* out) {
            return DecodeOptimumBlockSequence(raw, b, e, total_size_hint, *dec, *aud, *exe, out);
        };
    }

    std::size_t seg_pos = 0;
    bool ok = true;
    while (out_data->size() < static_cast<std::size_t>(legacy.total_data_size)) {
        std::size_t p = seg_pos;
        std::uint64_t stream_tag = 0;
        if (!read_stream_tag(&p, &stream_tag)) { ok = false; break; }
        if ((stream_tag & 0x0fu) != 0u) { ok = false; break; }
        const std::uint64_t stream_bytes = stream_tag >> 4u;
        if (stream_bytes > raw_len - p) { ok = false; break; }
        const std::size_t stream_end = p + static_cast<std::size_t>(stream_bytes);
        if (getenv("NZOPT_TRACE_TDO")) {
            fprintf(stderr, "[TDO] chain segment: p=%zu stream_end=%zu out_data_size_before=%zu\n",
                    p, stream_end, out_data->size());
        }
        if (!decode_seq(p, stream_end, out_data)) { ok = false; break; }
        seg_pos = stream_end;
    }

    if (!ok || out_data->size() != static_cast<std::size_t>(legacy.total_data_size)) {
        out_data->clear();
        if (out_error_message) *out_error_message = "optimum: decode failed";
        return false;
    }

    if (const char* dp = getenv("NZOPT_DUMP_PRECHECK")) {
        // Pre-checksum dump: lets a failing decode be diffed against the
        // oracle even though the gate below is about to clear out_data.
        FILE* f = fopen(dp, "wb");
        if (f) { fwrite(out_data->data(), 1, out_data->size(), f); fclose(f); }
        fprintf(stderr, "[TDO] dumped pre-checksum output (%zu bytes) to %s\n", out_data->size(), dp);
    }

    // Checksum self-verify (mirrors TryDecodeLegacyLzhd's own gate above): a
    // stored per-file checksum mismatch means "decline, let the caller fall
    // back to the bridge" rather than "trust it anyway".
    //
    // History: an earlier pass through this session found a live,
    // reproducible bug in the literal 4-context mixer's ctxC seed formula
    // (NzOptimumLzDecoder::DecodeBlock, the `(local_81 & 1u) == 0u` branch
    // right after a match): on a real 246KB C++ source file
    // (arc_source.cpp.nz-style archive), byte 132408 decoded as 0x64 instead
    // of the correct 0x69, with the range-coder `code` register and every
    // mixer/rep-array input up to that point confirmed bit-for-bit identical
    // to the real linux32/nz binary via GDB, and `lo`/`hi` silently
    // diverging only after that literal. Root-caused via disassembly at
    // 0x0809eb9e-0x0809ebb5: the real binary computes
    // `signshift = (uint8_t)prevHi >> 7` (a `movzx eax,al` before the
    // `sar eax,7`, i.e. eax is always in [0,255], so the shift just extracts
    // bit 7 as 0/1) but this port instead sign-extended `prevHi` to
    // `int8_t` first, giving -1 instead of +1 whenever bit 7 was set --
    // fixed in-place (see the comment at that branch). Re-validated against
    // all 4 golden vectors, the previously-failing real archive, freshly
    // regenerated matchfix/bigdist/smalldist/hientropy engineered-repeat
    // archives, and tests/native_only_v2.sh with zero regressions, so the
    // checksum gate below now follows the same shape as the sibling
    // -cd/-cD/-cc gates (skip verification only when the archive truly
    // carries no usable checksum) rather than an extra-conservative
    // unconditional decline.
    if (legacy.checksum_verification_supported &&
        legacy.checksum_mode != ChecksumMode::kNone &&
        !legacy.entries.empty()) {
        std::size_t cursor = 0;
        for (const LegacyCnEntry& e : legacy.entries) {
            const std::size_t n = static_cast<std::size_t>(e.size);
            if (cursor + n > out_data->size()) break;
            if (!e.has_checksum) {
                out_data->clear();
                if (out_error_message) *out_error_message = "optimum: entry missing checksum, declining";
                return false;
            }
            const std::uint32_t got =
                ComputeBufferChecksum(legacy.checksum_mode, out_data->data() + cursor, n);
            if (got != e.checksum) {
                out_data->clear();
                if (out_error_message) *out_error_message = "optimum: checksum mismatch";
                return false;
            }
            cursor += n;
        }
    }
    return true;
}

// The original's decode banner and summary. It writes each status line over the
// previous one with a 79-space clear, reports the thread count it would use, names
// the compressor with its working-set size, and closes with a throughput line plus
// an IO line. Reproduced here so `nz_recon`'s console output diffs against `nz`'s.
// The working-set figure the original prints beside the compressor name. Ours is
// this port's own allocation for that engine -- the original's number comes from its
// own budgeting (it reports 13 MB where this engine allocates 0.3 MB), so this is
// the one field in the decode banner that is deliberately OUR value and not a clone.
std::uint64_t LegacyEngineWorkingSet(std::uint32_t method, std::uint32_t p0, std::uint32_t p1) {
    (void)p1;
    if (p0 == 0u) return 0u;   // store: the original reports [0 MB]
    if (method == 0x3bu) return (p0 == 6u) ? 0x1083080ull : 0x3f780ull;   // -cO / -co
    if (method == 0x4bu) return 0x2000000ull;                            // -cc
    if (method == 0x2bu) return 0x400000ull;                             // lzpf / lzhd family
    return 0x10000ull;
}

// Throughput unit, chosen the way the original does: it prints "6000 B/s" for a
// 6-byte decode and "55 KB/s" alongside it, i.e. the unit steps up past nine of the
// current one, matching the size column's rule.
std::string FormatRate(double bytes_per_second) {
    static const char* kU[] = {"B/s", "KB/s", "MB/s", "GB/s"};
    double v = bytes_per_second;
    int i = 0;
    while (i < 3 && v > 9.0 * 1024.0) { v /= 1024.0; ++i; }
    char b[64];
    std::snprintf(b, sizeof(b), "%.0f %s", v, kU[i]);
    return std::string(b);
}

double ElapsedSince(const std::chrono::steady_clock::time_point& t0) {
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
}

// The original's compression banner and summary. Shapes matched exactly; the
// memory/IO-buffer figures are this port's own (it does not implement the original's
// buffer budgeting), and `bpb` is out*8/(in+1) -- fitted to five measured samples,
// two of which rule out the obvious out*8/in (6 -> 55 prints 62.857 = 55*8/7, and
// 100 -> 154 prints 12.198 = 154*8/101).
void PrintEncodeHeader(std::ostream& os, const std::string& archive_path,
                       const std::string& compressor_name, std::uint64_t engine_bytes,
                       unsigned memory_mb, unsigned read_mb, unsigned write_mb, bool verbose) {
    os << "Archive: " << archive_path << '\n';
    os << "Threads: " << HostThreadCount() << ", memory: " << memory_mb
       << " MB, IO-buffers: " << read_mb << '+' << write_mb << " MB\n";
    if (verbose) os << "Setting up IO write buffer: " << write_mb << " MB\n";
    ClearStatusLine(os);
    os << "Compressor #0: " << compressor_name << " ["
       << ((engine_bytes + 512u * 1024u) / (1024u * 1024u)) << " MB]";
    if (verbose) os << " IO-buffer: " << read_mb << " MB.";
    os << '\n';
}

void PrintEncodeFooter(std::ostream& os, std::uint64_t in_bytes, std::uint64_t out_bytes,
                       double seconds, bool verbose) {
    const double bps = (seconds > 0.0) ? (double)in_bytes / seconds : 0.0;
    char buf[224];
    ClearStatusLine(os);
    // Note: no trailing period on this line in the original; the IO line has one.
    std::snprintf(buf, sizeof(buf), "Compressed %s into %s in %.2fs, %s",
                  FormatGrouped(in_bytes).c_str(), FormatGrouped(out_bytes).c_str(),
                  seconds, FormatRate(bps).c_str());
    os << buf;
    if (verbose) {
        std::snprintf(buf, sizeof(buf), " (%.3f bpb)",
                      (double)out_bytes * 8.0 / (double)(in_bytes + 1u));
        os << buf;
    }
    os << '\n';
    std::snprintf(buf, sizeof(buf), "IO-in: %.2fs, %s.", seconds, FormatRate(bps).c_str());
    os << buf << '\n';
}

void PrintDecodeHeader(std::ostream& os, const std::string& archive_path,
                       const std::string& compressor_label, std::uint64_t engine_bytes) {
    os << "Archive: " << archive_path << '\n';
    os << "Threads: " << HostThreadCount() << '\n';
    ClearStatusLine(os);
    os << "Compressor #0: " << compressor_label << " ["
       << ((engine_bytes + 512u * 1024u) / (1024u * 1024u)) << " MB]\n";
}

// `<name>` then five spaces, then the running figure rewritten in place: back four,
// four characters, four spaces -- and eight backspaces once the file is done. This
// is the original's exact cursor dance.
// The four-character field the original rewrites in place: megabytes done.
std::string FormatSizeColumnCompact(std::uint64_t bytes) {
    char b[32];
    std::snprintf(b, sizeof(b), "%llu MB", (unsigned long long)(bytes / (1024u * 1024u)));
    return std::string(b);
}

void PrintFileProgress(std::ostream& os, const std::string& name, const std::string& field4) {
    ClearStatusLine(os);
    os << name << "     " << "\b\b\b\b" << field4 << "    " << "\b\b\b\b\b\b\b\b";
    os.flush();
}

void PrintDecodeFooter(std::ostream& os, std::uint64_t bytes, double seconds) {
    const double bps = (seconds > 0.0) ? (double)bytes / seconds : 0.0;
    char buf[192];
    ClearStatusLine(os);
    std::snprintf(buf, sizeof(buf), "Decompressed %s bytes in %.2fs, %s.",
                  FormatGrouped(bytes).c_str(), seconds, FormatRate(bps).c_str());
    os << buf << '\n';
    std::snprintf(buf, sizeof(buf), "IO-in: %.2fs, %s.", seconds, FormatRate(bps).c_str());
    os << buf << '\n';
}

int RunLegacyCnExtractOrTest(
    const CliOptions& options,
    const LegacyCnContext& legacy,
    bool test_mode,
    std::ostream& os) {
    const auto run_start = std::chrono::steady_clock::now();
    bool header_printed = false;
    if (!legacy.native_payload_supported) {
        std::vector<unsigned char> bridged_data;
        std::string lzhd_decode_error;
        if (TryDecodeLegacyLzhd(legacy, &bridged_data, &lzhd_decode_error)) {
            LegacyCnContext bridged = legacy;
            bridged.native_payload_supported = true;
            bridged.data_offset = 0u;
            bridged.data = std::move(bridged_data);
            if (options.verbose) {
                os << "[native] decoded -cd payload natively ("
                   << LegacyCompressorLabel(legacy.legacy_method, legacy.legacy_method_p0, legacy.legacy_method_p1)
                   << ").\n";
            }
            return RunLegacyCnExtractOrTest(options, bridged, test_mode, os);
        }
        // Native -co (nz_optimum1, method_p0==5, single-container flag 0x05)
        // AND -cO (nz_optimum2, method_p0==6, single-container flag 0x06) via
        // TryDecodeLegacyOptimum, backed by NzOptimumLzDecoder (a byte-exact
        // port of the real binary's FUN_0809e600) or NzOptimum2LzDecoder (a
        // byte-exact port of FUN_080a5d90) respectively -- see
        // tests/test_optimum_lz.cpp / tests/test_optimum2_lz.cpp and
        // work/reports/decomp_optimum/optimum_lz_core_ARCHITECTURE.md. This
        // supersedes the long-standing "wrong decoder" finding from an earlier
        // session (NzLzhdDecode/DecLZ is never reached by a real -co decode;
        // the real per-block core is FUN_0809e600, not FUN_080b5240).
        // TryDecodeLegacyOptimum checksum-gates its own result internally
        // (mirroring TryDecodeLegacyLzhd immediately above), so a mismatch or
        // any malformed-bitstream/out-of-window condition already declines
        // before reaching here -- no extra bridge cross-check needed.
        // Parallel-container -cO (flag 0x0f) and decr_param==0 (BWT, either
        // engine) remain unported and continue to route to the bridge below,
        // as does the parallel-container case for -co (TryDecodeLegacyOptimum
        // only parses a single stream_tag's worth of blocks; parallel-
        // container framing would fail that parse and decline harmlessly, or
        // in the unlikely event it doesn't, the checksum gate still catches
        // it).
        std::string optimum_decode_error;
        std::vector<unsigned char> optimum_native_data;
        if (TryDecodeLegacyOptimum(legacy, &optimum_native_data, &optimum_decode_error)) {
            LegacyCnContext bridged = legacy;
            bridged.native_payload_supported = true;
            bridged.data_offset = 0u;
            bridged.data = std::move(optimum_native_data);
            if (options.verbose) {
                os << "[native] decoded " << (legacy.legacy_method_p0 == 6u ? "-cO" : "-co")
                   << " payload natively ("
                   << LegacyCompressorLabel(legacy.legacy_method, legacy.legacy_method_p0, legacy.legacy_method_p1)
                   << ").\n";
            }
            return RunLegacyCnExtractOrTest(options, bridged, test_mode, os);
        } else if (options.verbose && !optimum_decode_error.empty()) {
            os << "[native] " << (legacy.legacy_method_p0 == 6u ? "-cO" : "-co")
               << " native decode declined: " << optimum_decode_error << '\n';
        }
        std::string cm_decode_error;
        std::vector<unsigned char> cm_native_data;
        const bool cm_native_ok = TryDecodeLegacyCm(legacy, &cm_native_data, &cm_decode_error);
        // Verify the native CM output against the legacy extract bridge before trusting
        // it. The native CM decoder currently has a known architectural mismatch with
        // the legacy decoder for short inputs (4-byte patterns repeated 3+ times), and
        // that mismatch surfaces as a silent data corruption that only the downstream
        // checksum would catch. Full-buffer comparison: if any byte differs, fall
        // through to the extract bridge path so the user gets byte-exact output.
        // The cross-check is skipped when the extract bridge is disabled (NZ_DISABLE_
        // EXTRACT_BRIDGE) to preserve the legacy fast path in CI.
        // The CM mixing bug (factors0_err arithmetic-shift port error) was fixed
        // 2026-06-08, so native CM is byte-exact for the general case. The bridge
        // cross-check is kept as a safety net ONLY when the bridge is available
        // (catches any residual edge case, e.g. tt16 word-list / stereo CM). When
        // the bridge is disabled (NZ_NO_BRIDGE), trust the native result directly.
        bool cm_verified = false;
        if (cm_native_ok
            && !LegacyBridgeDisabled()
            && std::getenv("NZ_DISABLE_EXTRACT_BRIDGE") == nullptr
            && !legacy.entries.empty()
            && legacy.total_data_size > 0u) {
            std::vector<unsigned char> bridge_data;
            std::string verify_error;
            if (TryDecodeLegacyWithExtractBridge(legacy, &bridge_data, &verify_error)) {
                if (cm_native_data.size() == bridge_data.size()
                    && std::memcmp(cm_native_data.data(), bridge_data.data(),
                                   cm_native_data.size()) == 0) {
                    cm_verified = true;
                } else if (options.verbose) {
                    os << "[native] CM native output differs from legacy; "
                          "falling back to extract bridge.\n";
                }
            }
        } else if (cm_native_ok) {
            cm_verified = true;
        }
        if (cm_verified) {
            bridged_data = std::move(cm_native_data);
            LegacyCnContext bridged = legacy;
            bridged.native_payload_supported = true;
            bridged.data_offset = 0u;
            bridged.data = std::move(bridged_data);
            if (options.verbose) {
                os << "[native] decoded -cc payload natively ("
                   << LegacyCompressorLabel(legacy.legacy_method, legacy.legacy_method_p0, legacy.legacy_method_p1)
                   << ").\n";
            }
            return RunLegacyCnExtractOrTest(options, bridged, test_mode, os);
        }
        std::string extract_bridge_error;
        if (TryDecodeLegacyWithExtractBridge(legacy, &bridged_data, &extract_bridge_error)) {
            LegacyCnContext bridged = legacy;
            bridged.native_payload_supported = true;
            bridged.data_offset = 0u;
            bridged.data = std::move(bridged_data);
            if (options.verbose) {
                os << "[bridge] decoded legacy payload via extract bridge ("
                   << LegacyCompressorLabel(legacy.legacy_method, legacy.legacy_method_p0, legacy.legacy_method_p1)
                   << ").\n";
            }
            return RunLegacyCnExtractOrTest(options, bridged, test_mode, os);
        }
        std::string gdb_bridge_error;
        if (TryDecodeLegacyWithGdbBridge(legacy, &bridged_data, &gdb_bridge_error)) {
            LegacyCnContext bridged = legacy;
            bridged.native_payload_supported = true;
            bridged.data_offset = 0u;
            bridged.data = std::move(bridged_data);
            if (options.verbose) {
                os << "[bridge] decoded legacy payload via gdb trace bridge ("
                   << LegacyCompressorLabel(legacy.legacy_method, legacy.legacy_method_p0, legacy.legacy_method_p1)
                   << ").\n";
            }
            return RunLegacyCnExtractOrTest(options, bridged, test_mode, os);
        }
        if (options.verbose) {
            if (!extract_bridge_error.empty()) {
                os << "[bridge] extract bridge failed: " << extract_bridge_error << '\n';
            }
            if (!gdb_bridge_error.empty()) {
                os << "[bridge] gdb bridge failed: " << gdb_bridge_error << '\n';
            }
        }
        return kLegacyNeedCompat;
    }
    if (legacy.total_data_size != legacy.data.size()) {
        os << "Data corrupted while reading file payload.\n";
        return 2;
    }

    const fs::path output_root = options.output_path.empty() ? fs::current_path() : fs::path(options.output_path);

    std::size_t processed = 0;
    std::size_t failed = 0;
    std::uint64_t bytes_ok = 0;
    std::size_t cursor = 0;

    if (!header_printed) {
        header_printed = true;
        PrintDecodeHeader(os, legacy.archive_path,
                          LegacyCompressorName(legacy.legacy_method, legacy.legacy_method_p0),
                          LegacyEngineWorkingSet(legacy.legacy_method, legacy.legacy_method_p0,
                                                 legacy.legacy_method_p1));
    }
    for (const LegacyCnEntry& e : legacy.entries) {
        if (cursor > legacy.data.size() || e.size > legacy.data.size() - cursor) {
            os << "Data corrupted while reading file payload: " << e.path << '\n';
            return 2;
        }

        const bool selected = MatchesAnyPattern(e.path, options.positional);
        const unsigned char* ptr = legacy.data.data() + cursor;
        const std::size_t n = static_cast<std::size_t>(e.size);
        cursor += n;

        if (!selected) {
            continue;
        }

        if (e.has_checksum && legacy.checksum_verification_supported &&
            options.checksum != ChecksumMode::kNone) {
            const std::uint32_t got = ComputeBufferChecksum(legacy.checksum_mode, ptr, n);
            if (got != e.checksum) {
                os << "Checksum mismatch: " << e.path << " (expected "
                   << FormatChecksum(legacy.checksum_mode, e.checksum) << ", got "
                   << FormatChecksum(legacy.checksum_mode, got) << ")\n";
                ++failed;
                continue;
            }
        }

        if (!test_mode) {
            const fs::path safe_rel = SanitizeExtractPath(e.path);
            if (safe_rel.empty()) {
                os << "Skipping unsafe path in archive: " << e.path << '\n';
                ++failed;
                continue;
            }

            const fs::path out_path = output_root / safe_rel;
            std::error_code ec;
            if (out_path.has_parent_path()) {
                fs::create_directories(out_path.parent_path(), ec);
            }
            if (!WriteExtractedFile(out_path, ptr, n,
                                    e.has_permissions ? e.permissions : 0600u)) {
                os << "Cannot write output file: " << out_path.string() << '\n';
                ++failed;
                continue;
            }

            if (e.has_mtime && !SetExtractedMtime(out_path, e.mtime_unix) &&
                options.verbose) {
                os << "Warning: cannot apply mtime to " << out_path.string() << '\n';
            }
        }

        PrintFileProgress(os, e.path, FormatSizeColumnCompact(e.size));

        ++processed;
        bytes_ok += e.size;
        if (options.verbose) {
            ClearStatusLine(os);
            os << (test_mode ? "tested " : "extract ") << e.path << '\n';
        }
    }

    if (failed > 0) {
        ClearStatusLine(os);
        os << (test_mode ? "Tested " : "Extracted ") << processed << " files, "
           << FormatGrouped(bytes_ok) << " bytes. Failures: " << failed << ".\n";
    } else {
        PrintDecodeFooter(os, bytes_ok, ElapsedSince(run_start));
    }

    return failed == 0 ? 0 : 2;
}

}  // namespace

ArchiveOpenError OpenArchive(
    const std::string& archive_path,
    ArchiveContext* out_context,
    std::string* out_error_message) {
    std::ifstream input(archive_path, std::ios::binary);
    if (!input) {
        if (out_error_message != nullptr) {
            *out_error_message = "Cannot open archive!";
        }
        return ArchiveOpenError::kCannotOpen;
    }

    std::array<unsigned char, 2> magic{};
    input.read(reinterpret_cast<char*>(magic.data()), static_cast<std::streamsize>(magic.size()));
    if (input.gcount() != static_cast<std::streamsize>(magic.size()) || magic != kMagicPrefix) {
        if (out_error_message != nullptr) {
            *out_error_message = "File is not a NanoZip archive.";
        }
        return ArchiveOpenError::kNotNanoZip;
    }

    std::string signature(kKnownSignatureBytes, '\0');
    input.read(&signature[0], static_cast<std::streamsize>(signature.size()));
    if (input.gcount() != static_cast<std::streamsize>(signature.size()) ||
        signature.rfind(kKnownSignaturePrefix, 0) != 0) {
        if (out_error_message != nullptr) {
            *out_error_message = "File is not a NanoZip archive.";
        }
        return ArchiveOpenError::kNotNanoZip;
    }

    unsigned version_major = 0;
    unsigned version_minor = 0;
    if (!ParseVersionFromSignature(signature, &version_major, &version_minor)) {
        if (out_error_message != nullptr) {
            *out_error_message = "File is not a NanoZip archive.";
        }
        return ArchiveOpenError::kNotNanoZip;
    }

    if (version_major > kSupportedMajor ||
        (version_major == kSupportedMajor && version_minor > kSupportedMinor)) {
        if (out_error_message != nullptr) {
            std::ostringstream oss;
            oss << "Archive file is made with incompatible version (" << version_major << '.';
            if (version_minor < 10) {
                oss << '0';
            }
            oss << version_minor << ").";
            *out_error_message = oss.str();
        }
        return ArchiveOpenError::kIncompatibleVersion;
    }

    std::array<char, 4> marker{};
    input.read(marker.data(), static_cast<std::streamsize>(marker.size()));
    if (input.gcount() != static_cast<std::streamsize>(marker.size())) {
        if (out_error_message != nullptr) {
            *out_error_message = "Data corrupted while reading headers!";
        }
        return ArchiveOpenError::kCorrupt;
    }

    if (marker != kReconMarker) {
        if (out_error_message != nullptr) {
            *out_error_message = "Archive layout is not reconstructed yet (legacy NanoZip stream).";
        }
        return ArchiveOpenError::kUnsupportedFormat;
    }

    std::uint8_t recon_major = 0;
    std::uint8_t recon_minor = 0;
    std::uint8_t flags = 0;
    std::uint8_t checksum_mode = 0;
    std::uint8_t compressor = 0;
    std::uint8_t reserved = 0;
    std::uint16_t reserved2 = 0;
    std::uint32_t entry_count = 0;

    if (!ReadLE(input, &recon_major) || !ReadLE(input, &recon_minor) || !ReadLE(input, &flags) ||
        !ReadLE(input, &checksum_mode) || !ReadLE(input, &compressor) || !ReadLE(input, &reserved) ||
        !ReadLE(input, &reserved2) || !ReadLE(input, &entry_count)) {
        if (out_error_message != nullptr) {
            *out_error_message = "Data corrupted while reading headers!";
        }
        return ArchiveOpenError::kCorrupt;
    }

    ArchiveContext ctx;
    ctx.archive_path = archive_path;
    ctx.header.signature = signature;
    ctx.header.version_major = static_cast<std::uint8_t>(version_major);
    ctx.header.version_minor = static_cast<std::uint8_t>(version_minor);
    ctx.header.reconstructed_layout = true;
    ctx.header.recon_format_major = recon_major;
    ctx.header.recon_format_minor = recon_minor;
    ctx.header.compressor = static_cast<Compressor>(compressor);
    ctx.header.checksum = static_cast<ChecksumMode>(checksum_mode);
    ctx.header.has_timestamps = (flags & kFlagHasTimestamps) != 0;
    ctx.header.has_permissions = (flags & kFlagHasPermissions) != 0;

    if (entry_count > 1000000u) {
        if (out_error_message != nullptr) {
            *out_error_message = "Data corrupted while reading headers!";
        }
        return ArchiveOpenError::kCorrupt;
    }

    ctx.entries.reserve(entry_count);
    for (std::uint32_t i = 0; i < entry_count; ++i) {
        std::uint16_t name_len = 0;
        if (!ReadLE(input, &name_len)) {
            if (out_error_message != nullptr) {
                *out_error_message = "Data corrupted while reading headers!";
            }
            return ArchiveOpenError::kCorrupt;
        }

        std::string name(name_len, '\0');
        if (name_len > 0) {
            input.read(&name[0], static_cast<std::streamsize>(name_len));
            if (input.gcount() != static_cast<std::streamsize>(name_len)) {
                if (out_error_message != nullptr) {
                    *out_error_message = "Data corrupted while reading headers!";
                }
                return ArchiveOpenError::kCorrupt;
            }
        }

        ArchiveEntry e;
        e.path = name;

        if (!ReadLE(input, &e.original_size) || !ReadLE(input, &e.stored_size) || !ReadLE(input, &e.permissions) ||
            !ReadLE(input, &e.mtime_unix) || !ReadLE(input, &e.checksum) || !ReadLE(input, &e.method)) {
            if (out_error_message != nullptr) {
                *out_error_message = "Data corrupted while reading headers!";
            }
            return ArchiveOpenError::kCorrupt;
        }

        std::array<char, 7> entry_reserved{};
        input.read(entry_reserved.data(), static_cast<std::streamsize>(entry_reserved.size()));
        if (input.gcount() != static_cast<std::streamsize>(entry_reserved.size())) {
            if (out_error_message != nullptr) {
                *out_error_message = "Data corrupted while reading headers!";
            }
            return ArchiveOpenError::kCorrupt;
        }

        ctx.entries.push_back(std::move(e));
    }

    const std::streamoff data_offset = input.tellg();
    if (data_offset < 0) {
        if (out_error_message != nullptr) {
            *out_error_message = "Data corrupted while reading headers!";
        }
        return ArchiveOpenError::kCorrupt;
    }
    ctx.data_offset = static_cast<std::uint64_t>(data_offset);

    input.seekg(0, std::ios::end);
    const std::streamoff end_offset = input.tellg();
    if (end_offset < 0) {
        if (out_error_message != nullptr) {
            *out_error_message = "Data corrupted while reading headers!";
        }
        return ArchiveOpenError::kCorrupt;
    }

    std::uint64_t needed = ctx.data_offset;
    for (const ArchiveEntry& e : ctx.entries) {
        needed += e.stored_size;
        if (needed > static_cast<std::uint64_t>(end_offset)) {
            if (out_error_message != nullptr) {
                *out_error_message = "Data corrupted while reading headers!";
            }
            return ArchiveOpenError::kCorrupt;
        }
    }

    if (out_context != nullptr) {
        *out_context = std::move(ctx);
    }
    if (out_error_message != nullptr) {
        out_error_message->clear();
    }
    return ArchiveOpenError::kNone;
}

bool ShouldUseLegacyBackend(const CliOptions& options) {
    if (options.command == Command::kW32c) {
        return false;
    }

    if (!options.unknown_switches.empty()) {
        return true;
    }

    const bool internal_bridge_supported = (options.compressor != Compressor::kNone);
    if ((options.command == Command::kAdd || options.command == Command::kSimulate) &&
        options.compressor != Compressor::kNone &&
        !internal_bridge_supported) {
        return true;
    }

    return false;
}

bool TryRunLegacyBackend(const CliOptions& options, std::ostream& os, int* exit_code) {
    const fs::path backend = FindLegacyBackend();
    if (backend.empty()) {
        return false;
    }

    os << "[compat] forwarding command to legacy backend: " << backend.string() << '\n' << std::flush;
    const int rc = RunLegacyWithSystem(backend, options.passthrough_args);
    if (exit_code != nullptr) {
        *exit_code = rc;
    }
    return true;
}

bool IsInternalLegacyCompressionBridgeCompressor(Compressor c) {
    // Disabled (2026-06-04): the legacy compression bridge was a fallback
    // for codecs the native encoder could not handle (e.g. -cO optimum
    // variants, -cc cm). Per the project goal of being 100% pure native
    // RE (no dependency on the original binary at runtime), the bridge
    // is disabled unconditionally. Codecs the native encoder cannot
    // handle now produce an explicit "unsupported" error rather than
    // silently invoking the legacy binary.
    (void)c;
    return false;
}

enum class LegacyNativeWrapper {
    kLzpfLiteralBits,
    kLzhdLiteralTag,
    kOptimumBwt,
    kCmRaw
};

struct LegacyNativeSpec {
    std::uint8_t method = 0u;
    std::uint8_t method_p0 = 0u;
    std::uint8_t method_p1 = 0u;
    LegacyNativeWrapper wrapper = LegacyNativeWrapper::kLzpfLiteralBits;
};

bool ResolveLegacyNativeSpec(Compressor compressor, LegacyNativeSpec* out_spec) {
    if (out_spec == nullptr) {
        return false;
    }

    switch (compressor) {
        case Compressor::kLzpf:
            *out_spec = LegacyNativeSpec{0x2bu, 1u, 0u, LegacyNativeWrapper::kLzpfLiteralBits};
            return true;
        case Compressor::kLzpfLarge:
            *out_spec = LegacyNativeSpec{0x2bu, 2u, 0u, LegacyNativeWrapper::kLzpfLiteralBits};
            return true;
        case Compressor::kLzhd:
            *out_spec = LegacyNativeSpec{0x2bu, 3u, 0u, LegacyNativeWrapper::kLzhdLiteralTag};
            return true;
        case Compressor::kLzhds:
            *out_spec = LegacyNativeSpec{0x2bu, 4u, 0u, LegacyNativeWrapper::kLzhdLiteralTag};
            return true;
        case Compressor::kOptimum1:
            *out_spec = LegacyNativeSpec{0x3bu, 5u, 0u, LegacyNativeWrapper::kOptimumBwt};
            return true;
        case Compressor::kOptimum2:
            *out_spec = LegacyNativeSpec{0x3bu, 6u, 0u, LegacyNativeWrapper::kOptimumBwt};
            return true;
        case Compressor::kCm:
            *out_spec = LegacyNativeSpec{0x4bu, 7u, 0u, LegacyNativeWrapper::kCmRaw};
            return true;
        default:
            break;
    }

    return false;
}

const char* LegacyNativeWrapperLabel(LegacyNativeWrapper wrapper) {
    switch (wrapper) {
        case LegacyNativeWrapper::kLzpfLiteralBits:
            return "native literal-only stream";
        case LegacyNativeWrapper::kLzhdLiteralTag:
            return "native literal-wrapper stream";
        case LegacyNativeWrapper::kOptimumBwt:
            return "native BWT-wrapper stream";
        case LegacyNativeWrapper::kCmRaw:
            return "native raw-wrapper stream";
        default:
            return "native stream";
    }
}

bool IsNativeLegacyCompressionAvailable(const CliOptions& options) {
    if (options.command != Command::kAdd && options.command != Command::kSimulate) {
        return false;
    }
    LegacyNativeSpec spec;
    return ResolveLegacyNativeSpec(options.compressor, &spec);
}

bool IsLegacyCompressionBridgeDisabled() {
    return IsEnvEnabled("NZ_DISABLE_COMPRESS_BRIDGE");
}

bool BuildLegacyLiteralFilenameTable(
    const std::vector<SourceFile>& sources,
    std::vector<unsigned char>* out_table,
    std::string* out_error_message) {
    if (out_table == nullptr) {
        if (out_error_message != nullptr) {
            *out_error_message = "internal error: null legacy table output";
        }
        return false;
    }

    out_table->clear();
    for (const SourceFile& src : sources) {
        if (src.archive_name.find('\0') != std::string::npos) {
            if (out_error_message != nullptr) {
                *out_error_message = "legacy filename table does not support NUL in names";
            }
            return false;
        }
        WriteLegacyVarint(src.size, out_table);
        out_table->insert(out_table->end(), src.archive_name.begin(), src.archive_name.end());
        out_table->push_back(0u);
    }

    if (out_table->size() < 2u) {
        if (out_error_message != nullptr) {
            *out_error_message = "legacy filename table too small";
        }
        return false;
    }

    return true;
}

bool BuildNativeLegacyStreamPayload(
    const LegacyNativeSpec& spec,
    const std::vector<SourceFile>& sources,
    std::uint64_t total_bytes,
    std::vector<unsigned char>* out_prefix_or_payload,
    bool* out_append_raw_sources,
    std::uint64_t* out_stream_bytes,
    std::string* out_error_message) {
    if (out_prefix_or_payload == nullptr || out_append_raw_sources == nullptr || out_stream_bytes == nullptr) {
        if (out_error_message != nullptr) {
            *out_error_message = "internal error: null native stream payload output";
        }
        return false;
    }

    out_prefix_or_payload->clear();
    *out_append_raw_sources = true;
    *out_stream_bytes = 0u;

    static constexpr std::uint64_t kNativeBwtMaxBytes = 1u << 15u;  // keep O(n^2 log n) path bounded

    switch (spec.wrapper) {
        case LegacyNativeWrapper::kLzpfLiteralBits: {
            if (total_bytes > (std::numeric_limits<std::uint64_t>::max() / 8u)) {
                if (out_error_message != nullptr) {
                    *out_error_message = "input too large for legacy literal bit-length tag";
                }
                return false;
            }
            WriteLegacyVarint(total_bytes * 8u, out_prefix_or_payload);
            *out_stream_bytes = static_cast<std::uint64_t>(out_prefix_or_payload->size()) + total_bytes;
            return true;
        }
        case LegacyNativeWrapper::kLzhdLiteralTag: {
            WriteLegacyVarint(0u, out_prefix_or_payload);
            out_prefix_or_payload->push_back(0x00u);
            *out_stream_bytes = static_cast<std::uint64_t>(out_prefix_or_payload->size()) + total_bytes;
            return true;
        }
        case LegacyNativeWrapper::kCmRaw: {
            if (total_bytes > static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max())) {
                if (out_error_message != nullptr) {
                    *out_error_message = "input too large for native -cc raw-size wrapper";
                }
                return false;
            }
            AppendU32LE(static_cast<std::uint32_t>(total_bytes), out_prefix_or_payload);
            *out_stream_bytes = static_cast<std::uint64_t>(out_prefix_or_payload->size()) + total_bytes;
            return true;
        }
        case LegacyNativeWrapper::kOptimumBwt: {
            if (total_bytes > static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max())) {
                if (out_error_message != nullptr) {
                    *out_error_message = "input too large for native -co/-cO BWT wrapper";
                }
                return false;
            }
            if (total_bytes > kNativeBwtMaxBytes) {
                if (out_error_message != nullptr) {
                    std::ostringstream oss;
                    oss << "native -co/-cO writer currently supports up to " << kNativeBwtMaxBytes
                        << " bytes (use legacy bridge for larger payloads)";
                    *out_error_message = oss.str();
                }
                return false;
            }
            if (total_bytes > 0x00ffffffu) {
                if (out_error_message != nullptr) {
                    *out_error_message = "input too large for native -co/-cO 24-bit primary index";
                }
                return false;
            }

            std::vector<unsigned char> raw;
            std::string raw_error;
            if (!LoadSourcesRawData(sources, &raw, &raw_error)) {
                if (out_error_message != nullptr) {
                    *out_error_message = raw_error;
                }
                return false;
            }

            std::vector<unsigned char> bwt_last;
            std::uint32_t primary_index = 0u;
            if (!ForwardBwt(raw, &bwt_last, &primary_index)) {
                if (out_error_message != nullptr) {
                    *out_error_message = "failed to build native BWT wrapper stream";
                }
                return false;
            }

            out_prefix_or_payload->reserve(4u + bwt_last.size() + 3u);
            AppendU32LE(static_cast<std::uint32_t>(raw.size()), out_prefix_or_payload);
            out_prefix_or_payload->insert(out_prefix_or_payload->end(), bwt_last.begin(), bwt_last.end());
            out_prefix_or_payload->push_back(static_cast<unsigned char>((primary_index >> 16u) & 0xffu));
            out_prefix_or_payload->push_back(static_cast<unsigned char>((primary_index >> 8u) & 0xffu));
            out_prefix_or_payload->push_back(static_cast<unsigned char>(primary_index & 0xffu));

            *out_append_raw_sources = false;
            *out_stream_bytes = static_cast<std::uint64_t>(out_prefix_or_payload->size());
            return true;
        }
        default:
            break;
    }

    if (out_error_message != nullptr) {
        *out_error_message = "native legacy stream wrapper is not supported";
    }
    return false;
}

int RunAddNativeLegacyStream(const CliOptions& options, const std::vector<SourceFile>& sources, std::ostream& os) {
    const auto add_start = std::chrono::steady_clock::now();
    LegacyNativeSpec spec;
    if (!ResolveLegacyNativeSpec(options.compressor, &spec)) {
        os << "Error: native legacy writer is not available for compressor "
           << CompressorToString(options.compressor) << ".\n";
        return 1;
    }

    std::uint64_t total_bytes = 0u;
    for (const SourceFile& src : sources) {
        if (src.size > (std::numeric_limits<std::uint64_t>::max() - total_bytes)) {
            os << "Error: input size overflow while building legacy stream.\n";
            return 1;
        }
        total_bytes += src.size;
    }

    const ChecksumMode legacy_checksum_mode = LegacyNormalizeChecksumModeForCompression(options.checksum);
    const bool checksum_mode_remapped =
        (options.checksum != ChecksumMode::kNone && legacy_checksum_mode != options.checksum);
    const std::uint8_t legacy_checksum_header = LegacyChecksumHeaderByte(legacy_checksum_mode);

    std::vector<unsigned char> table;
    std::string table_error;
    if (!BuildLegacyLiteralFilenameTable(sources, &table, &table_error)) {
        os << "Error: " << table_error << '\n';
        return 1;
    }

    std::vector<unsigned char> table_span;
    if (!WriteLegacyTableSpan(static_cast<std::uint64_t>(table.size()) - 2u, &table_span)) {
        os << "Error: legacy filename table is too large for current encoder path.\n";
        return 1;
    }

    std::vector<unsigned char> stream_payload;
    bool append_raw_sources = true;
    std::uint64_t stream_bytes = 0u;
    std::string stream_error;
    if (!BuildNativeLegacyStreamPayload(
            spec,
            sources,
            total_bytes,
            &stream_payload,
            &append_raw_sources,
            &stream_bytes,
            &stream_error)) {
        os << "Error: " << stream_error << ".\n";
        return 1;
    }
    std::vector<unsigned char> stream_tag;
    WriteLegacyVarint(stream_bytes << 4u, &stream_tag);

    std::vector<unsigned char> checksum_bytes;
    std::string checksum_error;
    if (!BuildLegacyChecksumBytes(sources, legacy_checksum_mode, &checksum_bytes, &checksum_error)) {
        os << "Error: " << checksum_error << '\n';
        return 1;
    }

    const fs::path out_path = ResolveArchivePath(options);
    std::error_code ec;
    if (out_path.has_parent_path()) {
        fs::create_directories(out_path.parent_path(), ec);
    }

    std::ofstream out(out_path, std::ios::binary | std::ios::trunc);
    if (!out) {
        os << "Cannot open output archive for writing: " << out_path.string() << '\n';
        return 1;
    }

    out.write(reinterpret_cast<const char*>(kMagicPrefix.data()), static_cast<std::streamsize>(kMagicPrefix.size()));
    out.write(kKnownSignature, static_cast<std::streamsize>(kKnownSignatureBytes));

    static constexpr std::array<unsigned char, 3> kLegacyHeaderPrefix = {0x1fu, 0x0fu, 0x09u};
    out.write(
        reinterpret_cast<const char*>(kLegacyHeaderPrefix.data()),
        static_cast<std::streamsize>(kLegacyHeaderPrefix.size()));
    if (legacy_checksum_header != 0u) {
        out.put(static_cast<char>(legacy_checksum_header));
    }

    // spec.method is the chunk varint: (csize<<4)|11.  Write exactly csize payload
    // bytes so the chunk scanner can locate the following type-1 table chunk.
    // p0 and p1 occupy slots 0 and 1; fill remaining slots with zeros.
    out.put(static_cast<char>(spec.method));
    out.put(static_cast<char>(spec.method_p0));
    out.put(static_cast<char>(spec.method_p1));
    {
        const unsigned codec_csize = static_cast<unsigned>(spec.method) >> 4u;
        for (unsigned i = 2u; i < codec_csize; ++i) {
            out.put(static_cast<char>(0u));
        }
    }

    // WriteLegacyTableSpan(N-2) and WriteLegacyVarint((N<<4)|1) produce identical
    // bytes, so table_span doubles as the type-1 chunk varint for the scanner.
    out.write(reinterpret_cast<const char*>(table_span.data()), static_cast<std::streamsize>(table_span.size()));
    out.write(reinterpret_cast<const char*>(table.data()), static_cast<std::streamsize>(table.size()));
    if (!checksum_bytes.empty()) {
        if (sources.size() == 1u) {
            const std::uint8_t checksum_tag = LegacyChecksumTag(legacy_checksum_mode);
            if (checksum_tag != 0u) {
                out.put(static_cast<char>(checksum_tag));
            }
        }
        out.write(reinterpret_cast<const char*>(checksum_bytes.data()), static_cast<std::streamsize>(checksum_bytes.size()));
    }
    out.write(reinterpret_cast<const char*>(stream_tag.data()), static_cast<std::streamsize>(stream_tag.size()));

    if (!stream_payload.empty()) {
        out.write(reinterpret_cast<const char*>(stream_payload.data()), static_cast<std::streamsize>(stream_payload.size()));
        if (!out) {
            os << "Error: write failure while building archive.\n";
            return 1;
        }
    }
    if (append_raw_sources) {
        std::string write_error;
        if (!WriteSourcesRawData(sources, &out, &write_error)) {
            os << "Error: " << write_error << ".\n";
            return 1;
        }
    }

    if (options.verbose) {
        os << "Warning: native " << CompressorToString(options.compressor)
           << " writer currently emits " << LegacyNativeWrapperLabel(spec.wrapper)
           << " (RE-substream), not full legacy compressed stream.\n";
    }
    if (checksum_mode_remapped) {
        os << "Note: -hf was mapped to legacy Fletcher32 checksum variant for this stream.\n";
    }
    PrintEncodeHeader(os, out_path.string(), CompressorToString(options.compressor),
                      /*engine_bytes=*/0u, /*memory_mb=*/512u, /*read_mb=*/20u,
                      /*write_mb=*/4u, options.verbose);
    if (options.verbose) {
        ClearStatusLine(os);
        os << "wrapper: " << LegacyNativeWrapperLabel(spec.wrapper) << '\n';
    }
    for (const auto& src : sources) {
        PrintFileProgress(os, src.archive_name, "100%");
    }
    {
        // Take the produced size from the stream itself and flush first: reading the
        // path before the ofstream is closed reports 0.
        const std::uint64_t produced = static_cast<std::uint64_t>(std::max<std::streamoff>(0, out.tellp()));
        out.flush();
        PrintEncodeFooter(os, total_bytes, produced, ElapsedSince(add_start), options.verbose);
    }
    return 0;
}

int RunSimulateNativeLegacyStream(
    const CliOptions& options,
    const std::vector<SourceFile>& sources,
    std::ostream& os) {
    LegacyNativeSpec spec;
    if (!ResolveLegacyNativeSpec(options.compressor, &spec)) {
        os << "Error: native legacy simulation is not available for compressor "
           << CompressorToString(options.compressor) << ".\n";
        return 1;
    }

    std::uint64_t total_input = 0u;
    for (const SourceFile& src : sources) {
        if (src.size > (std::numeric_limits<std::uint64_t>::max() - total_input)) {
            os << "Error: input size overflow while simulating legacy stream.\n";
            return 1;
        }
        total_input += src.size;
    }

    const ChecksumMode legacy_checksum_mode = LegacyNormalizeChecksumModeForCompression(options.checksum);
    const bool checksum_mode_remapped =
        (options.checksum != ChecksumMode::kNone && legacy_checksum_mode != options.checksum);
    const std::size_t checksum_bytes_per_file = LegacyChecksumBytesPerFile(legacy_checksum_mode);
    const std::size_t checksum_value_bytes = checksum_bytes_per_file * sources.size();
    const std::size_t checksum_tag_bytes =
        (checksum_value_bytes > 0u && sources.size() == 1u && LegacyChecksumTag(legacy_checksum_mode) != 0u) ? 1u : 0u;
    const std::size_t checksum_header_bytes = (LegacyChecksumHeaderByte(legacy_checksum_mode) != 0u) ? 1u : 0u;

    std::vector<unsigned char> table;
    std::string table_error;
    if (!BuildLegacyLiteralFilenameTable(sources, &table, &table_error)) {
        os << "Error: " << table_error << '\n';
        return 1;
    }

    std::vector<unsigned char> table_span;
    if (!WriteLegacyTableSpan(static_cast<std::uint64_t>(table.size()) - 2u, &table_span)) {
        os << "Error: legacy filename table is too large for current encoder path.\n";
        return 1;
    }

    std::vector<unsigned char> stream_payload;
    bool append_raw_sources = true;
    std::uint64_t stream_bytes = 0u;
    std::string stream_error;
    if (!BuildNativeLegacyStreamPayload(
            spec,
            sources,
            total_input,
            &stream_payload,
            &append_raw_sources,
            &stream_bytes,
            &stream_error)) {
        os << "Error: " << stream_error << ".\n";
        return 1;
    }
    (void)append_raw_sources;

    std::vector<unsigned char> stream_tag;
    WriteLegacyVarint(stream_bytes << 4u, &stream_tag);

    const std::uint64_t estimated_archive_bytes =
        2u + kKnownSignatureBytes + 3u + static_cast<std::uint64_t>(checksum_header_bytes) + 3u +
        static_cast<std::uint64_t>(table_span.size()) +
        static_cast<std::uint64_t>(table.size()) +
        static_cast<std::uint64_t>(checksum_tag_bytes + checksum_value_bytes) +
        static_cast<std::uint64_t>(stream_tag.size()) +
        stream_bytes;

    if (checksum_mode_remapped) {
        os << "Note: -hf was mapped to legacy Fletcher32 checksum variant for this stream.\n";
    }
    os << "Simulation mode (no output written)\n";
    os << "Compressor: " << CompressorToString(options.compressor)
       << " (" << LegacyNativeWrapperLabel(spec.wrapper) << ")\n";
    os << "Files    : " << sources.size() << '\n';
    os << "Input    : " << total_input << " bytes\n";
    os << "Estimate : " << estimated_archive_bytes << " bytes\n";
    return 0;
}

bool TryRunLegacyCompressionBridge(const CliOptions& options, std::ostream& os, int* exit_code) {
    if (options.command != Command::kAdd && options.command != Command::kSimulate) {
        return false;
    }
    if (!IsInternalLegacyCompressionBridgeCompressor(options.compressor)) {
        return false;
    }
    if (IsLegacyCompressionBridgeDisabled()) {
        return false;
    }

    const fs::path backend = FindLegacyBackend();
    if (backend.empty()) {
        return false;
    }

    os << "[bridge] using legacy compressor backend: " << backend.string() << '\n' << std::flush;
    const int rc = RunLegacyWithSystem(backend, options.passthrough_args);
    if (exit_code != nullptr) {
        *exit_code = rc;
    }
    return true;
}

int RunAdd(const CliOptions& options, std::ostream& os) {
    const auto add_start = std::chrono::steady_clock::now();
    const bool native_legacy_stream = IsNativeLegacyCompressionAvailable(options);
    if (!native_legacy_stream && IsInternalLegacyCompressionBridgeCompressor(options.compressor)) {
        int bridge_exit = 0;
        if (TryRunLegacyCompressionBridge(options, os, &bridge_exit)) {
            return bridge_exit;
        }
    }

    std::vector<SourceFile> sources;
    std::vector<std::string> warnings;
    std::string error;

    const bool need_checksums = (options.checksum != ChecksumMode::kNone);
    if (!BuildSourceList(options, &sources, &warnings, &error, need_checksums)) {
        int bridge_exit = 0;
        if (TryRunLegacyCompressionBridge(options, os, &bridge_exit)) {
            return bridge_exit;
        }
        for (const std::string& w : warnings) {
            os << "Warning: " << w << '\n';
        }
        os << "Error: " << error << '\n';
        return 1;
    }

    for (const std::string& w : warnings) {
        os << "Warning: " << w << '\n';
    }

    if (native_legacy_stream) {
        std::ostringstream native_log;
        const int native_exit = RunAddNativeLegacyStream(options, sources, native_log);
        if (native_exit == 0) {
            os << native_log.str();
            return 0;
        }

        int bridge_exit = 0;
        if (TryRunLegacyCompressionBridge(options, os, &bridge_exit)) {
            if (options.verbose) {
                os << "Warning: native writer failed; used legacy bridge backend instead.\n";
            }
            return bridge_exit;
        }

        os << native_log.str();
        return native_exit;
    }

    if (options.compressor != Compressor::kNone) {
        os << "Warning: compressor " << CompressorToString(options.compressor)
           << " is not reconstructed; data will be stored without compression.\n";
    }

    const fs::path out_path = ResolveArchivePath(options);
    std::error_code ec;
    if (out_path.has_parent_path()) {
        fs::create_directories(out_path.parent_path(), ec);
    }

    std::ofstream out(out_path, std::ios::binary | std::ios::trunc);
    if (!out) {
        os << "Cannot open output archive for writing: " << out_path.string() << '\n';
        return 1;
    }

    // Header: [magic][signature][marker][fmt][flags][checksum][compressor][reserved]
    out.write(reinterpret_cast<const char*>(kMagicPrefix.data()), static_cast<std::streamsize>(kMagicPrefix.size()));
    out.write(kKnownSignature, static_cast<std::streamsize>(kKnownSignatureBytes));
    out.write(kReconMarker.data(), static_cast<std::streamsize>(kReconMarker.size()));

    WriteLE<std::uint8_t>(out, kReconFormatMajor);
    WriteLE<std::uint8_t>(out, kReconFormatMinor);

    std::uint8_t flags = 0;
    if (!options.no_timestamps) {
        flags |= kFlagHasTimestamps;
    }
    if (!options.no_permissions) {
        flags |= kFlagHasPermissions;
    }

    WriteLE<std::uint8_t>(out, flags);
    WriteLE<std::uint8_t>(out, static_cast<std::uint8_t>(options.checksum));
    WriteLE<std::uint8_t>(out, static_cast<std::uint8_t>(options.compressor));
    WriteLE<std::uint8_t>(out, 0);
    WriteLE<std::uint16_t>(out, 0);
    WriteLE<std::uint32_t>(out, static_cast<std::uint32_t>(sources.size()));

    for (const SourceFile& src : sources) {
        if (src.archive_name.size() > 0xffffu) {
            os << "Error: file name too long for archive: " << src.archive_name << '\n';
            return 1;
        }

        WriteLE<std::uint16_t>(out, static_cast<std::uint16_t>(src.archive_name.size()));
        out.write(src.archive_name.data(), static_cast<std::streamsize>(src.archive_name.size()));

        WriteLE<std::uint64_t>(out, src.size);
        WriteLE<std::uint64_t>(out, src.size);
        WriteLE<std::uint32_t>(out, src.permissions);
        WriteLE<std::int64_t>(out, src.mtime_unix);
        WriteLE<std::uint32_t>(out, src.checksum);
        WriteLE<std::uint8_t>(out, 0);

        static constexpr std::array<char, 7> kEntryReserved = {0, 0, 0, 0, 0, 0, 0};
        out.write(kEntryReserved.data(), static_cast<std::streamsize>(kEntryReserved.size()));
    }

    std::vector<char> buffer(kBufferSize);
    std::uint64_t total_bytes = 0;

    for (const SourceFile& src : sources) {
        std::ifstream input(src.source_path, std::ios::binary);
        if (!input) {
            os << "Error: cannot read input file: " << src.source_path.string() << '\n';
            return 1;
        }

        while (input) {
            input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
            const std::streamsize got = input.gcount();
            if (got <= 0) {
                break;
            }
            out.write(buffer.data(), got);
            if (!out) {
                os << "Error: write failure while building archive.\n";
                return 1;
            }
            total_bytes += static_cast<std::uint64_t>(got);
        }
    }

    PrintEncodeHeader(os, out_path.string(), CompressorToString(options.compressor),
                      /*engine_bytes=*/0u, /*memory_mb=*/512u, /*read_mb=*/20u,
                      /*write_mb=*/4u, options.verbose);
    for (const auto& src : sources) {
        PrintFileProgress(os, src.archive_name, "100%");
    }
    {
        // Take the produced size from the stream itself and flush first: reading the
        // path before the ofstream is closed reports 0.
        const std::uint64_t produced = static_cast<std::uint64_t>(std::max<std::streamoff>(0, out.tellp()));
        out.flush();
        PrintEncodeFooter(os, total_bytes, produced, ElapsedSince(add_start), options.verbose);
    }
    return 0;
}

int RunSimulate(const CliOptions& options, std::ostream& os) {
    const bool native_legacy_stream = IsNativeLegacyCompressionAvailable(options);
    if (!native_legacy_stream && IsInternalLegacyCompressionBridgeCompressor(options.compressor)) {
        int bridge_exit = 0;
        if (TryRunLegacyCompressionBridge(options, os, &bridge_exit)) {
            return bridge_exit;
        }
    }

    std::vector<SourceFile> sources;
    std::vector<std::string> warnings;
    std::string error;

    if (!BuildSourceList(options, &sources, &warnings, &error, false)) {
        int bridge_exit = 0;
        if (TryRunLegacyCompressionBridge(options, os, &bridge_exit)) {
            return bridge_exit;
        }
        for (const std::string& w : warnings) {
            os << "Warning: " << w << '\n';
        }
        os << "Error: " << error << '\n';
        return 1;
    }

    for (const std::string& w : warnings) {
        os << "Warning: " << w << '\n';
    }

    if (native_legacy_stream) {
        std::ostringstream native_log;
        const int native_exit = RunSimulateNativeLegacyStream(options, sources, native_log);
        if (native_exit == 0) {
            os << native_log.str();
            return 0;
        }

        int bridge_exit = 0;
        if (TryRunLegacyCompressionBridge(options, os, &bridge_exit)) {
            if (options.verbose) {
                os << "Warning: native simulation failed; used legacy bridge backend instead.\n";
            }
            return bridge_exit;
        }

        os << native_log.str();
        return native_exit;
    }

    std::uint64_t total_input = 0;
    std::uint64_t estimated_overhead = 2 + kKnownSignatureBytes + 4 + 1 + 1 + 1 + 1 + 1 + 2 + 4;

    for (const SourceFile& src : sources) {
        total_input += src.size;
        estimated_overhead += 2 + static_cast<std::uint64_t>(src.archive_name.size()) + 8 + 8 + 4 + 8 + 4 + 1 + 7;
        if (options.verbose) {
            os << "simulate " << src.archive_name << " (" << src.size << " bytes)\n";
        }
    }

    os << "Simulation mode (no output written)\n";
    os << "Compressor: " << CompressorToString(options.compressor) << '\n';
    if (options.compressor != Compressor::kNone) {
        os << "Note: compression engines are not fully reconstructed; ratio estimate uses store-mode baseline.\n";
    }
    os << "Files    : " << sources.size() << '\n';
    os << "Input    : " << total_input << " bytes\n";
    os << "Estimate : " << (total_input + estimated_overhead) << " bytes\n";
    return 0;
}

int RunList(const CliOptions& options, std::ostream& os) {
    ArchiveContext context;
    std::string error;
    const ArchiveOpenError open_error = OpenArchive(options.archive_path, &context, &error);
    if (open_error != ArchiveOpenError::kNone) {
        if (open_error == ArchiveOpenError::kUnsupportedFormat) {
            LegacyCnContext legacy_cn;
            std::string legacy_error;
            if (TryParseLegacyCnArchive(options.archive_path, &legacy_cn, &legacy_error)) {
                return RunLegacyCnList(options, legacy_cn, os);
            }

            int code = 0;
            if (TryRunLegacyBackend(options, os, &code)) {
                return code;
            }
            if (!legacy_error.empty()) {
                os << legacy_error << '\n';
                return 1;
            }
        }
        os << error << '\n';
        return 1;
    }

    const bool has_checksum = context.header.checksum != ChecksumMode::kNone;

    os << "Archive: " << context.archive_path << '\n';
    if (has_checksum) {
        os << "checksum ";
    }
    os << "perm yyyy-mmm-dd hh:mm:ss     size  file\n";

    std::uint64_t total_size = 0;
    std::size_t total_files = 0;

    for (const ArchiveEntry& e : context.entries) {
        if (!MatchesAnyPattern(e.path, options.positional)) {
            continue;
        }

        if (has_checksum) {
            os << std::setw(8) << std::left << FormatChecksum(context.header.checksum, e.checksum) << ' ';
        }

        os << std::setw(4) << std::right << FormatMode(e.permissions) << ' '
           << FormatMtimeStored(e.mtime_unix)
           << FormatSizeColumn(e.original_size) << "  "
           << e.path << '\n';

        total_size += e.original_size;
        ++total_files;
    }

    os << "Total of " << total_files << " files, " << FormatGrouped(total_size) << " bytes.\n";
    return 0;
}

int RunExtractOrTest(const CliOptions& options, bool test_mode, std::ostream& os) {
    const auto run_start = std::chrono::steady_clock::now();
    ArchiveContext context;
    std::string error;
    const ArchiveOpenError open_error = OpenArchive(options.archive_path, &context, &error);
    if (open_error != ArchiveOpenError::kNone) {
        if (open_error == ArchiveOpenError::kUnsupportedFormat) {
            LegacyCnContext legacy_cn;
            std::string legacy_error;
            if (TryParseLegacyCnArchive(options.archive_path, &legacy_cn, &legacy_error)) {
                const int legacy_rc = RunLegacyCnExtractOrTest(options, legacy_cn, test_mode, os);
                if (legacy_rc != kLegacyNeedCompat) {
                    return legacy_rc;
                }

                int code = 0;
                if (TryRunLegacyBackend(options, os, &code)) {
                    return code;
                }
                os << "Legacy compressor stream is not reconstructed yet "
                      "(native extract/test currently supports -cn, literal-only substreams of -cf/-cF/-cd/-cD, "
                      "the observed small-file BWT wrapper of -co/-cO, and the observed literal-wrapper substream of -cc). "
                   << "Detected payload mode: " << LegacyPayloadModeLabel(legacy_cn.payload_mode) << ".\n";
                return 1;
            }

            int code = 0;
            if (TryRunLegacyBackend(options, os, &code)) {
                return code;
            }
            if (!legacy_error.empty()) {
                os << legacy_error << '\n';
                return 1;
            }
        }
        os << error << '\n';
        return 1;
    }

    std::ifstream in(context.archive_path, std::ios::binary);
    if (!in) {
        os << "Cannot open archive!\n";
        return 1;
    }
    in.seekg(static_cast<std::streamoff>(context.data_offset), std::ios::beg);

    const fs::path output_root = options.output_path.empty() ? fs::current_path() : fs::path(options.output_path);

    std::size_t processed = 0;
    std::size_t failed = 0;
    std::uint64_t bytes_ok = 0;

    for (const ArchiveEntry& entry : context.entries) {
        const bool selected = MatchesAnyPattern(entry.path, options.positional);
        fs::path safe_rel;
        fs::path out_path;
        std::ofstream out;

        if (!selected) {
            if (!SkipBytes(in, entry.stored_size)) {
                os << "Data corrupted while reading headers!\n";
                return 2;
            }
            continue;
        }

        if (!test_mode) {
            safe_rel = SanitizeExtractPath(entry.path);
            if (safe_rel.empty()) {
                os << "Skipping unsafe path in archive: " << entry.path << '\n';
                ++failed;
                if (!SkipBytes(in, entry.stored_size)) {
                    os << "Data corrupted while reading headers!\n";
                    return 2;
                }
                continue;
            }

            out_path = output_root / safe_rel;
            std::error_code ec;
            if (out_path.has_parent_path()) {
                fs::create_directories(out_path.parent_path(), ec);
            }
            out.open(out_path, std::ios::binary | std::ios::trunc);
            if (!out) {
                os << "Cannot write output file: " << out_path.string() << '\n';
                ++failed;
                if (!SkipBytes(in, entry.stored_size)) {
                    os << "Data corrupted while reading headers!\n";
                    return 2;
                }
                continue;
            }
        }

        std::uint32_t calculated = 0;
        if (!CopyFileData(in,
                          test_mode ? nullptr : &out,
                          entry.stored_size,
                          &calculated,
                          context.header.checksum)) {
            os << "Data corrupted while reading file payload: " << entry.path << '\n';
            ++failed;
            continue;
        }

        if (context.header.checksum != ChecksumMode::kNone && calculated != entry.checksum) {
            os << "Checksum mismatch: " << entry.path << " (expected "
               << FormatChecksum(context.header.checksum, entry.checksum) << ", got "
               << FormatChecksum(context.header.checksum, calculated) << ")\n";
            ++failed;
            continue;
        }

        if (!test_mode) {
            out.close();
            std::string metadata_warning;
            const bool metadata_ok = ApplyExtractedMetadata(
                out_path,
                context.header.has_permissions,
                entry.permissions,
                context.header.has_timestamps,
                entry.mtime_unix,
                &metadata_warning);
            if (!metadata_ok && options.verbose && !metadata_warning.empty()) {
                os << "Warning: " << metadata_warning << '\n';
            }
        }

        ++processed;
        bytes_ok += entry.original_size;

        if (options.verbose) {
            os << (test_mode ? "tested " : "extract ") << entry.path << '\n';
        }
    }

    if (failed > 0) {
        ClearStatusLine(os);
        os << (test_mode ? "Tested " : "Extracted ") << processed << " files, "
           << FormatGrouped(bytes_ok) << " bytes. Failures: " << failed << ".\n";
    } else {
        PrintDecodeFooter(os, bytes_ok, ElapsedSince(run_start));
    }

    return failed == 0 ? 0 : 2;
}

int RunInfo(std::ostream& os) {
    const std::string cpu = ParseProcValue("/proc/cpuinfo", "model name\t:");
    const std::string mem_total = ParseProcValue("/proc/meminfo", "MemTotal:");
    const std::string mem_avail = ParseProcValue("/proc/meminfo", "MemAvailable:");

    (void)cpu; (void)mem_total; (void)mem_avail;
    // `info` in the original prints the banner's host summary line again, then the
    // CPU identification and its feature list. The identification reads
    //   CPU "<vendor>" family <f> [ext 0x<extended family>], model <m & 0xf>, stepping <s>
    // -- measured: this host is family 6, model 79, stepping 1 and the original
    // prints "family 6 [ext 0x00], model 15, stepping 1", i.e. the model is masked
    // to its low nibble and the bracketed value is the EXTENDED FAMILY (0 for
    // family 6), not the extended model.
    // (the host summary line is already on screen: PrintBanner emits it)
    const std::string vendor   = ParseProcValue("/proc/cpuinfo", "vendor_id\t:");
    const std::string family_s = ParseProcValue("/proc/cpuinfo", "cpu family\t:");
    const std::string model_s  = ParseProcValue("/proc/cpuinfo", "model\t\t:");
    const std::string step_s   = ParseProcValue("/proc/cpuinfo", "stepping\t:");
    const std::string flags    = ParseProcValue("/proc/cpuinfo", "flags\t\t:");

    const unsigned family = family_s.empty() ? 0u : (unsigned)strtoul(family_s.c_str(), nullptr, 10);
    const unsigned model  = model_s.empty()  ? 0u : (unsigned)strtoul(model_s.c_str(), nullptr, 10);
    const unsigned step   = step_s.empty()   ? 0u : (unsigned)strtoul(step_s.c_str(), nullptr, 10);
    const unsigned ext_family = (family >= 15u) ? (family - 15u) : 0u;

    char idbuf[256];
    snprintf(idbuf, sizeof(idbuf),
             "CPU \"%s\" family %u [ext 0x%02x], model %u, stepping %u",
             vendor.empty() ? "unknown" : vendor.c_str(),
             family, ext_family, model & 0x0fu, step);
    os << idbuf << '\n';

    // Feature list, in the original's own order and spelling.
    static const struct { const char* flag; const char* shown; } kFeat[] = {
        {"mmx", "MMX"}, {"sse", "SSE1"}, {"sse2", "SSE2"}, {"pni", "SSE3"},
        {"ssse3", "SSSE3"}, {"sse4_1", "SSE41"}, {"sse4_2", "SSE42"},
        {"ht", "Hyper-Threading"},
    };
    std::string feat;
    for (const auto& f : kFeat) {
        const std::string needle = std::string(" ") + f.flag + " ";
        const std::string hay = std::string(" ") + flags + " ";
        if (hay.find(needle) != std::string::npos) {
            if (!feat.empty()) feat += ' ';
            feat += f.shown;
        }
    }
    os << "CPU-features: " << feat << '\n';
    return 0;
}

}  // namespace recon
}  // namespace nz
