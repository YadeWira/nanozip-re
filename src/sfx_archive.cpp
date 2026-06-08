#include "nz_sfx/sfx_archive.hpp"
#include "lzpf_arith.h"
#include "nz_cm.h"
#include "nz_lzhd.h"
#include "nz_text_transform.h"
#include "nz_postfilter.h"
#include "nz_texttransform_num.h"

#include <algorithm>
#include <array>
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
    if (mode == ChecksumMode::kCrc16 || mode == ChecksumMode::kFletcher16) {
        oss << std::setw(4) << (checksum & 0xffffu);
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
    // Accumulated file sizes across all per-stream type-1 tables.
    std::map<std::string, std::uint64_t> size_accum;

    for (int guard = 0; guard < 1024 && pos < bytes.size(); ++guard) {
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
                tp = static_cast<std::size_t>(
                    std::distance(bytes.begin(), nul_it)) + 1u;
            }
            // Record the first main-stream type-1 chunk as the canonical table.
            if (found_codec && is_main && !found_table) {
                table_start = pos;
                table_end   = pos + csize;
                found_table = true;
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
    std::size_t p = table_start;
    std::uint64_t total_data_size = 0;
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
        total_data_size += file_size;
        if (native_store_payload && total_data_size > bytes.size()) {
            if (out_error_message != nullptr) {
                *out_error_message = "Data corrupted while reading headers!";
            }
            return false;
        }
        entries.push_back(std::move(e));
    }

    if (p != table_end || entries.empty()) {
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
    if (!native_store_payload) {
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
        if (!prefix_found) {
            if (out_error_message != nullptr) {
                *out_error_message = "Legacy stream prefix is not recognized.";
            }
            return false;
        }
        metadata_end = prefix_start;
        payload_start = data_offset;

        // Parse checksums from the end of metadata.
        const std::size_t checksum_bytes_per_file =
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
    }

    // Best-effort metadata extraction (single-file path is the most reliable).
    if (entries.size() == 1u && metadata_end > metadata_begin) {
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
    if (multiblock_scanner_added_entries || entries.size() > 1u) {
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

    if (!native_store_payload && !entries.empty() && payload_start <= bytes.size()) {
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
                    // Multi-stream support: the encoder may chain multiple
                    // [stream_tag][stream_data] segments back-to-back when
                    // the file is large (legacy-observed for big.nz, p1=15:
                    // stream 1 = 576 B, stream 2 = 19 B). All streams share
                    // the same dict + hash_table state.
                    std::size_t stream_data_start = sp;
                    std::size_t stream_data_end = sp + static_cast<std::size_t>(stream_bytes);
                    std::size_t bp = stream_data_start;
                    // Decode the lzpf block-header varint (1-3 bytes, custom encoding).
                    auto decode_lzpf_header = [&](std::size_t& pos, std::uint32_t& out_uvar9) -> bool {
                        if (pos >= bytes.size()) return false;
                        std::uint8_t b0 = bytes[pos++];
                        std::uint32_t v = static_cast<std::uint32_t>(b0) ^ (b0 & 0x80u);
                        if ((b0 & 0x80u) != 0u) {
                            if (pos >= bytes.size()) return false;
                            std::uint8_t b1 = bytes[pos++];
                            v = (static_cast<std::uint32_t>(b1) ^ (b1 & 0x80u)) * 0x80u +
                                0x80u + v;
                            if ((b1 & 0x80u) != 0u) {
                                if (pos >= bytes.size()) return false;
                                std::uint8_t b2 = bytes[pos++];
                                v = static_cast<std::uint32_t>(b2) * 0x4000u + 0x4000u + v;
                            }
                        }
                        out_uvar9 = v;
                        return true;
                    };
                    // Multi-block loop. Each block produces up to 32 KiB into
                    // a sliding-window dict whose size is method_p1-dependent
                    // (legacy `param_1[1]`):
                    //   dict_size = (p1 + 1) * 64 KiB
                    // Empirically observed via gdb on legacy:
                    //   p1=0 → 64 KiB, p1=1 → 128 KiB, p1=3 → 256 KiB, p1=15 → 1 MiB.
                    // NOTE: earlier notes incorrectly said p1=0 → 128 KiB; the
                    // actual wrap behaviour (cursor hits 65536-32772=32764<32768
                    // after one block) confirms 64 KiB for p1=0.
                    // Layout: 4-byte left-pad (zero) before dict_base so the
                    // dispatcher's `hash_at_minus2(out)` read at cursor=0
                    // (post-wrap) is safe. Initial cursor = 4 — the encoder's
                    // dict starts as if 4 bytes were already "written"
                    // (initial pad). src_off in bytecode is relative to
                    // dict_base; position N in bytecode reads source[N-4].
                    // Cursor wraps to 0 when remaining < 32 KiB (mirrors
                    // legacy FUN_080b6bb0 — overwrites the leading 4 bytes
                    // of dict with new block data, no copy). Hash table
                    // persists across blocks. last_lz_dest re-initialised
                    // to -1 per block (FUN_08097570 line 138).
                    const std::size_t window_left_pad = 4u;
                    const std::size_t window_capacity =
                        (static_cast<std::size_t>(method_p1) + 1u) * 0x10000u;
                    const std::size_t window_wrap_threshold = 0x8000u;  // 32 KiB
                    const std::size_t window_initial_cursor = 4u;
                    std::vector<std::uint8_t> window_alloc(
                        window_left_pad + window_capacity, 0);
                    std::uint8_t* const window = window_alloc.data() + window_left_pad;
                    std::vector<unsigned char> decoded(
                        static_cast<std::size_t>(total_data_size), 0);
                    // Hash table sizing differs by variant:
                    //   A: 8192 × i32 = 32 KiB (13-bit hash).
                    //   B: 16M × i32 = 64 MiB (24-bit hash) + 8 KiB byte buffer.
                    // The variant-B allocation is large but matches the legacy
                    // `nz_lzpf_large` codec footprint. Allocated lazily — only
                    // when method_p0 == 2.
                    //
                    // BOTH variants initialize the hash table to 3, NOT 0.
                    // GDB trace (2026-06-04) on linux32/nz confirms that
                    // nz_lzpf_large also fills the hash table with the value
                    // 3 before any block is processed. Using 0 for variant B
                    // (the previous default) caused silent data corruption
                    // for multi-file archives with mixed random/repeat/zero
                    // files (regression fixture
                    // tests/fixtures/lzpf/regression_cF_multi.nz).
                    std::vector<std::int32_t> hash_table(
                        is_variant_b ? std::size_t{0x1000000u} : std::size_t{8192u},
                        std::int32_t{3});
                    std::vector<std::uint8_t> byte_buffer_b(
                        is_variant_b ? std::size_t{0x2000u} : std::size_t{0u}, 0);
                    std::size_t window_cursor = window_initial_cursor;
                    std::size_t total_written = 0;
                    std::size_t input_pos = bp;
                    bool decode_ok = true;
                    nzr::lzpf::LpcPredictor pf_pred{};
                    // LMS inter-channel state (FUN_08096e20) persists across blocks
                    // when the prefilter is stereo-split. Zero-init; reset only at
                    // the start of a new archive (the outer parse function allocates
                    // these afresh per archive).
                    nzr::lzpf::LmsObject pf_lms_ch1{};
                    nzr::lzpf::LmsObject pf_lms_ch2{};
                    pf_lms_ch1.Init();
                    pf_lms_ch2.Init();
                    while (total_written < total_data_size) {
                        // If we've consumed the current stream's bytes and
                        // there's more output to produce, advance to the
                        // next stream tag in the chain.
                        if (input_pos >= stream_data_end) {
                            if (input_pos != stream_data_end) {
                                decode_ok = false; break;
                            }
                            std::uint64_t next_tag = 0;
                            if (!ReadLegacyVarint(bytes, &input_pos, bytes.size(), &next_tag) ||
                                (next_tag & 0x0fu) != 0u) {
                                decode_ok = false; break;
                            }
                            const std::uint64_t next_bytes = next_tag >> 4u;
                            if (next_bytes == 0u ||
                                next_bytes > static_cast<std::uint64_t>(bytes.size() - input_pos)) {
                                decode_ok = false; break;
                            }
                            stream_data_start = input_pos;
                            stream_data_end = input_pos + static_cast<std::size_t>(next_bytes);
                        }
                        std::uint32_t uvar9 = 0;
                        if (!decode_lzpf_header(input_pos, uvar9)) {
                            decode_ok = false; break;
                        }
                        // Only LZ77+side-stream mode is implemented natively.
                        // Other modes (`uVar9 & 7 == 4` prefilter+arith, or
                        // `& 1 == 0` raw bytecode without side-stream) fall
                        // through to the bridge.
                        // Mode dispatch (per FUN_08097570):
                        //   (uvar9 & 7) == 4: prefilter+arith → bridge (task #13)
                        //   (uvar9 & 2) == 0: literal block (memcpy raw bytes)
                        //   (uvar9 & 2) != 0 + (uvar9 & 1): LZ77 + arith side-stream
                        //   (uvar9 & 2) != 0 + !(uvar9 & 1): LZ77, raw bytecode (no side-stream)
                        const bool mode_prefilter = ((uvar9 & 7u) == 4u);
                        const bool mode_literal = !mode_prefilter && ((uvar9 & 2u) == 0u);
                        const bool mode_lz77_side = !mode_prefilter && (uvar9 & 2u) && (uvar9 & 1u);
                        if (mode_prefilter) {
                            // uVar18 (bit 3 of uvar9) selects lzpf (0) vs lzhd-large (1) core.
                            // lzhd-large prefilter (FUN_080a9ca0) not yet ported.
                            const std::uint32_t uvar18 = (uvar9 >> 3u) & 1u;
                            if (uvar18 != 0u) { decode_ok = false; break; }
                            std::uint64_t block_out_size = uvar9 >> 4u;
                            if (block_out_size == 0u) block_out_size = 0x8000u;
                            if (block_out_size > 0x8001u) { decode_ok = false; break; }
                            if (total_written + block_out_size > total_data_size) {
                                decode_ok = false; break;
                            }
                            if (window_capacity - window_cursor < window_wrap_threshold) {
                                window_cursor = 0;
                            }
                            const std::size_t block_start_in_window = window_cursor;
                            const std::size_t avail_in = stream_data_end - input_pos;
                            // Auto-detect stereo split from the prefilter header byte
                            // (FUN_080a5330 line 50: channels = (hdr>>1) % 3).
                            // If channels != 0, is_stereo_variant must be true so the
                            // LMS inter-channel predictor (FUN_08096e20) runs. The LMS
                            // objects persist across blocks in the outer loop.
                            const std::uint8_t pf_hdr = bytes[input_pos];
                            const std::uint32_t pf_channels = (pf_hdr >> 1u) % 3u;
                            const bool is_stereo_pf = (pf_channels != 0u);
                            const std::size_t pf_consumed = nzr::lzpf::DecodePrefilterStream(
                                bytes.data() + input_pos, avail_in,
                                window + block_start_in_window,
                                static_cast<std::size_t>(block_out_size),
                                is_stereo_pf,
                                &pf_pred,
                                is_stereo_pf ? &pf_lms_ch1 : nullptr,
                                is_stereo_pf ? &pf_lms_ch2 : nullptr);
                            if (pf_consumed == 0) { decode_ok = false; break; }
                            input_pos += pf_consumed;
                            window_cursor += static_cast<std::size_t>(block_out_size);
                            std::memcpy(decoded.data() + total_written,
                                        window + block_start_in_window,
                                        static_cast<std::size_t>(block_out_size));
                            total_written += static_cast<std::size_t>(block_out_size);
                            continue;
                        }
                        // Raw-bytecode LZ77 (no side stream) not yet ported.
                        if (!mode_literal && !mode_lz77_side) { decode_ok = false; break; }
                        std::uint64_t block_out_size = uvar9 >> 3u;
                        if (block_out_size == 0u) block_out_size = 0x8000u;
                        if (block_out_size > 0x8001u) { decode_ok = false; break; }
                        if (total_written + block_out_size > total_data_size) {
                            decode_ok = false; break;
                        }
                        if (mode_literal) {
                            // LITERAL: copy block_out_size bytes from input → user output AND dict.
                            // (Mirrors FUN_08097570 lines 81-95.)
                            if (input_pos + block_out_size > stream_data_end) {
                                decode_ok = false; break;
                            }
                            // Pre-block sliding-window wrap.
                            if (window_capacity - window_cursor < window_wrap_threshold) {
                                window_cursor = 0;
                            }
                            const std::size_t block_start_in_window = window_cursor;
                            std::memcpy(window + block_start_in_window,
                                        bytes.data() + input_pos,
                                        static_cast<std::size_t>(block_out_size));
                            std::memcpy(decoded.data() + total_written,
                                        bytes.data() + input_pos,
                                        static_cast<std::size_t>(block_out_size));
                            window_cursor += static_cast<std::size_t>(block_out_size);
                            input_pos += static_cast<std::size_t>(block_out_size);
                            total_written += static_cast<std::size_t>(block_out_size);
                            continue;
                        }
                        if (input_pos + 2u > stream_data_end) { decode_ok = false; break; }
                        const std::uint16_t side_count =
                            static_cast<std::uint16_t>(bytes[input_pos]) |
                            (static_cast<std::uint16_t>(bytes[input_pos + 1u]) << 8u);
                        input_pos += 2u;
                        const std::size_t arith_size = stream_data_end - input_pos;
                        std::vector<std::uint8_t> bytecode(side_count + 16u, 0);
                        const std::size_t consumed = nzr::lzpf::DecodeArithBuffer(
                            bytes.data() + input_pos, arith_size,
                            bytecode.data(), side_count, /*max_len=*/12);
                        if (consumed == 0 || consumed > arith_size) {
                            decode_ok = false; break;
                        }
                        input_pos += consumed;
                        // Pre-block sliding-window wrap (mirrors FUN_080b6bb0
                        // — wraps cursor to 0, re-using the leading bytes of
                        // the dict; the 4-byte left-pad allocated outside
                        // ensures hash_at_minus2 reads stay in-bounds).
                        if (window_capacity - window_cursor < window_wrap_threshold) {
                            window_cursor = 0;
                        }
                        const std::size_t block_start_in_window = window_cursor;
                        std::int32_t last_lz_dest = -1;  // re-init per block
                        const bool dispatch_ok = is_variant_b
                            ? nzr::lzpf::DecodeLz77VariantB(
                                  bytecode.data(), side_count,
                                  window, window_capacity,
                                  &window_cursor, static_cast<std::size_t>(block_out_size),
                                  hash_table.data(), byte_buffer_b.data(),
                                  &last_lz_dest)
                            : nzr::lzpf::DecodeLz77VariantA(
                                  bytecode.data(), side_count,
                                  window, window_capacity,
                                  &window_cursor, static_cast<std::size_t>(block_out_size),
                                  hash_table.data(), &last_lz_dest);
                        if (!dispatch_ok) {
                            decode_ok = false; break;
                        }
                        if (window_cursor != block_start_in_window + block_out_size) {
                            decode_ok = false; break;
                        }
                        std::memcpy(decoded.data() + total_written,
                                    window + block_start_in_window,
                                    static_cast<std::size_t>(block_out_size));
                        total_written += static_cast<std::size_t>(block_out_size);
                    }
                    if (decode_ok && total_written == total_data_size) {
                        bool vok = validate_decoded_candidate(decoded);
                        if (vok) {
                            native_literal_payload = true;
                            literal_data_offset = 0u;
                            literal_data_size = decoded.size();
                            literal_data_owned = true;
                            literal_data_buffer = std::move(decoded);
                        }
                        // Defensive cross-check: when the native LZ77+arith
                        // path produces a size-correct candidate but its
                        // checksums do not match (or no checksums exist),
                        // leave native_literal_payload=false. The caller in
                        // RunLegacyCnExtractOrTest will then attempt the
                        // legacy extract-bridge and adopt its output if the
                        // bridge produces a checksum-valid candidate. This
                        // guarantees byte-exact decode for -cf/-cF even if
                        // the native LZ77 dispatcher drifts on inputs that
                        // don't have per-entry checksums (e.g. multi-file
                        // archives with literal-only substream segments
                        // that the current single-stream literal detector
                        // rejects). Skippable via NZ_DISABLE_LZPF_BRIDGE=1.
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
    ctx.data_offset = native_store_payload ? data_offset_u64 : 0u;
    ctx.total_data_size = total_data_size;
    if (native_store_payload) {
        const std::size_t data_offset = static_cast<std::size_t>(data_offset_u64);
        ctx.data.assign(bytes.begin() + static_cast<std::ptrdiff_t>(data_offset), bytes.end());
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
               method == 0x4bu && method_p0 == 7u &&
               payload_start < bytes.size()) {
        // For native CM decode: store the raw compressed stream so
        // TryDecodeLegacyCm can parse stream_tag + block headers directly.
        // NOTE: -co/-cO (0x3b) and -cd (0x2b) are NOT populated — large blocks use
        // a virtual-stream LZ framing (not flat payload_size) that crashes a flat
        // DecLZ call; they bridge until that framing is reverse-engineered.
        ctx.data.assign(bytes.begin() + static_cast<std::ptrdiff_t>(payload_start),
                        bytes.end());
    }

    *out_context = std::move(ctx);
    if (out_error_message != nullptr) {
        out_error_message->clear();
    }
    return true;
}

int RunLegacyCnList(const CliOptions& options, const LegacyCnContext& legacy, std::ostream& os) {
    const bool has_checksum = legacy.checksum_mode != ChecksumMode::kNone;
    os << "Archive: " << legacy.archive_path << '\n';
    os << "Compressor: "
       << LegacyCompressorLabel(legacy.legacy_method, legacy.legacy_method_p0, legacy.legacy_method_p1)
       << '\n';
    os << "Payload: " << LegacyPayloadModeLabel(legacy.payload_mode) << '\n';
    if (has_checksum) {
        os << "checksum ";
    }
    os << "perm yyyy-mmm-dd hh:mm:ss     size  file\n";

    std::uint64_t total_size = 0;
    std::size_t total_files = 0;
    for (const LegacyCnEntry& e : legacy.entries) {
        if (!MatchesAnyPattern(e.path, options.positional)) {
            continue;
        }

        if (has_checksum) {
            const std::uint32_t shown = e.has_checksum ? e.checksum : 0;
            os << std::setw(8) << std::left << FormatChecksum(legacy.checksum_mode, shown) << ' ';
        }
        os << std::setw(4) << std::right << FormatMode(e.has_permissions ? e.permissions : 0u) << ' '
           << FormatMtime(e.has_mtime ? e.mtime_unix : 0) << " "
           << std::setw(8) << std::right << HumanBytes(e.size) << "   "
           << e.path << '\n';

        total_size += e.size;
        ++total_files;
    }

    os << "Total of " << total_files << " files, " << total_size << " bytes.\n";
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

    if (legacy.legacy_method != 0x2bu ||
        (legacy.legacy_method_p0 != 3u && legacy.legacy_method_p0 != 4u))
        return false;
    if (legacy.data.empty()) return false;

    const auto* raw = legacy.data.data();
    const std::size_t raw_len = legacy.data.size();

    // Pre-allocate full output with 16-byte zero prefix for safe history reads
    // (DecLZ reads cur_ptr[-5] etc. from the first byte).
    static constexpr std::size_t kWindowPad = 16u;
    const std::size_t total_out = static_cast<std::size_t>(legacy.total_data_size);
    std::vector<unsigned char> buf(kWindowPad + total_out, 0u);
    unsigned char* const window_base = buf.data() + kWindowPad;

    NzLzhdDecoder* dec = NzLzhdCreate();
    if (!dec) {
        if (out_error_message) *out_error_message = "lzhd: allocation failed";
        return false;
    }

    std::size_t pos = 0u;
    std::size_t written = 0u;
    bool ok = true;

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

        // out_size for this block: everything remaining (single-block archives)
        // or a per-block portion.  We pass what's left; DecLZ stops when done.
        const std::uint32_t block_out = static_cast<std::uint32_t>(total_out - written);

        NzLzhdDecode(dec, block_in, block_in_size,
                     window_base + written, block_out, window_base);
        written += block_out;
    }

    NzLzhdDestroy(dec);

    if (!ok) {
        if (out_error_message) *out_error_message = "lzhd: malformed block stream";
        return false;
    }
    if (written != total_out) {
        if (out_error_message) *out_error_message = "lzhd: output size mismatch";
        return false;
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

    // Read stream_tag varint: value = N, stream_bytes = N >> 4, low nibble must be 0.
    std::size_t pos = 0;
    std::uint64_t stream_tag = 0;
    {
        unsigned shift = 7;
        unsigned char c = raw[pos++];
        stream_tag = static_cast<std::uint64_t>(c & 0x7fu);
        while ((c & 0x80u) != 0u) {
            if (pos >= raw_len || shift >= 63u) {
                if (out_error_message) *out_error_message = "cm: truncated stream_tag";
                return false;
            }
            c = raw[pos++];
            stream_tag += (static_cast<std::uint64_t>((c & 0x7fu) + 1u) << shift);
            shift += 7u;
        }
    }
    if ((stream_tag & 0x0fu) != 0u) {
        if (out_error_message) *out_error_message = "cm: bad stream_tag alignment";
        return false;
    }
    const std::uint64_t stream_bytes = stream_tag >> 4u;
    if (stream_bytes > raw_len - pos) {
        if (out_error_message) *out_error_message = "cm: stream_bytes exceeds data";
        return false;
    }
    const std::size_t stream_end = pos + static_cast<std::size_t>(stream_bytes);

    NzCmDecoder* cm = NzCmCreate(legacy.cm_a_bits, legacy.cm_b_bits, legacy.cm_window_size);
    if (!cm) {
        if (out_error_message) *out_error_message = "cm: allocation failed";
        return false;
    }

    out_data->reserve(static_cast<std::size_t>(legacy.total_data_size));
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
        // Read dece_param.
        if (pos >= stream_end) { ok = false; break; }
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
            pos += vlen;
        }

        if (!param6 || out_size == 0u) continue;

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

        // param2: u32-wise RLE expansion driven by the param2 side stream.
        if (param2_flag) {
            std::vector<std::uint8_t> exp(remaining);
            std::uint32_t esz = remaining;
            if (!NzBwtRleDecodeU32(param2_data.data(),
                                   static_cast<std::uint32_t>(param2_data.size()),
                                   work.data(), cur_size, exp.data(), &esz)
                || esz == 0u) { ok = false; break; }
            exp.resize(esz);
            work.swap(exp);
            cur_size = esz;
        }

        // param1 (AddBytesFilter) and dece (exe filter) not yet ported.
        if (param1_flag) { ok = false; break; }

        // Text transforms, applied in reference order: 0x10 (number transform),
        // then 0x08 (dictionary). Other bits (0x80/0x04/0x02/0x20/0x40/0x01) not
        // yet ported -> decline so the caller can bridge.
        if (tt_enabled && (tt_flags & ~(0x10u | 0x08u))) { ok = false; break; }
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
            std::vector<std::uint8_t> tbuf(remaining);
            const std::uint32_t expanded = NzTextTransformDict(
                work.data(), cur_size, tbuf.data(), remaining);
            if (expanded == 0) { ok = false; break; }
            tbuf.resize(expanded);
            work.swap(tbuf);
            cur_size = expanded;
        }

        if (dece_param) { ok = false; break; }

        out_data->insert(out_data->end(), work.begin(), work.begin() + cur_size);
    }

    NzCmDestroy(cm);

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
    return true;
}

// Decode -co/-cO (nz_optimum1/2) natively. These use the same flat block framing
// as -cc (chunk-header "stream_tag" + per-block Header: payload_size u32, decr_param,
// param6, size18, staged, params, tt, dece) but the core codec is DecLZ (decr_param
// == 1), driven through a persistent raw window (LZ back-references span blocks).
// The reference (nzdec_v0) decodes -cO via DecodeLZ; the ported DecLZ is byte-exact
// against it. The decoded raw stream is then run through the param2/param1/tt/dece
// post-filter pipeline (same as -cc). decr_param == 0 (BWT) blocks are not yet
// ported and cause a decline -> bridge.
[[maybe_unused]] static bool TryDecodeLegacyOptimum(
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

    std::size_t pos = 0;
    std::uint64_t stream_tag = 0;
    {
        unsigned shift = 7;
        unsigned char c = raw[pos++];
        stream_tag = static_cast<std::uint64_t>(c & 0x7fu);
        while ((c & 0x80u) != 0u) {
            if (pos >= raw_len || shift >= 63u) { return false; }
            c = raw[pos++];
            stream_tag += (static_cast<std::uint64_t>((c & 0x7fu) + 1u) << shift);
            shift += 7u;
        }
    }
    if ((stream_tag & 0x0fu) != 0u) return false;
    const std::uint64_t stream_bytes = stream_tag >> 4u;
    if (stream_bytes > raw_len - pos) return false;
    const std::size_t stream_end = pos + static_cast<std::size_t>(stream_bytes);

    // Persistent raw window for DecLZ. Sum(size18) <= total_data_size because the
    // post-transforms (param2 RLE / tt dict+number) only expand. Reserve generously
    // and bounds-check so a reallocation can never move window_base mid-decode.
    // DecLZ reads context bytes before the cursor (cur_ptr[-2..-6]) and copies
    // matches from earlier output, so the window needs leading zero-padding
    // (the reference MemBlocks pads data_org by 64 bytes).
    static constexpr std::size_t kWindowPad = 64u;
    const std::size_t window_cap =
        static_cast<std::size_t>(legacy.total_data_size) + (1u << 20);
    std::vector<std::uint8_t> rawbuf(kWindowPad + window_cap, 0u);
    std::uint8_t* const window_base = rawbuf.data() + kWindowPad;
    std::size_t raw_pos = 0;

    NzLzhdDecoder* dec = NzLzhdCreate();
    if (!dec) { return false; }

    out_data->reserve(static_cast<std::size_t>(legacy.total_data_size));
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

        // decr_param == 0 (BWT) path not yet ported.
        if (decr_param == 0u) { ok = false; break; }

        // params 14/15 (BWT-only) appear only for decr_param==0, so for the LZ
        // path we go straight to param2/param1/param16/tt/dece.
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
        if (param1_flag) {
            if (pos + 4u > stream_end) { ok = false; break; }
            std::uint32_t vlen = static_cast<std::uint32_t>(raw[pos]) |
                (static_cast<std::uint32_t>(raw[pos+1]) << 8u) |
                (static_cast<std::uint32_t>(raw[pos+2]) << 16u) |
                (static_cast<std::uint32_t>(raw[pos+3]) << 24u);
            pos += 4u + vlen;
            if (pos > stream_end) { ok = false; break; }
        }
        if (pos + 1u > stream_end) { ok = false; break; }
        pos++;  // param16
        if (pos >= stream_end) { ok = false; break; }
        const std::uint8_t tt_enabled = raw[pos++];
        std::uint8_t tt_flags = 0;
        std::vector<std::uint8_t> tt16_data;
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
            std::vector<std::uint8_t> tt2_data;
            if ((tt_flags & 2u) && !read_varint_str(tt2_data)) { ok = false; break; }
            if ((tt_flags & 16u) && !read_varint_str(tt16_data)) { ok = false; break; }
        }
        if (pos >= stream_end) { ok = false; break; }
        const std::uint8_t dece_param = raw[pos++];
        if (dece_param) {
            if (pos + 4u > stream_end) { ok = false; break; }
            std::uint32_t vlen = static_cast<std::uint32_t>(raw[pos]) |
                (static_cast<std::uint32_t>(raw[pos+1]) << 8u) |
                (static_cast<std::uint32_t>(raw[pos+2]) << 16u) |
                (static_cast<std::uint32_t>(raw[pos+3]) << 24u);
            pos += 4u + vlen;
            if (pos > stream_end) { ok = false; break; }
        }

        if (!param6 || out_size == 0u) continue;

        // Decode this block's LZ payload into the persistent window.
        if (raw_pos + out_size > window_cap) { ok = false; break; }
        NzLzhdDecode(dec, payload, payload_size, window_base + raw_pos, out_size, window_base);
        std::vector<std::uint8_t> work(window_base + raw_pos, window_base + raw_pos + out_size);
        raw_pos += out_size;
        std::uint32_t cur_size = out_size;

        const std::size_t prev_size = out_data->size();
        const std::uint32_t remaining =
            static_cast<std::uint32_t>(legacy.total_data_size) -
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
        if (param1_flag) { ok = false; break; }
        if (tt_enabled && (tt_flags & ~(0x10u | 0x08u))) { ok = false; break; }
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
            std::vector<std::uint8_t> tbuf(remaining);
            const std::uint32_t n = NzTextTransformDict(work.data(), cur_size, tbuf.data(), remaining);
            if (n == 0) { ok = false; break; }
            tbuf.resize(n); work.swap(tbuf); cur_size = n;
        }
        if (dece_param) { ok = false; break; }

        out_data->insert(out_data->end(), work.begin(), work.begin() + cur_size);
    }

    NzLzhdDestroy(dec);

    if (!ok || out_data->size() != static_cast<std::size_t>(legacy.total_data_size)) {
        out_data->clear();
        if (out_error_message) *out_error_message = "optimum: decode failed";
        return false;
    }
    return true;
}

int RunLegacyCnExtractOrTest(
    const CliOptions& options,
    const LegacyCnContext& legacy,
    bool test_mode,
    std::ostream& os) {
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
        // NOTE: native -co/-cO (TryDecodeLegacyOptimum) is intentionally NOT wired
        // in. Small -cO blocks use a flat DecLZ framing that decodes natively, but
        // larger -cO files switch to the same virtual-stream LZ framing as -cd
        // (the reference nzdec_ref also crashes on them), which makes a flat DecLZ
        // call wild-read and SIGSEGV. Until the virtual-stream framing is reversed,
        // -co/-cO route to the bridge. See PROGRESO_2026-06-08.md §optimum.
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
            std::ofstream out(out_path, std::ios::binary | std::ios::trunc);
            if (!out) {
                os << "Cannot write output file: " << out_path.string() << '\n';
                ++failed;
                continue;
            }
            out.write(reinterpret_cast<const char*>(ptr), static_cast<std::streamsize>(n));
            if (!out) {
                os << "Cannot write output file: " << out_path.string() << '\n';
                ++failed;
                continue;
            }
            out.close();

            std::string metadata_warning;
            const bool metadata_ok = ApplyExtractedMetadata(
                out_path,
                e.has_permissions,
                e.permissions,
                e.has_mtime,
                e.mtime_unix,
                &metadata_warning);
            if (!metadata_ok && options.verbose && !metadata_warning.empty()) {
                os << "Warning: " << metadata_warning << '\n';
            }
        }

        ++processed;
        bytes_ok += e.size;
        if (options.verbose) {
            os << (test_mode ? "tested " : "extract ") << e.path << '\n';
        }
    }

    if (test_mode) {
        os << "Tested " << processed << " files, " << bytes_ok << " bytes.";
    } else {
        os << "Extracted " << processed << " files, " << bytes_ok << " bytes.";
    }
    if (failed > 0) {
        os << " Failures: " << failed << '.';
    }
    os << '\n';

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
    os << "Archive: " << out_path.string() << '\n';
    os << "Compressor: " << CompressorToString(options.compressor)
       << " (" << LegacyNativeWrapperLabel(spec.wrapper) << ")\n";
    os << "Total of " << sources.size() << " files, " << total_bytes << " bytes.\n";
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

        if (options.verbose) {
            os << "added  " << src.archive_name << " (" << src.size << " bytes)\n";
        }
    }

    os << "Archive: " << out_path.string() << '\n';
    os << "Compressor: " << CompressorToString(options.compressor) << " (stored)\n";
    os << "Total of " << sources.size() << " files, " << total_bytes << " bytes.\n";
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
           << FormatMtime(e.mtime_unix) << " "
           << std::setw(8) << std::right << HumanBytes(e.original_size) << "   "
           << e.path << '\n';

        total_size += e.original_size;
        ++total_files;
    }

    os << "Total of " << total_files << " files, " << total_size << " bytes.\n";
    return 0;
}

int RunExtractOrTest(const CliOptions& options, bool test_mode, std::ostream& os) {
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

    if (test_mode) {
        os << "Tested " << processed << " files, " << bytes_ok << " bytes.";
    } else {
        os << "Extracted " << processed << " files, " << bytes_ok << " bytes.";
    }
    if (failed > 0) {
        os << " Failures: " << failed << '.';
    }
    os << '\n';

    return failed == 0 ? 0 : 2;
}

int RunInfo(std::ostream& os) {
    const std::string cpu = ParseProcValue("/proc/cpuinfo", "model name\t:");
    const std::string mem_total = ParseProcValue("/proc/meminfo", "MemTotal:");
    const std::string mem_avail = ParseProcValue("/proc/meminfo", "MemAvailable:");

    os << "Host information\n";
    if (!cpu.empty()) {
        os << "CPU: " << cpu << '\n';
    }
    if (!mem_total.empty()) {
        os << "MemTotal: " << mem_total << '\n';
    }
    if (!mem_avail.empty()) {
        os << "MemAvailable: " << mem_avail << '\n';
    }
    if (cpu.empty() && mem_total.empty() && mem_avail.empty()) {
        os << "(basic host info unavailable on this platform)\n";
    }
    return 0;
}

}  // namespace recon
}  // namespace nz
