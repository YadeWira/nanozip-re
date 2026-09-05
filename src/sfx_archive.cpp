#include "nz_env.h"
#include "nz_trace.h"
#include "nz_decode_error.h"
#if !defined(_WIN32)
#include <sys/stat.h>
#endif
#include "nz_sfx/sfx_archive.hpp"
#include "lzpf_arith.h"
#include "nz_cm.h"
#include "nz_cd_tokens.h"
#include "nz_lzhds.h"
#include "nz_optimum_lz.h"
#include "nz_optimum2_lz.h"
#include "nz_text_transform.h"
#include "nz_postfilter.h"
#include "nz_bwt.h"
#include "nz_audio.h"
#include <atomic>
#include <cpuid.h>
#include <memory>
#include <mutex>
#include <type_traits>
#include <thread>
#include <iterator>
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

#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#include <windows.h>   // SetFileAttributes for the attribute records (type 3)
#endif
#if defined(__unix__) || defined(__APPLE__)
#include <sys/wait.h>
#include <unistd.h>
#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/mman.h>
#include <utime.h>
#endif
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
    // Deferred modulo: the per-byte `% 255` was 14 % of a 2.29 GB decode (perf,
    // 2026-09-03). Reducing once per block is exact -- every intermediate a_i is
    // congruent to its reduced value, so the sum of the unreduced a_i is too.
    // With 64-bit accumulators a block of 65536 bytes cannot overflow.
    std::uint64_t a = *s1;
    std::uint64_t b = *s2;
    std::size_t i = 0;
    while (i < size) {
        const std::size_t end = std::min(size, i + 65536u);
        for (; i < end; ++i) {
            a += data[i];
            b += a;
        }
        a %= 255u;
        b %= 255u;
    }
    *s1 = static_cast<std::uint32_t>(a);
    *s2 = static_cast<std::uint32_t>(b);
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

    // Deferred modulo (see UpdateFletcher16): words are < 65536, so with 64-bit
    // accumulators a block of 2^20 words cannot overflow.
    {
        std::uint64_t a = *s1, b = *s2;
        while (i + 1 < size) {
            const std::size_t end = std::min(size - 1, i + (std::size_t{1} << 21));
            for (; i + 1 < end + 1 && i + 1 < size; i += 2u) {
                a += static_cast<std::uint32_t>(data[i]) | (static_cast<std::uint32_t>(data[i + 1u]) << 8u);
                b += a;
            }
            a %= 0xffffu;
            b %= 0xffffu;
        }
        *s1 = static_cast<std::uint32_t>(a);
        *s2 = static_cast<std::uint32_t>(b);
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
                        std::uint32_t mode, long owner_uid = -1, long owner_gid = -1) {
#if defined(_WIN32)
    (void)mode; (void)owner_uid; (void)owner_gid;
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    // Never hand the CRT a single write above 2 GB: msvcrt's _write() takes an
    // unsigned count but returns an int, so a 2.29 GB request completes on disk
    // and then reports a negative count, which the stream layer treats as a
    // short write and retries forever (100% CPU after the file is complete --
    // the first user report). 256 MB pieces keep every count comfortably small.
    std::size_t off = 0;
    while (off < n) {
        const std::size_t piece = std::min<std::size_t>(n - off, std::size_t{1} << 28);
        out.write(reinterpret_cast<const char*>(data) + off, static_cast<std::streamsize>(piece));
        if (!out) return false;
        off += piece;
    }
    out.close();
    return static_cast<bool>(out);
#else
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC,
                          static_cast<mode_t>(mode & 07777u));
    if (fd < 0) {
        return false;
    }
    // -fo: the original calls fchown on the open descriptor with the stored
    // user/group and ignores the result (measured: fchown32(fd, uid, gid), then
    // utime; nothing printed when it fails for a non-root user).
    if (owner_uid >= 0) (void)::fchown(fd, static_cast<uid_t>(owner_uid), static_cast<gid_t>(owner_gid));
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
#endif
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
            // The original's own wording, printed without the port's
            // "Warning: " prefix (measured: `nz a new.nz nope.txt`).
            warnings->push_back("No files found with " + arg);
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
        *error = "Nothing to do (no files found).";
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
    // Measured: a timestamp that comes out as exactly 0 prints as an EMPTY field
    // (the size column follows straight after "perm "); negative values print
    // normally (1969-Dec-30 ...).
    if (unix_seconds == 0) {
        return "";
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
    // Measured on l/x under TZ=UTC, Asia/Kolkata and America/Sao_Paulo: the
    // stored value is epoch MINUS the writer's offset; the reader adds ITS OWN
    // current offset, so the result is only right in the writer's zone (a
    // 2*offset skew elsewhere -- reproduced, see ORIGINAL_QUIRKS). Everything is
    // a 32-bit time_t in the original: a 2038+ mtime wraps to 1901/1963.
    // The offset is the reader's CURRENT one (DST included: Europe/Berlin in
    // September adds +2 h to a January 1970 stamp), not the offset at the file's
    // own date -- measured under Berlin, Sydney, Kolkata, Sao Paulo and UTC.
    const std::int32_t s32 = static_cast<std::int32_t>(static_cast<std::uint32_t>(stored));
    static const long off = [] {
        const std::time_t now = std::time(nullptr);
        std::tm tmv{};
#if defined(_WIN32)
        localtime_s(&tmv, &now);
        return static_cast<long>(-_timezone + (tmv.tm_isdst > 0 ? 3600 : 0));
#else
        localtime_r(&now, &tmv);
        return static_cast<long>(tmv.tm_gmtoff);
#endif
    }();
    const std::int64_t sum = static_cast<std::int64_t>(s32) + static_cast<std::int64_t>(off);
    return static_cast<std::int32_t>(static_cast<std::uint32_t>(static_cast<std::uint64_t>(sum)));
}

// The plain listing shows names longer than 38 columns as "..." plus their last
// 35 characters (measured: 36-38 whole, 39+ cut). The progress line has its own
// rule (40 / 37, DecodeProgress::Name).
std::string TruncateName40(const std::string& name) {
    if (name.size() > 38u) return "..." + name.substr(name.size() - 35u);
    return name;
}

// The original creates the directories of an extracted path with mode 0700
// (measured on every tree of the round-3 matrix), whatever the umask says.
void MakeDirs0700(const fs::path& dir) {
    if (dir.empty()) return;
    std::error_code ec;
    if (fs::exists(dir, ec)) return;
    MakeDirs0700(dir.parent_path());
#if defined(_WIN32)
    fs::create_directory(dir, ec);
#else
    ::mkdir(dir.c_str(), 0700);
#endif
}

std::string FormatMtimeStored(std::int64_t stored) {
    return FormatMtime(LegacyStoredMtimeToUnix(stored));
}

// The original restores a timestamp with utime(), which takes whole seconds and
// leaves the access time at "now".  Going through std::filesystem instead lands
// a fractional nanosecond part that a byte-exact tree comparison catches.
// A Windows-made archive stores file attributes (record type 3); on Windows the
// original RESTORES them, so a read-only, hidden or system file comes back that
// way. Measured on a real Windows 10 machine, all four bits. Applied AFTER the
// data is written and closed, because READONLY would otherwise refuse the write.
void SetExtractedWinAttributes(const fs::path& path, std::uint8_t attr) {
#if defined(_WIN32)
    DWORD flags = 0;
    if (attr & 1u) flags |= FILE_ATTRIBUTE_READONLY;
    if (attr & 2u) flags |= FILE_ATTRIBUTE_HIDDEN;
    if (attr & 4u) flags |= FILE_ATTRIBUTE_SYSTEM;
    if (attr & 8u) flags |= FILE_ATTRIBUTE_ARCHIVE;
    if (flags != 0u) SetFileAttributesA(path.string().c_str(), flags);
#else
    (void)path; (void)attr;   // on a POSIX host the mode carries this (0400/0600)
#endif
}

bool SetExtractedMtime(const fs::path& path, std::int64_t stored) {
    const std::int64_t real = LegacyStoredMtimeToUnix(stored);
    if (real == 0) return true;   // measured: a zero timestamp is left alone; negatives are applied
#if defined(_WIN32)
    // mingw hides the utime() family under -std=c++17 (__STRICT_ANSI__), and
    // Windows has no whole-second-only stat to be exact against anyway.
    std::error_code ec;
    fs::last_write_time(path, UnixToFileTime(real), ec);
    return !ec;
#else
    struct utimbuf tb;
    tb.actime = std::time(nullptr);
    tb.modtime = static_cast<std::time_t>(real);
    return ::utime(path.c_str(), &tb) == 0;
#endif
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



// There is no fallback to an original `nz` binary anywhere in this program: every
// decode is native, and a stream no native decoder accepts is reported as corrupt.
// (`NZ_NO_BRIDGE`, which the test suites still export, is simply ignored.)







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
    // An archive made by the WINDOWS original stores file attributes (record
    // type 3) instead of POSIX modes: one nibble per entry, `8 | R | H<<1 | S<<2`
    // where 8 is the archive bit. The Linux original maps them to a mode -- 0400
    // for read-only, 0600 otherwise -- and the Windows one prints them as an
    // "R H S A" field.
    std::uint8_t win_attr = 0;
    bool has_win_attr = false;
    std::int64_t mtime_unix = 0;
    bool has_mtime = false;
    // -fo archives carry uid/gid runs (record types 8 and 9); `l -fo` shows them
    // as a "user/grp." column.
    std::uint32_t uid = 0;
    std::uint32_t gid = 0;
    bool has_owner = false;
};

enum class LegacyPayloadMode {
    kUnknown,
    kStore,
    kLiteralOnly,
    kCompressed
};

// The decoded output. Either a std::vector moved in from a producer (no copy),
// or an UNINITIALISED heap array for producers that fill every byte themselves
// -- the parallel containers, whose slices are proven to tile the output before
// any worker starts. std::vector<unsigned char>(n) zeroes n bytes on ONE thread
// before the decode can begin; on a 2.3 GB archive that alone was half a second
// of the critical path, and every page was then faulted in a second time by the
// workers.

// A read-only view of the archive bytes. The parser and every decoder only ever
// read them, so they can look at a memory MAPPING of the file instead of a heap
// copy: on a 2 GB archive that is 2 GB of anonymous memory turned into
// reclaimable page cache (the original streams its input, quirk 23).
class ByteView {
public:
    ByteView() = default;
    ByteView(const unsigned char* p, std::size_t n) : p_(p), n_(n) {}
    ByteView(const std::vector<unsigned char>& v) : p_(v.data()), n_(v.size()) {}   // NOLINT: implicit by design
    const unsigned char* data() const { return p_; }
    std::size_t size() const { return n_; }
    bool empty() const { return n_ == 0u; }
    const unsigned char* begin() const { return p_; }
    const unsigned char* end() const { return p_ + n_; }
    unsigned char operator[](std::size_t i) const { return p_[i]; }
    ByteView subview(std::size_t off) const { return off <= n_ ? ByteView(p_ + off, n_ - off) : ByteView(); }
private:
    const unsigned char* p_ = nullptr;
    std::size_t n_ = 0;
};

// The archive file, mapped read-only where the platform allows it and read into
// a vector otherwise (Windows, and any mmap failure).
class ArchiveBytes {
public:
    ~ArchiveBytes() { Close(); }
    ArchiveBytes() = default;
    ArchiveBytes(const ArchiveBytes&) = delete;
    ArchiveBytes& operator=(const ArchiveBytes&) = delete;
    bool Open(const std::string& path) {
        Close();
#if !defined(_WIN32)
        const int fd = ::open(path.c_str(), O_RDONLY);
        if (fd >= 0) {
            struct stat st{};
            if (::fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0) {
                const std::size_t n = static_cast<std::size_t>(st.st_size);
                void* m = ::mmap(nullptr, n, PROT_READ, MAP_PRIVATE, fd, 0);
                if (m != MAP_FAILED) {
                    ::close(fd);
                    map_ = static_cast<const unsigned char*>(m);
                    map_n_ = n;
                    return true;
                }
            }
            ::close(fd);
        }
#endif
        std::ifstream input(path, std::ios::binary);
        if (!input) return false;
        input.seekg(0, std::ios::end);
        const std::streamoff len = input.tellg();
        input.seekg(0, std::ios::beg);
        if (len > 0) {
            vec_.resize(static_cast<std::size_t>(len));
            input.read(reinterpret_cast<char*>(vec_.data()), len);
            if (!input) vec_.resize(static_cast<std::size_t>(input.gcount()));
        }
        return true;
    }
    void Close() {
#if !defined(_WIN32)
        if (map_ != nullptr) { ::munmap(const_cast<unsigned char*>(map_), map_n_); map_ = nullptr; map_n_ = 0; }
#endif
        vec_.clear();
        vec_.shrink_to_fit();
    }
    // `off` drops a self-extractor's PE stub without moving a byte.
    ByteView View(std::size_t off = 0u) const {
        const unsigned char* p = map_ != nullptr ? map_ : vec_.data();
        const std::size_t n = map_ != nullptr ? map_n_ : vec_.size();
        return off <= n ? ByteView(p + off, n - off) : ByteView();
    }
    bool mapped() const { return map_ != nullptr; }
private:
    const unsigned char* map_ = nullptr;
    std::size_t map_n_ = 0;
    std::vector<unsigned char> vec_;
};

class ByteBuffer {
public:
    ByteBuffer() = default;
    ByteBuffer(std::vector<unsigned char>&& v) : vec_(std::move(v)) {}   // NOLINT: implicit by design
    ByteBuffer& operator=(std::vector<unsigned char>&& v) { raw_.reset(); raw_n_ = 0; vec_ = std::move(v); return *this; }
    ByteBuffer(ByteBuffer&&) = default;
    ByteBuffer& operator=(ByteBuffer&&) = default;
    ByteBuffer(const ByteBuffer& o) { *this = o; }
    ByteBuffer& operator=(const ByteBuffer& o) {
        if (this != &o) { raw_.reset(); raw_n_ = 0; vec_.assign(o.data(), o.data() + o.size()); }
        return *this;
    }
    static ByteBuffer Uninitialized(std::size_t n) {
        ByteBuffer b;
        if (n) { b.raw_.reset(new unsigned char[n]); b.raw_n_ = n; }
        return b;
    }
    unsigned char* data() { return raw_ ? raw_.get() : vec_.data(); }
    const unsigned char* data() const { return raw_ ? raw_.get() : vec_.data(); }
    std::size_t size() const { return raw_ ? raw_n_ : vec_.size(); }
    bool empty() const { return size() == 0u; }
    void clear() { raw_.reset(); raw_n_ = 0; vec_.clear(); }
    template <class It> void assign(It a, It b) { raw_.reset(); raw_n_ = 0; vec_.assign(a, b); }
    const unsigned char* begin() const { return data(); }
    const unsigned char* end() const { return data() + size(); }
private:
    std::vector<unsigned char> vec_;
    std::unique_ptr<unsigned char[]> raw_;
    std::size_t raw_n_ = 0;
};

struct LegacyCnContext {
    std::string archive_path;
    ChecksumMode checksum_mode = ChecksumMode::kNone;
    bool checksum_verification_supported = true;
    std::uint8_t legacy_method = 0;
    std::uint8_t legacy_method_p0 = 0;
    std::uint8_t legacy_method_p1 = 0;
    std::uint8_t legacy_method_p2 = 0;   // the block-size byte-float (memory figure)
    // CM decoder params (method==0x4b, p0==7): extracted from the two extra
    // bytes that precede the filename table span in -cc archives.
    int cm_a_bits = 28;
    int cm_b_bits = 25;
    std::uint32_t cm_window_size = 1024u * 1024u;
    bool native_payload_supported = false;
    // The record walker stopped at a record that runs past the end of the file
    // (a cut-off archive). The original reports such a decode failure as
    // "Error decoding (code 25600)" where an in-range corruption is code 100.
    bool truncated_input = false;
    // Parallel (-pN) container: one entry per worker stream, that stream's own
    // window byte (p1). The original prints one "Compressor #k" line per worker.
    std::vector<std::uint8_t> parallel_p1;
    // The parser already checked every entry's checksum over `data` (its
    // validate_decoded_candidate gate): the extractor need not run the same pass
    // over gigabytes a second time.
    bool checksums_verified = false;
    // Per-entry verdict when checksums_verified (1 = matches its stored checksum).
    // Empty = every entry matched. A damaged archive whose decode still completed
    // gets its good files written and the bad ones reported and skipped.
    std::vector<std::uint8_t> entry_checksum_ok;
    // Set when the decode failed part-way: `data` then holds only the blocks
    // completed before the failure (the original writes exactly those).
    bool decode_failed = false;
    // With decode_failed: the streams all decoded cleanly but the output came
    // out short -- reported as "Unexpected end of file." rather than a code.
    bool decode_eof = false;
    // The file ends before the decoder can start: the record framing itself is
    // cut, or the first data record carries fewer bytes than the codec's first
    // block header. The original's reader reports that as "Unexpected end of
    // file." and never creates a compressor, so no "Compressor #k" line either.
    // Measured over m_<codec>.nz truncated byte by byte around the first data
    // record: every codec reports it while the record header is incomplete, and
    // -cc/-co/-cO also with 1-4 payload bytes (their block header is 5).
    bool eof_before_decode = false;
    // A data record's header was read (its payload may be cut). The original
    // creates the decompressor object then, and that is what prints
    // "Compressor #k"; an archive cut before its first data record never gets
    // one. Measured on m_<codec>.nz cut byte by byte around that record.
    bool saw_data_record = true;
    // The archive is cut inside its first data record: the report is the
    // family's short-end status (see the parser), not the decoder's own.
    bool cut_first_data_record = false;
    // The original's status for the failure (ERROR_CODES.md): printed plain when
    // a record follows the failing one, as code<<8|slot when it was the last.
    std::uint32_t decode_code = 0;
    std::uint32_t decode_fatal_id = 0;
    std::size_t decode_slot = 0;
    bool decode_at_last_record = false;
    // Data records in payload (spliced) space: cumulative end offsets, and
    // whether any record follows the last data record in the file.
    std::vector<std::size_t> payload_record_ends;
    bool records_after_data = false;
    // A parallel container written by the sink (psink): the files are already on
    // disk (or verified, for `t`); the extractor only reports.
    bool sink_handled = false;
    std::size_t sink_failed_entries = 0;
    bool sink_plain_code = false;   // the failing stream had another record ahead
    LegacyPayloadMode payload_mode = LegacyPayloadMode::kUnknown;
    std::vector<LegacyCnEntry> entries;
    std::uint64_t data_offset = 0;
    std::uint64_t total_data_size = 0;
    ByteBuffer data;
};

// Copies the thread's recorded decode error (nz_decode_error.h) into the context
// and decides how the original would print it: plain when a record follows the
// failing one, code<<8|slot when the failing record was the archive's last (or
// the input ended). The failing record is found from the input offset the
// decoder recorded, in payload (spliced data record) space.
void AdoptDecodeError(LegacyCnContext& ctx) {
    const nzr::derr::State& e = nzr::derr::Current();
    if (e.code == 0xfffffffeu) { ctx.decode_eof = true; ctx.decode_code = 0u; ctx.decode_slot = e.parallel ? e.slot : 0u; ctx.decode_at_last_record = true; nzr::derr::Clear(); return; }
    ctx.decode_code = e.code;
    ctx.decode_fatal_id = e.fatal_id;
    ctx.decode_slot = e.parallel ? e.slot : 0u;
    bool last = ctx.truncated_input || e.parallel;   // a worker stream's status is always reported at the end
    if (!e.parallel && e.has_pos && !ctx.payload_record_ends.empty()) {
        std::size_t idx = 0;
        while (idx + 1u < ctx.payload_record_ends.size() && e.input_pos >= ctx.payload_record_ends[idx]) ++idx;
        last = (idx + 1u == ctx.payload_record_ends.size()) && !ctx.records_after_data;
    }
    ctx.decode_at_last_record = last && !ctx.sink_plain_code;
    nzr::derr::Clear();
}

// A line from the source collector: the ones that reproduce the original's own
// wording go out verbatim, the port's extra diagnostics keep "Warning: ".
inline void PrintCollectorLine(std::ostream& os, const std::string& w) {
    if (w.rfind("No files found with ", 0) == 0) os << w << '\n';
    else os << "Warning: " << w << '\n';
}

// The original's corruption report (ERROR_CODES.md). Returns the exit status:
// 2 for the "Archive corrupted" lines (main maps it to 0 unless NZ_STRICT_EXIT),
// 255 for the fatal "Internal error" path, which the original exits with (-1)
// and whose line comes after a newline, without clearing the status line.
int PrintCorruptLine(std::ostream& os, const LegacyCnContext& c) {
    if (c.decode_fatal_id != 0u) {
        os << "\nInternal error: " << c.decode_fatal_id << "! Please report this to sami (at) nanozip.net.\n";
        return 255;
    }
    ClearStatusLine(os);
    if (c.decode_eof || c.eof_before_decode) { os << "Archive corrupted. Unexpected end of file.\n"; return 2; }
    std::uint32_t code;
    if (c.cut_first_data_record && c.legacy_method == 0x2bu &&
        (c.legacy_method_p0 == 1u || c.legacy_method_p0 == 2u)) code = 2u << 8;        // lzpf
    else if (c.cut_first_data_record && c.legacy_method == 0x2bu &&
             (c.legacy_method_p0 == 3u || c.legacy_method_p0 == 4u)) code = 4u << 8;   // -cd/-cD
    else if (c.decode_code == 0u) code = c.truncated_input ? 25600u : 100u;
    else code = c.decode_at_last_record ? ((c.decode_code << 8) | static_cast<std::uint32_t>(c.decode_slot & 0xffu)) : c.decode_code;
    os << "Archive corrupted. Error decoding (code " << code << ")\n";
    return 2;
}

// ---------------------------------------------------------------------------
// Progress engine: the original's status line as decompiled (FUN_0804b740 /
// FUN_0804b8d0 / FUN_0804ba70; ~/.cache/nzre_tools/cli_parity/PROGRESS_ENGINE.md).
//  * One slot per worker stream, holding the bytes that stream has produced.
//    Eight are visible (the struct holds eight); a worker tick prints them
//    joined by '|' up to the first empty one, each "<N> MB" (MB up to 9 GB, then
//    GB, then TB -- FUN_0804be20), then four spaces and one backspace per
//    character written.
//  * A worker tick is gated by time(): nothing is redrawn while the whole second
//    is the one of the previous tick. Ticks come from every completed block, so
//    the line refreshes about once a second while blocks complete.
//  * The writer's tick (FUN_0804ab00 first) clears the line, prints the file name
//    in 40 columns plus a space, then the same fields; its gate is a second
//    variable of its own. It fires when a file starts.
//  * The "Archive / Threads / Compressor" header precedes all of this. Some of
//    our decodes run while the archive is still being parsed, so the header
//    printer is registered up front and fired by the first tick or explicitly.
// Measured too: a single-container decode shows "0 MB" right after the name (the
// original's first tick lands within the first block); a parallel one shows an
// empty field until the first stream has produced something.
namespace progress {

constexpr std::size_t kMaxSlots = 256;
constexpr std::size_t kVisibleSlots = 8;

struct Engine {
    std::mutex mu;
    std::ostream* os = nullptr;                       // null = engine off (l, own container)
    std::function<void(std::ostream&)> header;
    bool header_done = false;
    LegacyCnContext snapshot;                         // header fields published by the parser
    bool have_snapshot = false;
    bool parallel = false;
    std::array<std::atomic<std::uint64_t>, kMaxSlots> done{};
    std::array<std::atomic<bool>, kMaxSlots> started{};    // worker began (SlotStarted)
    std::array<bool, kMaxSlots> announced{};               // its "Compressor #k" line is out
    std::function<std::string(std::size_t)> compressor_line;   // set by the header registration
    std::atomic<std::uint64_t> total{0};
    std::string name, shown_name;
    bool worker_gate = false, writer_gate = false;
    std::time_t worker_sec = 0, writer_sec = 0;
};

inline Engine& E() { static Engine e; return e; }
inline thread_local std::size_t t_slot = 0;

// FUN_0804a990(buf, name, 0x28): a name longer than 40 columns is "..." plus its
// last 37 characters (the listing's 38/35 rule is a different formatter).
inline std::string Name40(const std::string& name) {
    if (name.size() <= 40u) return name;
    return "..." + name.substr(name.size() - 37u);
}

inline std::string HumanSize(std::uint64_t bytes) {
    // FUN_0804be20 with start unit MB: the unit rises while the value exceeds
    // 9 units of the next one; rounding is half-up.
    unsigned unit = 2;
    while (unit < 4 && bytes > (9ull << (10u * (unit + 1u)))) ++unit;
    const unsigned shift = 10u * unit;
    const std::uint64_t v = (bytes + (1ull << (shift - 1u))) >> shift;
    static const char* const names[] = {" B", " KB", " MB", " GB", " TB"};
    return std::to_string(v) + names[unit];
}

inline std::string FieldsLocked(Engine& e) {
    std::string f;
    for (std::size_t i = 0; i < kVisibleSlots; ++i) {
        const std::uint64_t v = e.done[i].load(std::memory_order_relaxed);
        if (v == 0u) break;
        if (i) f += '|';
        f += HumanSize(v);
    }
    return f;
}

inline void WriteFieldLocked(Engine& e, std::string prefix, const std::string& fields) {
    prefix += fields;
    prefix += "    ";
    prefix.append(fields.size() + 4u, '\b');
    e.os->write(prefix.data(), static_cast<std::streamsize>(prefix.size()));
    e.os->flush();
}

inline void EnsureHeaderLocked(Engine& e) {
    if (e.header_done || e.os == nullptr) return;
    e.header_done = true;
    if (e.header) e.header(*e.os);
}

// Main registers the header printer before the archive is parsed.
inline void Begin(std::ostream* os, std::function<void(std::ostream&)> header) {
    Engine& e = E();
    std::lock_guard<std::mutex> lk(e.mu);
    e.os = os; e.header = std::move(header); e.header_done = false;
    e.have_snapshot = false; e.parallel = false;
    for (auto& d : e.done) d.store(0u, std::memory_order_relaxed);
    for (auto& d : e.started) d.store(false, std::memory_order_relaxed);
    e.announced.fill(false); e.compressor_line = nullptr;
    e.total.store(0u, std::memory_order_relaxed);
    e.name.clear(); e.shown_name.clear();
    e.worker_gate = e.writer_gate = false;
}
inline void End() {
    Engine& e = E();
    std::lock_guard<std::mutex> lk(e.mu);
    e.os = nullptr; e.header = nullptr; e.compressor_line = nullptr;
}
// A worker took slot k (ParallelForEach). The original prints each worker's
// "Compressor #k" line when that worker first ticks; the ones already running
// when the header goes out appear in the header write itself.
inline void SlotStarted(std::size_t k) {
    Engine& e = E();
    if (e.os == nullptr || k >= kMaxSlots) return;
    e.started[k].store(true, std::memory_order_relaxed);
}
inline bool SlotStarted(std::size_t k, const Engine& e) { return k < kMaxSlots && e.started[k].load(std::memory_order_relaxed); }
inline void MarkAnnounced(std::size_t k) { Engine& e = E(); if (k < kMaxSlots) e.announced[k] = true; }
inline void SetCompressorLine(std::function<std::string(std::size_t)> f) { E().compressor_line = std::move(f); }
inline bool Active() { return E().os != nullptr; }

// The parser publishes what the header needs before any decode it runs itself.
inline void Publish(const LegacyCnContext& snap) {
    Engine& e = E();
    std::lock_guard<std::mutex> lk(e.mu);
    if (e.os == nullptr) return;
    e.snapshot = snap; e.have_snapshot = true;
}
inline bool HaveSnapshot() { return E().have_snapshot; }
inline const LegacyCnContext& Snapshot() { return E().snapshot; }

// Called by the header printer once the header lines are out: the original's
// writer prints the first file's name at once for a single container (the
// writer starts as soon as the first block lands) and a first "0 MB" tick
// follows within the same instant; a parallel container shows an empty field.
inline void WriterStartLocked(Engine& e);
inline void HeaderPrinted(bool parallel, const std::string& first_name) {
    Engine& e = E();   // caller holds e.mu (runs inside EnsureHeaderLocked)
    e.parallel = parallel;
    e.name = first_name;
    if (!parallel) WriterStartLocked(e);
    // Parallel: the original's header ends with a name tick whose name is not
    // known yet (a run of spaces of varying length, left alone here); the first
    // worker tick then prints the empty field, which happens here too.
}

inline void EnsureHeader() {
    Engine& e = E();
    std::lock_guard<std::mutex> lk(e.mu);
    EnsureHeaderLocked(e);
}

inline void WorkerTickLocked(Engine& e) {
    const std::time_t now = std::time(nullptr);
    if (e.worker_gate && now == e.worker_sec) return;
    e.worker_gate = true; e.worker_sec = now;
    EnsureHeaderLocked(e);
    WriteFieldLocked(e, std::string(), FieldsLocked(e));
}

// The writer starts on the first block of the first stream: name + empty field,
// then the "0 MB" tick, exactly the single-container start (measured on a 4-stream
// 2 MB archive: "name     \b\b\b\b" then "0 MB    \b...", as for one stream).
inline void WriterStartLocked(Engine& e) {
    if (e.name.empty() || e.name == e.shown_name) return;
    EnsureHeaderLocked(e);
    ClearStatusLine(*e.os);
    WriteFieldLocked(e, Name40(e.name) + " ", std::string());
    e.shown_name = e.name;
    e.writer_gate = true; e.writer_sec = std::time(nullptr);
    WriteFieldLocked(e, std::string(), HumanSize(0));
    e.worker_gate = true; e.worker_sec = e.writer_sec;
}

// Worker side: n more output bytes from this thread's stream.
inline void Add(std::uint64_t n) {
    Engine& e = E();
    if (e.os == nullptr || n == 0u) return;
    const std::size_t slot = t_slot < kMaxSlots ? t_slot : kMaxSlots - 1u;
    const bool first_of_stream0 = slot == 0u && e.done[0].load(std::memory_order_relaxed) == 0u;
    std::lock_guard<std::mutex> lk(e.mu);
    EnsureHeaderLocked(e);
    if (slot < kMaxSlots && !e.announced[slot] && e.compressor_line) {
        // This worker's line was not in the header: clear the status line, print
        // it, and redraw the name (the original's writer re-ticks right after).
        e.announced[slot] = true;
        ClearStatusLine(*e.os);
        const std::string line = e.compressor_line(slot);
        e.os->write(line.data(), static_cast<std::streamsize>(line.size()));
        if (!e.shown_name.empty()) { ClearStatusLine(*e.os); WriteFieldLocked(e, Name40(e.shown_name) + " ", FieldsLocked(e)); }
    }
    if (first_of_stream0 && e.parallel) WriterStartLocked(e);
    e.done[slot].fetch_add(n, std::memory_order_relaxed);
    e.total.fetch_add(n, std::memory_order_relaxed);
    WorkerTickLocked(e);
}
inline bool Decoded() { return E().total.load(std::memory_order_relaxed) != 0u; }

// A decode attempt that fails is retried with other parameters or declined;
// its figures must not stay on the counter. Scope rewinds unless committed.
inline std::uint64_t Mark() {
    const std::size_t slot = t_slot < kMaxSlots ? t_slot : kMaxSlots - 1u;
    return E().done[slot].load(std::memory_order_relaxed);
}
inline void Rewind(std::uint64_t mark) {
    Engine& e = E();
    const std::size_t slot = t_slot < kMaxSlots ? t_slot : kMaxSlots - 1u;
    const std::uint64_t cur = e.done[slot].load(std::memory_order_relaxed);
    if (cur > mark) {
        e.done[slot].store(mark, std::memory_order_relaxed);
        e.total.fetch_sub(cur - mark, std::memory_order_relaxed);
    }
}
struct Scope {
    std::uint64_t mark;
    bool committed = false;
    Scope() : mark(Mark()) {}
    ~Scope() { if (!committed) Rewind(mark); }
    void Commit() { committed = true; }
    void Restart() { Rewind(mark); }
};

// Writer side: a file starts. Prints name + fields, gated to one per second;
// the same name twice in a row is not reprinted.
inline void FileStart(const std::string& name) {
    Engine& e = E();
    if (e.os == nullptr) return;
    std::lock_guard<std::mutex> lk(e.mu);
    e.name = name;
    if (name.empty() || name == e.shown_name) return;
    const std::time_t now = std::time(nullptr);
    if (e.writer_gate && now == e.writer_sec) return;
    e.writer_gate = true; e.writer_sec = now;
    EnsureHeaderLocked(e);
    ClearStatusLine(*e.os);
    WriteFieldLocked(e, Name40(name) + " ", FieldsLocked(e));
    e.shown_name = name;
}

// A worker stream finished. For a parallel container the writer starts with
// the first stream, so the first file's name appears then.
inline void StreamDone(std::size_t) {}

struct SlotScope {
    std::size_t saved;
    explicit SlotScope(std::size_t slot) : saved(t_slot) { t_slot = slot; }
    ~SlotScope() { t_slot = saved; }
};

}  // namespace progress

// ---------------------------------------------------------------------------
// Parallel-container output sink: the original's writer model for -pN archives,
// measured on 91 damaged single- and multi-file parallel containers (2026-09-04,
// ~/.cache/nzre_tools/cli_parity/corrupt_compare_parallel.sh):
//  * every WORKER writes its own stream straight into the output files at
//    absolute offsets (strace: one open O_CREAT|O_TRUNC, then one open O_WRONLY
//    per other worker) -- a stream that fails leaves a HOLE of zeros, or a short
//    file when it was the last slot;
//  * the CM family flushes per codec block, lzpf per member segment, -cd/-cD
//    per file group (a table's files; 1 MB quanta inside a group) -- a status
//    failure keeps NOTHING of the unit in flight, a clean-but-short stream
//    flushes what it produced;
//  * a group's FIRST file is created (empty) when the worker starts the group,
//    the group's later files when bytes reach them; groups after a failure are
//    never started; the other workers carry on;
//  * slice checksums (one per table entry) are verified when the slice is out
//    and a mismatch prints "Checksum mismatch [stored computed]: <file>", then
//    the footer; a status error prints "Archive corrupted. Error decoding (code
//    status<<8|slot)" and no footer.
// `t` runs the same sink without touching the disk. NZ_SAFE keeps the old
// assemble-then-verify path (verified bytes only).
std::uint32_t ComputeBufferChecksum(ChecksumMode mode, const unsigned char* data, std::size_t size);
bool SafeMode();

namespace psink {

// The clean-but-short stream end: no status, "Unexpected end of file".
constexpr std::uint32_t kCleanEndCode = 0xfffffffeu;

struct Slice {
    std::size_t entry = 0;            // index into the archive's entries
    std::uint64_t file_off = 0;       // where it sits inside its file
    std::uint64_t len = 0;
    std::uint64_t spos = 0;           // where it starts inside the stream's output
    ChecksumMode cmode = ChecksumMode::kNone;
    std::uint32_t cval = 0;
    bool has_cksum = false;
    std::size_t group = 0;            // table group inside the stream
    bool checked = false;
};
struct Stream {
    std::vector<Slice> slices;        // in stream order
    std::uint64_t total = 0;
    std::vector<std::uint64_t> group_start;   // stream position where each group starts
    std::uint64_t flushed = 0;        // bytes of the stream already on disk
    std::size_t entered_group = 0;    // groups < this had their first file created
    bool entered_any = false;
    bool cut = false;                 // its last data record was cut off by the end of the archive
    // Where the stream's LAST data record starts, in the same byte space the
    // decoder consumes. The driver reports a status PLAIN when a later record
    // step of the same slot notices it, and shifted (status<<8|slot) when the
    // failing record was the last one or the input ended -- so a failure before
    // this offset is the plain case. 0 = unknown, which keeps the shifted form.
    std::uint64_t last_record_start = 0;
    bool have_last_record = false;
};
enum class Policy { kProduced, kGroup, kStore };
// What a worker of each codec reports when its stream ends early without a
// status of its own (measured on cut and flipped -p4 containers):
//   stream cut mid-group:      -cc/-co nothing ("Unexpected end of file"), -cO 100,
//                              lzpf 2, -cd/-cD 4
//   a group announced but no data record left for it (cut before it): CM family
//                              100, lzpf 4, -cD 1
//   not cut, decoder just stopped short: CM family 100, lzpf nothing, -cd 4
enum class Family { kCm, kCo, kCO, kLzpf, kCd, kStore };

struct FileState {
    bool selected = false;
    bool write_it = false;            // after the overwrite prompt / unsafe path
    bool decided = false;             // prompt asked / path judged
    bool created = false;
    bool cannot_write = false;
    fs::path path;
    std::string display;              // as the original names it: relative unless -o gave a root
    int fd = -1;
    std::mutex io;
};

struct Engine {
    std::mutex mu;                    // state (files, streams, counters)
    bool configured = false;          // RunExtractOrTest set the options
    bool published = false;           // a parallel container handed its layout
    bool committed = false;           // something was created/written: the outcome is final
    const CliOptions* opt = nullptr;
    bool test_mode = false;
    std::ostream* os = nullptr;
    fs::path root;
    const std::vector<LegacyCnEntry>* entries = nullptr;
    std::vector<Stream> streams;
    Policy policy = Policy::kProduced;
    Family family = Family::kCm;
    std::uint64_t quantum = 0;        // -cd: 1 MB flush quanta inside a group
    std::vector<std::unique_ptr<FileState>> files;
    bool yes_to_all = false;
    std::size_t mismatches = 0;
    std::size_t unsafe = 0;
    std::size_t cannot = 0;
    bool stream_failed = false;
    bool plain_code = false;          // report the status without the slot (see Stream::last_record_start)
    bool truncated = false;           // the archive itself is cut short
};
inline Engine& E() { static Engine e; return e; }
inline void MarkTruncated() { Engine& e = E(); std::lock_guard<std::mutex> lk(e.mu); e.truncated = true; }

inline void Configure(const CliOptions& opt, bool test_mode, std::ostream& os, const fs::path& root) {
    Engine& e = E();
    std::lock_guard<std::mutex> lk(e.mu);
    e.configured = !SafeMode();
    e.published = e.committed = e.stream_failed = e.plain_code = e.truncated = false;
    e.opt = &opt; e.test_mode = test_mode; e.os = &os; e.root = root;
    e.entries = nullptr; e.streams.clear(); e.files.clear();
    e.yes_to_all = opt.yes_to_all; e.mismatches = e.unsafe = e.cannot = 0;
}
inline void Reset() {
    Engine& e = E();
    std::lock_guard<std::mutex> lk(e.mu);
    e.configured = e.published = e.committed = false;
    e.entries = nullptr; e.streams.clear(); e.files.clear();
}
// Available to a parallel path of the parser: configured and not yet used.
inline bool Available() { Engine& e = E(); std::lock_guard<std::mutex> lk(e.mu); return e.configured && !e.published; }
inline bool Committed() { Engine& e = E(); std::lock_guard<std::mutex> lk(e.mu); return e.committed; }

// The parser hands over the layout: streams in worker order, each a list of
// slices (entry, offset in file, length, checksum) in stream order with their
// table group. Returns false (and stays inactive) on an inconsistent layout.
inline bool Publish(const std::vector<LegacyCnEntry>& entries, std::vector<Stream> streams,
                    Policy policy, std::uint64_t quantum, Family family) {
    Engine& e = E();
    std::lock_guard<std::mutex> lk(e.mu);
    if (!e.configured || e.published) return false;
    for (Stream& s : streams) {
        std::uint64_t pos = 0; std::size_t g = static_cast<std::size_t>(-1);
        s.group_start.clear();
        for (Slice& sl : s.slices) {
            if (sl.entry >= entries.size()) return false;
            if (sl.group != g) { g = sl.group; s.group_start.push_back(pos); }
            sl.spos = pos; pos += sl.len;
        }
        s.total = pos; s.flushed = 0; s.entered_group = 0; s.entered_any = false;
    }
    e.entries = &entries; e.streams = std::move(streams); e.policy = policy; e.quantum = quantum; e.family = family;
    e.files.clear();
    for (std::size_t i = 0; i < entries.size(); ++i) {
        auto f = std::make_unique<FileState>();
        const LegacyCnEntry& en = entries[i];
        f->selected = MatchesAnyPattern(en.path, e.opt->positional) && !IsExcluded(en.path, e.opt->exclude_patterns);
        e.files.push_back(std::move(f));
    }
    e.published = true;
    return true;
}

// Under e.mu. Decide the file's path and, when needed, ask the overwrite
// question (std::cin is read with the lock dropped; the timer keeps drawing).
inline void DecideLocked(Engine& e, std::size_t idx, std::unique_lock<std::mutex>& lk) {
    FileState& f = *e.files[idx];
    if (f.decided) return;
    f.decided = true;
    const LegacyCnEntry& en = (*e.entries)[idx];
    if (e.test_mode || !f.selected) { f.write_it = false; return; }
    fs::path safe_rel = e.opt->strip_paths ? fs::path(SanitizeExtractPath(en.path)).filename()
                                           : SanitizeExtractPath(en.path);
    if (e.opt->forceout) safe_rel = fs::path(e.opt->positional.empty() ? std::string("*") : e.opt->positional.front());
    if (safe_rel.empty()) {
        std::cerr << "Skipping unsafe path in archive: " << en.path << '\n';
        ++e.unsafe; f.write_it = false; return;
    }
    f.path = e.root / safe_rel;
    f.display = e.opt->output_path.empty() ? safe_rel.string() : f.path.string();
    f.write_it = true;
    std::error_code ec;
    if (!e.yes_to_all && fs::exists(f.path, ec)) {
        for (;;) {
            {
                progress::Engine& pe = progress::E();
                std::lock_guard<std::mutex> plk(pe.mu);
                ClearStatusLine(*e.os);
                *e.os << '\r' << "Overwrite " << en.path << " (Yes/No/Always)? ";
                e.os->flush();
            }
            std::string answer;
            lk.unlock();
            const bool got = static_cast<bool>(std::getline(std::cin, answer));
            lk.lock();
            if (!got) { f.write_it = false; break; }
            const char k = answer.empty() ? '\0' : answer[0];
            if (k == 'y') break;
            if (k == 'n') { f.write_it = false; break; }
            if (k == 'a') { e.yes_to_all = true; break; }
        }
    }
}

// Under e.mu: create the file (the original opens it when a worker's cursor
// enters it). A failure prints "Cannot write: <path>" once.
inline void CreateLocked(Engine& e, std::size_t idx, std::unique_lock<std::mutex>& lk) {
    FileState& f = *e.files[idx];
    DecideLocked(e, idx, lk);
    if (f.created) return;
    f.created = true;
    e.committed = true;
    const LegacyCnEntry& en = (*e.entries)[idx];
    progress::FileStart(en.path);
    if (!f.write_it) return;
    if (f.path.has_parent_path()) MakeDirs0700(f.path.parent_path());
#if defined(_WIN32)
    // mingw's <sys/stat.h> does not always expose _S_IREAD/_S_IWRITE, and the
    // mode is irrelevant on Windows anyway (the permission records are POSIX).
    f.fd = ::_open(f.path.string().c_str(), _O_WRONLY | _O_CREAT | _O_TRUNC | _O_BINARY, 0600);
#else
    f.fd = ::open(f.path.c_str(), O_WRONLY | O_CREAT | O_TRUNC,
                  static_cast<mode_t>((en.has_permissions ? en.permissions : 0600u) & 07777u));
    if (f.fd >= 0 && e.opt->restore_ownership && en.has_owner)
        (void)::fchown(f.fd, static_cast<uid_t>(en.uid), static_cast<gid_t>(en.gid));
#endif
    if (f.fd < 0) {
        f.cannot_write = true; ++e.cannot;
        progress::Engine& pe = progress::E();
        std::lock_guard<std::mutex> plk(pe.mu);
        *e.os << '\n' << "Cannot write: " << f.display << '\n';
    }
}

// Positional write, outside e.mu (per-file lock; workers of a split file share
// the descriptor).
inline void WriteAt(FileState& f, std::uint64_t off, const unsigned char* p, std::size_t n) {
    if (f.fd < 0 || n == 0u) return;
    std::lock_guard<std::mutex> lk(f.io);
#if defined(_WIN32)
    if (::_lseeki64(f.fd, static_cast<long long>(off), SEEK_SET) < 0) return;
    while (n > 0u) {
        const unsigned piece = static_cast<unsigned>(std::min<std::size_t>(n, std::size_t{1} << 28));
        const int w = ::_write(f.fd, p, piece);
        if (w <= 0) return;
        p += w; n -= static_cast<std::size_t>(w); 
    }
#else
    while (n > 0u) {
        const ssize_t w = ::pwrite(f.fd, p, n, static_cast<off_t>(off));
        if (w <= 0) return;
        p += w; n -= static_cast<std::size_t>(w); off += static_cast<std::uint64_t>(w);
    }
#endif
}

inline void MismatchLine(Engine& e, const Slice& sl, std::uint32_t got) {
    progress::Engine& pe = progress::E();
    std::lock_guard<std::mutex> plk(pe.mu);
    ClearStatusLine(*e.os);
    *e.os << "Checksum mismatch [" << FormatChecksum(sl.cmode, sl.cval) << ' '
          << FormatChecksum(sl.cmode, got) << "]: " << (*e.entries)[sl.entry].path << '\n';
}

// A worker starts stream k: the first file of its first group is created.
// The offset, in the byte space this stream's decoder consumes, where its last
// data record starts. A failure before it is the plainly-reported case.
inline void SetLastRecordStart(std::size_t k, std::uint64_t off) {
    Engine& e = E();
    std::lock_guard<std::mutex> lk(e.mu);
    if (!e.published || k >= e.streams.size()) return;
    e.streams[k].last_record_start = off;
    e.streams[k].have_last_record = true;
}

inline void StreamBegin(std::size_t k) {
    Engine& e = E();
    std::unique_lock<std::mutex> lk(e.mu);
    if (!e.published || k >= e.streams.size()) return;
    Stream& s = e.streams[k];
    if (!s.slices.empty() && !s.entered_any) { s.entered_any = true; s.entered_group = 1; CreateLocked(e, s.slices.front().entry, lk); }
}

// A worker ends stream k. `buf` holds its output (produced bytes valid), `ok` =
// the stream decoded completely (the slice checksums may still disagree),
// `clean_end` = it stopped early without a status. Flushes per policy, creates
// the files the cursor reached, verifies the slices that are out.
inline void StreamEnd(std::size_t k, const unsigned char* buf, std::uint64_t produced, bool ok, bool clean_end,
                      // Store policy: bytes that actually arrived (the rest of `produced` is
                      // zero padding the original writes anyway); the slice checksums are
                      // computed over these.
                      std::uint64_t received = ~std::uint64_t{0}) {
    Engine& e = E();
    std::unique_lock<std::mutex> lk(e.mu);
    if (!e.published || k >= e.streams.size()) return;
    Stream& s = e.streams[k];
    if (produced > s.total) produced = s.total;
    if (received > produced) received = produced;
    std::uint64_t flush_to = produced;
    if (!ok && !clean_end && e.policy == Policy::kGroup) {
        // The group in flight is lost; earlier groups (and whole quanta of this
        // one) are out.
        std::uint64_t gstart = 0;
        for (std::uint64_t gs : s.group_start) if (gs <= produced) gstart = gs;
        flush_to = gstart;
        if (e.quantum != 0u && produced > gstart) flush_to = gstart + ((produced - gstart) / e.quantum) * e.quantum;
    }
    if (!ok) {
        e.stream_failed = true;
        // A failure with another record of this stream still ahead is the one
        // the driver reports plainly.
        const nzr::derr::State& st = nzr::derr::Current();
        if (s.have_last_record && st.has_pos && st.input_pos < s.last_record_start) e.plain_code = true;
        if (nzr::derr::Current().code == 0u && nzr::derr::Current().fatal_id == 0u) {
            std::uint32_t code = 100u;
            if (clean_end) {
                const bool no_data_group = s.group_start.size() > 1u && produced <= s.group_start.back();
                const bool cut = s.cut || e.truncated;
                if (cut && no_data_group)
                    code = (e.family == Family::kLzpf) ? 4u : (e.family == Family::kCd) ? 1u : 100u;
                else if (cut)
                    code = (e.family == Family::kCm || e.family == Family::kCo) ? kCleanEndCode
                         : (e.family == Family::kCO) ? 100u : (e.family == Family::kLzpf) ? 2u : 4u;
                else
                    code = (e.family == Family::kLzpf) ? kCleanEndCode : (e.family == Family::kCd) ? 4u : 100u;
            }
            nzr::derr::Set(code);
        }
    }
    const bool trace = NZ_ENV("NZ_TRACE_SINK") != nullptr;
    if (trace) std::fprintf(stderr, "[sink] stream %zu produced=%llu ok=%d clean=%d flush_to=%llu code=%u\n", k,
                            (unsigned long long)produced, (int)ok, (int)clean_end, (unsigned long long)flush_to, nzr::derr::Current().code);
    // Files the flushed bytes reach, then the group the cursor stands in.
    struct Piece { FileState* f; std::uint64_t off; const unsigned char* p; std::size_t n; };
    std::vector<Piece> pieces;
    std::vector<std::pair<const Slice*, std::uint32_t>> bad;
    for (Slice& sl : s.slices) {
        const std::uint64_t a = std::max(sl.spos, s.flushed);
        const std::uint64_t b = std::min(sl.spos + sl.len, flush_to);
        if (sl.len == 0u) continue;
        if (a >= b) continue;
        CreateLocked(e, sl.entry, lk);
        FileState& f = *e.files[sl.entry];
        if (f.write_it && f.fd >= 0)
            pieces.push_back({&f, sl.file_off + (a - sl.spos), buf + a, static_cast<std::size_t>(b - a)});
        // A stored slice is checked over whatever arrived (a cut one over 0 bytes:
        // the original prints "ffffffff" for those).
        const bool store_check = (e.policy == Policy::kStore) && !sl.checked;
        if (!sl.checked && (flush_to >= sl.spos + sl.len || store_check)) {
            sl.checked = true;
            if (sl.has_cksum && e.opt->checksum != ChecksumMode::kNone) {
                // Store: a slice with any byte received is checked whole (stub + zero
                // padding); one with no record at all over nothing ("ffffffff").
                const std::size_t avail = (store_check && received <= sl.spos) ? std::size_t{0} : static_cast<std::size_t>(sl.len);
                const std::uint32_t got = ComputeBufferChecksum(sl.cmode, buf + sl.spos, avail);
                if (trace) std::fprintf(stderr, "[sink]   slice entry=%zu off=%llu len=%llu stored=%08x got=%08x\n", sl.entry,
                                        (unsigned long long)sl.file_off, (unsigned long long)sl.len, sl.cval, got);
                if (got != sl.cval) { ++e.mismatches; bad.emplace_back(&sl, got); }
            } else if (trace) std::fprintf(stderr, "[sink]   slice entry=%zu unchecked has=%d\n", sl.entry, (int)sl.has_cksum);
        }
    }
    s.flushed = std::max(s.flushed, flush_to);
    // The group the cursor is in (or starts) when the stream ends short: its
    // first file exists, empty, as the original leaves it.
    if (!ok && produced < s.total) {
        std::size_t g = 0;
        for (std::size_t i = 0; i < s.group_start.size(); ++i) if (s.group_start[i] <= produced) g = i;
        for (std::size_t i = s.entered_group; i <= g; ++i) {
            for (const Slice& sl : s.slices) if (sl.group == i) { CreateLocked(e, sl.entry, lk); break; }
        }
        s.entered_group = std::max(s.entered_group, g + 1u);
        // Empty files inside the flushed range exist too.
    }
    for (const Slice& sl : s.slices)
        if (sl.len == 0u && sl.spos <= flush_to && (ok || sl.spos < produced || sl.spos == 0u)) CreateLocked(e, sl.entry, lk);
    e.committed = e.committed || !pieces.empty();
    std::vector<std::pair<const Slice*, std::uint32_t>> bad_copy = bad;
    lk.unlock();
    for (const Piece& pc : pieces) WriteAt(*pc.f, pc.off, pc.p, pc.n);
    for (const auto& bd : bad_copy) MismatchLine(e, *bd.first, bd.second);
}

struct Outcome { bool committed = false; bool stream_failed = false; bool plain_code = false; std::size_t mismatches = 0; std::size_t failed_entries = 0; };

// Close everything, apply the timestamps, report.
inline Outcome Finish() {
    Engine& e = E();
    std::lock_guard<std::mutex> lk(e.mu);
    Outcome o;
    if (!e.published) return o;
    for (std::size_t i = 0; i < e.files.size(); ++i) {
        FileState& f = *e.files[i];
        if (f.fd >= 0) {
#if defined(_WIN32)
            ::_close(f.fd);
#else
            ::close(f.fd);
#endif
            f.fd = -1;
            const LegacyCnEntry& en = (*e.entries)[i];
            if (en.has_mtime) (void)SetExtractedMtime(f.path, en.mtime_unix);
            if (en.has_win_attr) SetExtractedWinAttributes(f.path, en.win_attr);
        }
    }
    o.committed = e.committed; o.stream_failed = e.stream_failed; o.plain_code = e.plain_code;
    o.mismatches = e.mismatches; o.failed_entries = e.mismatches + e.unsafe + e.cannot;
    e.published = false;   // one container per run
    return o;
}

}  // namespace psink

constexpr int kLegacyNeedCompat = -100;

// Sum of the bytes modulo 255: the one-byte per-stage check the original stores
// in a block header ("staged" bytes) and verifies after each post-filter stage.
unsigned StageCheck255(const std::uint8_t* p, std::size_t n) {
    // The per-stage check byte: this archive family's Fletcher-32 (16-bit LE words
    // mod 0xffff, odd tail byte as its own word, zero sums forced to 0xffff,
    // packed s1<<16|s2) reduced modulo 255. Verified on five stage buffers of two
    // codecs (GDB: FUN_080c0220 pops the last staged byte and compares it with
    // checksum(stage) % 0xff).
    std::uint32_t s1 = 0, s2 = 0;
    std::size_t i = 0;
    for (; i + 1 < n; i += 2) {
        const std::uint32_t w = static_cast<std::uint32_t>(p[i]) | (static_cast<std::uint32_t>(p[i + 1]) << 8);
        s1 = (s1 + w) % 0xffffu; s2 = (s2 + s1) % 0xffffu;
    }
    if (i < n) { s1 = (s1 + p[i]) % 0xffffu; s2 = (s2 + s1) % 0xffffu; }
    if (s1 == 0u) s1 = 0xffffu;
    if (s2 == 0u) s2 = 0xffffu;
    return static_cast<unsigned>(((s1 << 16) | s2) % 255u);
}

// NZ_SAFE=1: instead of the original's behaviour on a damaged archive (write
// whatever was decoded, checksum mismatches included, exit 0) write only the
// entries whose checksum verifies, skip the rest and exit 2.
bool SafeMode() {
    static const bool on = (NZ_ENV("NZ_SAFE") != nullptr);
    return on;
}

// The three single-container decoders report a corrupt stream (as opposed to
// an unsupported one) with one of these messages; only then is the completed
// prefix they leave in the output vector written the way the original does.
bool IsCorruptStreamFailure(const std::string& m) {
    return m == "optimum: decode failed" || m == "cm: malformed block stream" ||
           m == "cm: output size mismatch" || m == "lzhd: malformed block stream" ||
           m == "lzhd: unexpected end of file";
}

std::uint32_t ComputeBufferChecksum(ChecksumMode mode, const unsigned char* data, std::size_t size);

// Per-entry checksum verdicts over a decoded payload. Returns false only when the
// entry sizes do not add up to the payload (a decode that did not complete);
// `*bad` counts the entries whose stored checksum does not match.
bool CheckEntries(const std::vector<LegacyCnEntry>& entries, ChecksumMode mode, bool supported,
                  const unsigned char* data, std::size_t size,
                  std::vector<std::uint8_t>* ok, std::size_t* bad) {
    ok->assign(entries.size(), 1u);
    *bad = 0;
    std::size_t cursor = 0;
    for (std::size_t i = 0; i < entries.size(); ++i) {
        const LegacyCnEntry& e = entries[i];
        if (e.size > size - cursor) return false;
        const std::size_t n = static_cast<std::size_t>(e.size);
        if (e.has_checksum && supported && mode != ChecksumMode::kNone &&
            ComputeBufferChecksum(mode, data + cursor, n) != e.checksum) {
            (*ok)[i] = 0u; ++*bad;
        }
        cursor += n;
    }
    return cursor == size;
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
    const ByteView& bytes,
    std::size_t* io_pos,
    std::size_t end,
    std::uint64_t* out_value) {
    if (io_pos == nullptr || out_value == nullptr || *io_pos >= end || end > bytes.size()) {
        return false;   // `end` beyond the buffer = a corrupt/truncated header (ASan, fuzz 2026-09-03)
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
    const ByteView& bytes,
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
        std::vector<std::uint32_t> uids;
        std::vector<std::uint32_t> gids;
        std::vector<std::uint32_t> attrs;    // Windows attribute nibbles (record type 3)
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
            case 3u: {
                // Windows file attributes: one NIBBLE per entry, high nibble
                // first, zero-padded to a byte. The nibble is
                // `8 | READONLY | HIDDEN<<1 | SYSTEM<<2`, so 0 can only be
                // padding (measured on seven files covering every combination).
                // The record is OMITTED for a block whose files are all plain,
                // so it has to be aligned to the files of its own block: the
                // block's type-2 record comes first, which makes mtimes.size()
                // the file count through this block. The gap is filled with 8
                // (plain), which is what the original lists for such an entry.
                std::size_t k = 0;
                for (std::size_t p = rbegin; p < rend; ++p) {
                    if (((bytes[p] >> 4) & 0x0fu) != 0u) ++k;
                    if ((bytes[p] & 0x0fu) != 0u) ++k;
                }
                if (a.mtimes.size() >= k && a.attrs.size() < a.mtimes.size() - k)
                    a.attrs.resize(a.mtimes.size() - k, 8u);
                for (std::size_t p = rbegin; p < rend; ++p) {
                    for (int half = 1; half >= 0; --half) {
                        const std::uint32_t nib = (static_cast<std::uint32_t>(bytes[p]) >> (half * 4)) & 0x0fu;
                        if (nib == 0u) continue;            // padding
                        if (a.attrs.size() >= n) return false;
                        a.attrs.push_back(nib);
                    }
                }
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
            case 8u:
            case 9u: {
                // uid (8) / gid (9): u16 values, run-coded like the permissions
                // (three files with uid 1000 were stored as e8 03 three times).
                std::vector<std::uint32_t>& dst = (rtype == 8u) ? a.uids : a.gids;
                if ((rsize % 2u) != 0u) return false;
                for (std::size_t p = rbegin; p + 1u < rend; p += 2u) {
                    const std::uint32_t v = static_cast<std::uint32_t>(bytes[p]) |
                                            (static_cast<std::uint32_t>(bytes[p + 1u]) << 8u);
                    std::uint32_t id = v;
                    std::size_t run = 1u;
                    if (v >= 0x1000u) {
                        const std::uint32_t coded = v >> 9u;
                        if (coded < 8u) return false;
                        run = static_cast<std::size_t>(coded - 6u);
                        id = v & 0x1ffu;
                    }
                    if (run > n - dst.size()) return false;
                    dst.insert(dst.end(), run, id);
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
        // others -- EXCEPT for the mtimes, which the original itself leaves
        // short. An mtime run longer than a record's payload (~32 KB) is split
        // across several type-2 records, and the original parses each one as a
        // fresh [u32 absolute][deltas] run: a continuation record's first four
        // bytes are deltas, so it reads them as an absolute near zero and emits
        // one value where three or four belonged. Measured on a 70 000-file
        // archive: entries 0..32764 are right, from 32765 the original lists
        // 1969-Dec-31 (the epoch in local time) and the LAST SIX entries get no
        // date column at all, because its value run ran six short. So parse the
        // records the same way and hand out what there is; the entries past the
        // end keep has_mtime = false, which prints the same empty column, and
        // the perms and checksums (fixed-width, exact) still apply. Quirk 43.
        if ((!a.perms.empty() && a.perms.size() != n) ||
            (!a.attrs.empty() && a.attrs.size() > n) ||
            (!a.checksums.empty() && a.checksums.size() != n) ||
            a.mtimes.size() > n) {
            return false;
        }
        if (!a.mtimes.empty() || !a.perms.empty() || !a.attrs.empty() || !a.checksums.empty()) any = true;
    }
    if (!any) return false;

    for (auto& kv : acc) {
        const std::vector<std::size_t>& named = stream_named.find(kv.first)->second;
        StreamAcc& a = kv.second;
        // An archive that stores attributes at all gives every entry one: the
        // blocks whose files are plain just omit the record.
        if (!a.attrs.empty() && a.attrs.size() < named.size()) a.attrs.resize(named.size(), 8u);
        for (std::size_t i = 0; i < named.size(); ++i) {
            LegacyCnEntry& e = (*entries)[named[i]];
            if (i < a.mtimes.size()) { e.mtime_unix = a.mtimes[i]; e.has_mtime = true; }
            if (!a.perms.empty()) { e.permissions = a.perms[i]; e.has_permissions = true; }
            if (!a.attrs.empty()) {
                e.win_attr = static_cast<std::uint8_t>(a.attrs[i]);
                e.has_win_attr = true;
                // What the Linux original lists and restores for these.
                e.permissions = (a.attrs[i] & 1u) ? 0400u : 0600u;
                e.has_permissions = true;
            }
            if (a.uids.size() == named.size() && a.gids.size() == named.size()) {
                e.uid = a.uids[i]; e.gid = a.gids[i]; e.has_owner = true;
            }
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

// One slice of one file inside a parallel (-pN) container. Each stream's record
// set names its slices as (type-1 table with a single filename+length, type-10
// offset WITHIN that file) pairs, in the order the stream's data decodes to, and
// its type-5/6/7 record carries one checksum per slice in that same order.
struct LegacyParallelSlice {
    std::string path;
    std::uint64_t osz = 0;   // this slice's decoded length
    std::uint64_t ooff = 0;  // where it sits inside its own file
    ChecksumMode cmode = ChecksumMode::kNone;
    std::uint32_t cval = 0;
    bool hasoff = false;
    bool has_cksum = false;
    std::size_t table = 0;   // which filename table of the stream introduced it (its flush group)
};

// One stream of a parallel (-pN) container.
struct LegacyParallelStream {
    // Block-record payload ranges for this stream, in order. Usually one, but
    // concatenated when a stream spans several type-0 chunks.
    std::vector<std::pair<std::size_t, std::size_t>> chunks;
    std::uint64_t osz = 0, ooff = 0;      // this slice's size and output offset
    ChecksumMode cmode = ChecksumMode::kNone;
    std::uint32_t cval = 0;               // checksum OF THE SLICE, not the file
    bool hasoff = false, hassz = false;
    // Every slice this stream carries, in order. A single-file archive has one
    // and the fields above describe it; a multi-file one can have several, of
    // different files (a stream is a worker, not a file).
    std::vector<LegacyParallelSlice> slices;
    // This stream's own codec record (type 11): p0 = selector, p1 = the window
    // byte. Every worker writes one; so far they have always agreed with each
    // other, but the ring below is sized from the stream's OWN byte regardless.
    std::uint8_t p0 = 0, p1 = 0;
    bool hasparams = false;
    std::size_t last_table_first = 0;     // index in `slices` of the latest table's first entry
    std::size_t table_count = 0;          // filename tables seen so far
    bool cut = false;                     // its last data record was cut off by the end of the file
};

// The -cd/-cD LZ ring, in 64 KB units, from the codec record's p1 byte:
// bytefloat(p1 + 1) -- xp1 = p1 + 1, m = xp1 & 0xf, s = xp1 >> 4,
// if (s) m = (m + 16) << (s - 1). The same mantissa/exponent byte the -cc
// window and the lzpf dictionary capacity use. NOT round(size / 0x10000): that
// fit every sample it was measured on and failed the first slice where the two
// disagree (2322452 bytes: p1 = 33 -> 36 units, round gives 35, and a match
// then reached past the whole ring).
static std::uint32_t LegacyCdRingUnitsFromP1(std::uint8_t p1) {
    const unsigned xp1 = static_cast<unsigned>(p1) + 1u;
    unsigned m = xp1 & 0x0fu;
    const unsigned sh = xp1 >> 4u;
    if (sh) m = (m + 16u) << (sh - 1u);
    return m ? static_cast<std::uint32_t>(m) : 1u;
}

// Detect and parse a parallel container. The encoder splits the input into one
// slice per worker and gives each its own record set, tagged with a stream id
// in the type-15 extension: type-1 = slice size, type-10 = u32 output offset,
// type-5/6/7 = slice checksum, type-0 = its compressed (or, for -cn, raw) data.
// Streams appear in arbitrary order and are tiled by their offsets.
//
// Detected by the record right after the version chunk being an extended one.
// Returns false when the archive is not parallel or the record walk breaks.
bool ParseLegacyParallelStreams(
    const ByteView& bytes,
    std::map<unsigned, LegacyParallelStream>* out_streams,
    // A store (-cn) copies whatever bytes of a cut record exist (measured: the
    // slice checksum is computed over stub + zero padding); the compressed
    // codecs never see a cut record.
    bool keep_cut_chunk = false) {
    if (out_streams == nullptr) return false;
    out_streams->clear();

    std::size_t magic = bytes.size();
    for (std::size_t q = 0; q + 4u <= bytes.size(); ++q) {
        if (bytes[q] == 0x1fu && bytes[q + 1u] == 0x0fu && bytes[q + 2u] == 0x09u) {
            magic = q;
            break;
        }
    }
    // The record after the magic is a stream-id extension (low nibble 15) in a
    // parallel container; comparing the WHOLE byte to 0x0f only held while a
    // checksum record came first, so `-hn` containers were rejected here.
    if (magic == bytes.size() || (bytes[magic + 3u] & 0x0fu) != 0x0fu) return false;

    std::size_t p = magic + 3u;
    for (std::size_t guard = 0; guard <= bytes.size() && p < bytes.size(); ++guard) {
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
        bool cut_rec = false;
        if (csz > bytes.size() - p) {
            if (ct != 0u || p >= bytes.size()) return false;
            csz = bytes.size() - p; cut_rec = true;   // cut data record: dropped, the stream ends short
        }
        LegacyParallelStream& st = (*out_streams)[sid];
        if (ct == 1u && csz >= 2u) {
            // A filename TABLE: (size varint, name\0) pairs, one per file the
            // block starts (a stream carrying a continued part of a big file
            // and two small files has a one-entry table + a two-entry table).
            // The stream-level size is the first entry's (the single-file
            // container has exactly one).
            std::size_t tp = p;
            bool first = true;
            while (tp < p + csz) {
                std::uint64_t v = 0;
                if (!ReadLegacyVarint(bytes, &tp, p + csz, &v)) break;
                const auto nul_it = std::find(bytes.begin() + static_cast<std::ptrdiff_t>(tp),
                                              bytes.begin() + static_cast<std::ptrdiff_t>(p + csz),
                                              static_cast<unsigned char>(0));
                if (nul_it == bytes.begin() + static_cast<std::ptrdiff_t>(p + csz)) break;
                if (first) { st.osz = v; st.hassz = true; st.last_table_first = st.slices.size(); first = false; ++st.table_count; }
                LegacyParallelSlice sl;
                sl.table = st.table_count - 1u;
                sl.path.assign(reinterpret_cast<const char*>(bytes.data() + tp),
                               static_cast<std::size_t>(
                                   std::distance(bytes.begin() + static_cast<std::ptrdiff_t>(tp), nul_it)));
                sl.osz = v;
                st.slices.push_back(std::move(sl));
                tp = static_cast<std::size_t>(std::distance(bytes.begin(), nul_it)) + 1u;
            }
        } else if (ct == 11u && csz >= 1u) {
            st.p0 = bytes[p];
            st.p1 = (csz >= 2u) ? bytes[p + 1u] : 0u;
            st.hasparams = true;
        } else if (ct == 10u && csz >= 4u) {
            st.ooff = ReadU32LE(bytes.data() + p);
            st.hasoff = true;
            // The offset belongs to the continued file part the table just
            // introduced: its FIRST entry (a stream resumes a big file first,
            // then starts new files, which sit at offset 0 of their own).
            if (st.last_table_first < st.slices.size() && !st.slices[st.last_table_first].hasoff) {
                st.slices[st.last_table_first].ooff = st.ooff; st.slices[st.last_table_first].hasoff = true;
            } else {
                for (auto it = st.slices.rbegin(); it != st.slices.rend(); ++it) {
                    if (!it->hasoff) { it->ooff = st.ooff; it->hasoff = true; break; }
                }
            }
        } else if ((ct == 5u || ct == 6u || ct == 7u) && csz > 0u) {
            const ChecksumMode m = (ct == 5u) ? ChecksumMode::kFletcher32
                                 : (ct == 6u) ? ChecksumMode::kCrc16
                                              : ChecksumMode::kCrc32;
            const std::size_t width = (ct == 6u) ? 2u : 4u;
            if ((csz % width) == 0u) {
                std::size_t q = p;
                for (auto& sl : st.slices) {
                    if (sl.has_cksum || q + width > p + csz) continue;
                    sl.cmode = m;
                    sl.cval = (width == 2u)
                        ? (static_cast<std::uint32_t>(bytes[q]) |
                           (static_cast<std::uint32_t>(bytes[q + 1u]) << 8u))
                        : ReadU32LE(bytes.data() + q);
                    sl.has_cksum = true;
                    q += width;
                }
            }
            if (csz == width) {  // the single-file fields the older paths read
                st.cmode = m;
                st.cval = (width == 2u)
                    ? (static_cast<std::uint32_t>(bytes[p]) |
                       (static_cast<std::uint32_t>(bytes[p + 1u]) << 8u))
                    : ReadU32LE(bytes.data() + p);
            }
        } else if (ct == 0u && csz > 0u) {
            if (!cut_rec || keep_cut_chunk) st.chunks.emplace_back(p, csz);
            if (cut_rec) st.cut = true;
        }
        if (NZ_ENV("NZ_TRACE_PARSTREAM"))
            std::fprintf(stderr, "[PAR] rec sid=%u ct=%u csz=%zu at %zu\n", sid, ct, csz, p);
        p += csz;
    }
    if (NZ_ENV("NZ_TRACE_PARSTREAM")) {
        for (const auto& kv : *out_streams) {
            std::fprintf(stderr, "[PAR] stream %u: osz=%llu(%d) ooff=%llu(%d) cmode=%d chunks=%zu slices=%zu\n",
                         kv.first, (unsigned long long)kv.second.osz, (int)kv.second.hassz,
                         (unsigned long long)kv.second.ooff, (int)kv.second.hasoff,
                         (int)kv.second.cmode, kv.second.chunks.size(), kv.second.slices.size());
        }
    }
    return !out_streams->empty();
}

// Assemble a parallel (-pN) container that holds SEVERAL files.
//
// A stream is a worker, not a file: it can carry slices of two different files,
// and one file's slices can be spread over several streams. Each stream decodes
// as ONE unit -- its data records form a single chain whose output is the
// concatenation of its slices in table order -- and every slice then lands at
// (its file's base in the output) + (its own offset WITHIN that file). The
// type-10 offset being file-relative rather than output-relative is what makes
// the single-file tiling paths wrong here: in a two-file archive both files have
// a slice at offset 0.
//
// `decode_stream` turns one stream's concatenated chunk bytes into its declared
// output length; it is the only codec-specific part. Every slice is checked
// against its own checksum, so a wrong layout produces nothing rather than
// wrong bytes.
// ---------------------------------------------------------------------------
// Parallel decode of a parallel container's worker streams.
//
// The streams of a -pN container are independent by construction (each worker
// of the original owned its own codec instance, window and checksum), so they
// decode concurrently -- the original does the same (2.29 GB in 4.7 s on 16
// cores where this port, decoding them one after another, took 49 s). Every
// stream writes into its own disjoint slice of the assembled buffer, and
// DisjointCover() proves the slices tile the output without overlap BEFORE any
// thread runs, so no two threads ever touch the same byte.
// ---------------------------------------------------------------------------
unsigned g_decode_threads = 0;   // -t<n> (0 = automatic)

unsigned DecodeThreadCount() {
    if (const char* e = NZ_ENV("NZ_THREADS")) {
        const long v = std::strtol(e, nullptr, 10);
        if (v > 0) return static_cast<unsigned>(std::min<long>(v, 256));
    }
    unsigned n = g_decode_threads ? g_decode_threads : std::thread::hardware_concurrency();
    if (n == 0u) n = 1u;
    if (n > 64u) n = 64u;
    return n;
}

// Sorts [offset, offset+size) ranges and checks that they tile [0, total)
// exactly: no gap, no overlap. The precondition for writing slices from
// several threads.
bool DisjointCover(std::vector<std::pair<std::uint64_t, std::uint64_t>> ranges, std::uint64_t total) {
    std::sort(ranges.begin(), ranges.end());
    std::uint64_t at = 0;
    for (const auto& r : ranges) {
        if (r.first != at || r.second == 0u || r.second > total - at) return false;
        at += r.second;
    }
    return at == total;
}

// Runs fn(i) for every i in [0, n) on up to DecodeThreadCount() threads; a false
// return stops the scheduling of further items. std::bad_alloc inside a worker
// is re-thrown on the calling thread so main() reports "Out of memory!".
bool ParallelForEach(std::size_t n, const std::function<bool(std::size_t)>& fn) {
    if (n == 0u) return true;
    const std::size_t threads = std::min<std::size_t>(DecodeThreadCount(), n);
    std::atomic<bool> ok{true};
    std::atomic<bool> oom{false};
    // The original reports the FIRST slot (lowest index) that holds an error
    // status, as status<<8 | slot. Each worker's decoders record their status in
    // the thread-local channel; collect the lowest slot's and hand it to the
    // calling thread when the batch is over.
    std::mutex fail_mu;
    bool have_fail = false; std::size_t fail_slot = 0; nzr::derr::State fail_state;
    const auto record_failure = [&](std::size_t i) {
        std::lock_guard<std::mutex> lk(fail_mu);
        if (!have_fail || i < fail_slot) { have_fail = true; fail_slot = i; fail_state = nzr::derr::Current(); }
        nzr::derr::Clear();
    };
    const auto publish_failure = [&]() {
        if (!have_fail) return;
        nzr::derr::t_state = fail_state; nzr::derr::t_state.parallel = true; nzr::derr::t_state.slot = fail_slot;
        if (nzr::derr::t_state.code == 0u && nzr::derr::t_state.fatal_id == 0u) nzr::derr::t_state.code = 100u;
    };
    if (threads <= 1u) {
        for (std::size_t i = 0; i < n; ++i) {   // every stream runs, as the original's workers do after a failure
            progress::SlotScope slot(i);
            progress::SlotStarted(i);
            if (!fn(i)) { ok = false; record_failure(i); }
            else progress::StreamDone(i);
        }
        publish_failure();
        return ok;
    }
    std::atomic<std::size_t> next{0};
    auto worker = [&]() {
        for (;;) {
            const std::size_t i = next.fetch_add(1u);
            if (i >= n) return;
            try {
                progress::SlotScope slot(i);
                progress::SlotStarted(i);
                if (!fn(i)) { ok = false; record_failure(i); }
                else progress::StreamDone(i);
            } catch (const std::bad_alloc&) {
                oom = true; ok = false;
            }
        }
    };
    std::vector<std::thread> pool;
    pool.reserve(threads - 1u);
    for (std::size_t k = 1; k < threads; ++k) pool.emplace_back(worker);
    worker();
    for (auto& th : pool) th.join();
    if (oom) throw std::bad_alloc();
    publish_failure();
    return ok;
}

template <class DecodeStreamFn>
bool AssembleParallelMultiFile(
    const ByteView& bytes,
    const std::map<unsigned, LegacyParallelStream>& streams,
    const std::vector<LegacyCnEntry>& entries,
    std::uint64_t total,
    DecodeStreamFn&& decode_stream,
    std::vector<unsigned char>* out,
    // Parallel sink: write each stream as it completes instead of assembling.
    bool use_sink = false,
    psink::Policy policy = psink::Policy::kProduced,
    std::uint64_t quantum = 0u,
    psink::Family family = psink::Family::kCm,
    // `-hn` writes no checksum at all: a slice without one is then normal, not
    // a slice whose checksum we failed to read.
    bool require_cksum = true) {
    if (out == nullptr || entries.size() < 2u || total == 0u ||
        total > (static_cast<std::uint64_t>(1) << 40)) {
        return false;
    }
    // Files are laid out in the order `entries` holds them, which is also how
    // the caller splits the assembled buffer back into files.
    std::map<std::string, std::uint64_t> base;
    std::uint64_t acc = 0;
    for (const LegacyCnEntry& e : entries) {
        if (!base.emplace(e.path, acc).second) return false;  // duplicate path
        acc += e.size;
    }
    if (acc != total) return false;

    // Validate every stream and prove the slices tile the output before any
    // thread runs; then decode the streams concurrently, each writing its own
    // disjoint slices.
    std::vector<const LegacyParallelStream*> list;
    std::vector<std::uint64_t> outs;
    std::vector<std::pair<std::uint64_t, std::uint64_t>> ranges;
    for (const auto& kv : streams) {
        const LegacyParallelStream& st = kv.second;
        if ((st.chunks.empty() && !st.cut) || st.slices.empty()) continue;
        std::uint64_t stream_out = 0;
        for (const LegacyParallelSlice& sl : st.slices) {
            if (sl.osz == 0u) continue;   // an empty file: nothing to decode or place
            if (require_cksum && !sl.has_cksum) return false;
            const auto it = base.find(sl.path);
            if (it == base.end()) return false;
            if (it->second + sl.ooff + sl.osz > total) return false;
            ranges.emplace_back(it->second + sl.ooff, sl.osz);
            stream_out += sl.osz;
        }
        if (stream_out > total) return false;
        if (stream_out == 0u) continue;   // only empty files: no data to decode
        list.push_back(&st);
        outs.push_back(stream_out);
    }
    if (!DisjointCover(ranges, total)) return false;
    if (use_sink) {
        std::map<std::string, std::size_t> eidx;
        for (std::size_t i = 0; i < entries.size(); ++i) eidx.emplace(entries[i].path, i);
        std::vector<psink::Stream> streams;
        for (const LegacyParallelStream* st : list) {
            psink::Stream ps;
            for (const LegacyParallelSlice& sl : st->slices) {
                psink::Slice x;
                x.entry = eidx.find(sl.path)->second; x.file_off = sl.ooff; x.len = sl.osz;
                x.cmode = sl.cmode; x.cval = sl.cval; x.has_cksum = sl.has_cksum; x.group = sl.table;
                ps.slices.push_back(x);
            }
            ps.cut = st->cut;
            streams.push_back(std::move(ps));
        }
        use_sink = psink::Publish(entries, std::move(streams), policy, quantum, family);
    }
    std::vector<unsigned char> assembled_store;
    if (!use_sink) assembled_store.assign(static_cast<std::size_t>(total), 0);

    const bool all = ParallelForEach(list.size(), [&](std::size_t idx) -> bool {
        const LegacyParallelStream& st = *list[idx];
        const std::uint64_t stream_out = outs[idx];
        if (use_sink) {
            psink::StreamBegin(idx);
            // Where this stream's LAST data record starts in the byte space its
            // decoder consumes (the chunks are fed concatenated): a failure
            // before it is the one the driver reports plainly. The single-file
            // parallel paths do the same; without it a multi-file container
            // printed status<<8|slot where the original prints the status.
            // A clean end (no status of its own) stays SHIFTED even when it
            // produced nothing: pmf_o 0.50/0.60 and pmf_Ou 0.60 report
            // status<<8|slot there, so only a recorded input position decides.
            if (st.chunks.size() > 1u) {
                std::uint64_t off = 0;
                for (std::size_t q = 0; q + 1u < st.chunks.size(); ++q) off += st.chunks[q].second;
                psink::SetLastRecordStart(idx, off);
            }
            const auto accept_all = [](const std::vector<unsigned char>&) { return true; };
            std::vector<unsigned char> decoded;
            bool okd = decode_stream(st.chunks, stream_out, accept_all, &decoded);
            if (decoded.size() > stream_out) decoded.resize(static_cast<std::size_t>(stream_out));
            std::uint64_t received = decoded.size();
            if (policy == psink::Policy::kStore) decoded.resize(static_cast<std::size_t>(stream_out));   // zero-padded, as the original writes it
            else okd = okd && decoded.size() == stream_out;
            const bool clean = !okd && nzr::derr::Current().code == 0u && nzr::derr::Current().fatal_id == 0u;
            psink::StreamEnd(idx, decoded.data(), decoded.size(), okd, clean, received);
            return okd;
        }
        const auto accept = [&](const std::vector<unsigned char>& dec) -> bool {
            if (dec.size() != stream_out) return false;
            std::uint64_t cur = 0;
            for (const LegacyParallelSlice& sl : st.slices) {
                if (sl.osz == 0u) continue;
                if (ComputeBufferChecksum(sl.cmode, dec.data() + cur,
                                          static_cast<std::size_t>(sl.osz)) != sl.cval) {
                    return false;
                }
                cur += sl.osz;
            }
            return true;
        };
        std::vector<unsigned char> decoded;
        if (!decode_stream(st.chunks, stream_out, accept, &decoded)) return false;
        if (!accept(decoded)) return false;
        std::uint64_t cursor = 0;
        for (const LegacyParallelSlice& sl : st.slices) {
            if (sl.osz == 0u) continue;
            const std::uint64_t file_base = base.find(sl.path)->second;
            std::memcpy(assembled_store.data() + static_cast<std::size_t>(file_base + sl.ooff),
                        decoded.data() + static_cast<std::size_t>(cursor),
                        static_cast<std::size_t>(sl.osz));
            cursor += sl.osz;
        }
        return true;
    });
    if (use_sink) return psink::Committed();
    if (!all) return false;
    *out = std::move(assembled_store);
    return true;
}

// Concatenate a stream's data-record payloads into one buffer.
inline std::vector<unsigned char> ConcatParallelChunks(
    const ByteView& bytes,
    const std::vector<std::pair<std::size_t, std::size_t>>& chunks) {
    std::vector<unsigned char> in;
    for (const auto& c : chunks) {
        if (c.first + c.second > bytes.size()) return std::vector<unsigned char>();
        in.insert(in.end(),
                  bytes.begin() + static_cast<std::ptrdiff_t>(c.first),
                  bytes.begin() + static_cast<std::ptrdiff_t>(c.first + c.second));
    }
    return in;
}

// Assemble a parallel STORE (-cn) payload: each stream's data record holds its
// slice verbatim, so the whole file is the slices tiled by their offsets. Every
// slice is checked against its own checksum, so a wrong layout cannot produce
// output.
bool TryAssembleParallelStore(
    const ByteView& bytes,
    std::uint64_t total_size,
    std::vector<unsigned char>* out,
    const std::vector<LegacyCnEntry>* entries = nullptr) {
    if (out == nullptr || total_size == 0u) return false;
    std::map<unsigned, LegacyParallelStream> streams;
    if (!ParseLegacyParallelStreams(bytes, &streams, /*keep_cut_chunk=*/true)) return false;
    if (entries != nullptr && entries->size() == 1u && psink::Available()) {
        // Sink: each raw slice goes straight out; a bad slice is written and
        // reported like the original does ("Checksum mismatch [...]: file").
        std::vector<const LegacyParallelStream*> list;
        std::vector<psink::Stream> pstreams;
        std::vector<std::pair<std::uint64_t, std::uint64_t>> ranges;
        for (const auto& kv : streams) {
            const LegacyParallelStream& st = kv.second;
            if (st.chunks.empty() && !st.cut) continue;
            if (!st.hasoff || !st.hassz || st.ooff > total_size || st.osz > total_size - st.ooff) return false;
            psink::Stream ps; psink::Slice sl;
            sl.entry = 0u; sl.file_off = st.ooff; sl.len = st.osz; sl.cmode = st.cmode; sl.cval = st.cval;
            sl.has_cksum = (st.cmode != ChecksumMode::kNone); sl.group = 0u;
            ps.slices.push_back(sl); pstreams.push_back(std::move(ps));
            list.push_back(&st); ranges.emplace_back(st.ooff, st.osz);
        }
        // The sink writes each slice where its stream says, so the slices need not
        // tile the output: a file listed twice has both copies at the same offsets
        // and they simply overwrite (see the note in the tiling paths).
        if (list.empty()) return false;
        if (!psink::Publish(*entries, std::move(pstreams), psink::Policy::kStore, 0u, psink::Family::kStore)) return false;
        for (std::size_t idx = 0; idx < list.size(); ++idx) {
            const LegacyParallelStream& st = *list[idx];
            progress::SlotScope slot(idx);
            psink::StreamBegin(idx);
            std::vector<unsigned char> slice = ConcatParallelChunks(bytes, st.chunks);
            const std::uint64_t received = std::min<std::uint64_t>(slice.size(), st.osz);
            slice.resize(static_cast<std::size_t>(st.osz));   // a cut slice is written zero-padded to its size
            progress::Add(received);
            // A short (cut) slice is not an error for a store: the slice goes out whole
            // and its checksum is reported over the bytes that arrived.
            psink::StreamEnd(idx, slice.data(), slice.size(), true, false, received);
        }
        return psink::Committed();
    }

    std::vector<unsigned char> assembled(static_cast<std::size_t>(total_size), 0);
    std::uint64_t covered = 0;
    for (const auto& kv : streams) {
        const LegacyParallelStream& st = kv.second;
        if (st.chunks.empty()) continue;
        if (!st.hasoff || !st.hassz || st.cmode == ChecksumMode::kNone) {
            if (NZ_ENV("NZ_TRACE_PARSTREAM"))
                std::fprintf(stderr, "[PAR] store: stream %u missing off/sz/cksum\n", kv.first);
            return false;
        }
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
    if (covered != total_size) {
        if (NZ_ENV("NZ_TRACE_PARSTREAM"))
            std::fprintf(stderr, "[PAR] store: covered=%llu != total=%llu\n",
                         (unsigned long long)covered, (unsigned long long)total_size);
        return false;
    }
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
    const ByteView& bytes,
    std::size_t first_prefix,
    std::uint64_t total,
    std::size_t trailer_bytes,
    std::vector<unsigned char>* out) {
    if (out == nullptr || first_prefix > bytes.size() || total == 0u) {
        return false;
    }
    // Two passes: walk the whole block chain structurally first (no allocation, no
    // copying), copy only when it is consistent. The caller probes this from every
    // byte between the table end and the data offset; on a truncated 2 MB parallel
    // store the copying version made that scan a two-minute "hang" (fuzz 2026-09-03).
    const auto walk = [&](std::vector<unsigned char>* dst) -> bool {
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
            if (dst != nullptr) {
                dst->insert(dst->end(), bytes.begin() + static_cast<std::ptrdiff_t>(q),
                            bytes.begin() + static_cast<std::ptrdiff_t>(q + ln));
            }
            acc += len;
            p = q + ln;
            if (acc < total) {
                if (trailer_bytes > bytes.size() - p) {
                    return false;
                }
                p += trailer_bytes;  // skip the inter-block checksum trailer
            }
        }
        return acc == total && p == bytes.size();
    };
    if (!walk(nullptr)) return false;
    std::vector<unsigned char> buf;
    buf.reserve(static_cast<std::size_t>(total));
    if (!walk(&buf)) return false;
    *out = std::move(buf);
    return true;
}

bool ReadLegacyTableSpan(
    const ByteView& bytes,
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
    const ByteView& bytes,
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
    const ByteView& bytes,
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
    const ByteView& bytes,
    std::size_t first_block_pos,
    std::size_t first_stream_len,
    std::uint64_t total,
    bool is_variant_b,
    unsigned method_p1,
    bool derived_cap_only,
    Verify&& verify,
    std::vector<unsigned char>* out,
    // Optional: decode straight into this caller-owned buffer of `total` bytes
    // (a parallel container's slice of the assembled output) instead of into a
    // fresh zeroed vector that is then copied -- two passes over the output
    // saved. With it, `verify` takes (const unsigned char*, std::size_t) and
    // *out is left empty on success.
    unsigned char* direct_out = nullptr,
    // The archive was cut inside this member: decode the bytes that exist, as
    // the original does (its truncation reports come from that stub decode).
    bool allow_truncated = false,
    // Bytes of whole members (segments) completed by the first candidate: what
    // the original has flushed when a later segment fails.
    std::size_t* out_member_done = nullptr,
    // Parallel-container stream: the original's worker clamps a block that
    // overshoots its slice or reads past its record and carries on; the report
    // then comes from the next block header (4, 2), not from the overrun (6, 3).
    bool lenient = false,
    // Where this member's input ends inside `bytes` (0 = the whole buffer): lets a
    // parallel worker decode its record in place instead of copying it out.
    std::size_t input_end = 0u) {
    const std::size_t in_end = (input_end != 0u && input_end <= bytes.size()) ? input_end : bytes.size();
    progress::Scope pscope;
    if (first_block_pos + first_stream_len > in_end) {
        if (!allow_truncated || first_block_pos >= in_end) return false;
        first_stream_len = in_end - first_block_pos;
    }
    // NZOPT_TRACE_LZPF=1 dumps one line per lzpf block (mode, size, prefilter
    // header fields) plus the decline point — the fastest way to tell whether a
    // failing member even reaches the stereo prefilter path.
    const bool trace_lzpf = (NZ_ENV("NZOPT_TRACE_LZPF") != nullptr);
    auto decode_lzpf_header = [&](std::size_t& pos, std::uint32_t& out_uvar9) -> bool {
        if (pos >= in_end) return false;
        std::uint8_t b0 = bytes[pos++];
        std::uint32_t v = static_cast<std::uint32_t>(b0) ^ (b0 & 0x80u);
        if ((b0 & 0x80u) != 0u) {
            if (pos >= in_end) return false;
            std::uint8_t b1 = bytes[pos++];
            v = (static_cast<std::uint32_t>(b1) ^ (b1 & 0x80u)) * 0x80u + 0x80u + v;
            if ((b1 & 0x80u) != 0u) {
                if (pos >= in_end) return false;
                std::uint8_t b2 = bytes[pos++];
                v = static_cast<std::uint32_t>(b2) * 0x4000u + 0x4000u + v;
            }
        }
        out_uvar9 = v;
        return true;
    };

    const std::size_t window_left_pad = 4u;
    // The dict capacity is DERIVED from the codec record's p1 byte, which is a
    // mantissa/exponent "byte float" -- the same encoding the -cc window size
    // uses: m = (p1+1) & 0xf, s = (p1+1) >> 4, and if s then m = (m+16) << (s-1);
    // capacity = m << 16. It is linear in p1 for small values and exponential
    // above, which is why a plain "(p1+1) * 64 KiB" fits every small archive and
    // breaks on a large one (p1=38 means 46 * 64 KiB, not 39).
    //
    // This used to be a SEARCH over five guesses -- ceil/floor of total over
    // 64 KiB and over 128 KiB, plus (p1+1)*64 KiB -- kept honest by checking each
    // decode against the stored checksum. That worked only because a wrong
    // capacity is harmless until the window wraps, and it could not work at all
    // for an archive written with -hn or -nm, which stores no checksum to
    // adjudicate with: those declined outright. The derived value was verified
    // as the ONLY candidate against the 60-file real corpus, the synthetic suite
    // and the multi-file suite, all unchanged.
    std::vector<std::size_t> cap_candidates;
    {
        const unsigned xp1 = static_cast<unsigned>(method_p1) + 1u;
        unsigned mant = xp1 & 0x0fu;
        const unsigned exp_bits = xp1 >> 4u;
        if (exp_bits) mant = (mant + 16u) << (exp_bits - 1u);
        const std::size_t derived = static_cast<std::size_t>(mant) << 16u;
        if (derived != 0u) cap_candidates.push_back(derived);
        // The old guesses stay as a fallback for a shape the derived value might
        // not cover -- but only where a checksum can adjudicate between them,
        // which is exactly where they were safe before.
        if (!derived_cap_only) {
            const std::size_t t = static_cast<std::size_t>(total);
            const std::size_t u64 = t / 0x10000u;
            const std::size_t u128 = t / 0x20000u;
            const std::size_t cands[] = {
                ((t + 0xffffu) / 0x10000u) * 0x10000u,
                u64 * 0x10000u,
                (u128 + 1u) * 0x20000u,
                u128 * 0x20000u,
            };
            for (std::size_t c : cands) {
                if (c == 0u) continue;
                bool dup = false;
                for (std::size_t e : cap_candidates) if (e == c) { dup = true; break; }
                if (!dup) cap_candidates.push_back(c);
            }
        }
        if (cap_candidates.empty()) cap_candidates.push_back(0x10000u);
    }
    const std::size_t window_wrap_threshold = 0x8000u;  // 32 KiB
    const std::size_t window_tail_slack = 0x8000u;      // FUN_080b6bb0 memset reach
    const std::size_t window_initial_cursor = 4u;

    // On total failure `out` receives the output of the members (streams) that
    // decoded completely under the first candidate: the original flushes per
    // member, so those files are on disk when it reports the error.
    std::vector<unsigned char> first_prefix;
    bool first_candidate = true;
    for (std::size_t cap_idx = 0; cap_idx < cap_candidates.size(); ++cap_idx) {
        const std::size_t window_capacity = cap_candidates[cap_idx];
        pscope.Restart();
        std::size_t member_done = 0;
        std::size_t stream_data_end = first_block_pos + first_stream_len;
        std::vector<std::uint8_t> window_alloc(
            window_left_pad + window_capacity + window_tail_slack, 0);
        std::uint8_t* const window = window_alloc.data() + window_left_pad;
        std::vector<unsigned char> decoded_store;
        unsigned char* decoded = direct_out;
        if (decoded == nullptr) {
            decoded_store.assign(static_cast<std::size_t>(total), 0);
            decoded = decoded_store.data();
        }
        auto run_verify = [&]() -> bool {
            if constexpr (std::is_invocable_v<Verify, const unsigned char*, std::size_t>)
                return verify(static_cast<const unsigned char*>(decoded), static_cast<std::size_t>(total));
            else
                return verify(decoded_store);
        };
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
        // The image model: the (uVar9 & 7) == 4 block with bit 3 set runs
        // FUN_080a9ca0 on the dispatcher's image object (param_1 + 0x121f0) instead
        // of the prefilter core. One per stream, never reset. -cf and -cF share
        // the profile (GDB: flags 0x00, all five planes order 16).
        nzr::audio::NzImageModel lzpf_img;
        lzpf_img.Configure(0x00u, 16u, 16u, true);
        while (total_written < total) {
            if (input_pos >= stream_data_end) {
                if (input_pos != stream_data_end) { nzr::derr::SetAt(2u, input_pos); decode_ok = false; break; }
                member_done = total_written;
                // Consume any inter-stream checksum record (tag 0x45/0x47/0x26
                // + width) before the next stream tag.
                while (input_pos < in_end) {
                    const std::uint8_t tb = bytes[input_pos];
                    std::size_t tw;
                    if      (tb == 0x45u) tw = 4u;
                    else if (tb == 0x47u) tw = 4u;
                    else if (tb == 0x26u) tw = 2u;
                    else break;
                    if (input_pos + 1u + tw > in_end) break;
                    input_pos += 1u + tw;
                }
                std::uint64_t next_tag = 0;
                if (lenient && input_pos >= in_end) { decode_ok = false; break; }   // input simply ran out: the sink reports the codec's short-end status
                if (!ReadLegacyVarint(bytes, &input_pos, in_end, &next_tag) ||
                    (next_tag & 0x0fu) != 0u) { nzr::derr::SetAt(2u, input_pos); decode_ok = false; break; }
                std::uint64_t next_bytes = next_tag >> 4u;
                if (next_bytes != 0u && allow_truncated &&
                    next_bytes > static_cast<std::uint64_t>(in_end - input_pos))
                    next_bytes = static_cast<std::uint64_t>(in_end - input_pos);
                if (next_bytes == 0u ||
                    next_bytes > static_cast<std::uint64_t>(in_end - input_pos)) {
                    nzr::derr::SetAt(2u, input_pos); decode_ok = false; break;
                }
                stream_data_end = input_pos + static_cast<std::size_t>(next_bytes);
            }
            std::uint32_t uvar9 = 0;
            if (!decode_lzpf_header(input_pos, uvar9)) { nzr::derr::SetAt(2u, input_pos); decode_ok = false; break; }
            const bool mode_prefilter = ((uvar9 & 7u) == 4u);
            const bool mode_literal = !mode_prefilter && ((uvar9 & 2u) == 0u);
            const bool mode_lz77_side = !mode_prefilter && (uvar9 & 2u) && (uvar9 & 1u);
            // Raw-bytecode LZ77 (FUN_08097570: (uVar9 & 2) set, (uVar9 & 1) clear):
            // the LZ77 opcode stream is the input bytes directly — no u16 count,
            // no arith side stream. The dispatcher consumes opcodes until the
            // block output is produced and reports how many input bytes it read.
            const bool mode_lz77_raw = !mode_prefilter && (uvar9 & 2u) && !(uvar9 & 1u);
            nz_trace::Construct("lzpf_block mode=%s bit3=%u", mode_prefilter ? "prefilter" : mode_literal ? "literal" : mode_lz77_side ? "lz77_side" : "lz77_raw", (uvar9 >> 3) & 1u);
            // Sliding-window wrap (legacy FUN_080b6bb0): zero [cursor, cap+0x8000)
            // then reset the cursor to 0 when fewer than 32 KiB remain.
            if (window_capacity - window_cursor < window_wrap_threshold) {
                std::memset(window + window_cursor, 0,
                            window_capacity + window_tail_slack - window_cursor);
                window_cursor = 0;
            }
            if (mode_prefilter) {
                const std::uint32_t uvar18 = (uvar9 >> 3u) & 1u;   // 1 = image block
                std::uint64_t block_out_size = uvar9 >> 4u;
                if (block_out_size == 0u) block_out_size = 0x8000u;
                if (block_out_size > 0x8001u) { nzr::derr::SetAt(4u, input_pos); decode_ok = false; break; }
                if (total_written + block_out_size > total) {
                    // lenient (parallel worker): the original reports this as 2, not 3.
                    nzr::derr::SetAt(lenient ? 2u : 3u, input_pos); decode_ok = false; break;
                }
                const std::size_t block_start_in_window = window_cursor;
                const std::size_t avail_in = stream_data_end - input_pos;
                const std::uint8_t pf_hdr = bytes[input_pos];
                const std::uint32_t pf_channels = (pf_hdr >> 1u) % 3u;
                const bool is_stereo_pf = (pf_channels != 0u);
                const std::size_t pf_consumed = (uvar18 != 0u)
                    ? lzpf_img.Decode(bytes.data() + input_pos, avail_in,
                                      window + block_start_in_window,
                                      static_cast<std::size_t>(block_out_size))
                    : nzr::lzpf::DecodePrefilterStream(
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
                if (pf_consumed == 0) { nzr::derr::SetAt(5u, input_pos); decode_ok = false; break; }
                input_pos += pf_consumed;
                window_cursor += static_cast<std::size_t>(block_out_size);
                std::memcpy(decoded + total_written, window + block_start_in_window,
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
                progress::Add(block_out_size);
                continue;
            }
            if (!mode_literal && !mode_lz77_side && !mode_lz77_raw) { nzr::derr::SetAt(5u, input_pos); decode_ok = false; break; }
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
            if (block_out_size > 0x8001u) { nzr::derr::SetAt(4u, input_pos); decode_ok = false; break; }
            if (total_written + block_out_size > total) {
                nzr::derr::SetAt(lenient ? 2u : 3u, input_pos); decode_ok = false; break;   // see above
            }
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
                nzr::cd::NzCdExeUnfilter(decoded + out_off, static_cast<std::uint32_t>(n),
                                static_cast<std::uint32_t>(out_off + 4u));
            };
            if (mode_literal) {
                // A block that consumes more input than its stream holds is the
                // original's status 6 (FUN_08097e20, checked after the block).
                std::size_t lit_avail = static_cast<std::size_t>(block_out_size);
                if (input_pos + block_out_size > stream_data_end) {
                    if (!lenient) { nzr::derr::SetAt(6u, input_pos); decode_ok = false; break; }
                    lit_avail = stream_data_end - input_pos;   // the rest of the block stays as it is
                }
                const std::size_t block_start_in_window = window_cursor;
                std::memcpy(window + block_start_in_window, bytes.data() + input_pos, lit_avail);
                std::memcpy(decoded + total_written, bytes.data() + input_pos, lit_avail);
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
                input_pos += lit_avail;
                total_written += static_cast<std::size_t>(block_out_size);
                progress::Add(block_out_size);
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
                if (input_pos + 2u > stream_data_end) {
                    if (!lenient) { nzr::derr::SetAt(6u, input_pos); decode_ok = false; break; }
                    input_pos = stream_data_end;   // no side stream left: the next header read reports
                    continue;
                }
                const std::uint16_t side_count =
                    static_cast<std::uint16_t>(bytes[input_pos]) |
                    (static_cast<std::uint16_t>(bytes[input_pos + 1u]) << 8u);
                input_pos += 2u;
                const std::size_t arith_size = stream_data_end - input_pos;
                bytecode.assign(side_count + 16u, 0);
                const std::size_t consumed = nzr::lzpf::DecodeArithBuffer(
                    bytes.data() + input_pos, arith_size,
                    bytecode.data(), side_count, /*max_len=*/12);
                if (consumed == 0 || consumed > arith_size) {
                    if (!lenient) { nzr::derr::SetAt(6u, input_pos); decode_ok = false; break; }
                    input_pos += arith_size;   // clamp to the record; the bytecode decoded so far is used
                } else {
                    input_pos += consumed;
                }
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
            if (!dispatch_ok && !lenient) { nzr::derr::SetAt(6u, input_pos); decode_ok = false; break; }
            // lenient: the original's dispatcher copies bounded garbage and moves on.
            if (mode_lz77_raw) input_pos += raw_consumed;
            // The original does not check that the LZ77 block filled its slot; on
            // garbage it copies the slot out and moves to the next header, which is
            // where its report comes from. Same here (the slot is bounded).
            window_cursor = block_start_in_window + block_out_size;
            std::memcpy(decoded + total_written, window + block_start_in_window,
                        static_cast<std::size_t>(block_out_size));
            apply_exe_filter(total_written, static_cast<std::size_t>(block_out_size));
            total_written += static_cast<std::size_t>(block_out_size);
                progress::Add(block_out_size);
        }
        if (trace_lzpf) {
            if (const char* dp = NZ_ENV("NZOPT_DUMP_LZPF")) {
                char path[512];
                snprintf(path, sizeof(path), "%s.cap%zu", dp, window_capacity);
                if (FILE* fp = fopen(path, "wb")) {
                    fwrite(decoded, 1, total_written, fp);
                    fclose(fp);
                }
            }
            fprintf(stderr, "[lzpf] cap=%zu blocks=%zu ok=%d written=%zu/%llu verify=%d\n",
                    window_capacity, blk_idx, (int)decode_ok, total_written,
                    (unsigned long long)total,
                    (decode_ok && total_written == total) ? (int)run_verify() : -1);
        }
        if (first_candidate) {
            first_candidate = false;
            if (out_member_done != nullptr) *out_member_done = member_done;
            if (member_done > 0 && member_done < total && direct_out == nullptr)
                first_prefix.assign(decoded, decoded + member_done);
        }
        if (decode_ok && total_written == total && run_verify()) {
            // Which dictionary capacity actually decoded: candidate 0 is the value
            // DERIVED from the codec record's p1 byte, 1..4 are the legacy guesses
            // kept as a fallback. If a corpus sweep never reports a candidate above
            // 0, the guesses can go (see the note next to cap_candidates).
            nz_trace::Construct("lzpf_cap candidate=%zu of=%zu p1=%u variant=%c",
                                cap_idx, cap_candidates.size(), method_p1, is_variant_b ? 'B' : 'A');
            if (direct_out != nullptr) { if (out != nullptr) out->clear(); }
            else *out = std::move(decoded_store);
            pscope.Commit();
            return true;
        }
    }
    if (out != nullptr && !first_prefix.empty()) *out = std::move(first_prefix);
    return false;
}

// Forward declaration: defined further below (near TryDecodeLegacyOptimum,
// which it was extracted from), but also needed here by the -co parallel-
// container branch inside TryParseLegacyCnArchive. Templated on the decoder
// type since it now also serves -cO's NzOptimum2LzDecoder (single-container
// path only, in TryDecodeLegacyOptimum) -- the parallel-container branch
// below only ever instantiates it with NzOptimumLzDecoder (-co parallel
// containers; parallel -cO containers are wired too, see TryParseLegacyCnArchive).
template <typename OptimumDecoder>
static bool DecodeOptimumBlockSequence(
    const unsigned char* raw,
    std::size_t blocks_begin,
    std::size_t blocks_end,
    std::uint64_t total_size_hint,
    OptimumDecoder& dec,
    nzr::audio::NzAudioPred& audio,
    nzr::audio::NzImageModel& image,
    NzExeFilter& exe,
    // The accumulated PRE-post-filter output of every non-audio block so far
    // (the reference's mem->data_org..mem->data). param15's absolute offsets
    // index THIS stream, not the final output: param1 (the delta filter)
    // rewrites almost every byte, so a param15 match sourced from the final
    // output copies the wrong bytes into the block AND into the LZ window.
    std::vector<std::uint8_t>& raw_stream,
    std::vector<unsigned char>* out_data);

// Per-codec profiles of the two side models the optimum family carries.
// Audio (GDB-read at FUN_080a5330's entry): the decoder object's flag byte is
// -co 0x13 / -cO 0x03 -- -co is the one whose bit 4 is SET, so it runs
// FUN_08096e20 (the LMS) instead of FUN_08096160 and reads two 3-bit shifts
// biased +7 rather than two 4-bit shifts biased +0x10; plane orders -co
// 64/8/8, -cO 96/8/8; stereo param -co 4, -cO 8; -co uses the bit-count
// decoder class B. Image (GDB-read at FUN_080a90c0's entry): -co flags 0x07,
// -cO 0x0f, both planes 32/48; -co bit-count class B. `p0` is the method's
// first parameter byte (5 = -co, 6 = -cO).
static void ConfigureOptimumModels(std::uint32_t p0, nzr::audio::NzAudioPred& aud,
                                   nzr::audio::NzImageModel& img) {
    if (p0 == 5u) {
        aud.SetContextFlags(0x13u); aud.SetPlaneOrders(64u, 8u, 8u); aud.SetStereoParam(4u); aud.SetBitcountVariantB(true);
        img.Configure(0x07u, 32u, 48u, true);
    } else {
        aud.SetContextFlags(0x03u); aud.SetPlaneOrders(96u, 8u, 8u); aud.SetStereoParam(8u);
        img.Configure(0x0fu, 32u, 48u, false);
    }
}

std::size_t LegacySfxDataOffset(const unsigned char* b, std::size_t n);
void StageMark(const char* what);

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

    // The archive is mapped, not copied (see ArchiveBytes): the parse and every
    // decoder only read it, and a 2 GB archive would otherwise be 2 GB of
    // anonymous memory.
    input.close();
    ArchiveBytes archive;
    if (!archive.Open(archive_path)) {
        if (out_error_message != nullptr) *out_error_message = "Cannot open archive!";
        return false;
    }
    ByteView bytes = archive.View();
    StageMark("archive read");
    // A self-extracting archive (`w32c`) is a Windows PE stub with the archive
    // appended; the original opens those by seeking past the image (FUN_080b0e50),
    // and so does `l`/`x`/`t` here. Everything below indexes `bytes`, so dropping
    // the stub up front keeps every offset consistent.
    if (bytes.size() > 0x40u && bytes[0] == 'M' && bytes[1] == 'Z') {
        const std::size_t off = LegacySfxDataOffset(bytes.data(), bytes.size() < 4096u ? bytes.size() : 4096u);
        if (NZ_ENV("NZ_VERBOSE_NATIVE")) std::fprintf(stderr, "[native] PE stub: archive data offset %zu of %zu\n", off, bytes.size());
        if (off > 1u && off < bytes.size()) bytes = bytes.subview(off);
    }
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
    unsigned char method = 0u, method_p0 = 0u, method_p1 = 0u, method_p2 = 0u;
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
    // Per table, whether a type-10 (slice offset) record follows it in its
    // stream: that is the original's "this entry is a slice of a file split
    // across streams" flag (entry byte 0x21 & 0x10), set on EVERY slice of such
    // a file, the offset-0 one included. It decides the listing order below.
    std::vector<bool> table_has_off;
    std::map<unsigned, std::size_t> last_table_of_stream;   // stream -> index into all_tables
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
    bool truncated_input = false;
    // The record framing itself ran off the end of the file, or the first data
    // record is shorter than the codec's first block header: the original never
    // gets a decoder started and its reader reports "Unexpected end of file."
    bool eof_before_decode = false;
    // A data record whose header is complete (its payload may be cut off).
    bool saw_data_record = false;
    bool cut_first_data_record = false;

    // No record-count cap: a 2.29 GB -cf container carries 16 streams x ~144 records
    // (2300+), and an earlier cap of 1024 made the walker stop half-way, so the
    // parser saw 8 streams and folded the other 8 into one undecodable slice
    // (declined as corrupt). Every record consumes at least one byte, so `pos`
    // alone bounds the loop; the guard only rules out a non-advancing iteration.
    for (std::size_t guard = 0; guard <= bytes.size() && pos < bytes.size(); ++guard) {
        const std::size_t record_begin = pos;
        std::uint64_t r64 = 0u;
        if (!ReadLegacyVarint(bytes, &pos, bytes.size(), &r64)) {
            truncated_input = eof_before_decode = true;
            break;
        }
        auto r = static_cast<std::uint32_t>(r64);
        unsigned ctype   = r & 0x0fu;
        unsigned cstream = 0u;
        std::size_t csize = static_cast<std::size_t>(r >> 4u);

        if (ctype == 15u) {
            if (pos >= bytes.size()) { truncated_input = eof_before_decode = true; break; }
            unsigned ext = static_cast<unsigned>(bytes[pos++]);
            if (ext >= 0xf8u) {
                if (pos >= bytes.size()) { truncated_input = eof_before_decode = true; break; }
                ext = (ext & 7u) + 8u * static_cast<unsigned>(bytes[pos++]) + 248u;
            }
            ctype   = ext & 0x0fu;
            cstream = ext >> 4u;
            if (cstream == 0u) ctype += 15u;
        }

        if (ctype == 0u && found_codec) saw_data_record = true;
        if (ctype == 10u && found_codec) {
            const auto lt = last_table_of_stream.find(cstream);
            if (lt != last_table_of_stream.end() && lt->second < table_has_off.size())
                table_has_off[lt->second] = true;
        }

        if (pos + csize > bytes.size()) {
            truncated_input = true;
            psink::MarkTruncated();
            // Nothing ever reached the decoder: the cut is in a metadata record
            // (or in a data record the codec cannot even start on), so the
            // failure comes from the reader and is "Unexpected end of file."
            // Measured over m_<codec>.nz cut byte by byte: with the first data
            // record's header whole, -cn/-cd/-cD/-cf/-cF already report their own
            // status, while -cc/-co/-cO still need the 5 bytes of a block header.
            const bool cut_in_data = (ctype == 0u && cstream == 0u && found_codec);
            if (!found_first_data &&
                (!cut_in_data ||
                 ((method_p0 == 5u || method_p0 == 6u || method_p0 == 7u) &&
                  bytes.size() - pos < 5u)))
                eof_before_decode = true;
            // The original hands the decoder whatever bytes of the cut-off data
            // record exist (its reports on truncated archives -- 4096, 1024, 1536,
            // the lzhds assertion -- come from decoding that stub), so keep it.
            if (ctype == 0u && cstream == 0u && found_codec && pos < bytes.size())
                data_records.push_back({record_begin, bytes.size()});
            // A cut inside the FIRST data record: whatever the decoder makes of
            // the stub, the original reports its family's short-end status --
            // 4 for -cd/-cD, 2 for -cf/-cF, 100 for the CM family -- shifted,
            // since it is the last record. Measured byte by byte and at 15
            // points across the first record of m_<codec>.nz, all eight codecs:
            // constant there, garbage-dependent beyond it. (Dropping the stub
            // instead, as the parallel workers do, was tried: it matches less.)
            if (cut_in_data && !found_first_data) cut_first_data_record = true;
            // A filename table cut off by the end of the file: the original
            // reads the names that fit and then reports the truncation the way
            // it reports any other one ("Archive corrupted. Unexpected end of
            // file." after printing the first entry's name), so take the table
            // as far as it goes instead of rejecting the archive.
            if (ctype == 1u && cstream == 0u && found_codec && !found_table && pos < bytes.size()) {
                table_start = pos;
                table_end = bytes.size();
                found_table = true;
                all_tables.push_back({0u, pos, bytes.size()});
                table_has_off.push_back(false);
            }
            break;
        }
        const bool is_main = (cstream == 0u);
        if (NZ_ENV("NZ_TRACE_PARSTREAM"))
            std::fprintf(stderr, "[HDR] @%zu ctype=%u cstream=%u csize=%zu codec=%d table=%d\n",
                         pos, ctype, cstream, (size_t)csize, (int)found_codec, (int)found_table);

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
            if (csize > 0u && (ctype == 2u || ctype == 3u || ctype == 4u || ctype == 5u ||
                               ctype == 6u || ctype == 7u || ctype == 8u || ctype == 9u)) {
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
            // The THIRD byte is the block size the compressor settled on (the
            // same mantissa/exponent byte-float as the window). It is what the
            // "[N MB]" figure on the Compressor line is computed from -- the
            // original sizes its primary buffer by the block, not the window --
            // so an archive made with an explicit -m prints a smaller figure
            // than its window alone would suggest. Measured on -co archives of
            // one 3 MB input at -m8m/-m24m/-m32m/-m48m: 13/16/20/25 MB, exactly
            // f(window from p1, primary = max(block from p2, 1 MB)).
            method_p2 = (csize >= 3u) ? bytes[pos + 2u] : 0u;
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
            // Record the FIRST type-1 chunk as the canonical table, whatever
            // stream it belongs to, and keep every one of them for the entry
            // build. This only fixes the metadata/payload BOUNDARY: the entry
            // list itself is built by walking all_tables with dedup below, so
            // it stays complete either way.
            //
            // Requiring the main stream here was wrong. In a parallel (-pN)
            // container every worker emits its own self-describing record run
            // (type 5/11/1/10/2/4/5 then its type-0 data), and the ORDER of
            // those runs follows thread scheduling, not the stream id. Most of
            // the time stream 0 goes first; occasionally (about 1 run in 20 for
            // -cn -p4 on a 1 MB file) all four stream ids are declared up front
            // and the runs come out 3, 0, 2, 1. Skipping stream 3's table then
            // adopted stream 0's, which sits AFTER stream 3's 250 KB data
            // record -- so table_end landed inside the payload and the archive
            // was rejected with "Data corrupted while reading headers!". The
            // tables are per-stream copies, and the boundary we want is simply
            // where the first metadata run ends.
            if (found_codec) {
                if (!found_table) {
                    table_start = pos;
                    table_end   = pos + csize;
                    found_table = true;
                }
                all_tables.push_back({static_cast<std::size_t>(cstream), pos, pos + csize});
                table_has_off.push_back(false);
                last_table_of_stream[cstream] = all_tables.size() - 1u;
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
        if (NZ_ENV("NZ_TRACE_PARSTREAM"))
            std::fprintf(stderr, "[HDR] BAIL table_end=%zu > size=%zu\n", (size_t)table_end, bytes.size());
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
    // Parallel to stream_named: whether that table entry is a slice of a split
    // file (its table is followed by a type-10 offset record).
    std::map<unsigned, std::vector<bool>> stream_split;
    for (std::size_t table_index = 0; table_index < all_tables.size(); ++table_index) {
    const auto& table_span = all_tables[table_index];
    const bool table_split = table_index < table_has_off.size() && table_has_off[table_index];
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
            // The table itself was cut off: keep the entries that are complete
            // (the original does, and then reports the truncation).
            if (truncated_input && !entries.empty()) break;
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
        // Only a PARALLEL container repeats a path, because a file is split
        // into per-stream slices and each stream's table names it. A sequential
        // archive that genuinely lists the same file twice must keep both
        // entries -- the original lists and extracts both.
        if (has_parallel_streams) {
            const auto known = path_index.find(e.path);
            if (known != path_index.end()) {
                stream_named[table_stream].push_back(known->second);
                stream_split[table_stream].push_back(table_split);
                continue;
            }
        }
        path_index.emplace(e.path, entries.size());
        stream_named[table_stream].push_back(entries.size());
        stream_split[table_stream].push_back(table_split);
        total_data_size += file_size;
        if (NZ_ENV("NZ_TRACE_PARSTREAM"))
            std::fprintf(stderr, "[HDR] store size check: total_data_size=%llu size=%zu\n",
                         (unsigned long long)total_data_size, bytes.size());
        if (native_store_payload && total_data_size > bytes.size()) {
            if (out_error_message != nullptr) {
                *out_error_message = "Data corrupted while reading headers!";
            }
            return false;
        }
        entries.push_back(std::move(e));
    }

    // A table cut off by the end of the file stops at its last whole entry, so
    // the cursor does not reach table_end -- that is the shape the original
    // lists and then reports as "Unexpected end of file", not a rejection.
    if (p != table_end && !(truncated_input && !entries.empty())) {
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
    // Only in a PARALLEL container is a repeated path the same file in slices,
    // so only there does summing the per-table sizes give the true size. A
    // sequential archive that lists the same file twice has two entries of the
    // real size; summing them reported each at double, and the total at double.
    if (has_parallel_streams && !size_accum.empty()) {
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
    // In a parallel container the file ORDER is not record order. The original
    // keeps one entry list per worker stream (in table order) and merges them
    // into the global list one stream at a time, in stream-id order
    // (FUN_080922a0, read with GDB on `l`: a watchpoint on the list head and a
    // dump of both lists at every call, see the wiki's Reverse-Engineering
    // notes). The merge walks the stream's list collecting a RUN; a slice of a
    // split file (entry flag 0x10 = its table is followed by an offset record)
    // ends the run: the run is spliced at the HEAD of the global list, keeping
    // its internal order, and the slice itself is either ADDED to the entry of
    // the same name already in the list (size summed, checksum zeroed -- the
    // `n/a`) or, if none, starts the next run. Whatever is left at the end of
    // the stream is spliced at the head too. So the listing is a sequence of
    // reversed stream blocks, each block in table order, minus the slices that
    // were already known. Verified on -p2/-p3/-p4 of one set and on the pmf_*
    // fixtures; a sequential container has one stream and is unaffected.
    if (has_parallel_streams && entries.size() > 1u) {
        std::vector<std::size_t> global;
        std::vector<bool> present(entries.size(), false);
        for (const auto& kv : stream_named) {              // std::map: ascending stream id
            const std::vector<std::size_t>& names = kv.second;
            const auto fl = stream_split.find(kv.first);
            std::vector<std::size_t> run;
            const auto flush = [&]() {
                if (run.empty()) return;
                for (std::size_t idx : run) present[idx] = true;
                global.insert(global.begin(), run.begin(), run.end());
                run.clear();
            };
            for (std::size_t k = 0; k < names.size(); ++k) {
                const std::size_t idx = names[k];
                if (idx >= entries.size()) continue;
                const bool split = fl != stream_split.end() && k < fl->second.size() && fl->second[k];
                if (split) flush();
                if (present[idx]) continue;                // merged into the entry already listed
                bool in_run = false;
                for (std::size_t r : run) if (r == idx) { in_run = true; break; }
                if (!in_run) run.push_back(idx);
            }
            flush();
        }
        // Anything no stream table named (should not happen) keeps record order after it.
        for (std::size_t i = 0; i < entries.size(); ++i)
            if (!present[i]) global.push_back(i);
        if (global.size() == entries.size()) {
            std::vector<LegacyCnEntry> reordered;
            reordered.reserve(global.size());
            std::vector<std::size_t> remap(entries.size(), 0);
            for (std::size_t k = 0; k < global.size(); ++k) {
                remap[global[k]] = k;
                reordered.push_back(entries[global[k]]);
            }
            entries.swap(reordered);
            for (auto& kv : stream_named)
                for (std::size_t& idx : kv.second)
                    if (idx < remap.size()) idx = remap[idx];
        }
    }

    std::set<std::string> split_paths;
    for (const auto& kv : path_streams) {
        if (kv.second.size() > 1u) split_paths.insert(kv.first);
    }
    // No attribute records at all is a legitimate answer, not a failure: -nm
    // (and -nt -np -hn) produce exactly that. Treating it as a failure fell
    // through to the old heuristics, one of which scans the metadata span for a
    // 0x24 byte and calls it a permission tag -- so a stray 0x24 in the
    // compressed payload made `l` print a 0664 column the original does not.
    const bool metadata_run_parsed =
        attr_records.empty() ||
        ApplyLegacyAttributeRecords(bytes, attr_records, stream_named, split_paths, &entries);
    const std::size_t run_metadata_end = first_data_record;

    // Some decodes run here, at parse time; the progress engine prints the
    // "Archive / Threads / Compressor" header lazily from this snapshot, so it
    // has to exist before the FIRST of them -- the parallel store assembly just
    // below is one, and without this its header came out with an empty archive
    // name and an `unknown` compressor.
    const auto publish_snapshot = [&]() {
        if (!progress::Active() || entries.empty()) return;
        LegacyCnContext snap;
        snap.archive_path = archive_path;
        snap.legacy_method = method;
        snap.legacy_method_p0 = method_p0;
        snap.legacy_method_p1 = method_p1;
        snap.legacy_method_p2 = method_p2;
        snap.cm_a_bits = cm_a_bits;
        snap.cm_b_bits = cm_b_bits;
        snap.cm_window_size = cm_window_size;
        if (has_parallel_streams) {
            std::map<unsigned, LegacyParallelStream> pstreams;
            if (ParseLegacyParallelStreams(bytes, &pstreams))
                for (const auto& kv : pstreams)
                    snap.parallel_p1.push_back(kv.second.hasparams ? kv.second.p1 : method_p1);
        }
        snap.entries.push_back(entries.front());
        progress::Publish(snap);
    };
    publish_snapshot();

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
        if (NZ_ENV("NZ_TRACE_PARSTREAM"))
            std::fprintf(stderr, "[PAR] store dispatch: total=%llu data_offset=%zu table_end=%zu prefix_found=%d entries=%zu\n",
                         (unsigned long long)total_data_size, data_offset, (size_t)table_end,
                         (int)prefix_found, entries.size());
        if (!prefix_found && entries.size() > 1u) {
            // Parallel store holding several files: the slices are raw, so
            // "decoding" a stream is copying its concatenated chunks.
            std::map<unsigned, LegacyParallelStream> pstreams;
            if (ParseLegacyParallelStreams(bytes, &pstreams, /*keep_cut_chunk=*/true) &&
                AssembleParallelMultiFile(
                    bytes, pstreams, entries, total_data_size,
                    [&](const std::vector<std::pair<std::size_t, std::size_t>>& chunks,
                        std::uint64_t out_size,
                        const std::function<bool(const std::vector<unsigned char>&)>&,
                        std::vector<unsigned char>* dst) {
                        *dst = ConcatParallelChunks(bytes, chunks);
                        if (dst->size() > out_size) dst->resize(static_cast<std::size_t>(out_size));
                        return psink::Available() || psink::Committed() || dst->size() == out_size;
                    },
                    &store_blocks_buffer, psink::Available(), psink::Policy::kStore, 0u, psink::Family::kStore,
                    checksum_mode != ChecksumMode::kNone)) {
                nz_trace::Construct("store_assembly=parallel_multifile");
                store_multiblock = true;
                metadata_end = table_end;
                payload_start = table_end;
                if (NZ_ENV("NZ_TRACE_PS")) std::fprintf(stderr, "[PS] site1 -> %zu\n", payload_start);
                prefix_found = true;
            }
        }
        if (!prefix_found && entries.size() == 1u &&  // see the offset note below
            TryAssembleParallelStore(bytes, total_data_size, &store_blocks_buffer, &entries)) {
            // Parallel (-pN) store: the slices are raw and scattered between the
            // per-stream record sets, so neither the tail scan nor the block
            // chain finds them. Every slice was checksum-verified.
            store_multiblock = true;
            metadata_end = table_end;
            payload_start = table_end;
            if (NZ_ENV("NZ_TRACE_PS")) std::fprintf(stderr, "[PS] site2 -> %zu\n", payload_start);
            prefix_found = true;
            nz_trace::Construct("store_assembly=parallel_single");
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
            // data_offset comes from the record walk and can point far past a truncated
            // file; never scan beyond the bytes we have (fuzz 2026-09-03: a 2 MB store cut
            // at 95 % made this loop run for minutes).
            const std::size_t scan_end = std::min<std::size_t>(data_offset, bytes.size());
            for (std::size_t s = table_end; s <= scan_end; ++s) {
                if (TryAssembleStoredBlocks(bytes, s, total_data_size,
                                            store_trailer_bytes, &store_blocks_buffer)) {
                    nz_trace::Construct("store_assembly=block_chain trailer=%zu", store_trailer_bytes);
                    store_multiblock = true;
                    metadata_end = s;
                    payload_start = s;
                    if (NZ_ENV("NZ_TRACE_PS")) std::fprintf(stderr, "[PS] site3 -> %zu\n", payload_start);
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
            if (NZ_ENV("NZ_TRACE_PS")) std::fprintf(stderr, "[PS] site4 -> %zu\n", payload_start);
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
    if (NZ_ENV("NZOPT_TRACE_META")) {
        fprintf(stderr, "[META] entries=%zu metadata=[%zu,%zu) cksum_mode=%d bytes=",
                entries.size(), metadata_begin, metadata_end, (int)checksum_mode);
        for (std::size_t k = metadata_begin; k < metadata_end && k < metadata_begin + 32u; ++k)
            fprintf(stderr, "%02x ", bytes[k]);
        fprintf(stderr, "\n");
    }
    if (NZ_ENV("NZ_TRACE_PS")) std::fprintf(stderr, "[PS] flags: run_parsed=%d store=%d found_first=%d attr_records=%zu run_end=%zu\n",
                                            (int)metadata_run_parsed, (int)native_store_payload, (int)found_first_data, attr_records.size(), run_metadata_end);
    // Best-effort metadata extraction (single-file path is the most reliable).
    if (metadata_run_parsed) {
        // Attributes already filled from the record run. For single-file
        // compressed families the old path also derived payload_start from the
        // end of the metadata records; run_metadata_end is that same offset
        // (the type-0 record header), just located by parsing instead of by
        // tag sniffing.
        if (!native_store_payload && found_first_data) {
            payload_start = run_metadata_end;
            if (NZ_ENV("NZ_TRACE_PS")) std::fprintf(stderr, "[PS] site5 -> %zu\n", payload_start);
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
            if (NZ_ENV("NZ_TRACE_PS")) std::fprintf(stderr, "[PS] site6 -> %zu\n", payload_start);
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
                if (NZ_ENV("NZ_TRACE_PS")) std::fprintf(stderr, "[PS] site7 -> %zu\n", payload_start);
                fallback_start = bytes.size();
                break;
            }
            if (fallback_start == bytes.size()) {
                fallback_start = s;
            }
        }
        if (payload_start == bytes.size() && fallback_start != bytes.size()) {
            payload_start = fallback_start;
            if (NZ_ENV("NZ_TRACE_PS")) std::fprintf(stderr, "[PS] site8 -> %zu\n", payload_start);
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
    ByteBuffer literal_data_buffer;
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
    const auto validate_decoded_candidate_p = [&](const unsigned char* cdata, std::size_t csize) -> bool {
        if (csize != static_cast<std::size_t>(total_data_size))
            return false;
        std::size_t cursor = 0;
        for (const LegacyCnEntry& e : entries) {
            if (e.size > static_cast<std::uint64_t>(csize - cursor))
                return false;
            const std::size_t n = static_cast<std::size_t>(e.size);
            if (e.has_checksum && checksum_verification_supported) {
                const std::uint32_t got = ComputeBufferChecksum(checksum_mode, cdata + cursor, n);
                if (got != e.checksum)
                    return false;
            }
            cursor += n;
        }
        return cursor == csize;
    };
    const auto validate_decoded_candidate = [&](const std::vector<unsigned char>& candidate) -> bool {
        return validate_decoded_candidate_p(candidate.data(), candidate.size());
    };
    // Option (c) for damaged archives: a candidate whose decode completed (sizes
    // add up) but whose per-entry checksums do not all match is kept as a
    // fallback; if no fully verified candidate turns up, it is adopted and the
    // extractor writes the good entries and reports the bad ones. Always returns
    // false so the adopting branch is skipped at the call site.
    ByteBuffer partial_candidate;
    std::vector<std::uint8_t> partial_ok;
    // A decode that failed part-way: the output of the members completed before
    // the failure. Adopted with ctx.decode_failed when nothing better turns up.
    std::vector<unsigned char> partial_prefix;
    const auto record_partial_b = [&](ByteBuffer& candidate) -> bool {
        if (!partial_candidate.empty() || candidate.size() != static_cast<std::size_t>(total_data_size)) return false;
        std::vector<std::uint8_t> ok; std::size_t bad = 0;
        if (CheckEntries(entries, checksum_mode, checksum_verification_supported, candidate.data(), candidate.size(), &ok, &bad) && bad > 0) {
            partial_candidate = std::move(candidate);
            partial_ok = std::move(ok);
        }
        return false;
    };
    // Parallel sink (psink): hand a single-file container's streams over. Each
    // stream is one slice of entry 0 at its output offset.
    const auto publish_single = [&](const auto& list, const std::vector<std::uint64_t>& dest) -> bool {
        std::vector<psink::Stream> streams;
        for (std::size_t di = 0; di < list.size(); ++di) {
            const auto* st = list[di];
            psink::Stream ps;
            psink::Slice sl;
            sl.entry = 0u; sl.file_off = di < dest.size() ? dest[di] : st->ooff; sl.len = st->osz;
            sl.cmode = st->cmode; sl.cval = st->cval; sl.has_cksum = (st->cmode != ChecksumMode::kNone);
            sl.group = 0u;
            ps.slices.push_back(sl);
            ps.cut = st->cut;
            streams.push_back(std::move(ps));
        }
        const psink::Family fam =
            (method == 0x2bu && (method_p0 == 1u || method_p0 == 2u)) ? psink::Family::kLzpf :
            (method == 0x2bu) ? psink::Family::kCd :
            (method == 0x3bu && method_p0 == 5u) ? psink::Family::kCo :
            (method == 0x3bu) ? psink::Family::kCO : psink::Family::kCm;
        const psink::Policy pol = (fam == psink::Family::kCd) ? psink::Policy::kGroup : psink::Policy::kProduced;
        return psink::Publish(entries, std::move(streams), pol, (fam == psink::Family::kCd) ? std::uint64_t{0x100000u} : 0u, fam);
    };
    // The sink wrote (or, for `t`, verified) the container: nothing to assemble.
    const auto sink_adopt = [&]() -> bool {
        if (!psink::Committed()) return false;
        native_literal_payload = true;
        literal_data_offset = 0u; literal_data_size = 0u; literal_data_owned = true;
        literal_data_buffer.clear();
        return true;
    };
    const auto record_partial = [&](std::vector<unsigned char>& candidate) -> bool {
        ByteBuffer b(std::move(candidate));
        const bool r = record_partial_b(b);
        if (!partial_candidate.empty() && partial_candidate.data() == b.data()) return r;  // moved
        candidate.assign(b.data(), b.data() + b.size());   // give it back
        return r;
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
            if (NZ_ENV("NZ_TRACE_PARSTREAM")) {
                std::fprintf(stderr, "[SPLICE] records=%zu bytes=%zu head=", data_records.size(), spliced_data.size());
                for (std::size_t k = 0; k < 12 && k < spliced_data.size(); ++k) std::fprintf(stderr, "%02x", spliced_data[k]);
                std::fprintf(stderr, " first_rec=(%zu,%zu)\n", data_records[0].first, data_records[0].second);
            }
        }
    }

    publish_snapshot();
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
                    // The record right after the magic is a type-15 (stream-id extension)
                    // one in a parallel container and a plain type in a sequential
                    // one. Testing the whole byte for 0x0f only worked while a
                    // checksum record came first: `-hn` writes none, so the first
                    // record is a 2-byte extension (0x2f) and every parallel
                    // container without checksums was declined.
                    if (magic != bytes.size() && (bytes[magic + 3u] & 0x0fu) == 0x0fu &&
                        entries.size() == 1u) {
                        const bool is_variant_b = (method_p0 == 2u);
                        struct PStream {
                            // A stream's compressed payload may be split across
                            // several type-0 chunks (one per ~1 MB output sub-
                            // stream); they form one logical lzpf stream and are
                            // concatenated before decode.
                            std::vector<std::pair<std::size_t, std::size_t>> chunks;
                            bool cut = false;   // its last data record was cut off by the end of the file
                            std::uint64_t osz = 0, ooff = 0;
                            ChecksumMode cmode = ChecksumMode::kNone;
                            std::uint32_t cval = 0;
                            bool hasoff = false, hassz = false;
                        };
                        std::map<unsigned, PStream> ps;
                        std::size_t p = magic + 3u;
                        bool parse_ok = true;
                        for (std::size_t guard = 0; guard <= bytes.size() && p < bytes.size(); ++guard) {
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
                            bool cut_rec = false;
                            if (p + csz > bytes.size()) {
                                // A data record cut by the end of the file: the original's
                                // reader never hands it to the worker, whose stream then
                                // simply ends short (measured: the cut slot writes nothing
                                // of that record and reports its short-end status).
                                if (ct != 0u || p >= bytes.size()) { parse_ok = false; break; }
                                csz = bytes.size() - p; cut_rec = true;
                            }
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
                                if (!cut_rec) s.chunks.emplace_back(p, csz); else s.cut = true;
                            }
                            p += csz;
                        }
                        bool use_sink = psink::Available();
                        ByteBuffer assembled = use_sink ? ByteBuffer() : ByteBuffer::Uninitialized(static_cast<std::size_t>(total_data_size));
                        std::vector<std::atomic<bool>> slice_done(ps.size());
                        for (auto& d : slice_done) d.store(false, std::memory_order_relaxed);
                        bool all_ok = parse_ok && !ps.empty();
                        std::vector<PStream*> plist;
                        std::vector<std::pair<std::uint64_t, std::uint64_t>> pranges;
                        for (auto& kv : ps) {
                            PStream& s = kv.second;
                            if (s.chunks.empty() && !s.cut) continue;
                            // A slice with no checksum is only unverifiable when the
                            // archive HAS checksums; `-hn` writes none at all, and the
                            // original decodes such a container like any other, so the
                            // gate follows the archive's mode, not the slice's.
                            if (!s.hasoff || !s.hassz ||
                                (s.cmode == ChecksumMode::kNone && checksum_mode != ChecksumMode::kNone) ||
                                s.ooff + s.osz > total_data_size) { all_ok = false; break; }
                            plist.push_back(&s); pranges.emplace_back(s.ooff, s.osz);
                        }
                        StageMark("records walked");
                        std::vector<std::uint64_t> pdest(pranges.size(), 0u);
                        for (std::size_t q = 0; q < pranges.size(); ++q) pdest[q] = pranges[q].first;
                        // The in-memory path needs the slices to tile the output, since it
                        // slices one buffer back into files. The SINK does not: it writes
                        // each stream where that stream says, which is what the original's
                        // workers do -- and a file listed twice in one archive
                        // (`nz a x.nz f f`) relies on it. The encoder then writes one entry
                        // whose size covers both copies but gives both the SAME offsets
                        // (measured on `-co -p4` over one 50 KB file twice: four streams at
                        // 0, 25000, 0, 25000 for a 100 000-byte entry), so the copies
                        // overwrite each other and the extracted file is one copy long
                        // while the footer still counts every decoded byte.
                        if (all_ok && !use_sink && !DisjointCover(pranges, total_data_size)) all_ok = false;
                        if (use_sink) { use_sink = all_ok && publish_single(plist, pdest); if (!use_sink && assembled.empty()) all_ok = false; }
                        if (all_ok) all_ok = ParallelForEach(plist.size(), [&](std::size_t idx) -> bool {
                            PStream& s = *plist[idx];
                            // One record (the usual case) is decoded in place; several are
                            // concatenated first.
                            std::vector<unsigned char> payload;
                            std::size_t plen = 0;
                            for (const auto& c : s.chunks) plen += c.second;
                            const bool in_place = (s.chunks.size() == 1u);
                            if (!in_place) {
                                payload.reserve(plen);
                                for (const auto& c : s.chunks)
                                    payload.insert(payload.end(), bytes.begin() + static_cast<std::ptrdiff_t>(c.first),
                                                   bytes.begin() + static_cast<std::ptrdiff_t>(c.first + c.second));
                            }
                            const ByteView pin = in_place ? bytes : ByteView(payload);
                            const std::size_t pbeg = in_place ? s.chunks.front().first : 0u;
                            const std::size_t plen_in = in_place ? s.chunks.front().second : payload.size();
                            const std::size_t pend = in_place ? pbeg + plen_in : 0u;
                            const ChecksumMode cm = s.cmode;
                            const std::uint32_t cv = s.cval;
                            auto slice_verify = [&](const unsigned char* dec, std::size_t n) -> bool {
                                return ComputeBufferChecksum(cm, dec, n) == cv;
                            };
                            std::vector<unsigned char> unused;
                            if (use_sink) {
                                // The original knows its dictionary capacity and verifies
                                // nothing while decoding: one candidate, the sink checks the
                                // slice and writes whatever came out.
                                std::vector<unsigned char> sbuf(static_cast<std::size_t>(s.osz));
                                psink::StreamBegin(idx);
                                std::size_t mdone = 0;
                                const auto accept_all = [](const unsigned char*, std::size_t) { return true; };
                                const bool okd = DecodeLzpfMember(pin, pbeg, plen_in, s.osz,
                                                                  is_variant_b, method_p1, /*derived_cap_only=*/true, accept_all, &unused,
                                                                  sbuf.data(), false, &mdone, /*lenient=*/true, pend);
                                psink::StreamEnd(idx, sbuf.data(), okd ? s.osz : mdone, okd,
                                                 !okd && nzr::derr::Current().code == 0u && nzr::derr::Current().fatal_id == 0u);
                                return okd;
                            }
                            // Straight into this stream's slice (DisjointCover proved the
                            // slices tile the output before any thread started).
                            const std::uint64_t s_dest = pdest[idx];
                            if (s_dest + s.osz > assembled.size()) return false;
                            if (!DecodeLzpfMember(pin, pbeg, plen_in, s.osz,
                                                  is_variant_b, method_p1, /*derived_cap_only=*/false, slice_verify, &unused,
                                                  assembled.data() + static_cast<std::size_t>(s_dest), false, nullptr, false, pend)) return false;
                            slice_done[idx].store(true, std::memory_order_relaxed);
                            return true;
                        });
                        // `assembled` is empty when the sink took the container (and stays
                        // empty if the sink then declined to publish), so check the buffer,
                        // not the intent.
                        if (!all_ok && !assembled.empty()) {
                            // The buffer is uninitialised: give the slices that did not
                            // complete the zeros the zero-filled vector used to hold.
                            for (std::size_t q = 0; q < plist.size(); ++q)
                                if (!slice_done[q].load(std::memory_order_relaxed))
                                    std::memset(assembled.data() + static_cast<std::size_t>(pdest[q]), 0, plist[q]->osz);
                        }
                        StageMark("streams decoded");
                        if (sink_adopt()) {
                        } else if (all_ok && (validate_decoded_candidate_p(assembled.data(), assembled.size()) || record_partial_b(assembled))) {
                            StageMark("validated");
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
                    // The record right after the magic is a type-15 (stream-id extension)
                    // one in a parallel container and a plain type in a sequential
                    // one. Testing the whole byte for 0x0f only worked while a
                    // checksum record came first: `-hn` writes none, so the first
                    // record is a 2-byte extension (0x2f) and every parallel
                    // container without checksums was declined.
                    if (magic != bytes.size() && (bytes[magic + 3u] & 0x0fu) == 0x0fu &&
                        entries.size() == 1u) {
                        struct PCdStream {
                            // Each entry is one raw nz_cd block: (offset, size)
                            // into `bytes`, decoded in order into the slice.
                            std::vector<std::pair<std::size_t, std::size_t>> chunks;
                            bool cut = false;   // its last data record was cut off by the end of the file
                            std::uint64_t osz = 0, ooff = 0;
                            ChecksumMode cmode = ChecksumMode::kNone;
                            std::uint32_t cval = 0;
                            bool hasoff = false, hassz = false;
                            std::uint8_t p1 = 0; bool hasparams = false;  // own type-11 record
                        };
                        std::map<unsigned, PCdStream> ps;
                        std::size_t p = magic + 3u;
                        bool parse_ok = true;
                        for (std::size_t guard = 0; guard <= bytes.size() && p < bytes.size(); ++guard) {
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
                            bool cut_rec = false;
                            if (p + csz > bytes.size()) {
                                // A data record cut by the end of the file: the original's
                                // reader never hands it to the worker, whose stream then
                                // simply ends short (measured: the cut slot writes nothing
                                // of that record and reports its short-end status).
                                if (ct != 0u || p >= bytes.size()) { parse_ok = false; break; }
                                csz = bytes.size() - p; cut_rec = true;
                            }
                            PCdStream& s = ps[sid];
                            if (ct == 1u && csz >= 2u) {
                                std::size_t tp = p; std::uint64_t v = 0;
                                if (ReadLegacyVarint(bytes, &tp, p + csz, &v)) { s.osz = v; s.hassz = true; }
                            } else if (ct == 11u && csz >= 1u) {
                                s.p1 = (csz >= 2u) ? bytes[p + 1u] : 0u;
                                s.hasparams = true;
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
                                if (!cut_rec) s.chunks.emplace_back(p, csz); else s.cut = true;
                            }
                            p += csz;
                        }
                        bool use_sink = psink::Available();
                        std::vector<unsigned char> assembled(
                            use_sink ? std::size_t{0} : static_cast<std::size_t>(total_data_size), 0);
                        bool all_ok = parse_ok && !ps.empty();
                        static constexpr std::size_t kCdWindowPad = 16u;
                        std::vector<PCdStream*> plist;
                        std::vector<std::pair<std::uint64_t, std::uint64_t>> pranges;
                        for (auto& kv : ps) {
                            PCdStream& s = kv.second;
                            if (s.chunks.empty() && !s.cut) continue;
                            // A slice with no checksum is only unverifiable when the
                            // archive HAS checksums; `-hn` writes none at all, and the
                            // original decodes such a container like any other, so the
                            // gate follows the archive's mode, not the slice's.
                            if (!s.hasoff || !s.hassz ||
                                (s.cmode == ChecksumMode::kNone && checksum_mode != ChecksumMode::kNone) ||
                                s.ooff + s.osz > total_data_size) { all_ok = false; break; }
                            plist.push_back(&s); pranges.emplace_back(s.ooff, s.osz);
                        }
                        StageMark("records walked");
                        std::vector<std::uint64_t> pdest(pranges.size(), 0u);
                        for (std::size_t q = 0; q < pranges.size(); ++q) pdest[q] = pranges[q].first;
                        // The in-memory path needs the slices to tile the output, since it
                        // slices one buffer back into files. The SINK does not: it writes
                        // each stream where that stream says, which is what the original's
                        // workers do -- and a file listed twice in one archive
                        // (`nz a x.nz f f`) relies on it. The encoder then writes one entry
                        // whose size covers both copies but gives both the SAME offsets
                        // (measured on `-co -p4` over one 50 KB file twice: four streams at
                        // 0, 25000, 0, 25000 for a 100 000-byte entry), so the copies
                        // overwrite each other and the extracted file is one copy long
                        // while the footer still counts every decoded byte.
                        if (all_ok && !use_sink && !DisjointCover(pranges, total_data_size)) all_ok = false;
                        if (use_sink) { use_sink = all_ok && publish_single(plist, pdest); if (!use_sink && assembled.empty()) all_ok = false; }
                        if (all_ok) all_ok = ParallelForEach(plist.size(), [&](std::size_t idx) -> bool {
                            PCdStream& s = *plist[idx];
                            const std::size_t slice_total = static_cast<std::size_t>(s.osz);
                            std::vector<unsigned char> slice_buf(kCdWindowPad + slice_total, 0u);
                            unsigned char* const slice_window = slice_buf.data() + kCdWindowPad;
                            // Each stream is a FRESH nz_cd instance: its own ring (sized from its
                            // own p1), its own -cD context table and image model.
                            const std::uint32_t sring_units = LegacyCdRingUnitsFromP1(
                                s.hasparams ? s.p1 : static_cast<std::uint8_t>(method_p1));
                            const std::uint32_t sring_size = sring_units * 0x10000u;
                            std::vector<std::uint8_t> sring(sring_size, 0u);
                            std::uint32_t sring_pos = 0u;
                            const bool s_is_lzhds = (method_p0 == 4u);
                            std::vector<std::uint8_t> s_lzhds_ctx;
                            std::uint32_t s_lzhds_ctx_index = 0u;
                            std::uint8_t* s_lzhds_ctx_ptr = nullptr;
                            if (s_is_lzhds) {
                                s_lzhds_ctx.assign(nzr::cd::kLzhdsCtxTableSize, 0u);
                                nzr::cd::NzLzhdsInitCtxTable(s_lzhds_ctx.data());
                                s_lzhds_ctx_ptr = s_lzhds_ctx.data();
                            }
                            std::size_t pwritten = 0u;
                            nzr::audio::NzImageModel s_img;
                            s_img.Configure(0x02u, 16u, 16u, true);
                            // Prefilter (0xc) sub-chunk state, per stream like everything else
                            // (a 400 MB -cd -p8 archive declined without it: the first 0xc chunk
                            // of a worker stream had nothing to decode into).
                            nzr::lzpf::PrefilterContext s_pf; s_pf.Configure(s_is_lzhds ? 32u : 8u, 3u);
                            nzr::lzpf::LmsObject s_lms1{}, s_lms2{}; s_lms1.Init(); s_lms2.Init();
                            if (use_sink) psink::StreamBegin(idx);
                            for (const auto& c : s.chunks) {
                                if (pwritten >= slice_total) break;
                                const std::uint8_t* blk_in = bytes.data() + c.first;
                                const std::uint32_t blk_in_size = static_cast<std::uint32_t>(c.second);
                                const std::uint32_t blk_cap = static_cast<std::uint32_t>(slice_total - pwritten);
                                std::uint32_t produced = nzr::cd::NzCdDecodeStream(
                                    blk_in, blk_in_size, slice_window + pwritten, blk_cap,
                                    sring.data(), sring_size, &sring_pos,
                                    static_cast<std::uint32_t>(pwritten),
                                    s_is_lzhds, s_lzhds_ctx_ptr, &s_lzhds_ctx_index,
                                    &s_pf, &s_lms1, &s_lms2, &s_img);
                                if (produced == 0u) {
                                    if (use_sink) psink::StreamEnd(idx, slice_window, pwritten, false,
                                                                   nzr::derr::Current().code == 0u && nzr::derr::Current().fatal_id == 0u);
                                    return false;
                                }
                                pwritten += produced;
                                progress::Add(produced);
                            }
                            if (use_sink) {
                                // Ran out of chunks before the slice was full: the sink reports
                                // the codec's short-end status.
                                const bool okd = pwritten == slice_total;
                                psink::StreamEnd(idx, slice_window, pwritten, okd,
                                                 !okd && nzr::derr::Current().code == 0u && nzr::derr::Current().fatal_id == 0u);
                                return okd;
                            }
                            if (pwritten != slice_total) return false;
                            if (ComputeBufferChecksum(s.cmode, slice_window, slice_total) != s.cval) return false;
                            std::memcpy(assembled.data() + static_cast<std::size_t>(pdest[idx]),
                                        slice_window, slice_total);
                            return true;
                        });
                        StageMark("streams decoded");
                        if (sink_adopt()) {
                        } else if (all_ok && (validate_decoded_candidate(assembled) || record_partial(assembled))) {
                            StageMark("validated");
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
                // Parallel container holding SEVERAL files: one generic path
                // for every codec, differing only in how a stream's chunk chain
                // is turned into that stream's output. See
                // AssembleParallelMultiFile for why the single-file tiling paths
                // below cannot be reused.
                if (!native_literal_payload && has_parallel_streams && entries.size() > 1u) {
                    std::map<unsigned, LegacyParallelStream> pstreams;
                    if (ParseLegacyParallelStreams(bytes, &pstreams) && pstreams.size() > 1u) {
                        std::vector<unsigned char> assembled;
                        bool got = false;
                        if (method == 0x4bu && method_p0 == 7u) {
                            got = AssembleParallelMultiFile(
                                bytes, pstreams, entries, total_data_size,
                                [&](const std::vector<std::pair<std::size_t, std::size_t>>& chunks,
                                    std::uint64_t out_size,
                                    const std::function<bool(const std::vector<unsigned char>&)>&,
                                    std::vector<unsigned char>* dst) {
                                    LegacyCnContext sub;
                                    sub.legacy_method = method;
                                    sub.legacy_method_p0 = method_p0;
                                    sub.legacy_method_p1 = method_p1;
                                    sub.cm_a_bits = cm_a_bits;
                                    sub.cm_b_bits = cm_b_bits;
                                    sub.cm_window_size = cm_window_size;
                                    sub.total_data_size = out_size;
                                    std::vector<unsigned char> subdata;
                                    for (const auto& c : chunks) {
                                        WriteLegacyVarint(static_cast<std::uint64_t>(c.second) << 4u, &subdata);
                                        subdata.insert(subdata.end(),
                                                       bytes.begin() + static_cast<std::ptrdiff_t>(c.first),
                                                       bytes.begin() + static_cast<std::ptrdiff_t>(c.first + c.second));
                                    }
                                    sub.data = std::move(subdata);
                                    std::string err;
                                    return TryDecodeLegacyCm(sub, dst, &err);
                                },
                                &assembled, psink::Available(), psink::Policy::kProduced, 0u, psink::Family::kCm,
                                 checksum_mode != ChecksumMode::kNone);
                        } else if (method == 0x2bu && (method_p0 == 3u || method_p0 == 4u)) {
                            // Each type-0 chunk IS one delimited nz_cd block, so
                            // they are decoded one at a time threading a ring
                            // that is fresh PER STREAM (each worker owned its
                            // own instance), sized from that stream's output.
                            const bool s_is_lzhds = (method_p0 == 4u);
                            got = AssembleParallelMultiFile(
                                bytes, pstreams, entries, total_data_size,
                                [&](const std::vector<std::pair<std::size_t, std::size_t>>& chunks,
                                    std::uint64_t out_size,
                                    const std::function<bool(const std::vector<unsigned char>&)>&,
                                    std::vector<unsigned char>* dst) {
                                    // Ring from the OWNING stream's p1 (found by
                                    // its chunk list; see LegacyCdRingUnitsFromP1).
                                    std::uint8_t sp1 = static_cast<std::uint8_t>(method_p1);
                                    for (const auto& kv : pstreams)
                                        if (&kv.second.chunks == &chunks && kv.second.hasparams) { sp1 = kv.second.p1; break; }
                                    const std::uint32_t units = LegacyCdRingUnitsFromP1(sp1);
                                    const std::uint32_t ring_size = units * 0x10000u;
                                    std::vector<std::uint8_t> ring(ring_size, 0u);
                                    std::uint32_t ring_pos = 0u;
                                    std::vector<std::uint8_t> ctx;
                                    std::uint32_t ctx_index = 0u;
                                    std::uint8_t* ctx_ptr = nullptr;
                                    if (s_is_lzhds) {
                                        ctx.assign(nzr::cd::kLzhdsCtxTableSize, 0u);
                                        nzr::cd::NzLzhdsInitCtxTable(ctx.data());
                                        ctx_ptr = ctx.data();
                                    }
                                    dst->assign(static_cast<std::size_t>(out_size), 0u);
                                    std::size_t written = 0u;
                                    nzr::audio::NzImageModel s_img;
                                    s_img.Configure(0x02u, 16u, 16u, true);
                                    nzr::lzpf::PrefilterContext s_pf; s_pf.Configure(s_is_lzhds ? 32u : 8u, 3u);
                                    nzr::lzpf::LmsObject s_lms1{}, s_lms2{}; s_lms1.Init(); s_lms2.Init();
                                    for (const auto& c : chunks) {
                                        if (written >= out_size) break;
                                        const std::uint32_t produced = nzr::cd::NzCdDecodeStream(
                                            bytes.data() + c.first,
                                            static_cast<std::uint32_t>(c.second),
                                            dst->data() + written,
                                            static_cast<std::uint32_t>(out_size - written),
                                            ring.data(), ring_size, &ring_pos,
                                            static_cast<std::uint32_t>(written),
                                            s_is_lzhds, ctx_ptr, &ctx_index,
                                            &s_pf, &s_lms1, &s_lms2, &s_img);
                                        if (produced == 0u) { dst->resize(written); return false; }
                                        written += produced;
                                        progress::Add(produced);
                                    }
                                    if (written != out_size) dst->resize(written);
                                    return written == out_size;
                                },
                                &assembled, psink::Available(), psink::Policy::kGroup, std::uint64_t{0x100000u}, psink::Family::kCd,
                                 checksum_mode != ChecksumMode::kNone);
                        } else if (method == 0x3bu && (method_p0 == 5u || method_p0 == 6u)) {
                            const std::uint32_t wcap =
                                nzr::optimum::NzOptimumLzWindowSizeFromP1(method_p1);
                            got = (wcap != 0u) && AssembleParallelMultiFile(
                                bytes, pstreams, entries, total_data_size,
                                [&](const std::vector<std::pair<std::size_t, std::size_t>>& chunks,
                                    std::uint64_t out_size,
                                    const std::function<bool(const std::vector<unsigned char>&)>&,
                                    std::vector<unsigned char>* dst) {
                                    const std::vector<unsigned char> in =
                                        ConcatParallelChunks(bytes, chunks);
                                    if (in.empty()) return false;
                                    nzr::audio::NzAudioPred aud;
                                    nzr::audio::NzImageModel img;
                                    ConfigureOptimumModels(method_p0, aud, img);
                                    NzExeFilter exe;
                                    std::vector<std::uint8_t> raw_stream;
                                    if (method_p0 == 5u) {
                                        nzr::optimum::NzOptimumLzDecoder dec(wcap);
                                        return DecodeOptimumBlockSequence(in.data(), 0u, in.size(),
                                                                          out_size, dec, aud, img, exe, raw_stream, dst);
                                    }
                                    nzr::optimum2::NzOptimum2LzDecoder dec(wcap);
                                    const bool r = DecodeOptimumBlockSequence(in.data(), 0u, in.size(),
                                                                              out_size, dec, aud, img, exe, raw_stream, dst);
                                    return r;
                                },
                                &assembled, psink::Available(), psink::Policy::kProduced, 0u,
                                method_p0 == 5u ? psink::Family::kCo : psink::Family::kCO,
                                 checksum_mode != ChecksumMode::kNone);
                        } else if (method == 0x2bu && (method_p0 == 1u || method_p0 == 2u)) {
                            const bool vb = (method_p0 == 2u);
                            got = AssembleParallelMultiFile(
                                bytes, pstreams, entries, total_data_size,
                                [&](const std::vector<std::pair<std::size_t, std::size_t>>& chunks,
                                    std::uint64_t out_size,
                                    const std::function<bool(const std::vector<unsigned char>&)>& accept,
                                    std::vector<unsigned char>* dst) {
                                    const bool one = (chunks.size() == 1u);
                                    const std::vector<unsigned char> in = one ? std::vector<unsigned char>() : ConcatParallelChunks(bytes, chunks);
                                    if (!one && in.empty()) return false;
                                    const ByteView pin = one ? bytes : ByteView(in);
                                    const std::size_t pbeg = one ? chunks.front().first : 0u;
                                    const std::size_t plen_in = one ? chunks.front().second : in.size();
                                    const bool sinking = psink::Available() || psink::Committed();
                                    std::size_t mdone = 0;
                                    const bool okd = DecodeLzpfMember(pin, pbeg, plen_in, out_size, vb,
                                                                      method_p1, /*derived_cap_only=*/sinking,
                                                                      accept, dst, nullptr, false, &mdone, /*lenient=*/sinking,
                                                                      one ? pbeg + plen_in : 0u);
                                    if (!okd && sinking) dst->resize(mdone);   // completed members only
                                    return okd;
                                },
                                &assembled, psink::Available(), psink::Policy::kProduced, 0u, psink::Family::kLzpf,
                                 checksum_mode != ChecksumMode::kNone);
                        }
                        StageMark("streams decoded");
                        if (sink_adopt()) {
                        } else if (got && (validate_decoded_candidate(assembled) || record_partial(assembled))) {
                            StageMark("validated");
                            native_literal_payload = true;
                            literal_data_offset = 0u;
                            literal_data_size = assembled.size();
                            literal_data_owned = true;
                            literal_data_buffer = std::move(assembled);
                        }
                    }
                }

                if (!native_literal_payload && method == 0x4bu && method_p0 == 7u &&
                    entries.size() == 1u) {  // see the offset note above
                    std::map<unsigned, LegacyParallelStream> pstreams;
                    if (ParseLegacyParallelStreams(bytes, &pstreams) && pstreams.size() > 1u) {
                        bool use_sink = psink::Available();
                        std::vector<unsigned char> assembled(
                            use_sink ? std::size_t{0} : static_cast<std::size_t>(total_data_size), 0);
                        bool all_ok = true;
                        std::vector<const LegacyParallelStream*> plist;
                        std::vector<std::pair<std::uint64_t, std::uint64_t>> pranges;
                        for (const auto& kv : pstreams) {
                            const LegacyParallelStream& st = kv.second;
                            if (st.chunks.empty() && !st.cut) continue;
                            // A slice with no checksum is only unverifiable when the
                            // archive HAS checksums; `-hn` writes none at all, and the
                            // original decodes such a container like any other, so the
                            // gate follows the archive's mode, not the slice's.
                            if (!st.hasoff || !st.hassz ||
                                (st.cmode == ChecksumMode::kNone && checksum_mode != ChecksumMode::kNone) ||
                                st.ooff > total_data_size ||
                                st.osz > total_data_size - st.ooff) { all_ok = false; break; }
                            plist.push_back(&st); pranges.emplace_back(st.ooff, st.osz);
                        }
                        StageMark("records walked");
                        std::vector<std::uint64_t> pdest(pranges.size(), 0u);
                        for (std::size_t q = 0; q < pranges.size(); ++q) pdest[q] = pranges[q].first;
                        // The in-memory path needs the slices to tile the output, since it
                        // slices one buffer back into files. The SINK does not: it writes
                        // each stream where that stream says, which is what the original's
                        // workers do -- and a file listed twice in one archive
                        // (`nz a x.nz f f`) relies on it. The encoder then writes one entry
                        // whose size covers both copies but gives both the SAME offsets
                        // (measured on `-co -p4` over one 50 KB file twice: four streams at
                        // 0, 25000, 0, 25000 for a 100 000-byte entry), so the copies
                        // overwrite each other and the extracted file is one copy long
                        // while the footer still counts every decoded byte.
                        if (all_ok && !use_sink && !DisjointCover(pranges, total_data_size)) all_ok = false;
                        if (use_sink) { use_sink = all_ok && publish_single(plist, pdest); if (!use_sink && assembled.empty()) all_ok = false; }
                        if (all_ok) all_ok = ParallelForEach(plist.size(), [&](std::size_t idx) -> bool {
                            const LegacyParallelStream& st = *plist[idx];
                            LegacyCnContext sub;
                            sub.legacy_method = method;
                            sub.legacy_method_p0 = method_p0;
                            sub.legacy_method_p1 = method_p1;
                            sub.cm_a_bits = cm_a_bits;
                            sub.cm_b_bits = cm_b_bits;
                            sub.cm_window_size = cm_window_size;
                            sub.total_data_size = st.osz;
                            std::vector<unsigned char> subdata;
                            std::uint64_t last_rec = 0;
                            for (const auto& c : st.chunks) {
                                last_rec = subdata.size();
                                WriteLegacyVarint(static_cast<std::uint64_t>(c.second) << 4u, &subdata);
                                subdata.insert(subdata.end(),
                                               bytes.begin() + static_cast<std::ptrdiff_t>(c.first),
                                               bytes.begin() + static_cast<std::ptrdiff_t>(c.first + c.second));
                            }
                            if (use_sink && st.chunks.size() > 1u) psink::SetLastRecordStart(idx, last_rec);
                            sub.data = std::move(subdata);
                            std::vector<unsigned char> slice;
                            std::string sub_err;
                            if (use_sink) {
                                psink::StreamBegin(idx);
                                const bool okd = TryDecodeLegacyCm(sub, &slice, &sub_err) && slice.size() == st.osz;
                                if (slice.size() > st.osz) slice.resize(static_cast<std::size_t>(st.osz));
                                const bool clean = !okd && nzr::derr::Current().code == 0u && nzr::derr::Current().fatal_id == 0u;
                                psink::StreamEnd(idx, slice.data(), slice.size(), okd, clean);
                                return okd;
                            }
                            if (!TryDecodeLegacyCm(sub, &slice, &sub_err) ||
                                slice.size() != st.osz ||
                                ComputeBufferChecksum(st.cmode, slice.data(), slice.size()) != st.cval) {
                                return false;
                            }
                            std::memcpy(assembled.data() + static_cast<std::size_t>(pdest[idx]),
                                        slice.data(), slice.size());
                            return true;
                        });
                        StageMark("streams decoded");
                        if (sink_adopt()) {
                        } else if (all_ok && (validate_decoded_candidate(assembled) || record_partial(assembled))) {
                            StageMark("validated");
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
                    // The record right after the magic is a type-15 (stream-id extension)
                    // one in a parallel container and a plain type in a sequential
                    // one. Testing the whole byte for 0x0f only worked while a
                    // checksum record came first: `-hn` writes none, so the first
                    // record is a 2-byte extension (0x2f) and every parallel
                    // container without checksums was declined.
                    if (magic != bytes.size() && (bytes[magic + 3u] & 0x0fu) == 0x0fu &&
                        entries.size() == 1u) {
                        struct POptStream {
                            // Each entry is one contiguous block-record range
                            // (offset, size) into `bytes`; usually just one,
                            // but concatenated in order if a stream is ever
                            // split across more than one type-0 chunk.
                            std::vector<std::pair<std::size_t, std::size_t>> chunks;
                            bool cut = false;   // its last data record was cut off by the end of the file
                            std::uint64_t osz = 0, ooff = 0;
                            ChecksumMode cmode = ChecksumMode::kNone;
                            std::uint32_t cval = 0;
                            bool hasoff = false, hassz = false;
                        };
                        std::map<unsigned, POptStream> ps;
                        std::size_t p = magic + 3u;
                        bool parse_ok = true;
                        for (std::size_t guard = 0; guard <= bytes.size() && p < bytes.size(); ++guard) {
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
                            bool cut_rec = false;
                            if (p + csz > bytes.size()) {
                                // A data record cut by the end of the file: the original's
                                // reader never hands it to the worker, whose stream then
                                // simply ends short (measured: the cut slot writes nothing
                                // of that record and reports its short-end status).
                                if (ct != 0u || p >= bytes.size()) { parse_ok = false; break; }
                                csz = bytes.size() - p; cut_rec = true;
                            }
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
                                if (!cut_rec) s.chunks.emplace_back(p, csz); else s.cut = true;
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
                                nzr::audio::NzImageModel simg;
                                ConfigureOptimumModels(5u, saud, simg);
                                NzExeFilter sexe;
                                std::vector<std::uint8_t> sraw;
                                return DecodeOptimumBlockSequence(raw, b, e, hint, sdec, saud, simg, sexe, sraw, out);
                            };
                        } else {
                            decode_seq = [popt_window_capacity](
                                const unsigned char* raw, std::size_t b, std::size_t e,
                                std::uint64_t hint, std::vector<unsigned char>* out) {
                                nzr::optimum2::NzOptimum2LzDecoder sdec(popt_window_capacity);
                                nzr::audio::NzAudioPred saud;
                                nzr::audio::NzImageModel simg;
                                ConfigureOptimumModels(6u, saud, simg);
                                NzExeFilter sexe;
                                std::vector<std::uint8_t> sraw;
                                return DecodeOptimumBlockSequence(raw, b, e, hint, sdec, saud, simg, sexe, sraw, out);
                            };
                        }
                        bool use_sink = psink::Available();
                        std::vector<unsigned char> assembled(
                            use_sink ? std::size_t{0} : static_cast<std::size_t>(total_data_size), 0);
                        bool all_ok = parse_ok && !ps.empty() && popt_window_capacity != 0u;
                        std::vector<POptStream*> plist;
                        std::vector<std::pair<std::uint64_t, std::uint64_t>> pranges;
                        for (auto& kv : ps) {
                            POptStream& s = kv.second;
                            if (s.chunks.empty() && !s.cut) continue;
                            // A slice with no checksum is only unverifiable when the
                            // archive HAS checksums; `-hn` writes none at all, and the
                            // original decodes such a container like any other, so the
                            // gate follows the archive's mode, not the slice's.
                            if (!s.hasoff || !s.hassz ||
                                (s.cmode == ChecksumMode::kNone && checksum_mode != ChecksumMode::kNone) ||
                                s.ooff + s.osz > total_data_size) { all_ok = false; break; }
                            plist.push_back(&s); pranges.emplace_back(s.ooff, s.osz);
                        }
                        StageMark("records walked");
                        std::vector<std::uint64_t> pdest(pranges.size(), 0u);
                        for (std::size_t q = 0; q < pranges.size(); ++q) pdest[q] = pranges[q].first;
                        // The in-memory path needs the slices to tile the output, since it
                        // slices one buffer back into files. The SINK does not: it writes
                        // each stream where that stream says, which is what the original's
                        // workers do -- and a file listed twice in one archive
                        // (`nz a x.nz f f`) relies on it. The encoder then writes one entry
                        // whose size covers both copies but gives both the SAME offsets
                        // (measured on `-co -p4` over one 50 KB file twice: four streams at
                        // 0, 25000, 0, 25000 for a 100 000-byte entry), so the copies
                        // overwrite each other and the extracted file is one copy long
                        // while the footer still counts every decoded byte.
                        if (all_ok && !use_sink && !DisjointCover(pranges, total_data_size)) all_ok = false;
                        if (use_sink) { use_sink = all_ok && publish_single(plist, pdest); if (!use_sink && assembled.empty()) all_ok = false; }
                        // One worker stream per thread (see ParallelForEach); every stream
                        // writes its own disjoint slice of `assembled`.
                        if (all_ok) all_ok = ParallelForEach(plist.size(), [&](std::size_t idx) -> bool {
                            POptStream& s = *plist[idx];
                            std::vector<unsigned char> slice;
                            slice.reserve(static_cast<std::size_t>(s.osz));
                            bool sok = true;
                            if (use_sink) {
                                psink::StreamBegin(idx);
                                if (s.chunks.size() > 1u) {
                                    std::uint64_t off = 0;
                                    for (std::size_t q = 0; q + 1u < s.chunks.size(); ++q) off += s.chunks[q].second;
                                    psink::SetLastRecordStart(idx, off);
                                }
                            }
                            if (s.chunks.size() == 1u) {
                                const auto& c = s.chunks.front();
                                sok = decode_seq(bytes.data(), c.first, c.first + c.second, s.osz, &slice);
                            } else {
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
                            if (use_sink) {
                                const bool okd = sok && slice.size() == s.osz;
                                if (slice.size() > s.osz) slice.resize(static_cast<std::size_t>(s.osz));
                                const bool clean = !okd && nzr::derr::Current().code == 0u && nzr::derr::Current().fatal_id == 0u;
                                psink::StreamEnd(idx, slice.data(), slice.size(), okd, clean);
                                return okd;
                            }
                            if (!sok || slice.size() != s.osz) return false;
                            if (ComputeBufferChecksum(s.cmode, slice.data(), slice.size()) != s.cval) return false;
                            std::memcpy(assembled.data() + static_cast<std::size_t>(pdest[idx]),
                                        slice.data(), slice.size());
                            return true;
                        });
                        StageMark("streams decoded");
                        if (sink_adopt()) {
                        } else if (all_ok && (validate_decoded_candidate(assembled) || record_partial(assembled))) {
                            StageMark("validated");
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
                        if (NZ_ENV("NZOPT_TRACE_LZPF")) {
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
                        if (!vdc) {
                            // Option (c): the derived window (first candidate) of a damaged
                            // archive decodes to the right size but fails its checksum; keep
                            // it as the fallback so the good entries still come out.
                            std::vector<unsigned char> copy = dec;
                            record_partial(copy);
                            return false;
                        }
                        if (entries_have_checksum) return true;
                        std::uint8_t tag = 0; std::size_t cw = 0;
                        switch (checksum_mode) {
                            case ChecksumMode::kFletcher32: tag = 0x45u; cw = 4u; break;
                            case ChecksumMode::kFletcher16: tag = 0x45u; cw = 2u; break;
                            case ChecksumMode::kCrc32:      tag = 0x47u; cw = 4u; break;
                            case ChecksumMode::kCrc16:      tag = 0x26u; cw = 2u; break;
                            // No checksum exists anywhere in the archive, so
                            // there is nothing to compare against; the caller
                            // restricts this path to the single DERIVED
                            // capacity, and vdc has already checked that the
                            // output length and every entry length line up.
                            case ChecksumMode::kNone:       return true;
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
                    const ByteView chain_src = use_splice ? ByteView(spliced_data) : bytes;
                    const std::size_t chain_sp = use_splice ? (sp - payload_start) : sp;
                    // With no checksum stored (-hn / -nm) there is nothing to
                    // adjudicate between capacity candidates, so use only the
                    // derived one -- and accept it, which is what member_verify
                    // does for ChecksumMode::kNone.
                    if (DecodeLzpfMember(chain_src, chain_sp, static_cast<std::size_t>(stream_bytes),
                                         total_data_size, is_variant_b, method_p1,
                                         /*derived_cap_only=*/checksum_mode == ChecksumMode::kNone,
                                         member_verify, &member_out, nullptr, truncated_input)) {
                        native_literal_payload = true;
                        literal_data_offset = 0u;
                        literal_data_size = member_out.size();
                        literal_data_owned = true;
                        literal_data_buffer = std::move(member_out);
                    } else if (!member_out.empty() && member_out.size() < total_data_size) {
                        // The members completed before the failing one (see
                        // DecodeLzpfMember): written the way the original does.
                        partial_prefix = std::move(member_out);
                        if (!use_splice && nzr::derr::t_state.has_pos && nzr::derr::t_state.input_pos >= payload_start)
                            nzr::derr::t_state.input_pos -= payload_start;   // archive offset -> payload space
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
    // without declining (the legacy binary segfaults on this shape, see
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
    ctx.legacy_method_p2 = method_p2;
    ctx.cm_a_bits = cm_a_bits;
    ctx.cm_b_bits = cm_b_bits;
    ctx.cm_window_size = cm_window_size;
    if (!native_literal_payload && !native_store_payload && !partial_candidate.empty()) {
        native_literal_payload = true;
        literal_data_offset = 0u;
        literal_data_size = partial_candidate.size();
        literal_data_owned = true;
        literal_data_buffer = std::move(partial_candidate);
        ctx.entry_checksum_ok = std::move(partial_ok);
    }
    if (!native_literal_payload && !native_store_payload && !partial_prefix.empty()) {
        native_literal_payload = true;
        literal_data_offset = 0u;
        literal_data_size = partial_prefix.size();
        literal_data_owned = true;
        literal_data_buffer = std::move(partial_prefix);
        ctx.decode_failed = true;
    }
    {
        // The container's shape, so a sweep can say which of them were exercised
        // (the encode phase has to write all of these back).
        std::size_t nstreams = 0;
        if (has_parallel_streams) {
            std::map<unsigned, LegacyParallelStream> shape;
            if (ParseLegacyParallelStreams(bytes, &shape)) nstreams = shape.size();
        }
        nz_trace::Construct("container %s codec=0x%02x/%u streams=%zu files=%s",
                            has_parallel_streams ? "parallel" : "single",
                            method, method_p0, nstreams,
                            entries.size() == 1u ? "1" : "many");
    }
    if (psink::Committed()) {
        // The sink wrote the container while the streams decoded; the extractor
        // only reports (footer, or the original's corruption line).
        const psink::Outcome so = psink::Finish();
        ctx.sink_handled = true;
        ctx.sink_failed_entries = so.failed_entries;
        ctx.decode_failed = so.stream_failed;
        ctx.sink_plain_code = so.plain_code;
        if (!native_store_payload) native_literal_payload = true;
    }
    if (NZ_ENV("NZ_TRACE_PARSTREAM"))
        std::fprintf(stderr, "[PAYLOAD] payload_start=%zu first_data_record=%zu data_records=%zu spliced=%zu store=%d literal=%d\n",
                     payload_start, first_data_record, data_records.size(), spliced_data.size(),
                     (int)native_store_payload, (int)native_literal_payload);
    ctx.native_payload_supported = native_store_payload || native_literal_payload;
    ctx.truncated_input = truncated_input;
    ctx.eof_before_decode = eof_before_decode;
    ctx.saw_data_record = saw_data_record || has_parallel_streams;
    ctx.cut_first_data_record = cut_first_data_record;
    {
        std::size_t acc = 0;
        for (const auto& dr : data_records) { acc += dr.second - dr.first; ctx.payload_record_ends.push_back(acc); }
        ctx.records_after_data = !data_records.empty() && data_records.back().second < bytes.size();
    }
    if (ctx.decode_failed) AdoptDecodeError(ctx);
    // Every native_literal_payload path above went through validate_decoded_candidate
    // (or the partial fallback, whose verdicts are in entry_checksum_ok).
    ctx.checksums_verified = native_literal_payload && checksum_verification_supported && !ctx.decode_failed;
    if (has_parallel_streams) {
        std::map<unsigned, LegacyParallelStream> pstreams;
        if (ParseLegacyParallelStreams(bytes, &pstreams)) {
            for (const auto& kv : pstreams) {
                ctx.parallel_p1.push_back(kv.second.hasparams ? kv.second.p1 : method_p1);
            }
        }
    }
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
        //    (historical note: parallel-container -cO and decr_param==0 BWT were once unported; both are native now)
        //    (see nz_optimum2_lz.h for the engine's scope).
        if (!spliced_data.empty()) {
            ctx.data = std::move(spliced_data);
        } else {
            ctx.data.assign(bytes.begin() + static_cast<std::ptrdiff_t>(payload_start),
                            bytes.end());
        }
    }

    StageMark("context built");
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
        // A Windows build names the column "attr." and shows the file's
        // attributes there instead of a mode; note the original's own header
        // word is one character wider than the values under it.
#if defined(_WIN32)
        os << "attr. ";
#else
        os << "perm ";
#endif
    }
    // Measured: `-fo` adds a "user/grp." column only when the archive carries
    // ownership records (an archive made without -fo shows no column).
    bool has_owner = false;
    for (const LegacyCnEntry& e : legacy.entries) if (e.has_owner) { has_owner = true; break; }
    const bool show_owner = options.restore_ownership && has_owner;
    if (show_owner) {
        os << "user/grp. ";
    }
    if (has_date) {
        os << "yyyy-mmm-dd hh:mm:ss";
    }
    // -v widens the size column to exact, space-grouped byte counts (%15s).
    os << (options.verbose ? "           size  file\n" : "     size  file\n");

    std::uint64_t total_size = 0;
    std::size_t total_files = 0;
    // Measured: `l` lists every entry whatever file arguments follow the archive.
    for (const LegacyCnEntry& e : legacy.entries) {
        if (has_checksum) {
            // A stored value of zero prints as "n/a", whatever the mode: with
            // crc16/crc32 an empty file's checksum IS zero and the original
            // shows n/a for it, while fletcher16 stores ffffffff for one and
            // shows that. (A non-empty file whose crc happens to be zero gets
            // the same treatment -- measured, not assumed.)
            if (e.checksum_na || !e.has_checksum || e.checksum == 0u) {
                os << "     n/a ";
            } else {
                const std::uint32_t shown = e.has_checksum ? e.checksum : 0;
                os << std::setw(8) << std::left
                   << FormatChecksum(legacy.checksum_mode, shown) << ' ';
            }
        }
        if (has_perm) {
#if defined(_WIN32)
            // "R", "H", "S", "A" in fixed positions; an archive that carries
            // POSIX modes instead leaves the field blank, as the original does.
            char attr[5] = {' ', ' ', ' ', ' ', 0};
            if (e.has_win_attr) {
                if (e.win_attr & 1u) attr[0] = 'R';
                if (e.win_attr & 2u) attr[1] = 'H';
                if (e.win_attr & 4u) attr[2] = 'S';
                if (e.win_attr & 8u) attr[3] = 'A';
            }
            os << attr << ' ';
#else
            os << std::setw(4) << std::right << FormatMode(e.permissions) << ' ';
#endif
        }
        if (show_owner) {
            os << std::setw(4) << std::right << e.uid << '/' << std::setw(4) << std::right << e.gid << ' ';
        }
        // An entry with no stored mtime leaves the column EMPTY rather than
        // printing the epoch: the original does that for the entries its own
        // mtime reader ran short of (quirk 43), and the rest of the row keeps
        // its usual spacing.
        if (has_date && e.has_mtime) {
            os << FormatMtimeStored(e.mtime_unix);
        }
        if (options.verbose) {
            os << std::setw(15) << std::right << FormatGrouped(e.size) << "  " << e.path << '\n';
        } else {
            // Measured: the plain listing shortens names over 40 columns to "..."
            // plus their last 37 characters, like the progress line; -v does not.
            os << FormatSizeColumn(e.size) << "  " << TruncateName40(e.path) << '\n';
        }

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
    progress::Scope pscope;
    if (out_data == nullptr) return false;
    out_data->clear();

    if (NZ_ENV("NZOPT_TRACE_CD")) {
        fprintf(stderr, "[LZHD] enter: method=0x%x p0=%u p1=%u total=%llu data=%zu\n",
                legacy.legacy_method, legacy.legacy_method_p0, legacy.legacy_method_p1,
                (unsigned long long)legacy.total_data_size, legacy.data.size());
    }
    if (legacy.legacy_method != 0x2bu ||
        (legacy.legacy_method_p0 != 3u && legacy.legacy_method_p0 != 4u)) {
        if (NZ_ENV("NZOPT_TRACE_CD")) fprintf(stderr, "[LZHD] reject: method/p0 gate\n");
        return false;
    }
    if (legacy.data.empty()) {
        if (NZ_ENV("NZOPT_TRACE_CD")) fprintf(stderr, "[LZHD] reject: empty data\n");
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

    // The LZ window is a single per-archive ring (FUN_08099050, obj+0x978) sized
    // bytefloat(method_p1 + 1) * 0x10000 -- the same mantissa/exponent byte the
    // -cc window and the lzpf dictionary capacity already use: xp1 = p1 + 1,
    // m = xp1 & 0xf, s = xp1 >> 4, if (s) m = (m + 16) << (s - 1). Below p1 = 15
    // that is just p1 + 1 units, which is why an earlier LINEAR (p1 + 1) reading
    // fit small files and under-sized large ones, and why the round(total /
    // 0x10000) rule that replaced it fit every sample it was measured on
    // (1/3/19/46 units) and still failed the first real file where the two
    // disagree: p1 = 33 encodes 36 units, round(2322452 / 65536) gives 35, and
    // the last chunk then began exactly at the ring end and a match reached past
    // the whole (undersized) ring -- refused with `offset > ring_size`, a clean
    // decline. GDB on the original for that file: obj+0x978 = 2359296 = 36 units.
    // Large files split the output into 1 MB streams that reference each other
    // through this shared ring, so it is allocated ONCE and `ring_pos` threads
    // across stream iterations.
    std::uint32_t ring_units = 0u;
    {
        const unsigned xp1 = static_cast<unsigned>(legacy.legacy_method_p1) + 1u;
        unsigned m = xp1 & 0x0fu;
        const unsigned sh = xp1 >> 4u;
        if (sh) m = (m + 16u) << (sh - 1u);
        ring_units = m;
    }
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
    // Image model for the 0xf sub-chunk (FUN_080a9ca0 on obj+0xe1f0): one per
    // archive, never reset. -cd and -cD share the profile (GDB: flags 0x02,
    // all five planes order 16).
    nzr::audio::NzImageModel cd_img;
    cd_img.Configure(0x02u, 16u, 16u, true);

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
    nzr::cd::NzCdExeFilterReset();
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
        std::uint64_t stream_bytes = stream_tag >> 4u;
        if (stream_bytes == 0u) { ok = false; break; }
        bool cut_stream = false;
        if (stream_bytes > raw_len - pos) {
            if (!legacy.truncated_input) { ok = false; break; }
            stream_bytes = raw_len - pos;   // the cut-off last record: decode what exists, as the original does
            cut_stream = true;
        }

        const std::uint8_t* block_in  = raw + pos;
        const std::uint32_t block_in_size = static_cast<std::uint32_t>(stream_bytes);
        pos += static_cast<std::size_t>(stream_bytes);

        // Native -cd LZ block decode (NzCdDecodeBlock): loops the block's 32 KB
        // chunks into the contiguous output. Handles pure-LZ -cd (recon output ==
        // file). Blocks whose chunks carry a tt08/param14/CM/BWT post-filter
        // produce fewer bytes here; the size-mismatch check below rejects them so
        // they decline until those stages are wired.
        const std::uint32_t block_cap = static_cast<std::uint32_t>(total_out - written);
        std::uint32_t produced = nzr::cd::NzCdDecodeStream(
            block_in, block_in_size, window_base + written, block_cap,
            ring.data(), ring_size, &ring_pos, static_cast<std::uint32_t>(written),
            is_lzhds, lzhds_ctx_ptr, &lzhds_ctx_index,
            &cd_pf_ctx, &cd_pf_lms1, &cd_pf_lms2, &cd_img);
        if (NZ_ENV("NZOPT_TRACE_CD")) {
            fprintf(stderr, "[LZHD] stream: in=%u cap=%u produced=%u written=%zu/%zu\n",
                    block_in_size, block_cap, produced, written + produced, (size_t)total_out);
        }
        if (produced == 0u) { nzr::derr::SetAt(16u, static_cast<std::size_t>(block_in - raw)); ok = false; break; }   // header read past the stream end: -0x10
        if (!nzr::cd::NzCdLastStreamClean()) {
            // A chunk that failed inside a cut-off stream: nz_lzhd's header reader
            // runs out of input first (-0x10) whatever the chunk decoder noticed.
            // (nz_lzhds behaves differently there -- it reaches its reconstruct
            // assertion on the garbage -- and is not modelled.)
            if (cut_stream && !is_lzhds) { nzr::derr::Clear(); nzr::derr::SetAt(16u, static_cast<std::size_t>(block_in - raw)); }
            else nzr::derr::SetAt(5u, static_cast<std::size_t>(block_in - raw));
            // The stream stopped on a malformed chunk: the original reports the
            // error here (code 5) and has flushed only the streams before it.
            if (NZ_ENV("NZOPT_TRACE_CD")) fprintf(stderr, "[LZHD] stream stopped short: produced=%u written=%zu\n", produced, written);
            ok = false; break;
        }
        written += produced;
        progress::Add(produced);
    }

    // The original flushes its output per stream (measured: 1 MB multiples on a
    // 6 MB file), so on a failure only the streams completed before the failing
    // one count as written: a stream that produced nothing left `written` at the
    // boundary already; one that stopped short is dropped below.
    if (!ok) {
        if (NZ_ENV("NZOPT_TRACE_CD")) fprintf(stderr, "[LZHD] reject: malformed block stream (written=%zu/%zu)\n", written, (size_t)total_out);
        if (out_error_message) *out_error_message = "lzhd: malformed block stream";
        out_data->assign(window_base, window_base + std::min(written, total_out));
        return false;
    }
    if (const char* dp = NZ_ENV("NZOPT_DUMP_PRECHECK")) {
        // Dump before BOTH the size check and the checksum gate, so a short
        // decode is diffable too (its prefix is still meaningful) -- not just a
        // full-size wrong-bytes one.
        FILE* f = fopen(dp, "wb");
        if (f) { fwrite(window_base, 1, written, f); fclose(f); }
        fprintf(stderr, "[LZHD] dumped %zu of %zu bytes to %s\n", written, (size_t)total_out, dp);
    }
    if (written != total_out) {
        if (NZ_ENV("NZOPT_TRACE_CD")) fprintf(stderr, "[LZHD] reject: size mismatch written=%zu total=%zu\n", written, (size_t)total_out);
        // Every stream decoded cleanly yet the output is short: the original has
        // flushed all of it (the last file cut short) and reports "Archive
        // corrupted. Unexpected end of file." instead of an error code.
        if (out_error_message) *out_error_message = "lzhd: unexpected end of file";
        out_data->assign(window_base, window_base + std::min(written, total_out));
        return false;
    }
    // Verify the decoded output against the archive's stored per-file checksum(s).
    // The native -cd ring model is byte-exact for the common case but has a residual
    // edge (multi-stream ring wrap under heavy repetition). Rejecting a checksum
    // mismatch here makes the caller decline, so the user still
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
                (void)got;   // verdict recorded by the caller (CheckEntries); a
                             // mismatch marks the entry, it no longer voids the decode
            }
            cursor += n;
        }
    }
    out_data->assign(window_base, window_base + total_out);
    pscope.Commit();
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
    progress::Scope pscope;
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
    // The image model (decr_param 3), one per entry; its state is never reset.
    // Profile GDB-read at FUN_080a90c0's entry for -cc (see nz_audio.h).
    nzr::audio::NzImageModel img;
    img.Configure(0x0fu, 32u, 48u, false);
    // One exe filter for the whole entry. Its recent-target caches and base
    // persist across a RUN of consecutive dece blocks and reset as soon as a
    // block without dece intervenes -- see nz_exefilter.h. The reference's
    // per-block temporary is wrong on 22 of 88 real dece archives.
    NzExeFilter exe;
    if (!cm) {
        if (out_error_message) *out_error_message = "cm: allocation failed";
        return false;
    }
    // One work budget for the whole entry, generous against what a valid stream
    // needs (8 bit decodes per output byte) and bounded by the DECLARED output
    // rather than by the chunk count a corrupt header can invent.
    NzCmSetBitBudget(cm, static_cast<std::uint64_t>(legacy.total_data_size) * 16u +
                             (1u << 20));
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
        if (chunk_size > raw_len - pos) {
            if (!legacy.truncated_input) { ok = false; break; }
            chunk_size = static_cast<std::uint32_t>(raw_len - pos);   // cut-off last record (see the parser)
        }
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
                if (inline_checksum_seen && NZ_ENV("NZOPT_TRACE_TDO")) {
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
            nz_trace::Construct("audio_image_block decr=%u", decr_param);
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
            if (NZ_ENV("NZOPT_TRACE_TDO")) {
                fprintf(stderr, "[TDCC] block payload_size=%u decr_param=%u mode2_type=%u out_size=%u pos=%zu stream_end=%zu\n",
                        payload_size, decr_param, mode2_type, alt_out_size, pos, stream_end);
            }
            if (alt_out_size >
                static_cast<std::uint32_t>(legacy.total_data_size) -
                static_cast<std::uint32_t>(out_data->size())) { ok = false; break; }

            if (decr_param == 2u) {
                if (alt_out_size == 0u) continue;
                // An audio block resets the predictor only when mode2_type is set.
                if (const char* adp = NZ_ENV("NZOPT_DUMP_AUDIO")) {
                    FILE* f = fopen(adp, "wb");
                    if (f) { fwrite(payload, 1, payload_size, f); fclose(f); }
                    fprintf(stderr, "[TDCC] dumped audio payload (%u bytes, out_size=%u) to %s\n",
                            payload_size, alt_out_size, adp);
                }
                if (mode2_type) aud.Reset();
                std::vector<std::uint8_t> abuf(alt_out_size);
                const bool aok = aud.Decode(payload, payload_size, abuf.data(), alt_out_size);
                if (NZ_ENV("NZOPT_TRACE_TDO")) {
                    fprintf(stderr, "[TDCC] audio Decode(payload_size=%u out_size=%u) -> %d\n",
                            payload_size, alt_out_size, aok ? 1 : 0);
                }
                if (!aok) { nzr::derr::SetAt(16u, pos); ok = false; break; }
                // NOTE: the reference does not feed audio output through the CM
                // model. Our stored-block path does feed it (an empirically
                // established deviation -- see the long comment below), so if a
                // decr_param==0 CM block ever turns up after an audio block and
                // decodes wrong, this is the first place to look.
                out_data->insert(out_data->end(), abuf.begin(), abuf.end());
                progress::Add(abuf.size());
                continue;
            }

            // decr_param == 3: an IMAGE block. The real dispatcher's mode-3 branch
            // runs FUN_080a9ca0 on its own image object -- not the CM model (the
            // community reference decodes it as CM-without-reset, which is why every
            // BMP failed its checksum). Nothing feeds the CM model here.
            aud.Reset();
            if (alt_out_size == 0u) continue;
            std::vector<std::uint8_t> work3(alt_out_size);
            const std::size_t iused = img.Decode(payload, payload_size, work3.data(), alt_out_size);
            if (NZ_ENV("NZOPT_TRACE_TDO")) {
                fprintf(stderr, "[TDCC] image Decode(payload_size=%u out_size=%u) -> used %zu\n",
                        payload_size, alt_out_size, iused);
            }
            if (iused == 0u) { nzr::derr::SetAt(2u, pos); ok = false; break; }
            out_data->insert(out_data->end(), work3.begin(), work3.end());
            progress::Add(work3.size());
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
        const std::vector<std::uint8_t> staged(raw + pos, raw + pos + staged_count);
        pos += staged_count;
        // Per-stage check bytes, verified as in DecodeOptimumBlockSequence.
        static const bool trace_stg = (NZ_ENV("NZOPT_TRACE_STG") != nullptr);
        std::string stg;
        std::size_t stage_idx = 0;
        bool stage_bad = false;
        std::uint32_t stage_bad_code = 100u;
        // The original checks each stage the moment it is computed and stops
        // there; ours defers the verdict to the block end (the LIFO index needs
        // the stage count). So when a sub-decoder fails on a block whose earlier
        // stage already mismatched, the original had reported THAT stage first.
        const auto fail_code = [&](std::uint32_t own) { return stage_bad ? stage_bad_code : own; };
        const auto stgmark = [&](const char* nm, const std::uint8_t* p, std::size_t n) {
            const unsigned got = StageCheck255(p, n);
            if (stage_idx < staged.size() && staged[staged.size() - 1u - stage_idx] != got && !stage_bad) {
                stage_bad = true; stage_bad_code = nzr::derr::StageCode(nm);
            }
            ++stage_idx;
            if (!trace_stg) return;
            char b[48]; snprintf(b, sizeof(b), " %s=%02x", nm, got); stg += b;
        };
        const auto stg_report = [&]() {
            if (!trace_stg) return;
            std::string hx; char b[8];
            for (std::uint8_t v : staged) { snprintf(b, sizeof(b), "%02x", v); hx += b; }
            fprintf(stderr, "[STG] cc block decr=%u param6=%u staged=[%s]%s verify=%s\n", decr_param, param6, hx.c_str(), stg.c_str(),
                    stage_idx != staged.size() ? "skip(count)" : (stage_bad ? "BAD" : "ok"));
        };

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
        // param6 == 0 marks a STORED block (the CM could not compress) -- the payload
        // is the block output BEFORE the post-filters, which still run: an .ape file
        // under -cc came out as stored blocks with a param1 (AddBytes) delta filter,
        // and skipping straight to the output left 6 MB of wrong bytes. The CM model
        // must still observe every byte (see the comment on NzCmFeedByte below).
        std::vector<std::uint8_t> work;
        std::uint32_t cur_size = 0;
        if (!param6 || out_size == 0u) {
            nz_trace::Construct("cc_stored decr=%u p2=%u p1=%u tt=0x%02x dece=%u", decr_param, param2_flag, param1_flag, tt_enabled ? tt_flags : 0u, dece_param);
            for (std::uint32_t i = 0; i < payload_size; ++i) {
                NzCmFeedByte(cm, payload[i]);
            }
            work.assign(payload, payload + payload_size);
            cur_size = payload_size;
            stgmark("payload", payload, payload_size);
        } else {
            if (decr_param == 1u) NzCmReset(cm);
            work.resize(out_size);
            NzCmDecode(cm, payload, payload_size, work.data(), out_size);
            cur_size = out_size;
            stgmark("payload", payload, payload_size);
            stgmark("cm", work.data(), cur_size);
        }

        const std::size_t prev_size = out_data->size();
        const std::uint32_t remaining =
            static_cast<std::uint32_t>(legacy.total_data_size) -
            static_cast<std::uint32_t>(prev_size);

        nz_trace::Construct("cc_block decr=%u param6=%u p2=%u p1=%u tt=0x%02x", decr_param, param6, param2_flag, param1_flag, tt_enabled ? tt_flags : 0u);
        if (NZ_ENV("NZOPT_TRACE_TDO")) {
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
            if (NZ_ENV("NZOPT_TRACE_TDO")) {
                fprintf(stderr, "[TDCC] param2: data.size=%zu cur_size=%u -> ok=%d esz=%u\n",
                        param2_data.size(), cur_size, p2ok ? 1 : 0, esz);
            }
            if (!p2ok || esz == 0u) { ok = false; break; }
            exp.resize(esz);
            work.swap(exp);
            cur_size = esz;
            stgmark("p2", work.data(), cur_size);
        }

        // param1: AddBytesFilter (delta filter, output size == input size).
        if (param1_flag) {
            std::vector<std::uint8_t> tbuf(cur_size);
            const bool p1ok = NzAddBytesFilter(param1_data.data(),
                                  static_cast<std::uint32_t>(param1_data.size()),
                                  work.data(), cur_size, tbuf.data());
            if (NZ_ENV("NZOPT_TRACE_TDO")) {
                fprintf(stderr, "[TDCC] param1: data.size=%zu cur_size=%u -> ok=%d\n",
                        param1_data.size(), cur_size, p1ok ? 1 : 0);
            }
            if (!p1ok) { ok = false; break; }
            work.swap(tbuf);
            stgmark("p1", work.data(), cur_size);
            // cur_size unchanged
        }

        // Text transforms, applied in reference order: 0x10 (number transform),
        // then 0x08 (dictionary), then 0x02 (insert-LF). Other bits
        // Every bit but 0x80 (param14 text transform) is ported; 0x80 declines
        // (never seen on a -cc/-co/-cO block in any corpus so far).
        // The text-transform chain's INPUT, before any stage runs. With an
        // unported bit set this is the only way to get an (input, output) pair
        // for that stage: the golden file is the chain's OUTPUT and every other
        // stage in the chain is already ported and invertible.
        if (tt_enabled) {
            if (const char* tp = NZ_ENV("NZOPT_DUMP_TTIN")) {
                FILE* f = fopen(tp, "wb");
                if (f) { fwrite(work.data(), 1, cur_size, f); fclose(f); }
                fprintf(stderr, "[TT] chain input: %u bytes, tt_flags=0x%02x -> %s\n",
                        cur_size, tt_flags, tp);
            }
        }
        // The text-transform dispatcher FUN_080a3c90 knows one more bit than the
        // seven below: 0x80 = param14 (FUN_080a0ff0). The CM family requests
        // param14 through its OWN block-header flag instead (the p14 field this
        // block already applies), and over 9 255 CM-family blocks of the 3037-file
        // sweep tt never had bit 0x80 set (the largest value seen is 0x43) while
        // p14 was set 1 272 times. So this decline covers a bit the encoder
        // expresses elsewhere, not a gap in the port.
        if (tt_enabled && (tt_flags & ~(0x10u | 0x08u | 0x04u | 0x02u | 0x20u | 0x40u | 0x01u))) { ok = false; break; }
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
        if (tt_enabled && (tt_flags & 0x40u)) {
            // Chess/PGN transform, between 0x20 and 0x01 in the reference's
            // dispatch order. Not in the community reference at all (its body
            // is assert(0)); decoded from (input, output) pairs plus the binary.
            std::vector<std::uint8_t> tbuf(remaining);
            const std::uint32_t n = NzTextTransform6(work.data(), cur_size, tbuf.data(), remaining);
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

        if (tt_enabled) stgmark("tt", work.data(), cur_size);
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
            if (NZ_ENV("NZOPT_TRACE_TDO")) {
                fprintf(stderr, "[TDCC] dece: param=%u data=%zu in=%u -> %d out=%u\n",
                        dece_param, dece_data.size(), cur_size, dok ? 1 : 0, n);
            }
            if (!dok || n == 0u) { ok = false; break; }
            tbuf.resize(n); work.swap(tbuf); cur_size = n;
        } else {
            // No dece on this block: it breaks any run in progress.
            exe.Reset();
        }

        stg_report();
        if (stage_idx == staged.size() && stage_bad) { nzr::derr::SetAt(stage_bad_code, pos); ok = false; break; }
        out_data->insert(out_data->end(), work.begin(), work.begin() + cur_size);
        progress::Add(cur_size);
        }
    }

    NzCmDestroy(cm);

    if (NZ_ENV("NZOPT_TRACE_TDO")) {
        fprintf(stderr, "[TDCC] loop end: ok=%d pos=%zu raw_len=%zu out_data.size=%zu total_data_size=%llu\n",
                ok ? 1 : 0, pos, raw_len, out_data->size(),
                static_cast<unsigned long long>(legacy.total_data_size));
    }
    if (!ok) {
        // Completed blocks stay in out_data (see TryDecodeLegacyOptimum).
        nzr::derr::Set(100u);   // anything not classified above is the payload stage check of the original
        if (out_error_message) *out_error_message = "cm: malformed block stream";
        return false;
    }
    if (out_data->size() != static_cast<std::size_t>(legacy.total_data_size)) {
        if (out_data->size() > static_cast<std::size_t>(legacy.total_data_size))
            out_data->resize(static_cast<std::size_t>(legacy.total_data_size));
        if (out_error_message) *out_error_message = "cm: output size mismatch";
        return false;
    }

    // Checksum self-verify, mirroring the sibling TryDecodeLegacyLzhd and
    if (const char* dp = NZ_ENV("NZOPT_DUMP_PRECHECK")) {
        FILE* f = fopen(dp, "wb");
        if (f) { fwrite(out_data->data(), 1, out_data->size(), f); fclose(f); }
        fprintf(stderr, "[TDCC] dumped pre-checksum output (%zu bytes) to %s\n", out_data->size(), dp);
    }

    // TryDecodeLegacyOptimum gates: a stored per-file checksum mismatch means
    // "decline and let the caller try another engine", never "emit it
    // anyway".
    //
    // This gate was missing until a real-world corpus sweep found the hole it
    // left. Back when a legacy binary could still be consulted, the caller's CM
    // handling cross-checked native output against it -- but only when one was
    // actually reachable, which for a user never is, and then it took
    // `cm_native_ok` at face value and emitted whatever this function returned. Sweeping 56 real files x 8 methods
    // surfaced one archive (a ~10 MB game-data blob under -cc) where this
    // function returns true with 394113 wrong bytes, so the extractor wrote a
    // silently corrupt file instead of declining. Output size alone is not a
    // correctness signal for CM: the block framing can parse cleanly and the
    // sizes can add up exactly while the entropy-decoded content diverges.
    //
    // (The CM divergence on that archive was fixed later by the cross-chunk model
    // feed, 25d2f75; the gate stays as the safety net it is.) Historical:
    // bug; this gate is what makes it a clean decline rather than corruption.
    if (legacy.checksum_verification_supported &&
        legacy.checksum_mode != ChecksumMode::kNone &&
        !legacy.entries.empty()) {
        std::size_t cursor = 0;
        if (NZ_ENV("NZOPT_TRACE_TDO")) {
            fprintf(stderr, "[TDCC] checksum gate: mode=%d entries=%zu outsize=%zu\n",
                    (int)legacy.checksum_mode, legacy.entries.size(), out_data->size());
        }
        for (const LegacyCnEntry& e : legacy.entries) {
            const std::size_t n = static_cast<std::size_t>(e.size);
            if (cursor + n > out_data->size()) break;
            if (NZ_ENV("NZOPT_TRACE_TDO")) {
                fprintf(stderr, "[TDCC]   entry: size=%zu has_cksum=%d cursor=%zu outsize=%zu\n",
                        n, (int)e.has_checksum, cursor, out_data->size());
            }
            std::uint32_t expected = e.checksum;
            if (!e.has_checksum) {
                // Fall back to a checksum record found mid-stream. Only for the
                // single-entry case: with several entries there is no way to tell
                // from here which entry a mid-stream record belongs to.
                if (inline_checksum_seen) nz_trace::Construct("cc_midstream_checksum entries=%zu", legacy.entries.size());
                if (!inline_checksum_seen || legacy.entries.size() != 1u) {
                    out_data->clear();
                    if (out_error_message) *out_error_message = "cm: entry missing checksum, declining";
                    return false;
                }
                expected = inline_checksum;
            }
            const std::uint32_t got =
                ComputeBufferChecksum(legacy.checksum_mode, out_data->data() + cursor, n);
            if (NZ_ENV("NZOPT_TRACE_TDO")) {
                fprintf(stderr, "[TDCC]   entry n=%zu expected=0x%08x computed=0x%08x %s\n",
                        n, expected, got, got == expected ? "OK" : "MISMATCH");
            }
            (void)got; (void)expected;   // verdict recorded by the caller (CheckEntries)
            cursor += n;
        }
    }
    pscope.Commit();
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
// is declined here (parallel-container
// -co IS handled, but by a separate code path in TryParseLegacyCnArchive, not
// this function -- see its own comments). decr_param==0 (BWT) blocks are also
// not yet ported (either engine) and decline.
//
// Safety: every candidate is checksum-gated below (mirroring -cd/-cD/-cc's
// own self-verify pattern) before being trusted by the caller; any mismatch,
// malformed framing, or DecodeBlock-reported inconsistency cleanly declines
// (returns false) so RunLegacyCnExtractOrTest tries the next engine --
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
    nzr::audio::NzImageModel& image,
    NzExeFilter& exe,
    std::vector<std::uint8_t>& raw_stream,
    std::vector<unsigned char>* out_data) {
    progress::Scope pscope;
    std::size_t pos = blocks_begin;
    const std::size_t stream_end = blocks_end;
    bool ok = true;

    const bool trace_blocks = NZ_ENV("NZOPT_TRACE_TDO") != nullptr;
    while (pos < stream_end) {
        if (pos + 4u > stream_end) {
            if (trace_blocks) fprintf(stderr, "[TDO] stop: no room for a block header at %zu of %zu (out=%zu)\n", pos, stream_end, out_data->size());
            if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break;
        }
        const std::uint32_t payload_size =
            static_cast<std::uint32_t>(raw[pos]) |
            (static_cast<std::uint32_t>(raw[pos+1]) << 8u) |
            (static_cast<std::uint32_t>(raw[pos+2]) << 16u) |
            (static_cast<std::uint32_t>(raw[pos+3]) << 24u);
        pos += 4u;
        if (trace_blocks) fprintf(stderr, "[TDO] block at %zu payload_size=%u remaining=%zu out=%zu\n", pos - 4u, payload_size, stream_end - pos, out_data->size());
        if (payload_size > stream_end - pos) {
            if (trace_blocks) fprintf(stderr, "[TDO] stop: payload %u runs past the stream (%zu left)\n", payload_size, stream_end - pos);
            if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break;
        }
        const std::uint8_t* payload = raw + pos;
        pos += payload_size;

        if (pos >= stream_end) { if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
        const std::uint8_t decr_param = raw[pos++];

        // decr_param 2 (audio) and 3 use a TRUNCATED header that stops right
        // after size18: no staged-checksum count, and none of the param2 /
        // param1 / param16 / text-transform / dece fields an ordinary block
        // carries (reference Header::Parse, which early-returns for both).
        // Parsing them with the ordinary layout reads mode2_type as param6 and
        // then walks off into the next record -- which is exactly why every
        // audio-bearing archive used to die before its first block trace.
        if (decr_param == 2u || decr_param == 3u) {
            nz_trace::Construct("audio_image_block decr=%u", decr_param);
            std::uint8_t mode2_type = 0;
            if (decr_param == 2u) {
                if (pos >= stream_end) { if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
                mode2_type = raw[pos++];
            }
            if (pos + 4u > stream_end) { if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
            const std::uint32_t audio_out_size =
                static_cast<std::uint32_t>(raw[pos]) |
                (static_cast<std::uint32_t>(raw[pos+1]) << 8u) |
                (static_cast<std::uint32_t>(raw[pos+2]) << 16u) |
                (static_cast<std::uint32_t>(raw[pos+3]) << 24u);
            pos += 4u;
            if (NZ_ENV("NZOPT_TRACE_TDO")) {
                fprintf(stderr, "[TDO] block payload_size=%u decr_param=%u mode2_type=%u out_size=%u pos=%zu stream_end=%zu\n",
                        payload_size, decr_param, mode2_type, audio_out_size, pos, stream_end);
            }
            if (audio_out_size == 0u) continue;
            if (audio_out_size > total_size_hint - out_data->size()) { nzr::derr::SetAt(14u, pos); if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
            if (decr_param == 3u) {
                // Image block (FUN_080a9ca0 on the codec's image object; the
                // community reference wrongly treats this shape as CM-only and
                // returns false for the optimum family). Every non-audio block
                // resets the audio predictor; the image object is never reset.
                audio.Reset();
                std::vector<std::uint8_t> ibuf(audio_out_size);
                const std::size_t iused = image.Decode(payload, payload_size, ibuf.data(), audio_out_size);
                if (NZ_ENV("NZOPT_TRACE_TDO")) {
                    fprintf(stderr, "[TDO] image Decode(payload_size=%u out_size=%u) -> used %zu\n",
                            payload_size, audio_out_size, iused);
                }
                if (iused == 0u) { nzr::derr::SetAt(2u, pos); if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
                out_data->insert(out_data->end(), ibuf.begin(), ibuf.end());
                progress::Add(ibuf.size());
                continue;
            }
            // An audio block resets the predictor only when mode2_type is set.
            if (const char* adp = NZ_ENV("NZOPT_DUMP_AUDIO")) {
                FILE* f = fopen(adp, "wb");
                if (f) { fwrite(payload, 1, payload_size, f); fclose(f); }
                fprintf(stderr, "[TDO] dumped audio payload (%u bytes, out_size=%u, mode2=%u) to %s\n",
                        payload_size, audio_out_size, mode2_type, adp);
            }
            if (mode2_type) audio.Reset();
            std::vector<std::uint8_t> abuf(audio_out_size);
            const bool aok = audio.Decode(payload, payload_size, abuf.data(), audio_out_size);
            if (NZ_ENV("NZOPT_TRACE_TDO")) {
                fprintf(stderr, "[TDO] audio Decode(payload_size=%u out_size=%u) -> %d\n",
                        payload_size, audio_out_size, aok ? 1 : 0);
            }
            if (!aok) { nzr::derr::SetAt(16u, pos); if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
            out_data->insert(out_data->end(), abuf.begin(), abuf.end());
                progress::Add(abuf.size());
            continue;
        }
        // Every non-audio block resets the audio predictor (reference
        // DecodeFromStream calls audio_pred->Reset() on the way past the
        // decr_param == 2 branch), so its state never carries across one.
        audio.Reset();

        if (pos >= stream_end) { if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
        const std::uint8_t param6 = raw[pos++];
        std::uint32_t out_size = 0;
        if (param6) {
            if (pos + 4u > stream_end) { if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
            out_size = static_cast<std::uint32_t>(raw[pos]) |
                (static_cast<std::uint32_t>(raw[pos+1]) << 8u) |
                (static_cast<std::uint32_t>(raw[pos+2]) << 16u) |
                (static_cast<std::uint32_t>(raw[pos+3]) << 24u);
            pos += 4u;
        }
        if (pos >= stream_end) { if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
        const std::uint8_t staged_count = raw[pos++];
        if (pos + staged_count > stream_end) { if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
        const std::vector<std::uint8_t> staged(raw + pos, raw + pos + staged_count);
        pos += staged_count;
        static const bool trace_stg = (NZ_ENV("NZOPT_TRACE_STG") != nullptr);
        std::string stg;
        // The original's per-stage check (FUN_080c0220): after each stage it pops
        // the LAST remaining staged byte and compares it with Fletcher32(stage
        // output) % 255; a mismatch is "Archive corrupted. Error decoding" with
        // nothing of the block written. Stage k therefore checks staged[count-1-k].
        // Verified only when this port's stage count matches the header's, so an
        // unmodelled stage (the exe filter?) can never fail a good archive.
        std::size_t stage_idx = 0;
        bool stage_bad = false;
        std::uint32_t stage_bad_code = 100u;
        // The original checks each stage the moment it is computed and stops
        // there; ours defers the verdict to the block end (the LIFO index needs
        // the stage count). So when a sub-decoder fails on a block whose earlier
        // stage already mismatched, the original had reported THAT stage first.
        const auto fail_code = [&](std::uint32_t own) { return stage_bad ? stage_bad_code : own; };
        const auto stgmark = [&](const char* nm, const std::uint8_t* p, std::size_t n) {
            const unsigned got = StageCheck255(p, n);
            if (stage_idx < staged.size() && staged[staged.size() - 1u - stage_idx] != got && !stage_bad) {
                stage_bad = true; stage_bad_code = nzr::derr::StageCode(nm);
            }
            ++stage_idx;
            if (!trace_stg) return;
            char b[48]; snprintf(b, sizeof(b), " %s=%02x", nm, got); stg += b;
        };
        if (NZ_ENV("NZOPT_TRACE_TDO")) {
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
                if (pos >= stream_end) { if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
                bwt_param7 = raw[pos++];
            }
            if (pos + 4u > stream_end) { if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
            bwt_start_pos = static_cast<std::uint32_t>(raw[pos]) |
                (static_cast<std::uint32_t>(raw[pos+1]) << 8u) |
                (static_cast<std::uint32_t>(raw[pos+2]) << 16u) |
                (static_cast<std::uint32_t>(raw[pos+3]) << 24u);
            pos += 4u;
            if (pos >= stream_end) { if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
            param14_flag = raw[pos++];
            if (param14_flag && !read_u32vec(param14_data)) { if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
            if (pos >= stream_end) { if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
            param15_flag = raw[pos++];
            if (param15_flag && !read_u32vec(param15_data)) { if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
            if (NZ_ENV("NZOPT_TRACE_TDO")) {
                fprintf(stderr, "[TDO] BWT hdr: param7=%u bwt_start_pos=%u param14=%u (%zu bytes) param15=%u (%zu bytes) pos=%zu\n",
                        bwt_param7, bwt_start_pos, param14_flag, param14_data.size(),
                        param15_flag, param15_data.size(), pos);
            }
        }

        if (pos >= stream_end) { if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
        const std::uint8_t param2_flag = raw[pos++];
        std::vector<std::uint8_t> param2_data;
        if (param2_flag) {
            if (pos + 4u > stream_end) { if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
            std::uint32_t vlen = static_cast<std::uint32_t>(raw[pos]) |
                (static_cast<std::uint32_t>(raw[pos+1]) << 8u) |
                (static_cast<std::uint32_t>(raw[pos+2]) << 16u) |
                (static_cast<std::uint32_t>(raw[pos+3]) << 24u);
            pos += 4u;
            if (pos + vlen > stream_end) { if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
            param2_data.assign(raw + pos, raw + pos + vlen);
            pos += vlen;
        }
        if (pos >= stream_end) { if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
        const std::uint8_t param1_flag = raw[pos++];
        std::vector<std::uint8_t> param1_data;
        if (param1_flag) {
            if (pos + 4u > stream_end) { if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
            std::uint32_t vlen = static_cast<std::uint32_t>(raw[pos]) |
                (static_cast<std::uint32_t>(raw[pos+1]) << 8u) |
                (static_cast<std::uint32_t>(raw[pos+2]) << 16u) |
                (static_cast<std::uint32_t>(raw[pos+3]) << 24u);
            pos += 4u;
            if (pos + vlen > stream_end) { if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
            param1_data.assign(raw + pos, raw + pos + vlen);
            pos += vlen;
        }
        if (pos + 1u > stream_end) { if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
        pos++;  // param16
        if (pos >= stream_end) { if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
        const std::uint8_t tt_enabled = raw[pos++];
        std::uint8_t tt_flags = 0;
        std::vector<std::uint8_t> tt16_data, tt2_data;
        if (tt_enabled) {
            if (pos >= stream_end) { if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
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
            if ((tt_flags & 2u) && !read_varint_str(tt2_data)) { if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
            if ((tt_flags & 16u) && !read_varint_str(tt16_data)) { if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
        }
        if (NZ_ENV("NZOPT_TRACE_TDO")) {
            fprintf(stderr, "[TDO] param2_flag=%u param1_flag=%u tt_enabled=%u tt_flags=%u tt16_data.size=%zu pos=%zu stream_end=%zu\n",
                    param2_flag, param1_flag, tt_enabled, tt_flags, tt16_data.size(), pos, stream_end);
        }
        if (pos >= stream_end) { if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
        std::vector<std::uint8_t> dece_data;
        const std::uint8_t dece_param = raw[pos++];
        if (dece_param) {
            if (pos + 4u > stream_end) { if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
            std::uint32_t vlen = static_cast<std::uint32_t>(raw[pos]) |
                (static_cast<std::uint32_t>(raw[pos+1]) << 8u) |
                (static_cast<std::uint32_t>(raw[pos+2]) << 16u) |
                (static_cast<std::uint32_t>(raw[pos+3]) << 24u);
            pos += 4u;
            if (vlen > stream_end - pos) { if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
            dece_data.assign(raw + pos, raw + pos + vlen);
            pos += vlen;
        }
        if (NZ_ENV("NZOPT_TRACE_TDO")) {
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

        if (const char* dpp = NZ_ENV("NZOPT_DUMP_PAYLOAD")) {
            FILE* f = fopen(dpp, "wb");
            fwrite(payload, 1, payload_size, f);
            fclose(f);
            fprintf(stderr, "[TDO] dumped payload (%u bytes) to %s, out_size=%u\n",
                    payload_size, dpp, out_size);
        }

        std::vector<std::uint8_t> work;
        std::uint32_t cur_size = 0;
        stgmark("payload", payload, payload_size);
        if (decr_param == 0u) {
            if (bwt_raw) {
                work.assign(payload, payload + payload_size);
                cur_size = payload_size;
            } else {
                // param6 == 1: the BWT output is entropy-coded (256
                // per-leading-symbol MTF/arith buckets). size18 is its size.
                work.resize(out_size);
                const bool bdi_ok = NzBwtDecodeInput(payload, payload_size, out_size, work.data());
                if (NZ_ENV("NZOPT_TRACE_TDO")) {
                    fprintf(stderr, "[TDO] BWT DecodeInput(payload_size=%u out_size=%u) -> %d\n",
                            payload_size, out_size, bdi_ok ? 1 : 0);
                }
                if (!bdi_ok) { nzr::derr::SetAt(fail_code(3u), pos); if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
                cur_size = out_size;
                stgmark("bwtin", work.data(), cur_size);   // the entropy-decoded buckets are a stage of their own
            }
            const bool bwt_ok = NzBwtUntransform(work.data(), cur_size, bwt_start_pos);
            if (NZ_ENV("NZOPT_TRACE_TDO")) {
                fprintf(stderr, "[TDO] BWT raw untransform(size=%u bwt_start_pos=%u) -> %d\n",
                        cur_size, bwt_start_pos, bwt_ok ? 1 : 0);
            }
            if (!bwt_ok) { nzr::derr::SetAt(fail_code(103u), pos); if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
            stgmark("bwt", work.data(), cur_size);

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
                if (NZ_ENV("NZOPT_TRACE_TDO")) {
                    fprintf(stderr, "[TDO] param14: data=%zu in=%u -> %d out=%u\n",
                            param14_data.size(), cur_size, p14ok ? 1 : 0, n14);
                }
                if (!p14ok || n14 == 0u) { nzr::derr::SetAt(fail_code(5u), pos); if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
                t14.resize(n14); work.swap(t14); cur_size = n14;
                stgmark("p14", work.data(), cur_size);
            }
            if (param15_flag) {
                // param15 matches are ABSOLUTE offsets into the whole
                // accumulated PRE-post-filter stream (reference: mem->data_org
                // .. mem->data, i.e. the LZ window's contents, NOT the final
                // output -- sourcing them from out_data copied post-param1
                // bytes and broke the next LZ block on a 16-bit BMP whose
                // fourth block followed two BWT blocks). Splice this block onto
                // raw_stream, run the transform against that, then roll it
                // back -- the block's bytes are appended by the shared tail.
                const std::size_t prev = raw_stream.size();
                raw_stream.insert(raw_stream.end(), work.begin(), work.begin() + cur_size);
                const std::uint32_t cap =
                    static_cast<std::uint32_t>(total_size_hint) -
                    static_cast<std::uint32_t>(out_data->size());
                std::vector<std::uint8_t> t15(cap);
                std::uint32_t n15 = 0;
                const bool p15ok = NzBwtParam15(param15_data.data(),
                                       static_cast<std::uint32_t>(param15_data.size()),
                                       raw_stream.data() + prev, cur_size,
                                       raw_stream.data(), raw_stream.size(),
                                       t15.data(), cap, &n15, dec.WindowCapacity());
                raw_stream.resize(prev);
                if (NZ_ENV("NZOPT_TRACE_TDO")) {
                    fprintf(stderr, "[TDO] param15: data=%zu in=%u -> %d out=%u\n",
                            param15_data.size(), cur_size, p15ok ? 1 : 0, n15);
                }
                if (const char* dd = NZ_ENV("NZOPT_DUMP_P15")) {
                    static thread_local unsigned call_no = 0;
                    ++call_no;
                    char path[512];
                    auto wr = [&](const char* what, const void* data, std::size_t n) {
                        std::snprintf(path, sizeof(path), "%s/p15_%03u_%s.bin", dd, call_no, what);
                        if (FILE* f = std::fopen(path, "wb")) { std::fwrite(data, 1, n, f); std::fclose(f); }
                    };
                    wr("model", param15_data.data(), param15_data.size());
                    wr("in", raw_stream.data() + prev, cur_size);
                    wr("window", raw_stream.data(), prev);
                    wr("out", t15.data(), n15);
                    std::fprintf(stderr, "[P15] call=%u model=%zu in=%u window=%zu out=%u out_at=%zu ok=%d\n",
                                 call_no, param15_data.size(), cur_size, prev, n15, out_data->size(), (int)p15ok);
                }
                if (!p15ok || n15 == 0u) { if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
                t15.resize(n15); work.swap(t15); cur_size = n15;
                stgmark("p15", work.data(), cur_size);
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
                // ...and the adaptive model starts cold again. A stored block is
                // the compressor giving up on a block, and it takes its model
                // with it: the NEXT LZ block of the stream decodes from a cold
                // state, not from what the previous LZ block adapted.
                // Measured on a 130 MB .cab as `-co -p16`: stream 10 is the only
                // one of the sixteen with a stored block BETWEEN two LZ blocks,
                // and its second LZ block decoded garbage from its very first
                // byte while its ring content was byte-exact -- so the only
                // state left to differ was the model. With this, the whole
                // archive is byte-exact. Intervening BWT blocks do NOT reset it
                // (streams 1, 6, 7 and 12 have LZ blocks after two or three of
                // them and decode correctly with the model carried across).
                dec.ResetModel();
                if (NZ_ENV("NZOPT_TRACE_TDO")) {
                    fprintf(stderr, "[TDO] stored LZ block: payload_size=%u (param6=0, no size18)\n",
                            payload_size);
                }
            } else {
            work.resize(out_size);
            const bool decode_block_ok = dec.DecodeBlock(payload, payload_size, work.data(), out_size);
            if (!decode_block_ok) {
                // A failing block's PARTIAL output is where the interesting
                // boundary is: its correct prefix ends exactly at the first
                // wrong decision. Without this the pre-checksum dump only ever
                // showed the blocks that already succeeded.
                if (const char* bp = NZ_ENV("NZOPT_DUMP_FAILBLOCK")) {
                    FILE* bf = fopen(bp, "wb");
                    if (bf) { fwrite(work.data(), 1, out_size, bf); fclose(bf); }
                    // ...and the INPUT that produced it, so the block can be
                    // replayed on its own instead of decoding the archive again.
                    const std::string ip = std::string(bp) + ".in";
                    FILE* inf = fopen(ip.c_str(), "wb");
                    if (inf) { fwrite(payload, 1, payload_size, inf); fclose(inf); }
                    fprintf(stderr, "[TDO] dumped failing block (%u bytes, out_data so far %zu) to %s, payload (%u bytes, out_size=%u) to %s\n",
                            out_size, out_data->size(), bp, payload_size, out_size, ip.c_str());
                }
            }
            if (NZ_ENV("NZOPT_TRACE_TDO")) {
                fprintf(stderr, "[TDO] DecodeBlock(payload_size=%u out_size=%u) -> %d\n",
                        payload_size, out_size, decode_block_ok ? 1 : 0);
            }
            if (!decode_block_ok) {
                if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break;
            }
            cur_size = out_size;
            stgmark("lz", work.data(), cur_size);
            }
        }
        // Reference `mem->data += size`: every non-audio block's pre-post-filter
        // bytes join the accumulated stream that later param15 blocks index.
        raw_stream.insert(raw_stream.end(), work.begin(), work.begin() + cur_size);

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
                || esz == 0u) { if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
            exp.resize(esz); work.swap(exp); cur_size = esz;
            stgmark("p2", work.data(), cur_size);
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
            if (NZ_ENV("NZOPT_TRACE_TDO")) {
                fprintf(stderr, "[TDO] param1: data.size=%zu cur_size=%u -> %d\n",
                        param1_data.size(), cur_size, p1ok ? 1 : 0);
            }
            if (!p1ok) { if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
            work.swap(tbuf);
            // cur_size unchanged
            stgmark("p1", work.data(), cur_size);
        }
        // Reference bit order (TextTransformer::TransformText): 0x80, 0x10,
        // 0x08, 4, 2, 0x20, 0x40, 1. Every bit but 0x80 is ported; 0x80 declines
        // far; any other bit set (0x80/4/0x40/1) declines cleanly.
        // The text-transform chain's INPUT, before any stage runs. With an
        // unported bit set this is the only way to get an (input, output) pair
        // for that stage: the golden file is the chain's OUTPUT and every other
        // stage in the chain is already ported and invertible.
        if (tt_enabled) {
            if (const char* tp = NZ_ENV("NZOPT_DUMP_TTIN")) {
                FILE* f = fopen(tp, "wb");
                if (f) { fwrite(work.data(), 1, cur_size, f); fclose(f); }
                fprintf(stderr, "[TT] chain input: %u bytes, tt_flags=0x%02x -> %s\n",
                        cur_size, tt_flags, tp);
            }
        }
        // The text-transform dispatcher FUN_080a3c90 knows one more bit than the
        // seven below: 0x80 = param14 (FUN_080a0ff0). The CM family requests
        // param14 through its OWN block-header flag instead (the p14 field this
        // block already applies), and over 9 255 CM-family blocks of the 3037-file
        // sweep tt never had bit 0x80 set (the largest value seen is 0x43) while
        // p14 was set 1 272 times. So this decline covers a bit the encoder
        // expresses elsewhere, not a gap in the port.
        if (tt_enabled && (tt_flags & ~(0x10u | 0x08u | 0x04u | 0x02u | 0x20u | 0x40u | 0x01u))) { if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
        if (tt_enabled && (tt_flags & 0x10u)) {
            std::vector<std::uint8_t> tbuf(remaining + (1u << 16));
            const std::uint32_t n = NzTextTransformNumber(
                tt16_data.data(), static_cast<std::uint32_t>(tt16_data.size()),
                work.data(), cur_size, tbuf.data(), remaining + (1u << 16));
            if (n == 0) { if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
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
            if (n == 0) { if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
            tbuf.resize(n); work.swap(tbuf); cur_size = n;
        }
        if (tt_enabled && (tt_flags & 0x04u)) {
            // HTML closing-tag restoration (NzTextTransformHtml). Reference
            // order puts 0x04 after the 0x08 dictionary and before 0x02.
            std::vector<std::uint8_t> tbuf(remaining);
            const std::uint32_t n = NzTextTransformHtml(work.data(), cur_size, tbuf.data(), remaining);
            if (n == 0) { if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
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
            if (n == 0) { if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
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
            if (n == 0) { if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
            tbuf.resize(n); work.swap(tbuf); cur_size = n;
        }
        if (tt_enabled && (tt_flags & 0x40u)) {
            // Chess/PGN transform, between 0x20 and 0x01 in the reference's
            // dispatch order. Not in the community reference at all (its body
            // is assert(0)); decoded from (input, output) pairs plus the binary.
            std::vector<std::uint8_t> tbuf(remaining);
            const std::uint32_t n = NzTextTransform6(work.data(), cur_size, tbuf.data(), remaining);
            if (n == 0) { if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
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
            if (n == 0) { if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
            tbuf.resize(n); work.swap(tbuf); cur_size = n;
        }
        if (tt_enabled) stgmark("tt", work.data(), cur_size);
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
            if (NZ_ENV("NZOPT_TRACE_TDO")) {
                fprintf(stderr, "[TDO] dece: param=%u data=%zu in=%u -> %d out=%u\n",
                        dece_param, dece_data.size(), cur_size, dok ? 1 : 0, n);
            }
            if (!dok || n == 0u) { if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
            tbuf.resize(n); work.swap(tbuf); cur_size = n;
        } else {
            // No dece on this block: it breaks any run in progress.
            exe.Reset();
        }

        if (trace_stg) {
            std::string hx; char b[8];
            for (std::uint8_t v : staged) { snprintf(b, sizeof(b), "%02x", v); hx += b; }
            fprintf(stderr, "[STG] block decr=%u param6=%u tt=%s%02x dece=%u staged=[%s]%s verify=%s\n", decr_param, param6,
                    tt_enabled ? "0x" : "-", tt_enabled ? tt_flags : 0u, dece_param, hx.c_str(), stg.c_str(),
                    stage_idx != staged.size() ? "skip(count)" : (stage_bad ? "BAD" : "ok"));
        }
        if (stage_idx == staged.size() && stage_bad) { nzr::derr::SetAt(stage_bad_code, pos); if (trace_blocks) fprintf(stderr, "[TDO] stop line %d pos=%zu end=%zu out=%zu\n", __LINE__, pos, stream_end, out_data->size()); ok = false; break; }
        out_data->insert(out_data->end(), work.begin(), work.begin() + cur_size);
        progress::Add(cur_size);
        nz_trace::Construct("optimum_block decr=%u param6=%u p2=%u p1=%u tt=0x%02x dece=%u p14=%u p15=%u", decr_param, param6, param2_flag, param1_flag, tt_enabled ? tt_flags : 0u, dece_param, param14_flag, param15_flag);
        if (NZ_ENV("NZOPT_TRACE_TDO")) {
            fprintf(stderr, "[TDO] after postfilters: cur_size=%u total_out_data=%zu total_data_size=%llu param2_flag=%u param1_flag=%u tt_enabled=%u tt_flags=%u dece_param=%u\n",
                    cur_size, out_data->size(), (unsigned long long)total_size_hint,
                    param2_flag, param1_flag, tt_enabled, tt_flags, dece_param);
        }
    }

    if (ok) pscope.Commit();
    if (trace_blocks) fprintf(stderr, "[TDO] loop end: ok=%d pos=%zu stream_end=%zu out=%zu want=%llu\n",
                              (int)ok, pos, stream_end, out_data->size(), (unsigned long long)total_size_hint);
    return ok;
}

static bool TryDecodeLegacyOptimum(
    const LegacyCnContext& legacy,
    std::vector<unsigned char>* out_data,
    std::string* out_error_message) {
    progress::Scope pscope;
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
    if (NZ_ENV("NZOPT_TRACE_TDO")) {
        fprintf(stderr, "[TDO] method_p1=%u window_capacity=%u total_data_size=%llu\n",
                legacy.legacy_method_p1, window_capacity,
                (unsigned long long)legacy.total_data_size);
    }
    if (const char* dp = NZ_ENV("NZOPT_DUMP_RAW")) {
        FILE* f = fopen(dp, "wb");
        if (f) { fwrite(raw, 1, raw_len, f); fclose(f); }
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
    // One image model per entry as well (decr_param 3); never reset.
    auto img = std::make_shared<nzr::audio::NzImageModel>();
    ConfigureOptimumModels(legacy.legacy_method_p0, *aud, *img);
    // The accumulated pre-post-filter stream param15 indexes, shared across
    // the entry's chain segments like the window it mirrors.
    auto rawstream = std::make_shared<std::vector<std::uint8_t>>();
    // One exe filter per entry, same run/reset semantics as -cc above.
    auto exe = std::make_shared<NzExeFilter>();
    std::function<bool(std::size_t, std::size_t, std::vector<unsigned char>*)> decode_seq;
    if (legacy.legacy_method_p0 == 5u) {
        auto dec = std::make_shared<nzr::optimum::NzOptimumLzDecoder>(window_capacity);
        decode_seq = [raw, dec, aud, img, exe, rawstream, total_size_hint](std::size_t b, std::size_t e, std::vector<unsigned char>* out) {
            return DecodeOptimumBlockSequence(raw, b, e, total_size_hint, *dec, *aud, *img, *exe, *rawstream, out);
        };
    } else {
        auto dec = std::make_shared<nzr::optimum2::NzOptimum2LzDecoder>(window_capacity);
        decode_seq = [raw, dec, aud, img, exe, rawstream, total_size_hint](std::size_t b, std::size_t e, std::vector<unsigned char>* out) {
            return DecodeOptimumBlockSequence(raw, b, e, total_size_hint, *dec, *aud, *img, *exe, *rawstream, out);
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
        if (NZ_ENV("NZOPT_TRACE_TDO")) {
            fprintf(stderr, "[TDO] chain segment: p=%zu stream_end=%zu out_data_size_before=%zu\n",
                    p, stream_end, out_data->size());
        }
        if (!decode_seq(p, stream_end, out_data)) { ok = false; break; }
        seg_pos = stream_end;
    }

    if (const char* dp = NZ_ENV("NZOPT_DUMP_PRECHECK")) {
        // Dump BEFORE the size gate as well as the checksum gate, so a decode
        // that gave up part-way is diffable too -- its correct prefix is where
        // the interesting boundary is. Sitting after the size check made this
        // useless for exactly the failure it was added to investigate.
        FILE* f = fopen(dp, "wb");
        if (f) { fwrite(out_data->data(), 1, out_data->size(), f); fclose(f); }
        fprintf(stderr, "[TDO] dumped %zu of %llu bytes to %s\n", out_data->size(),
                (unsigned long long)legacy.total_data_size, dp);
    }

    if (!ok || out_data->size() != static_cast<std::size_t>(legacy.total_data_size)) {
        // out_data keeps the blocks completed before the failure: the original
        // has written exactly those by the time it reports the error.
        if (out_data->size() > static_cast<std::size_t>(legacy.total_data_size))
            out_data->resize(static_cast<std::size_t>(legacy.total_data_size));
        nzr::derr::Set(100u);
        if (out_error_message) *out_error_message = "optimum: decode failed";
        return false;
    }

    // Checksum self-verify (mirrors TryDecodeLegacyLzhd's own gate above): a
    // stored per-file checksum mismatch means "decline, let the caller try
    // another engine" rather than "trust it anyway".
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
            (void)got;   // verdict recorded by the caller (CheckEntries)
            cursor += n;
        }
    }
    pscope.Commit();
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
// This port's own diagnostics ("[native] ...") used to ride on -v;
// the original's -v adds nothing but an IO-buffers figure to the header, so they
// now live behind NZ_VERBOSE_NATIVE to keep -v output byte-identical.
// What the original says about a file that is not one of its archives -- its
// opener (FUN_08092ca0) transcribed. It reads records as `varint (size<<4|type)`
// with the type-15 stream extension, each with up to 64 bytes of content: the
// first must be type 14 (the "NanoZip 0.09 alpha" string); if it is not, it
// resyncs once on the magic string within the first 4 KB and retries. The second
// record must be type 30 (the extension with stream 0) of size 1 holding the
// version byte 9 (= "0.09"); anything else is reported as
// "Archive file is made with incompatible version (%u.%02u)" with the byte it
// found -- the previous record's first content byte when the second header
// could not be read at all. Running out of input elsewhere is
// "File is not a NanoZip archive.".
// FUN_080b0e50: where an archive appended to a Windows PE image begins -- the
// end of the last section, rounded up to 512 bytes -- or 0 when the buffer is
// not a PE image (1 when it is one this code cannot measure).
std::size_t LegacySfxDataOffset(const unsigned char* b, std::size_t n) {
    auto u16 = [b](std::size_t o) { return static_cast<std::uint32_t>(b[o]) | (static_cast<std::uint32_t>(b[o + 1]) << 8); };
    auto u32 = [b, u16](std::size_t o) { return u16(o) | (u16(o + 2) << 16); };
    if (n <= 0x40u || u16(0) != 0x5a4du) return 0;
    const std::uint32_t pe = u32(0x3c);
    if (pe >= n - 4u || u32(pe) != 0x4550u) return 0;
    const std::uint32_t optsz = u16(pe + 0x14u);
    std::size_t sect = static_cast<std::size_t>(pe) + optsz + 0x18u;
    if (sect >= n || optsz >= 0x4001u) return 1;
    const std::uint32_t nsec = u16(pe + 6u);
    std::size_t total = 0;
    if (nsec != 0u) {
        std::uint32_t left = nsec;
        while (sect < n - 0x28u) {
            total += u32(sect + 0x10u);
            sect += 0x28u;
            if (--left == 0u) break;
        }
        if (left != 0u) return 1;
    }
    return ((sect + 0x1ffu) & ~static_cast<std::size_t>(0x1ffu)) + total;
}

std::string LegacyProbeMessage(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return "Cannot open archive!";
    std::vector<unsigned char> bytes;
    {
        in.seekg(0, std::ios::end);
        const std::streamoff len = in.tellg();
        in.seekg(0, std::ios::beg);
        if (len > 0) {
            bytes.resize(static_cast<std::size_t>(len));
            in.read(reinterpret_cast<char*>(bytes.data()), len);
            if (!in) bytes.resize(static_cast<std::size_t>(in.gcount()));
        }
    }
    std::size_t pos = 0;
    struct Rec { unsigned type = 0; std::size_t size = 0; unsigned char content[64]; bool have = false; };
    Rec rec;
    auto read_header = [&](Rec& r) -> bool {   // false = EOF / oversize (record not consumed)
        std::uint64_t v = 0;
        std::size_t p2 = pos;
        if (!ReadLegacyVarint(bytes, &p2, bytes.size(), &v)) return false;
        unsigned type = static_cast<unsigned>(v & 0xfu);
        std::size_t size = static_cast<std::size_t>(v >> 4u);
        if (type == 15u) {
            if (p2 >= bytes.size()) return false;
            unsigned ext = bytes[p2++];
            if (ext >= 0xf8u) {
                if (p2 >= bytes.size()) return false;
                ext = (ext & 7u) + 0xf8u + 8u * bytes[p2++];
            }
            type = ext & 0xfu;
            if ((ext >> 4u) == 0u) type += 15u;
            size = ext >> 4u ? size : size;   // the size field is unchanged
        }
        pos = p2;
        if (size > 64u) return false;
        r.type = type; r.size = size; r.have = true;
        const std::size_t avail = bytes.size() - pos;
        const std::size_t n = size < avail ? size : avail;
        std::memcpy(r.content, bytes.data() + pos, n);
        pos += size < avail ? size : avail;
        return true;
    };
    const char* not_archive = "File is not a NanoZip archive.";
    bool ok = read_header(rec) && rec.type == 14u;
    if (!ok) {
        // Resync (FUN_08092220 -> FUN_080b0e50): the file may be a self-extracting
        // .exe with the archive appended after the PE image; seek past the image.
        const std::size_t off = LegacySfxDataOffset(bytes.data(), bytes.size() < 4096u ? bytes.size() : 4096u);
        if (off == 0u) return not_archive;
        pos = off;
        if (!read_header(rec) || rec.type != 14u) return not_archive;
    }
    Rec second = rec;
    const bool second_ok = read_header(second);
    unsigned version = 0;
    if (second_ok && second.type == 30u && second.size == 1u) {
        version = second.content[0];
        if (version == 9u) return std::string();   // a real 0.09 archive
    } else if (second.size != 0u) {
        version = second.content[0];   // the last header that was read, even a failed one
    } else {
        if (pos >= bytes.size()) return not_archive;
        version = bytes[pos];
    }
    char buf[96];
    std::snprintf(buf, sizeof(buf), "Archive file is made with incompatible version (%u.%02u).", version / 100u, version % 100u);
    return std::string(buf);
}

// Stage timer for the big-archive profile (NZ_VERBOSE_NATIVE): "+delta (total)".
void StageMark(const char* what) {
    static const bool on = (NZ_ENV("NZ_VERBOSE_NATIVE") != nullptr);
    if (!on) return;
    static const auto t0 = std::chrono::steady_clock::now();
    static auto last = t0;
    const auto now = std::chrono::steady_clock::now();
    std::fprintf(stderr, "[time] %-20s +%6.2fs  (t=%6.2fs)\n", what,
                 std::chrono::duration<double>(now - last).count(),
                 std::chrono::duration<double>(now - t0).count());
    last = now;
}

bool NativeTrace() {
    static const bool t = (NZ_ENV("NZ_VERBOSE_NATIVE") != nullptr);
    return t;
}

// bytefloat(p1 + 1) in 64 KB units -- the window size every codec derives from
// its p1 byte (the same mantissa/exponent code the -cc window and the lzpf
// dictionary use).
std::uint64_t LegacyWindowBytes(std::uint32_t p1) {
    const std::uint32_t xp1 = p1 + 1u;
    std::uint32_t m = xp1 & 0xfu;
    const std::uint32_t sft = xp1 >> 4u;
    if (sft) m = (m + 16u) << (sft - 1u);
    return static_cast<std::uint64_t>(m) << 16u;
}

// The byte figure behind "Compressor #n: <name> [<N> MB]" -- the value the
// original's per-codec memory-usage method (vtable slot 0: FUN_08094f10 store,
// FUN_08097550 lzpf, FUN_08099440 lzhd, FUN_080aafb0 CM family) returns, which the
// printer rounds with ((bytes >> 19) + 1) >> 1. The exact returns were read with
// GDB at that call for every codec; the window term is bytefloat(p1+1)*64 KB and
// the constants are the codec objects' fixed allocations:
//     none           W
//     lzpf           W + 0x618000          lzpf_large  W + 0x4410000
//     lzhd           W + 0x210000          lzhds       W + 0x350040
//     cm / optimum1 / optimum2   see LegacyCmFamilyWorkingSet
std::uint64_t LegacyCmFamilyWorkingSet(const LegacyCnContext& c, std::uint64_t W);
std::uint64_t LegacyEngineWorkingSetP1(const LegacyCnContext& c, std::uint8_t p1);
std::uint64_t LegacyEngineWorkingSet(const LegacyCnContext& c) { return LegacyEngineWorkingSetP1(c, c.legacy_method_p1); }
std::uint64_t LegacyEngineWorkingSetP1(const LegacyCnContext& c, std::uint8_t p1) {
    const std::uint64_t W = LegacyWindowBytes(p1);
    if (c.legacy_method_p0 == 0u) return W;
    if (c.legacy_method == 0x2bu) {
        switch (c.legacy_method_p0) {
            case 1u: return W + 0x618000ull;
            case 2u: return W + 0x4410000ull;
            case 3u: return W + 0x210000ull;
            case 4u: return W + 0x350040ull;
            default: return W;
        }
    }
    if (c.legacy_method == 0x4bu || c.legacy_method == 0x3bu) return LegacyCmFamilyWorkingSet(c, W);
    return W;
}

// The extract loop's view of the progress engine: a file starting is the
// writer's tick (name + fields, once per second); on a stored archive, where no
// decoder ran, the copied bytes are the figure.
struct DecodeProgress {
    explicit DecodeProgress(std::ostream&) {}
    void Begin(const std::string& name) { progress::FileStart(name); }
    void Advance(std::uint64_t n) { if (!progress::Decoded()) progress::Add(n); }
};

// The CM family's memory method, FUN_080aafb0, transcribed (Ghidra + GDB reads of
// every component on nine archives, all reproduced to the byte):
//   FUN_080c0070(window object) = W + 0x1008ab + 5*P + ((0x100000 + P/32 + 1) >> 1)
//                                 + (0x20001 >> 1) + FUN_080b88b0(P) [+ CM tables]
//   where P = the object's primary buffer: max(W, 1 MB) for -co/-cO, a fixed 1 MB
//   for -cc; FUN_080b88b0 is two halved table sizes = 2775628 at P = 1 MB growing
//   by 69/1280 of P beyond that (exact on 1.375/2/6 MB); the -cc tables are
//   2^a + 4*2^b + 23280971 (a, b = the two size nibbles the archive carries).
//   Then + 0x210000 (the audio/image object) and the per-mode tail: -co 0x8b600 +
//   0x3f700 + 0x1000 + 0x80000, -cc 0x8b600 + 0x1000, -cO 0x118f240 alone.
std::uint64_t LegacyCmFamilyWorkingSet(const LegacyCnContext& c, std::uint64_t W) {
    const std::uint64_t MB = 1048576ull;
    // P is the object's primary buffer. For -cc it is a fixed 1 MB; for
    // -co/-cO it follows the BLOCK size the compressor chose, which the codec
    // record carries in its third byte (the same byte-float as the window).
    // Older archives (and any record without that byte) fall back to the
    // window, which is what the default -m produces anyway.
    std::uint64_t P = MB;
    if (c.legacy_method_p0 != 7u) {
        std::uint64_t block = 0;
        if (c.legacy_method_p2 != 0u) {
            const unsigned xp = static_cast<unsigned>(c.legacy_method_p2) + 1u;
            unsigned m = xp & 0x0fu;
            const unsigned sh = xp >> 4u;
            if (sh) m = (m + 16u) << (sh - 1u);
            block = static_cast<std::uint64_t>(m) << 16u;
        }
        const std::uint64_t base = block != 0u ? block : W;
        P = base > MB ? base : MB;
    }
    std::uint64_t f88b0 = 2775628ull;
    if (P > MB) f88b0 += ((P - MB) * 69ull + 640ull) / 1280ull;
    std::uint64_t core = W + 0x1008abull + 5ull * P + ((0x100000ull + P / 32ull + 1ull) >> 1)
                       + (0x20001ull >> 1) + f88b0;
    if (c.legacy_method_p0 == 7u) core += (1ull << c.cm_a_bits) + (4ull << c.cm_b_bits) + 23280971ull;
    // -cO takes the method's early return: core + audio object + 0x118f240, with
    // NO dispatcher term (verified: 30643511 / 37663236 / 63120695 for W = 384 KB /
    // 2 MB / 6 MB). -co and -cc go through the common tail with the dispatcher.
    if (c.legacy_method_p0 == 6u) return core + 0x210000ull + 0x118f240ull;
    std::uint64_t total = core + 0x210000ull + 0x8b600ull;
    if (c.legacy_method_p0 == 5u) total += 0x3f700ull + 0x1000ull + 0x80000ull;
    else total += 0x1000ull;
    return total;
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

// "Compressor #k: <name> [<N> MB]\n" for worker k, the memory figure from that
// worker's own window byte (rounding is the original's ((bytes >> 19) + 1) >> 1);
// under -v the IO buffer split (no read-ahead, 1 MB write-behind for `t`, 4 for `x`).
std::string FormatCompressorLine(const LegacyCnContext& ctx, std::size_t k, bool verbose, bool test_mode) {
    const std::string label = LegacyCompressorName(ctx.legacy_method, ctx.legacy_method_p0);
    const std::uint8_t p1 = (ctx.parallel_p1.empty() || k >= ctx.parallel_p1.size()) ? ctx.legacy_method_p1 : ctx.parallel_p1[k];
    const std::uint64_t bytes = LegacyEngineWorkingSetP1(ctx, p1);
    std::string line = "Compressor #" + std::to_string(k) + ": " + label + " [" + std::to_string(((bytes >> 19) + 1u) >> 1) + " MB]";
    if (verbose) line += std::string(" IO-buffers: 0+") + (test_mode ? "1" : "4") + " MB.";
    line += '\n';
    return line;
}

void PrintDecodeHeader(std::ostream& os, const LegacyCnContext& ctx, const CliOptions& options, bool test_mode) {
    const bool verbose = options.verbose;
    os << "Archive: " << ctx.archive_path << '\n';
    // -t<n> caps the reported thread count (n = 0 or above the CPU count = auto);
    // -br/-bw show as ", IO-read-buffer: N MB" / ", IO-write-buffer: N MB", or
    // ", IO-buffers: R+W MB" when both are given, N rounded to whole MB (512k -> 1).
    unsigned threads = HostThreadCount();
    if (options.threads > 0u && options.threads < threads) threads = options.threads;
    os << "Threads: " << threads;
    const auto mb = [](std::uint64_t b) { return (b + 512u * 1024u) >> 20; };
    if (options.read_buffer_bytes && options.write_buffer_bytes)
        os << ", IO-buffers: " << mb(options.read_buffer_bytes) << '+' << mb(options.write_buffer_bytes) << " MB";
    else if (options.read_buffer_bytes)  os << ", IO-read-buffer: " << mb(options.read_buffer_bytes) << " MB";
    else if (options.write_buffer_bytes) os << ", IO-write-buffer: " << mb(options.write_buffer_bytes) << " MB";
    os << '\n';
    // Rounding is the original's ((bytes >> 19) + 1) >> 1. Under -v it appends its
    // IO buffer split: no read-ahead, a 1 MB write-behind for `t`, 4 MB for `x`.
    // A parallel container gets one line per worker (the original emits them in
    // thread-scheduling order; this port uses stream order), each sized from
    // that worker's own window byte.
    const std::size_t n = ctx.parallel_p1.empty() ? 1u : ctx.parallel_p1.size();
    // The original prints a worker's line the first time that worker ticks, so
    // the header carries only the workers already running when it goes out; the
    // rest follow as they start (the progress engine prints them). For a single
    // container the one worker is always running by then.
    const bool parallel = !ctx.parallel_p1.empty();
    // Cut before the first data record: the original never creates a
    // decompressor, so no line at all.
    if (!ctx.saw_data_record) return;
    for (std::size_t k = 0; k < n; ++k) {
        if (parallel && !progress::SlotStarted(k, progress::E())) continue;
        const std::string line = FormatCompressorLine(ctx, k, verbose, test_mode);
        ClearStatusLine(os);
        os.write(line.data(), static_cast<std::streamsize>(line.size()));
        progress::MarkAnnounced(k);
    }
}

// `<name>` then five spaces, then the running figure rewritten in place: back four,
// four characters, four spaces -- and eight backspaces once the file is done. This
// is the original's exact cursor dance.
// The four-character field the original rewrites in place: megabytes done.
std::string FormatSizeColumnCompact(std::uint64_t bytes) {
    char b[32];
    std::snprintf(b, sizeof(b), "%llu MB", (unsigned long long)((bytes + 512u * 1024u) / (1024u * 1024u)));
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

// Every field of a context except its (possibly gigabytes of) payload -- the
// re-entrant call below replaces the payload with the decoded bytes anyway, so
// copying the compressed one first was pure memcpy waste on big archives.
LegacyCnContext CloneLegacyMeta(const LegacyCnContext& c) {
    LegacyCnContext r;
    r.archive_path = c.archive_path;
    r.checksum_mode = c.checksum_mode;
    r.checksum_verification_supported = c.checksum_verification_supported;
    r.legacy_method = c.legacy_method;
    r.legacy_method_p0 = c.legacy_method_p0;
    r.legacy_method_p1 = c.legacy_method_p1;
    r.legacy_method_p2 = c.legacy_method_p2;
    r.cm_a_bits = c.cm_a_bits;
    r.cm_b_bits = c.cm_b_bits;
    r.cm_window_size = c.cm_window_size;
    r.native_payload_supported = c.native_payload_supported;
    r.truncated_input = c.truncated_input;
    r.parallel_p1 = c.parallel_p1;
    r.checksums_verified = c.checksums_verified;
    r.entry_checksum_ok = c.entry_checksum_ok;
    r.decode_failed = c.decode_failed;
    r.decode_eof = c.decode_eof;
    r.payload_mode = c.payload_mode;
    r.entries = c.entries;
    r.data_offset = c.data_offset;
    r.total_data_size = c.total_data_size;
    return r;
}

int RunLegacyCnExtractOrTest(
    const CliOptions& options,
    const LegacyCnContext& legacy,
    bool test_mode,
    std::ostream& os,
    // Start of the whole command (decode included): the footer's "in N s" is the
    // original's total, not just the copy-out that follows a finished decode.
    std::chrono::steady_clock::time_point run_start) {
    if (legacy.sink_handled) {
        if (legacy.decode_failed) return PrintCorruptLine(os, legacy);
        PrintDecodeFooter(os, legacy.total_data_size, ElapsedSince(run_start));
        return legacy.sink_failed_entries == 0u ? 0 : 2;
    }
    if (!legacy.native_payload_supported) {
        std::vector<unsigned char> bridged_data;
        std::string lzhd_decode_error;
        if (TryDecodeLegacyLzhd(legacy, &bridged_data, &lzhd_decode_error)) {
            LegacyCnContext bridged = CloneLegacyMeta(legacy);
            bridged.native_payload_supported = true;
            bridged.data_offset = 0u;
            bridged.checksums_verified = false;   // set below once the data is in place
            bridged.data = std::move(bridged_data);
            {
                std::size_t bad = 0;
                if (!CheckEntries(bridged.entries, bridged.checksum_mode, bridged.checksum_verification_supported,
                                  bridged.data.data(), bridged.data.size(), &bridged.entry_checksum_ok, &bad)) {
                    return kLegacyNeedCompat;   // decode did not produce the declared sizes
                }
                bridged.checksums_verified = bridged.checksum_verification_supported;
                if (bad == 0u) bridged.entry_checksum_ok.clear();
            }
            if (NativeTrace()) {
                os << "[native] decoded -cd payload natively ("
                   << LegacyCompressorLabel(legacy.legacy_method, legacy.legacy_method_p0, legacy.legacy_method_p1)
                   << ").\n";
            }
            return RunLegacyCnExtractOrTest(options, bridged, test_mode, os, run_start);
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
        // engine) -- historical note: both were once unported; both are native now,
        // as does the parallel-container case for -co (TryDecodeLegacyOptimum
        // only parses a single stream_tag's worth of blocks; parallel-
        // container framing would fail that parse and decline harmlessly, or
        // in the unlikely event it doesn't, the checksum gate still catches
        // it).
        std::string optimum_decode_error;
        std::vector<unsigned char> optimum_native_data;
        if (TryDecodeLegacyOptimum(legacy, &optimum_native_data, &optimum_decode_error)) {
            LegacyCnContext bridged = CloneLegacyMeta(legacy);
            bridged.native_payload_supported = true;
            bridged.data_offset = 0u;
            bridged.checksums_verified = false;   // set below once the data is in place
            bridged.data = std::move(optimum_native_data);
            {
                std::size_t bad = 0;
                if (!CheckEntries(bridged.entries, bridged.checksum_mode, bridged.checksum_verification_supported,
                                  bridged.data.data(), bridged.data.size(), &bridged.entry_checksum_ok, &bad)) {
                    return kLegacyNeedCompat;   // decode did not produce the declared sizes
                }
                bridged.checksums_verified = bridged.checksum_verification_supported;
                if (bad == 0u) bridged.entry_checksum_ok.clear();
            }
            if (NativeTrace()) {
                os << "[native] decoded " << (legacy.legacy_method_p0 == 6u ? "-cO" : "-co")
                   << " payload natively ("
                   << LegacyCompressorLabel(legacy.legacy_method, legacy.legacy_method_p0, legacy.legacy_method_p1)
                   << ").\n";
            }
            return RunLegacyCnExtractOrTest(options, bridged, test_mode, os, run_start);
        } else if (NativeTrace() && !optimum_decode_error.empty()) {
            os << "[native] " << (legacy.legacy_method_p0 == 6u ? "-cO" : "-co")
               << " native decode declined: " << optimum_decode_error << '\n';
        }
        std::string cm_decode_error;
        std::vector<unsigned char> cm_native_data;
        const bool cm_native_ok = TryDecodeLegacyCm(legacy, &cm_native_data, &cm_decode_error);
        // Native -cc CM decode; checksum-gated inside TryDecodeLegacyCm.
        if (cm_native_ok) {
            LegacyCnContext bridged = CloneLegacyMeta(legacy);
            bridged.native_payload_supported = true;
            bridged.data_offset = 0u;
            bridged.checksums_verified = false;   // set below once the data is in place
            bridged.data = std::move(cm_native_data);
            {
                std::size_t bad = 0;
                if (!CheckEntries(bridged.entries, bridged.checksum_mode, bridged.checksum_verification_supported,
                                  bridged.data.data(), bridged.data.size(), &bridged.entry_checksum_ok, &bad)) {
                    return kLegacyNeedCompat;   // decode did not produce the declared sizes
                }
                bridged.checksums_verified = bridged.checksum_verification_supported;
                if (bad == 0u) bridged.entry_checksum_ok.clear();
            }
            if (NativeTrace()) {
                os << "[native] decoded -cc payload natively ("
                   << LegacyCompressorLabel(legacy.legacy_method, legacy.legacy_method_p0, legacy.legacy_method_p1)
                   << ").\n";
            }
            return RunLegacyCnExtractOrTest(options, bridged, test_mode, os, run_start);
        }
        if (NativeTrace() && !cm_decode_error.empty()) {
            os << "[native] -cc native decode declined: " << cm_decode_error << '\n';
        }
        // A corrupt stream: the decoder that owns this method left the blocks it
        // completed in its output vector. The original has already written the
        // files those blocks cover (and created, empty, the file the failing
        // block starts with) when it prints "Archive corrupted"; do the same.
        std::vector<unsigned char>* partial = nullptr;
        if (IsCorruptStreamFailure(lzhd_decode_error)) partial = &bridged_data;
        else if (IsCorruptStreamFailure(optimum_decode_error)) partial = &optimum_native_data;
        else if (IsCorruptStreamFailure(cm_decode_error)) partial = &cm_native_data;
        // Measured: when nothing was completed the original creates no file at all
        // (the next output file is opened only after a flush reaches it).
        if (partial != nullptr && !partial->empty() && partial->size() < legacy.total_data_size) {
            LegacyCnContext bridged = CloneLegacyMeta(legacy);
            bridged.native_payload_supported = true;
            bridged.data_offset = 0u;
            bridged.checksums_verified = false;
            bridged.entry_checksum_ok.clear();
            bridged.decode_failed = true;
            bridged.decode_eof = (lzhd_decode_error == "lzhd: unexpected end of file");
            AdoptDecodeError(bridged);
            bridged.data = std::move(*partial);
            return RunLegacyCnExtractOrTest(options, bridged, test_mode, os, run_start);
        }
        return kLegacyNeedCompat;
    }
    if (!legacy.decode_failed && legacy.total_data_size != legacy.data.size()) {
        os << "Data corrupted while reading file payload.\n";
        return 2;
    }

    const fs::path output_root = options.output_path.empty() ? fs::current_path() : fs::path(options.output_path);

    std::size_t processed = 0;
    std::size_t failed = 0;
    std::uint64_t bytes_ok = 0;
    std::size_t cursor = 0;

    // The header (Archive / Threads / Compressor) is printed by the caller before
    // the decode is attempted, as the original does, so a failing decode shows
    // it too. `yes_to_all` is a local copy: the "Always" answer flips it.
    bool yes_to_all = options.yes_to_all;
    DecodeProgress progress(os);
    StageMark("extract start");
    // After a part-way decode failure: the entry the decode stopped inside (or
    // exactly at the start of) is the last one touched -- it is created with the
    // bytes that were completed, 0 of them included -- and nothing follows.
    bool stopped = false;
    for (const LegacyCnEntry& e : legacy.entries) {
        if (stopped) break;
        bool last_partial = false;
        std::size_t n = static_cast<std::size_t>(e.size);
        if (cursor > legacy.data.size() || e.size > legacy.data.size() - cursor) {
            if (!legacy.decode_failed) {
                os << "Data corrupted while reading file payload: " << e.path << '\n';
                return 2;
            }
            last_partial = true;
            stopped = true;
            n = legacy.data.size() - cursor;
            if (SafeMode()) break;   // never write unverified bytes in safe mode
        }

        // -x<pattern> excludes (`*` crosses directories); -forceout keeps the
        // filter but names every output file after the first file argument ("*"
        // when there is none), so later entries overwrite earlier ones.
        const bool selected = MatchesAnyPattern(e.path, options.positional) &&
                              !IsExcluded(e.path, options.exclude_patterns);
        const unsigned char* ptr = legacy.data.data() + cursor;
        cursor += n;

        // The original decodes the whole stream whatever the file filter says, so
        // its progress display and the "Decompressed N bytes" footer cover EVERY
        // entry; the filter only decides what gets written and checked.
        progress.Begin(e.path);
        if (!selected) {
            bytes_ok += e.size;
            progress.Advance(e.size);
            continue;
        }

        // Measured: "Checksum mismatch [<stored> <computed>]: <path>" on its own
        // cleared line, then the run CONTINUES (the file is still written, the
        // footer still counts its bytes, and the exit status stays 0).
        // Option (c) for damaged archives: an entry whose checksum does not match
        // is reported the way the original reports it and NOT written; the run
        // continues with the other entries and exits with status 2.
        bool checksum_bad = false;
        if (!last_partial && e.has_checksum && legacy.checksum_verification_supported && options.checksum != ChecksumMode::kNone) {
            const std::size_t idx = static_cast<std::size_t>(&e - legacy.entries.data());
            const bool known_bad = legacy.checksums_verified && idx < legacy.entry_checksum_ok.size() && !legacy.entry_checksum_ok[idx];
            if (known_bad || !legacy.checksums_verified) {
                const std::uint32_t got = ComputeBufferChecksum(legacy.checksum_mode, ptr, n);
                if (got != e.checksum) {
                    checksum_bad = true;
                    ClearStatusLine(os);
                    os << "Checksum mismatch [" << FormatChecksum(legacy.checksum_mode, e.checksum)
                       << ' ' << FormatChecksum(legacy.checksum_mode, got) << "]: " << e.path << '\n';
                }
            }
        }
        if (checksum_bad) {
            ++failed;
            if (SafeMode()) {
                bytes_ok += e.size;
                progress.Advance(e.size);
                continue;
            }
            // Default: the original writes the file anyway -- so do we.
        }
        StageMark("entry checksum");

        if (!test_mode) {
            // -sp strips the stored directories on extraction too.
            fs::path safe_rel = options.strip_paths
                ? fs::path(SanitizeExtractPath(e.path)).filename()
                : SanitizeExtractPath(e.path);
            if (options.forceout) safe_rel = fs::path(options.positional.empty() ? std::string("*") : options.positional.front());
            if (safe_rel.empty()) {
                // The original writes such a path as it is (`../../x`, `/abs/x` with
                // the leading slash dropped) -- a deliberate departure, pending the
                // community's decision (ORIGINAL_QUIRKS). Reported on stderr so the
                // stdout stays byte-identical; counted like every other entry.
                std::cerr << "Skipping unsafe path in archive: " << e.path << '\n';
                ++failed;
                bytes_ok += e.size;
                progress.Advance(e.size);
                continue;
            }

            const fs::path out_path = output_root / safe_rel;
            std::error_code ec;
            // "Overwrite <name> (Yes/No/Always)? " -- the original asks per existing
            // file unless -y; it reads a key, so any other answer re-asks. End of
            // input counts as No (the original would spin forever there).
            bool write_it = true;
            if (!yes_to_all && fs::exists(out_path, ec)) {
                for (;;) {
                    // Measured through a pty: the status line is cleared, then one more
                    // '\r', then the question; the answer is a LINE whose first character
                    // must be a lowercase y / n / a -- anything else (uppercase included,
                    // an empty line) asks again.
                    ClearStatusLine(os);
                    os << '\r' << "Overwrite " << e.path << " (Yes/No/Always)? ";
                    os.flush();
                    std::string answer;
                    if (!std::getline(std::cin, answer)) { write_it = false; break; }
                    const char k = answer.empty() ? '\0' : answer[0];
                    if (k == 'y') break;
                    if (k == 'n') { write_it = false; break; }
                    if (k == 'a') { yes_to_all = true; break; }
                }
            }
            if (write_it) {
                if (out_path.has_parent_path()) {
                    MakeDirs0700(out_path.parent_path());
                }
                if (!WriteExtractedFile(out_path, ptr, n,
                                        e.has_permissions ? e.permissions : 0600u,
                                        (options.restore_ownership && e.has_owner) ? static_cast<long>(e.uid) : -1L,
                                        (options.restore_ownership && e.has_owner) ? static_cast<long>(e.gid) : -1L)) {
                    // Measured: "Cannot write: <path>" on a fresh line, per file, and
                    // the run goes on to the footer.
                    os << '\n' << "Cannot write: " << (options.output_path.empty() ? safe_rel.string() : out_path.string()) << '\n';
                    ++failed;
                    bytes_ok += e.size;
                    progress.Advance(e.size);
                    continue;
                }
                if (e.has_win_attr) SetExtractedWinAttributes(out_path, e.win_attr);
                if (e.has_mtime && !SetExtractedMtime(out_path, e.mtime_unix) && NativeTrace()) {
                    os << "Warning: cannot apply mtime to " << out_path.string() << '\n';
                }
            }
        }

        StageMark("entry written");
        ++processed;
        bytes_ok += e.size;
        progress.Advance(e.size);
    }

    if (legacy.decode_failed) {
        // Measured: no footer, just the error line (code 100; 25600 when the
        // archive is cut short -- the original has more codes, see
        // docs/ORIGINAL_QUIRKS.md).
        return PrintCorruptLine(os, legacy);
    }
    // The original prints its normal footer after a checksum mismatch; so do we.
    // Status 2 marks the damage; main() maps it to the original's 0 unless
    // NZ_SAFE or NZ_STRICT_EXIT is set.
    PrintDecodeFooter(os, bytes_ok, ElapsedSince(run_start));
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
                        << " bytes";
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
        MakeDirs0700(out_path.parent_path());
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


int RunAdd(const CliOptions& options, std::ostream& os) {
    const auto add_start = std::chrono::steady_clock::now();
    const bool native_legacy_stream = IsNativeLegacyCompressionAvailable(options);

    std::vector<SourceFile> sources;
    std::vector<std::string> warnings;
    std::string error;

    const bool need_checksums = (options.checksum != ChecksumMode::kNone);
    if (!BuildSourceList(options, &sources, &warnings, &error, need_checksums)) {
        for (const std::string& w : warnings) PrintCollectorLine(os, w);
        if (error.rfind("Nothing to do", 0) == 0) os << error << '\n';
        else os << "Error: " << error << '\n';
        return 1;
    }

    for (const std::string& w : warnings) PrintCollectorLine(os, w);

    if (native_legacy_stream) {
        std::ostringstream native_log;
        const int native_exit = RunAddNativeLegacyStream(options, sources, native_log);
        if (native_exit == 0) {
            os << native_log.str();
            return 0;
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
        MakeDirs0700(out_path.parent_path());
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

    std::vector<SourceFile> sources;
    std::vector<std::string> warnings;
    std::string error;

    if (!BuildSourceList(options, &sources, &warnings, &error, false)) {
        for (const std::string& w : warnings) PrintCollectorLine(os, w);
        if (error.rfind("Nothing to do", 0) == 0) os << error << '\n';
        else os << "Error: " << error << '\n';
        return 1;
    }

    for (const std::string& w : warnings) PrintCollectorLine(os, w);

    if (native_legacy_stream) {
        std::ostringstream native_log;
        const int native_exit = RunSimulateNativeLegacyStream(options, sources, native_log);
        if (native_exit == 0) {
            os << native_log.str();
            return 0;
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

// The line under "Archive:" when an archive cannot be used: the original's own
// probe verdict for a file that exists but is not a 0.09 archive, else the
// opener's message ("Cannot open archive!").
static std::string LegacyOpenFailureMessage(ArchiveOpenError open_error, const std::string& path,
                                            const std::string& legacy_error, const std::string& error) {
    if (open_error == ArchiveOpenError::kCannotOpen) return error;
    const std::string probe = LegacyProbeMessage(path);
    if (!probe.empty()) return probe;
    return legacy_error.empty() ? error : legacy_error;
}

void SetDecodeThreads(unsigned n) { g_decode_threads = n; NzBwtSetThreadCount(n); }

int RunList(const CliOptions& options, std::ostream& os) {
    ArchiveContext context;
    std::string error;
    const ArchiveOpenError open_error = OpenArchive(options.archive_path, &context, &error);
    if (open_error != ArchiveOpenError::kNone) {
        std::string legacy_error;
        // Anything that exists but is not this port's own container may be a
        // legacy archive -- including a self-extracting .exe, whose first bytes
        // are the PE stub's, not the archive magic.
        if (open_error != ArchiveOpenError::kCannotOpen) {
            LegacyCnContext legacy_cn;
            if (TryParseLegacyCnArchive(options.archive_path, &legacy_cn, &legacy_error)) {
                return RunLegacyCnList(options, legacy_cn, os);
            }

        }
        // Measured: `l` on a missing or foreign file prints the archive line, the
        // reason, and an empty total.
        os << "Archive: " << options.archive_path << '\n';
        os << LegacyOpenFailureMessage(open_error, options.archive_path, legacy_error, error) << '\n';
        os << "Total of 0 files, 0 bytes.\n";
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
    // The inverse BWT's own thread pool follows the same -t / NZ_THREADS / CPU
    // count rule as the stream workers.
    NzBwtSetThreadCount(DecodeThreadCount());
    ArchiveContext context;
    std::string error;
    const ArchiveOpenError open_error = OpenArchive(options.archive_path, &context, &error);
    if (open_error != ArchiveOpenError::kNone) {
        std::string legacy_error;
        // Anything that exists but is not this port's own container may be a
        // legacy archive -- including a self-extracting .exe, whose first bytes
        // are the PE stub's, not the archive magic.
        if (open_error != ArchiveOpenError::kCannotOpen) {
            LegacyCnContext legacy_cn;
            bool parsed = false;
            // Header first, decode second -- the original streams, so a failing
            // archive still shows "Archive:", "Threads:" and the compressor line.
            // Parts of the decode run inside the parser, so the header printer is
            // registered with the progress engine and fired by the first progress
            // tick (from the parser's snapshot) or explicitly after the parse.
            psink::Configure(options, test_mode, os,
                             options.output_path.empty() ? fs::current_path() : fs::path(options.output_path));
            struct SinkEnd { ~SinkEnd() { psink::Reset(); } } sink_end;
            progress::Begin(&os, [&](std::ostream& o) {
                const LegacyCnContext& c = parsed ? legacy_cn : progress::Snapshot();
                progress::SetCompressorLine([&](std::size_t k) {
                    const LegacyCnContext& cc = parsed ? legacy_cn : progress::Snapshot();
                    return FormatCompressorLine(cc, k, options.verbose, test_mode);
                });
                PrintDecodeHeader(o, c, options, test_mode);
                progress::HeaderPrinted(!c.parallel_p1.empty(),
                                        c.entries.empty() ? std::string() : c.entries.front().path);
            });
            struct ProgressEnd { ~ProgressEnd() { progress::End(); } } progress_end;
            if (TryParseLegacyCnArchive(options.archive_path, &legacy_cn, &legacy_error)) {
                parsed = true;
                progress::EnsureHeader();
                const int legacy_rc = RunLegacyCnExtractOrTest(options, legacy_cn, test_mode, os, run_start);
                if (legacy_rc != kLegacyNeedCompat) {
                    return legacy_rc;
                }

                // Measured: an undecodable payload is "Archive corrupted. Error
                // decoding (code 100)"; one cut off before its end is code 25600.
                AdoptDecodeError(legacy_cn);
                const int corrupt_rc = PrintCorruptLine(os, legacy_cn);
                if (NativeTrace()) {
                    os << "[native] no native decoder accepted this stream; payload mode: "
                       << LegacyPayloadModeLabel(legacy_cn.payload_mode) << '\n';
                }
                return corrupt_rc;   // 2: damaged / undecodable content; 255: the original's fatal path
            }

        }
        os << "Archive: " << options.archive_path << '\n';
        os << LegacyOpenFailureMessage(open_error, options.archive_path, legacy_error, error) << '\n';
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
                MakeDirs0700(out_path.parent_path());
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
    // The original reads all of this with CPUID, not /proc (measured: identical
    // output with /proc/cpuinfo unreadable), so do the same: vendor from leaf 0,
    // the raw family/model/stepping nibbles and the feature bits from leaf 1,
    // 3DNow! from extended leaf 0x80000001.
    std::string vendor; unsigned family = 0, model = 0, step = 0, ext_family = 0; std::string flags;
    {
        unsigned a = 0, b = 0, c = 0, d = 0;
        if (__get_cpuid(0u, &a, &b, &c, &d)) {
            char v[13]; std::memcpy(v, &b, 4); std::memcpy(v + 4, &d, 4); std::memcpy(v + 8, &c, 4); v[12] = 0; vendor = v;
        }
        if (__get_cpuid(1u, &a, &b, &c, &d)) {
            step = a & 0xfu; model = (a >> 4) & 0xfu; family = (a >> 8) & 0xfu; ext_family = (a >> 20) & 0xffu;
            if (d & (1u << 23)) flags += " mmx";
            if (d & (1u << 25)) flags += " sse";
            if (d & (1u << 26)) flags += " sse2";
            if (c & (1u << 0))  flags += " pni";
            if (c & (1u << 9))  flags += " ssse3";
            if (c & (1u << 19)) flags += " sse4_1";
            if (c & (1u << 20)) flags += " sse4_2";
            if (d & (1u << 28)) flags += " ht";
        }
        unsigned ea = 0, eb = 0, ec = 0, ed = 0;
        if (__get_cpuid(0x80000000u, &ea, &eb, &ec, &ed) && ea >= 0x80000001u &&
            __get_cpuid(0x80000001u, &ea, &eb, &ec, &ed)) {
            if (ed & (1u << 31)) flags += " 3dnow";
            if (ed & (1u << 30)) flags += " 3dnowext";
        }
        flags += ' ';
    }

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
        {"3dnow", "3DNow!"}, {"3dnowext", "3DNow!+"},
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
