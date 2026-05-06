#pragma once

#include <cstdint>

namespace nz {
namespace sfx {
namespace linux32 {

// RE map for NanoZip Linux32 cm/optimum family (base: work/linux32/nz).
enum class CmFamilyMethod {
    kEstimateMemory,
    kDestructor,
    kDelete,
    kReset,
    kLoadParams,
    kProcess
};

enum class CmSubEngineMethod {
    kDestructor,
    kMemoryContribution,
    kOp0c,
    kOp10,
    kReset,
    kOp1c,
    kOp20
};

struct CmFamilyLayout {
    std::uint32_t method_selector = 0x24;
    std::uint32_t core_base = 0x40;
    std::uint32_t mode_flags = 0x38c18;
    std::uint32_t subengine = 0x8b5c0;
    std::uint32_t aux_stream_a = 0x8b5f8;
    std::uint32_t aux_stream_b = 0x8b5fc;
};

constexpr std::uint32_t kCmFamilyVtable = 0x08132ea8;
constexpr std::uint32_t kCmSubEngineSmallVtable = 0x08132e08;
constexpr std::uint32_t kCmSubEngineBigVtable = 0x08132e48;

const char* CmFamilyMethodName(CmFamilyMethod method);
std::uint32_t CmFamilyMethodAddress(CmFamilyMethod method);

const char* CmSubEngineMethodName(CmSubEngineMethod method);
std::uint32_t CmSubEngineMethodAddressSmall(CmSubEngineMethod method);
std::uint32_t CmSubEngineMethodAddressBig(CmSubEngineMethod method);

}  // namespace linux32
}  // namespace sfx
}  // namespace nz
