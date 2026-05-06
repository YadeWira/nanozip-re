#include "nz_sfx/linux32_cm_map.hpp"

namespace nz {
namespace sfx {
namespace linux32 {

const char* CmFamilyMethodName(CmFamilyMethod method) {
    switch (method) {
        case CmFamilyMethod::kEstimateMemory:
            return "nz_cm_family_estimate_memory";
        case CmFamilyMethod::kDestructor:
            return "nz_cm_family_dtor";
        case CmFamilyMethod::kDelete:
            return "nz_cm_family_delete";
        case CmFamilyMethod::kReset:
            return "nz_cm_family_reset";
        case CmFamilyMethod::kLoadParams:
            return "nz_cm_family_load_params";
        case CmFamilyMethod::kProcess:
            return "nz_cm_family_process";
    }
    return "unknown";
}

std::uint32_t CmFamilyMethodAddress(CmFamilyMethod method) {
    switch (method) {
        case CmFamilyMethod::kEstimateMemory:
            return 0x080aafb0;
        case CmFamilyMethod::kDestructor:
            return 0x080ab090;
        case CmFamilyMethod::kDelete:
            return 0x080ab140;
        case CmFamilyMethod::kReset:
            return 0x080aaf70;
        case CmFamilyMethod::kLoadParams:
            return 0x080ab160;
        case CmFamilyMethod::kProcess:
            return 0x080aa850;
    }
    return 0;
}

const char* CmSubEngineMethodName(CmSubEngineMethod method) {
    switch (method) {
        case CmSubEngineMethod::kDestructor:
            return "subengine_dtor";
        case CmSubEngineMethod::kMemoryContribution:
            return "subengine_mem_contribution";
        case CmSubEngineMethod::kOp0c:
            return "subengine_op_0c";
        case CmSubEngineMethod::kOp10:
            return "subengine_op_10";
        case CmSubEngineMethod::kReset:
            return "subengine_reset";
        case CmSubEngineMethod::kOp1c:
            return "subengine_op_1c";
        case CmSubEngineMethod::kOp20:
            return "subengine_op_20";
    }
    return "unknown";
}

std::uint32_t CmSubEngineMethodAddressSmall(CmSubEngineMethod method) {
    switch (method) {
        case CmSubEngineMethod::kDestructor:
            return 0x080a0770;
        case CmSubEngineMethod::kMemoryContribution:
            return 0x0809e5c0;
        case CmSubEngineMethod::kOp0c:
            return 0x0809e5a0;
        case CmSubEngineMethod::kOp10:
            return 0x0809e4e0;
        case CmSubEngineMethod::kReset:
            return 0x0809e5d0;
        case CmSubEngineMethod::kOp1c:
            return 0x080a0740;
        case CmSubEngineMethod::kOp20:
            return 0x080a0520;
    }
    return 0;
}

std::uint32_t CmSubEngineMethodAddressBig(CmSubEngineMethod method) {
    switch (method) {
        case CmSubEngineMethod::kDestructor:
            return 0x080a9080;
        case CmSubEngineMethod::kMemoryContribution:
            return 0x080a5d50;
        case CmSubEngineMethod::kOp0c:
            return 0x080a5d30;
        case CmSubEngineMethod::kOp10:
            return 0x080a5c70;
        case CmSubEngineMethod::kReset:
            return 0x080a5d60;
        case CmSubEngineMethod::kOp1c:
            return 0x080a9050;
        case CmSubEngineMethod::kOp20:
            return 0x080a87a0;
    }
    return 0;
}

}  // namespace linux32
}  // namespace sfx
}  // namespace nz
