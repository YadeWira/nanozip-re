#include "nz_sfx/sfx_archive.hpp"
#include "nz_sfx/sfx_cli.hpp"

#include <iostream>

int main(int argc, char** argv) {
    using nz::recon::CliOptions;
    using nz::recon::Command;

    nz::recon::PrintBanner(std::cout);
    std::cout << std::flush;

    CliOptions options = nz::recon::ParseCli(argc, argv);
    if (!options.unknown_command.empty()) {
        std::cout << "\nUnknown command " << options.unknown_command << '\n';
    }
    if (!options.error.empty()) {
        std::cout << "Error: " << options.error << '\n';
    }

    if (options.show_usage) {
        nz::recon::PrintUsage((argc > 0 && argv != nullptr) ? argv[0] : "nz_recon", std::cout);
        return options.unknown_command.empty() && options.error.empty() ? 0 : 1;
    }

    if (options.show_advanced_help || options.command == Command::kHelp) {
        nz::recon::PrintAdvancedHelp(std::cout);
        return 0;
    }

    if (!options.unknown_switches.empty()) {
        std::cout << "Warning: unsupported switch(es) in reconstruction:";
        for (const std::string& sw : options.unknown_switches) {
            std::cout << ' ' << sw;
        }
        std::cout << '\n';
    }

    if (nz::recon::ShouldUseLegacyBackend(options)) {
        int legacy_exit = 0;
        if (nz::recon::TryRunLegacyBackend(options, std::cout, &legacy_exit)) {
            return legacy_exit;
        }
    }

    switch (options.command) {
        case Command::kAdd:
            return nz::recon::RunAdd(options, std::cout);
        case Command::kSimulate:
            return nz::recon::RunSimulate(options, std::cout);
        case Command::kList:
            return nz::recon::RunList(options, std::cout);
        case Command::kTest:
            return nz::recon::RunExtractOrTest(options, true, std::cout);
        case Command::kExtract:
            return nz::recon::RunExtractOrTest(options, false, std::cout);
        case Command::kInfo:
            return nz::recon::RunInfo(std::cout);
        case Command::kW32c:
            std::cout << "SFX creation is intentionally omitted in this reconstruction.\n";
            return 2;
        case Command::kHelp:
            nz::recon::PrintAdvancedHelp(std::cout);
            return 0;
        case Command::kUnknown:
        default:
            nz::recon::PrintUsage((argc > 0 && argv != nullptr) ? argv[0] : "nz_recon", std::cout);
            return 1;
    }
}
