#include "nz_sfx/sfx_archive.hpp"
#include "nz_sfx/sfx_cli.hpp"
#include "nz_cm.h"

#include <cstdlib>
#include <iostream>
#include <new>

int main(int argc, char** argv) {
    using nz::recon::CliOptions;
    using nz::recon::Command;

    NzCmInitAll();

    nz::recon::PrintBanner(std::cerr);
    std::cout << std::flush;

    CliOptions options = nz::recon::ParseCli(argc, argv);

    // The original's process exit status is 0 on EVERY path -- unknown command,
    // missing archive, corrupt data, checksum mismatch (all measured). Scripts
    // that want a meaningful status can set NZ_STRICT_EXIT=1 to get this port's
    // own codes instead.
    const bool strict_exit = (std::getenv("NZ_STRICT_EXIT") != nullptr);
    const auto finish = [strict_exit](int rc) { return strict_exit ? rc : 0; };

    // Measured messages, each WITHOUT the usage text and without a leading blank
    // line: "Unknown command q", "Error: Archive name missing...",
    // "Unknown argument: -zz" (the first unknown switch stops the run).
    if (!options.unknown_command.empty()) {
        std::cout << "Unknown command " << options.unknown_command << '\n';
        return finish(1);
    }
    if (!options.error.empty()) {
        if (options.error == "archive name missing") {
            std::cout << "Error: Archive name missing...\n";
        } else {
            std::cout << "Error: " << options.error << '\n';
        }
        return finish(1);
    }

    if (options.show_usage) {
        nz::recon::PrintUsage((argc > 0 && argv != nullptr) ? argv[0] : "nz_recon", std::cout);
        return 0;
    }

    if (options.show_advanced_help || options.command == Command::kHelp) {
        nz::recon::PrintAdvancedHelp(std::cout);
        return 0;
    }

    if (!options.unknown_switches.empty()) {
        std::cout << "Unknown argument: " << options.unknown_switches.front() << '\n';
        return finish(1);
    }

    // The original's out-of-memory report. The 32-bit builds hold the decoded
    // stream in memory, so an archive whose content does not fit their address
    // space ends here instead of in an uncaught std::bad_alloc abort.
    int rc = 0;
    try {
    switch (options.command) {
        case Command::kAdd:
            rc = nz::recon::RunAdd(options, std::cout); break;
        case Command::kSimulate:
            rc = nz::recon::RunSimulate(options, std::cout); break;
        case Command::kList:
            rc = nz::recon::RunList(options, std::cout); break;
        case Command::kTest:
            rc = nz::recon::RunExtractOrTest(options, true, std::cout); break;
        case Command::kExtract:
            rc = nz::recon::RunExtractOrTest(options, false, std::cout); break;
        case Command::kInfo:
            rc = nz::recon::RunInfo(std::cout); break;
        case Command::kW32c:
            std::cout << "SFX creation is intentionally omitted in this reconstruction.\n";
            rc = 2; break;
        case Command::kHelp:
            nz::recon::PrintAdvancedHelp(std::cout); break;
        case Command::kUnknown:
        default:
            nz::recon::PrintUsage((argc > 0 && argv != nullptr) ? argv[0] : "nz_recon", std::cout);
            rc = 1; break;
    }
    } catch (const std::bad_alloc&) {
        nz::recon::ClearStatusLine(std::cout);
        std::cout << "Out of memory!\n";
        rc = 1;
    }
    return finish(rc);
}
