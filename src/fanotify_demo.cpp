#include <cstdlib>
#include <exception>
#include <filesystem>
#include <iostream>
#include <string>
#include <system_error>
#include <vector>

#include <nlohmann/json.hpp>

#include "AuditStore.hpp"
#include "Correlator.hpp"
#include "FileTelemetry.hpp"
#include "Policy.hpp"
#include "RiskEvaluator.hpp"
#include "RunContext.hpp"

namespace {

struct FanotifyDemoOptions {
    std::string watch_dir = "/etc";
    std::string target_file = "/etc/passwd";
    std::string policy_file = "config/runtime_policy.json";
    std::string db_path = "kernelgate_fanotify.db";
    int duration_seconds = 15;
    bool reset_db = false;
};

void printUsage() {
    std::cout << "KernelGate fanotify demo usage:\n";
    std::cout << "  sudo ./build/kernelgate-fanotify-demo\n";
    std::cout << "  sudo ./build/kernelgate-fanotify-demo --watch-dir <dir>\n";
    std::cout << "  sudo ./build/kernelgate-fanotify-demo --target-file <file>\n";
    std::cout << "  sudo ./build/kernelgate-fanotify-demo --duration <seconds>\n";
    std::cout << "  sudo ./build/kernelgate-fanotify-demo --db <sqlite_db>\n";
    std::cout << "  sudo ./build/kernelgate-fanotify-demo --reset-db\n";
}

FanotifyDemoOptions parseArgs(int argc, char* argv[]) {
    FanotifyDemoOptions options;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];

        if (arg == "--help") {
            printUsage();
            std::exit(0);
        }

        if (arg == "--watch-dir") {
            if (i + 1 >= argc) {
                throw std::runtime_error("--watch-dir requires a directory");
            }

            options.watch_dir = argv[++i];
            continue;
        }

        if (arg == "--target-file") {
            if (i + 1 >= argc) {
                throw std::runtime_error("--target-file requires a file path");
            }

            options.target_file = argv[++i];
            continue;
        }

        if (arg == "--duration") {
            if (i + 1 >= argc) {
                throw std::runtime_error("--duration requires seconds");
            }

            options.duration_seconds = std::stoi(argv[++i]);
            continue;
        }

        if (arg == "--db") {
            if (i + 1 >= argc) {
                throw std::runtime_error("--db requires a database path");
            }

            options.db_path = argv[++i];
            continue;
        }

        if (arg == "--reset-db") {
            options.reset_db = true;
            continue;
        }

        throw std::runtime_error("Unknown argument: " + arg);
    }

    return options;
}

void resetDatabaseIfRequested(const FanotifyDemoOptions& options) {
    if (!options.reset_db) {
        return;
    }

    std::error_code ec;
    std::filesystem::remove(options.db_path, ec);

    if (ec) {
        throw std::runtime_error(
            "Failed to reset database " + options.db_path + ": " + ec.message()
        );
    }

    std::cout << "[AUDIT] Reset database: " << options.db_path << "\n";
}

} // namespace

int main(int argc, char* argv[]) {
    try {
        const auto options = parseArgs(argc, argv);

        nlohmann::json startup = {
            {"project", "KernelGate"},
            {"module", "phase-10-fanotify-file-telemetry"},
            {"status", "running"},
            {"goal", "real kernel-backed file access telemetry"}
        };

        std::cout << startup.dump(4) << "\n\n";

        const std::string run_id = kernelgate::generateRunId();
        std::cout << "[RUN] Run ID: " << run_id << "\n\n";

        resetDatabaseIfRequested(options);

        const auto policy =
            kernelgate::loadPolicyFromFile(options.policy_file);

        kernelgate::AuditStore audit_store(options.db_path);
        audit_store.initialize();

        kernelgate::FileWatchConfig watch_config;
        watch_config.watch_path = options.watch_dir;
        watch_config.target_file = options.target_file;
        watch_config.duration_seconds = options.duration_seconds;
        watch_config.max_events = 5;

        std::cout << "[FANOTIFY] Watching directory: "
                  << watch_config.watch_path << "\n";

        std::cout << "[FANOTIFY] Target file: "
                  << watch_config.target_file << "\n";

        std::cout << "[FANOTIFY] Duration: "
                  << watch_config.duration_seconds << " seconds\n\n";

        std::cout << "Open another terminal and run:\n";
        std::cout << "  cat " << watch_config.target_file
                  << " > /dev/null\n\n";

        const auto events =
            kernelgate::FanotifyFileSource::captureFileEvents(watch_config);

        std::cout << "[FANOTIFY] Captured events: "
                  << events.size() << "\n\n";

        kernelgate::RiskEvaluator evaluator(policy);

        std::vector<kernelgate::EvaluationResult> evaluated_events;
        evaluated_events.reserve(events.size());

        for (const auto& event : events) {
            audit_store.insertRawEvent(event, run_id);

            std::cout << "[REAL_EVENT] " << event.event_id
                      << " | type=" << kernelgate::eventTypeToString(event.event_type)
                      << " | pid=" << event.pid
                      << " | process=" << event.process_name
                      << " | file=" << event.file_path.value_or("")
                      << "\n";

            const auto result = evaluator.evaluate(event);
            evaluated_events.push_back(result);

            if (result.matches.empty()) {
                std::cout << "  [MATCH] none\n";
            } else {
                for (const auto& match : result.matches) {
                    std::cout << "  [MATCH] " << match.rule_id
                              << " | +" << match.risk_points
                              << " | reason=" << match.reason
                              << "\n";
                }
            }

            std::cout << "  [EVENT_SCORE] " << result.total_risk_score
                      << " | verdict=" << result.verdict << "\n\n";
        }

        kernelgate::Correlator correlator(policy);
        const auto incidents = correlator.correlate(evaluated_events);

        for (const auto& incident : incidents) {
            audit_store.insertIncident(incident, run_id);
            audit_store.insertIncidentRuleMatches(incident, run_id);

            std::cout << "[INCIDENT] " << incident.incident_id << "\n";
            std::cout << "  Chain: "
                      << kernelgate::buildChainSummary(incident) << "\n";
            std::cout << "  Risk score: "
                      << incident.total_risk_score << "\n";
            std::cout << "  Verdict: "
                      << incident.verdict << "\n\n";
        }

        std::cout << "================ Fanotify Demo Summary ================\n";
        std::cout << "Events captured: " << events.size() << "\n";
        std::cout << "Incidents generated: " << incidents.size() << "\n";
        std::cout << "Audit database: " << options.db_path << "\n";
        std::cout << "Run ID: " << run_id << "\n";
        std::cout << "=======================================================\n";

        if (events.empty()) {
            std::cout << "\nNo matching fanotify event captured.\n";
            std::cout << "Make sure you accessed the target file during the watch window.\n";
        }

        return 0;

    } catch (const std::exception& ex) {
        std::cerr << "KernelGate fanotify error: " << ex.what() << "\n";
        printUsage();
        return 1;
    }
}
