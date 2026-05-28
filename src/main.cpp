#include <exception>
#include <filesystem>
#include <iostream>
#include <string>
#include <system_error>
#include <vector>

#include <nlohmann/json.hpp>

#include "AuditStore.hpp"
#include "Correlator.hpp"
#include "Event.hpp"
#include "Incident.hpp"
#include "Policy.hpp"
#include "ProcEnricher.hpp"
#include "RiskEvaluator.hpp"
#include "RunContext.hpp"
#include "UemClient.hpp"

namespace {

struct CliOptions {
    std::string policy_file = "config/runtime_policy.json";
    std::string event_file = "sample_events/suspicious_chain.json";
    std::string db_path = "kernelgate.db";

    bool reset_db = false;
    bool inspect_pid_mode = false;
    int inspect_pid = -1;

    bool upload_enabled = false;
    std::string control_plane_url = "http://127.0.0.1:8000";
    std::string device_id = "kernelgate-endpoint-01";
};

void printUsage() {
    std::cout << "KernelGate usage:\n";
    std::cout << "  ./build/kernelgate-agent\n";
    std::cout << "  ./build/kernelgate-agent --events <event_json>\n";
    std::cout << "  ./build/kernelgate-agent --policy <policy_json>\n";
    std::cout << "  ./build/kernelgate-agent --db <sqlite_db>\n";
    std::cout << "  ./build/kernelgate-agent --reset-db\n";
    std::cout << "  ./build/kernelgate-agent --inspect-pid <pid>\n";
    std::cout << "  ./build/kernelgate-agent --upload\n";
    std::cout << "  ./build/kernelgate-agent --control-plane-url <url>\n";
    std::cout << "  ./build/kernelgate-agent --device-id <id>\n";
    std::cout << "  ./build/kernelgate-agent --help\n";
}

CliOptions parseArgs(int argc, char* argv[]) {
    CliOptions options;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];

        if (arg == "--help") {
            printUsage();
            std::exit(0);
        }

        if (arg == "--events") {
            if (i + 1 >= argc) {
                throw std::runtime_error("--events requires a file path");
            }
            options.event_file = argv[++i];
            continue;
        }

        if (arg == "--policy") {
            if (i + 1 >= argc) {
                throw std::runtime_error("--policy requires a file path");
            }
            options.policy_file = argv[++i];
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

        if (arg == "--inspect-pid") {
            if (i + 1 >= argc) {
                throw std::runtime_error("--inspect-pid requires a PID");
            }
            options.inspect_pid_mode = true;
            options.inspect_pid = std::stoi(argv[++i]);
            continue;
        }

        if (arg == "--upload") {
            options.upload_enabled = true;
            continue;
        }

        if (arg == "--control-plane-url") {
            if (i + 1 >= argc) {
                throw std::runtime_error("--control-plane-url requires a URL");
            }
            options.control_plane_url = argv[++i];
            continue;
        }

        if (arg == "--device-id") {
            if (i + 1 >= argc) {
                throw std::runtime_error("--device-id requires an ID");
            }
            options.device_id = argv[++i];
            continue;
        }

        throw std::runtime_error("Unknown argument: " + arg);
    }

    return options;
}

int runInspectPidMode(int pid) {
    const auto process_info = kernelgate::ProcEnricher::inspectPid(pid);

    if (!process_info.has_value()) {
        std::cerr << "[PROC] Failed to inspect PID: " << pid << "\n";
        return 1;
    }

    const auto& info = process_info.value();

    std::cout << "================ KernelGate /proc Inspection ================\n";
    std::cout << "[PROC] PID: " << info.pid << "\n";
    std::cout << "[PROC] PPID: " << info.ppid << "\n";
    std::cout << "[PROC] UID: " << info.uid << "\n";
    std::cout << "[PROC] Name: " << info.name << "\n";
    std::cout << "[PROC] Exe: " << info.exe_path << "\n";
    std::cout << "[PROC] Cmdline: " << info.command_line << "\n";
    std::cout << "==============================================================\n";

    return 0;
}

void resetDatabaseIfRequested(const CliOptions& options) {
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

int runDefaultPipeline(const CliOptions& options) {
    nlohmann::json startup = {
        {"project", "KernelGate"},
        {"module", "phase-7-uem-upload"},
        {"status", "running"},
        {"goal", "C++ endpoint runtime policy engine"}
    };

    std::cout << startup.dump(4) << "\n\n";

    const std::string run_id = kernelgate::generateRunId();
    std::cout << "[RUN] Run ID: " << run_id << "\n\n";

    resetDatabaseIfRequested(options);

    kernelgate::AuditStore audit_store(options.db_path);
    audit_store.initialize();

    std::cout << "[AUDIT] SQLite audit store initialized at "
              << options.db_path << "\n\n";

    const auto policy = kernelgate::loadPolicyFromFile(options.policy_file);

    std::cout << "[POLICY] Loaded runtime policy from "
              << options.policy_file << "\n";

    std::cout << "[POLICY] Version: " << policy.policy_version
              << " | Mode: " << policy.mode << "\n";

    std::cout << "[POLICY] Thresholds: warning="
              << policy.risk_thresholds.warning
              << ", high=" << policy.risk_thresholds.high
              << ", critical=" << policy.risk_thresholds.critical
              << "\n";

    std::cout << "[POLICY] Rules loaded: "
              << policy.rules.size() << "\n\n";

    const auto events = kernelgate::loadEventsFromFile(options.event_file);

    std::cout << "[EVENTS] Loaded " << events.size()
              << " synthetic runtime events from "
              << options.event_file << "\n\n";

    kernelgate::RiskEvaluator evaluator(policy);

    std::vector<kernelgate::EvaluationResult> evaluated_events;
    evaluated_events.reserve(events.size());

    int aggregate_risk_score = 0;

    for (const auto& event : events) {
        audit_store.insertRawEvent(event, run_id);

        std::cout << "[EVENT] " << event.event_id
                  << " | type=" << kernelgate::eventTypeToString(event.event_type)
                  << " | pid=" << event.pid
                  << " | process=" << event.process_name
                  << "\n";

        const auto result = evaluator.evaluate(event);
        evaluated_events.push_back(result);

        if (result.matches.empty()) {
            std::cout << "  [MATCH] none\n";
        } else {
            for (const auto& match : result.matches) {
                std::cout << "  [MATCH] " << match.rule_id
                          << " | +" << match.risk_points
                          << " | severity=" << match.severity
                          << " | reason=" << match.reason
                          << "\n";
            }
        }

        std::cout << "  [EVENT_SCORE] " << result.total_risk_score
                  << " | verdict=" << result.verdict << "\n\n";

        aggregate_risk_score += result.total_risk_score;
    }

    kernelgate::Correlator correlator(policy);
    const auto incidents = correlator.correlate(evaluated_events);

    std::cout << "================ KernelGate Phase 7 Incidents ================\n";
    std::cout << "Incidents generated: " << incidents.size() << "\n\n";

    for (const auto& incident : incidents) {
        audit_store.insertIncident(incident, run_id);
        audit_store.insertIncidentRuleMatches(incident, run_id);

        std::cout << "[INCIDENT] " << incident.incident_id << "\n";
        std::cout << "  PID: " << incident.pid << "\n";
        std::cout << "  Process: " << incident.process_name << "\n";
        std::cout << "  Path: " << incident.process_path << "\n";
        std::cout << "  First seen: " << incident.first_seen << "\n";
        std::cout << "  Last seen: " << incident.last_seen << "\n";
        std::cout << "  Chain: " << kernelgate::buildChainSummary(incident) << "\n";
        std::cout << "  Risk score: " << incident.total_risk_score << "\n";
        std::cout << "  Verdict: " << incident.verdict << "\n";

        std::cout << "  Matched rules:\n";
        for (const auto& match : incident.matched_rules) {
            std::cout << "    - " << match.rule_id
                      << " | +" << match.risk_points
                      << " | " << match.reason
                      << "\n";
        }

        if (options.upload_enabled) {
            kernelgate::UemClient uem_client(options.control_plane_url);
            const bool uploaded = uem_client.uploadIncident(
                incident,
                run_id,
                options.device_id
            );

            if (!uploaded) {
                std::cerr << "  [UPLOAD] Incident upload failed\n";
            }
        }

        std::cout << "\n";
    }

    std::cout << "================ KernelGate Phase 7 Summary ==================\n";
    std::cout << "Events processed: " << events.size() << "\n";
    std::cout << "Aggregate event risk score: " << aggregate_risk_score << "\n";
    std::cout << "Incidents generated: " << incidents.size() << "\n";
    std::cout << "Audit database: " << options.db_path << "\n";
    std::cout << "Run ID: " << run_id << "\n";
    std::cout << "Event file: " << options.event_file << "\n";
    std::cout << "Policy file: " << options.policy_file << "\n";
    std::cout << "Upload enabled: " << (options.upload_enabled ? "true" : "false") << "\n";
    std::cout << "Control plane URL: " << options.control_plane_url << "\n";
    std::cout << "==============================================================\n\n";

    std::cout << "KernelGate Phase 7 UEM upload completed successfully.\n";
    return 0;
}

} // namespace

int main(int argc, char* argv[]) {
    try {
        const CliOptions options = parseArgs(argc, argv);

        if (options.inspect_pid_mode) {
            return runInspectPidMode(options.inspect_pid);
        }

        return runDefaultPipeline(options);

    } catch (const std::exception& ex) {
        std::cerr << "KernelGate error: " << ex.what() << "\n";
        printUsage();
        return 1;
    }
}
