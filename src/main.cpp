#include <exception>
#include <iostream>
#include <vector>

#include <nlohmann/json.hpp>

#include "AuditStore.hpp"
#include "Correlator.hpp"
#include "Event.hpp"
#include "Incident.hpp"
#include "Policy.hpp"
#include "RiskEvaluator.hpp"

int main() {
    try {
        nlohmann::json startup = {
            {"project", "KernelGate"},
            {"module", "phase-3-sqlite-audit-store"},
            {"status", "running"},
            {"goal", "C++ endpoint runtime policy engine"}
        };

        std::cout << startup.dump(4) << "\n\n";

        const std::string db_path = "kernelgate.db";
        kernelgate::AuditStore audit_store(db_path);
        audit_store.initialize();

        std::cout << "[AUDIT] SQLite audit store initialized at "
                  << db_path << "\n\n";

        const std::string policy_file = "config/runtime_policy.json";
        const auto policy = kernelgate::loadPolicyFromFile(policy_file);

        std::cout << "[POLICY] Loaded runtime policy from "
                  << policy_file << "\n";

        std::cout << "[POLICY] Version: " << policy.policy_version
                  << " | Mode: " << policy.mode << "\n";

        std::cout << "[POLICY] Thresholds: warning="
                  << policy.risk_thresholds.warning
                  << ", high=" << policy.risk_thresholds.high
                  << ", critical=" << policy.risk_thresholds.critical
                  << "\n";

        std::cout << "[POLICY] Rules loaded: "
                  << policy.rules.size() << "\n\n";

        const std::string event_file = "sample_events/suspicious_chain.json";
        const auto events = kernelgate::loadEventsFromFile(event_file);

        std::cout << "[EVENTS] Loaded " << events.size()
                  << " synthetic runtime events from "
                  << event_file << "\n\n";

        kernelgate::RiskEvaluator evaluator(policy);

        std::vector<kernelgate::EvaluationResult> evaluated_events;
        evaluated_events.reserve(events.size());

        int aggregate_risk_score = 0;

        for (const auto& event : events) {
            audit_store.insertRawEvent(event);

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

        std::cout << "================ KernelGate Phase 3 Incidents ================\n";
        std::cout << "Incidents generated: " << incidents.size() << "\n\n";

        for (const auto& incident : incidents) {
            audit_store.insertIncident(incident);
            audit_store.insertIncidentRuleMatches(incident);

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

            std::cout << "\n";
        }

        std::cout << "================ KernelGate Phase 3 Summary ==================\n";
        std::cout << "Events processed: " << events.size() << "\n";
        std::cout << "Aggregate event risk score: " << aggregate_risk_score << "\n";
        std::cout << "Incidents generated: " << incidents.size() << "\n";
        std::cout << "Audit database: " << db_path << "\n";
        std::cout << "==============================================================\n\n";

        std::cout << "KernelGate Phase 3 SQLite audit completed successfully.\n";
        return 0;

    } catch (const std::exception& ex) {
        std::cerr << "KernelGate error: " << ex.what() << "\n";
        return 1;
    }
}
