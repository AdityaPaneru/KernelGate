#include <exception>
#include <iostream>
#include <vector>

#include <nlohmann/json.hpp>

#include "Event.hpp"
#include "Policy.hpp"
#include "RiskEvaluator.hpp"

int main() {
    try {
        nlohmann::json startup = {
            {"project", "KernelGate"},
            {"module", "phase-1-risk-evaluation"},
            {"status", "running"},
            {"goal", "C++ endpoint runtime policy engine"}
        };

        std::cout << startup.dump(4) << "\n\n";

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

        int aggregate_risk_score = 0;
        std::vector<kernelgate::RuleMatch> aggregate_matches;

        for (const auto& event : events) {
            std::cout << "[EVENT] " << event.event_id
                      << " | type=" << kernelgate::eventTypeToString(event.event_type)
                      << " | pid=" << event.pid
                      << " | process=" << event.process_name
                      << "\n";

            const auto result = evaluator.evaluate(event);

            if (result.matches.empty()) {
                std::cout << "  [MATCH] none\n";
            } else {
                for (const auto& match : result.matches) {
                    std::cout << "  [MATCH] " << match.rule_id
                              << " | +" << match.risk_points
                              << " | severity=" << match.severity
                              << " | reason=" << match.reason
                              << "\n";

                    aggregate_matches.push_back(match);
                }
            }

            std::cout << "  [EVENT_SCORE] " << result.total_risk_score
                      << " | verdict=" << result.verdict << "\n\n";

            aggregate_risk_score += result.total_risk_score;
        }

        const std::string overall_verdict =
            evaluator.verdictForScore(aggregate_risk_score);

        std::cout << "================ KernelGate Phase 1 Summary ================\n";
        std::cout << "Events processed: " << events.size() << "\n";
        std::cout << "Matched rules: " << aggregate_matches.size() << "\n";
        std::cout << "Total risk score: " << aggregate_risk_score << "\n";
        std::cout << "Overall verdict: " << overall_verdict << "\n";
        std::cout << "=============================================================\n\n";

        std::cout << "KernelGate Phase 1 risk evaluation completed successfully.\n";
        return 0;

    } catch (const std::exception& ex) {
        std::cerr << "KernelGate error: " << ex.what() << "\n";
        return 1;
    }
}
