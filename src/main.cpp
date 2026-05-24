#include <exception>
#include <iostream>

#include <nlohmann/json.hpp>

#include "Event.hpp"
#include "Policy.hpp"

int main() {
    try {
        nlohmann::json startup = {
            {"project", "KernelGate"},
            {"module", "phase-1B-policy-loader"},
            {"status", "running"},
            {"goal", "C++ endpoint runtime policy engine"}
        };

        std::cout << startup.dump(4) << "\n\n";

        const std::string policy_file = "config/runtime_policy.json";
        const auto policy = kernelgate::loadPolicyFromFile(policy_file);

        std::cout << "Loaded runtime policy from "
                  << policy_file << "\n";

        std::cout << "Policy version: "
                  << policy.policy_version << "\n";

        std::cout << "Mode: "
                  << policy.mode << "\n";

        std::cout << "Risk thresholds: "
                  << "warning=" << policy.risk_thresholds.warning
                  << ", high=" << policy.risk_thresholds.high
                  << ", critical=" << policy.risk_thresholds.critical
                  << "\n";

        std::cout << "Rules loaded: "
                  << policy.rules.size() << "\n\n";

        for (const auto& rule : policy.rules) {
            std::cout << "- Rule: " << rule.rule_id
                      << " | type=" << rule.event_type
                      << " | risk_points=" << rule.risk_points
                      << " | severity=" << rule.severity
                      << " | name=" << rule.name
                      << "\n";
        }

        std::cout << "\n";

        const std::string event_file = "sample_events/suspicious_chain.json";
        const auto events = kernelgate::loadEventsFromFile(event_file);

        std::cout << "Loaded " << events.size()
                  << " synthetic runtime events from "
                  << event_file << "\n\n";

        for (const auto& event : events) {
            const auto normalized = kernelgate::eventToJson(event);
            std::cout << normalized.dump(4) << "\n\n";
        }

        std::cout << "KernelGate Phase 1B policy loading completed successfully.\n";
        return 0;

    } catch (const std::exception& ex) {
        std::cerr << "KernelGate error: " << ex.what() << "\n";
        return 1;
    }
}
