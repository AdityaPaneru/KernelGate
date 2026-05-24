#pragma once

#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace kernelgate {

struct RiskThresholds {
    int warning = 40;
    int high = 70;
    int critical = 90;
};

struct PolicyRule {
    std::string rule_id;
    std::string name;
    std::string event_type;
    int risk_points = 0;
    std::string severity;

    std::vector<std::string> match_path_prefix;
    std::vector<std::string> sensitive_paths;
    std::vector<int> restricted_ports;
};

struct RuntimePolicy {
    std::string policy_version;
    std::string mode;
    RiskThresholds risk_thresholds;
    std::vector<PolicyRule> rules;
};

RuntimePolicy policyFromJson(const nlohmann::json& j);
RuntimePolicy loadPolicyFromFile(const std::string& file_path);

nlohmann::json policyToJson(const RuntimePolicy& policy);

} // namespace kernelgate
