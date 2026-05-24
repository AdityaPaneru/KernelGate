#include "Policy.hpp"

#include <fstream>
#include <stdexcept>

namespace kernelgate {

namespace {

std::vector<std::string> getStringArray(
    const nlohmann::json& j,
    const std::string& key
) {
    std::vector<std::string> values;

    if (!j.contains(key) || !j.at(key).is_array()) {
        return values;
    }

    for (const auto& item : j.at(key)) {
        values.push_back(item.get<std::string>());
    }

    return values;
}

std::vector<int> getIntArray(
    const nlohmann::json& j,
    const std::string& key
) {
    std::vector<int> values;

    if (!j.contains(key) || !j.at(key).is_array()) {
        return values;
    }

    for (const auto& item : j.at(key)) {
        values.push_back(item.get<int>());
    }

    return values;
}

} // namespace

RuntimePolicy policyFromJson(const nlohmann::json& j) {
    RuntimePolicy policy;

    policy.policy_version = j.value("policy_version", "unknown");
    policy.mode = j.value("mode", "REPORT_ONLY");

    if (j.contains("risk_thresholds")) {
        const auto& thresholds = j.at("risk_thresholds");

        policy.risk_thresholds.warning =
            thresholds.value("warning", policy.risk_thresholds.warning);

        policy.risk_thresholds.high =
            thresholds.value("high", policy.risk_thresholds.high);

        policy.risk_thresholds.critical =
            thresholds.value("critical", policy.risk_thresholds.critical);
    }

    if (!j.contains("rules") || !j.at("rules").is_array()) {
        throw std::runtime_error("Policy file must contain a rules array");
    }

    for (const auto& rule_json : j.at("rules")) {
        PolicyRule rule;

        rule.rule_id = rule_json.value("rule_id", "");
        rule.name = rule_json.value("name", "");
        rule.event_type = rule_json.value("event_type", "");
        rule.risk_points = rule_json.value("risk_points", 0);
        rule.severity = rule_json.value("severity", "UNKNOWN");

        rule.match_path_prefix =
            getStringArray(rule_json, "match_path_prefix");

        rule.sensitive_paths =
            getStringArray(rule_json, "sensitive_paths");

        rule.restricted_ports =
            getIntArray(rule_json, "restricted_ports");

        policy.rules.push_back(rule);
    }

    return policy;
}

RuntimePolicy loadPolicyFromFile(const std::string& file_path) {
    std::ifstream input(file_path);

    if (!input.is_open()) {
        throw std::runtime_error("Failed to open policy file: " + file_path);
    }

    nlohmann::json root;
    input >> root;

    return policyFromJson(root);
}

nlohmann::json policyToJson(const RuntimePolicy& policy) {
    nlohmann::json j;

    j["policy_version"] = policy.policy_version;
    j["mode"] = policy.mode;

    j["risk_thresholds"] = {
        {"warning", policy.risk_thresholds.warning},
        {"high", policy.risk_thresholds.high},
        {"critical", policy.risk_thresholds.critical}
    };

    j["rules"] = nlohmann::json::array();

    for (const auto& rule : policy.rules) {
        nlohmann::json rule_json;

        rule_json["rule_id"] = rule.rule_id;
        rule_json["name"] = rule.name;
        rule_json["event_type"] = rule.event_type;
        rule_json["risk_points"] = rule.risk_points;
        rule_json["severity"] = rule.severity;

        if (!rule.match_path_prefix.empty()) {
            rule_json["match_path_prefix"] = rule.match_path_prefix;
        }

        if (!rule.sensitive_paths.empty()) {
            rule_json["sensitive_paths"] = rule.sensitive_paths;
        }

        if (!rule.restricted_ports.empty()) {
            rule_json["restricted_ports"] = rule.restricted_ports;
        }

        j["rules"].push_back(rule_json);
    }

    return j;
}

} // namespace kernelgate
