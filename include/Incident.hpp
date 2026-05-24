#pragma once

#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "Event.hpp"
#include "RiskEvaluator.hpp"

namespace kernelgate {

struct Incident {
    std::string incident_id;

    int pid = -1;
    int uid = -1;

    std::string process_name;
    std::string process_path;

    std::string first_seen;
    std::string last_seen;

    int total_risk_score = 0;
    std::string verdict = "CLEAN";

    std::vector<KernelEvent> events;
    std::vector<RuleMatch> matched_rules;
};

nlohmann::json incidentToJson(const Incident& incident);
std::string buildChainSummary(const Incident& incident);

} // namespace kernelgate
