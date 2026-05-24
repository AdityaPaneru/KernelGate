#include "Incident.hpp"

#include <sstream>

namespace kernelgate {

nlohmann::json incidentToJson(const Incident& incident) {
    nlohmann::json j;

    j["incident_id"] = incident.incident_id;
    j["pid"] = incident.pid;
    j["uid"] = incident.uid;
    j["process_name"] = incident.process_name;
    j["process_path"] = incident.process_path;
    j["first_seen"] = incident.first_seen;
    j["last_seen"] = incident.last_seen;
    j["total_risk_score"] = incident.total_risk_score;
    j["verdict"] = incident.verdict;
    j["chain"] = buildChainSummary(incident);

    j["events"] = nlohmann::json::array();
    for (const auto& event : incident.events) {
        j["events"].push_back(eventToJson(event));
    }

    j["matched_rules"] = nlohmann::json::array();
    for (const auto& match : incident.matched_rules) {
        nlohmann::json match_json;
        match_json["rule_id"] = match.rule_id;
        match_json["rule_name"] = match.rule_name;
        match_json["risk_points"] = match.risk_points;
        match_json["severity"] = match.severity;
        match_json["reason"] = match.reason;

        j["matched_rules"].push_back(match_json);
    }

    return j;
}

std::string buildChainSummary(const Incident& incident) {
    std::ostringstream chain;

    for (std::size_t i = 0; i < incident.events.size(); ++i) {
        chain << eventTypeToString(incident.events[i].event_type);

        if (i + 1 < incident.events.size()) {
            chain << " -> ";
        }
    }

    return chain.str();
}

} // namespace kernelgate
