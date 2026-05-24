#include "Correlator.hpp"

#include <iomanip>
#include <map>
#include <sstream>

namespace kernelgate {

Correlator::Correlator(RuntimePolicy policy)
    : policy_(std::move(policy)) {}

std::vector<Incident> Correlator::correlate(
    const std::vector<EvaluationResult>& evaluated_events
) const {
    std::map<int, Incident> incidents_by_pid;

    for (const auto& result : evaluated_events) {
        if (result.matches.empty()) {
            continue;
        }

        const auto& event = result.event;
        auto& incident = incidents_by_pid[event.pid];

        if (incident.events.empty()) {
            incident.pid = event.pid;
            incident.uid = event.uid;
            incident.process_name = event.process_name;
            incident.process_path = event.process_path;
            incident.first_seen = event.timestamp;
        }

        incident.last_seen = event.timestamp;
        incident.events.push_back(event);
        incident.total_risk_score += result.total_risk_score;

        for (const auto& match : result.matches) {
            incident.matched_rules.push_back(match);
        }
    }

    std::vector<Incident> incidents;
    incidents.reserve(incidents_by_pid.size());

    int index = 1;

    for (auto& [pid, incident] : incidents_by_pid) {
        incident.incident_id = makeIncidentId(index++);
        incident.verdict = verdictForScore(incident.total_risk_score);
        incidents.push_back(incident);
    }

    return incidents;
}

std::string Correlator::verdictForScore(int score) const {
    if (score >= policy_.risk_thresholds.critical) {
        return "CRITICAL";
    }

    if (score >= policy_.risk_thresholds.high) {
        return "HIGH";
    }

    if (score >= policy_.risk_thresholds.warning) {
        return "WARNING";
    }

    if (score > 0) {
        return "LOW";
    }

    return "CLEAN";
}

std::string Correlator::makeIncidentId(int index) const {
    std::ostringstream id;
    id << "INC-" << std::setw(3) << std::setfill('0') << index;
    return id.str();
}

} // namespace kernelgate
