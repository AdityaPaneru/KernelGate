#include "RiskEvaluator.hpp"

#include <algorithm>

namespace kernelgate {

RiskEvaluator::RiskEvaluator(RuntimePolicy policy)
    : policy_(std::move(policy)) {}

EvaluationResult RiskEvaluator::evaluate(const KernelEvent& event) const {
    EvaluationResult result;
    result.event = event;

    for (const auto& rule : policy_.rules) {
        std::string reason;

        if (ruleMatchesEvent(rule, event, reason)) {
            RuleMatch match;
            match.rule_id = rule.rule_id;
            match.rule_name = rule.name;
            match.risk_points = rule.risk_points;
            match.severity = rule.severity;
            match.reason = reason;

            result.matches.push_back(match);
            result.total_risk_score += rule.risk_points;
        }
    }

    result.verdict = verdictForScore(result.total_risk_score);
    return result;
}

std::string RiskEvaluator::verdictForScore(int score) const {
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

bool RiskEvaluator::ruleMatchesEvent(
    const PolicyRule& rule,
    const KernelEvent& event,
    std::string& reason
) const {
    const std::string event_type = eventTypeToString(event.event_type);

    if (rule.event_type != event_type) {
        return false;
    }

    switch (event.event_type) {
        case EventType::EXEC:
            return matchesExecRule(rule, event, reason);

        case EventType::FILE_ACCESS:
            return matchesFileRule(rule, event, reason);

        case EventType::NET_CONNECT:
            return matchesNetworkRule(rule, event, reason);

        default:
            return false;
    }
}

bool RiskEvaluator::matchesExecRule(
    const PolicyRule& rule,
    const KernelEvent& event,
    std::string& reason
) const {
    for (const auto& prefix : rule.match_path_prefix) {
        if (startsWith(event.process_path, prefix) ||
            containsText(event.command_line, prefix)) {
            reason = "execution matched risky path prefix: " + prefix;
            return true;
        }
    }

    return false;
}

bool RiskEvaluator::matchesFileRule(
    const PolicyRule& rule,
    const KernelEvent& event,
    std::string& reason
) const {
    if (!event.file_path.has_value()) {
        return false;
    }

    for (const auto& sensitive_path : rule.sensitive_paths) {
        if (event.file_path.value() == sensitive_path) {
            reason = "sensitive file accessed: " + sensitive_path;
            return true;
        }
    }

    return false;
}

bool RiskEvaluator::matchesNetworkRule(
    const PolicyRule& rule,
    const KernelEvent& event,
    std::string& reason
) const {
    if (!event.dest_port.has_value()) {
        return false;
    }

    const int port = event.dest_port.value();

    const auto found = std::find(
        rule.restricted_ports.begin(),
        rule.restricted_ports.end(),
        port
    );

    if (found != rule.restricted_ports.end()) {
        reason = "restricted outbound port connection: " + std::to_string(port);
        return true;
    }

    return false;
}

bool RiskEvaluator::startsWith(
    const std::string& value,
    const std::string& prefix
) {
    return value.rfind(prefix, 0) == 0;
}

bool RiskEvaluator::containsText(
    const std::string& value,
    const std::string& text
) {
    return value.find(text) != std::string::npos;
}

} // namespace kernelgate
