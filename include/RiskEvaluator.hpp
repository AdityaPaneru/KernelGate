#pragma once

#include <string>
#include <vector>

#include "Event.hpp"
#include "Policy.hpp"

namespace kernelgate {

struct RuleMatch {
    std::string rule_id;
    std::string rule_name;
    int risk_points = 0;
    std::string severity;
    std::string reason;
};

struct EvaluationResult {
    KernelEvent event;
    int total_risk_score = 0;
    std::string verdict = "CLEAN";
    std::vector<RuleMatch> matches;
};

class RiskEvaluator {
public:
    explicit RiskEvaluator(RuntimePolicy policy);

    EvaluationResult evaluate(const KernelEvent& event) const;
    std::string verdictForScore(int score) const;

private:
    RuntimePolicy policy_;

    bool ruleMatchesEvent(
        const PolicyRule& rule,
        const KernelEvent& event,
        std::string& reason
    ) const;

    bool matchesExecRule(
        const PolicyRule& rule,
        const KernelEvent& event,
        std::string& reason
    ) const;

    bool matchesFileRule(
        const PolicyRule& rule,
        const KernelEvent& event,
        std::string& reason
    ) const;

    bool matchesNetworkRule(
        const PolicyRule& rule,
        const KernelEvent& event,
        std::string& reason
    ) const;

    static bool startsWith(const std::string& value, const std::string& prefix);
    static bool containsText(const std::string& value, const std::string& text);
};

} // namespace kernelgate
