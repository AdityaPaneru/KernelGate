#pragma once

#include <string>
#include <vector>

#include "Incident.hpp"
#include "Policy.hpp"
#include "RiskEvaluator.hpp"

namespace kernelgate {

class Correlator {
public:
    explicit Correlator(RuntimePolicy policy);

    std::vector<Incident> correlate(
        const std::vector<EvaluationResult>& evaluated_events
    ) const;

private:
    RuntimePolicy policy_;

    std::string verdictForScore(int score) const;
    std::string makeIncidentId(int index) const;
};

} // namespace kernelgate
