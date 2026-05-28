#pragma once

#include <string>

#include "Incident.hpp"

namespace kernelgate {

class UemClient {
public:
    explicit UemClient(std::string base_url);

    bool uploadIncident(
        const Incident& incident,
        const std::string& run_id,
        const std::string& device_id
    ) const;

private:
    std::string base_url_;

    static std::string buildIncidentPayload(
        const Incident& incident,
        const std::string& run_id,
        const std::string& device_id
    );
};

} // namespace kernelgate
