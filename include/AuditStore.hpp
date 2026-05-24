#pragma once

#include <string>
#include <vector>

#include <sqlite3.h>

#include "Event.hpp"
#include "Incident.hpp"

namespace kernelgate {

class AuditStore {
public:
    explicit AuditStore(const std::string& db_path);
    ~AuditStore();

    AuditStore(const AuditStore&) = delete;
    AuditStore& operator=(const AuditStore&) = delete;

    void initialize();

    void insertRawEvent(const KernelEvent& event);
    void insertIncident(const Incident& incident);
    void insertIncidentRuleMatches(const Incident& incident);

private:
    sqlite3* db_ = nullptr;
    std::string db_path_;

    void execute(const std::string& sql);
    void open();
    void close();

    static std::string optionalStringValue(
        const std::optional<std::string>& value
    );

    static int optionalIntValue(
        const std::optional<int>& value
    );
};

} // namespace kernelgate
