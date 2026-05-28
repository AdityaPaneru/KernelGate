#pragma once

#include <optional>
#include <string>

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

    void insertRawEvent(const KernelEvent& event, const std::string& run_id);
    void insertIncident(const Incident& incident, const std::string& run_id);
    void insertIncidentRuleMatches(
        const Incident& incident,
        const std::string& run_id
    );

private:
    sqlite3* db_ = nullptr;
    std::string db_path_;

    void execute(const std::string& sql);
    void open();
    void close();

    void ensureColumnExists(
        const std::string& table_name,
        const std::string& column_name,
        const std::string& column_definition
    );

    static std::string optionalStringValue(
        const std::optional<std::string>& value
    );

    static int optionalIntValue(
        const std::optional<int>& value
    );
};

} // namespace kernelgate
