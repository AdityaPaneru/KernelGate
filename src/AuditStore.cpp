#include "AuditStore.hpp"

#include <iostream>
#include <stdexcept>

namespace kernelgate {

AuditStore::AuditStore(const std::string& db_path)
    : db_path_(db_path) {
    open();
}

AuditStore::~AuditStore() {
    close();
}

void AuditStore::open() {
    if (sqlite3_open(db_path_.c_str(), &db_) != SQLITE_OK) {
        std::string error = sqlite3_errmsg(db_);
        throw std::runtime_error("Failed to open SQLite database: " + error);
    }
}

void AuditStore::close() {
    if (db_ != nullptr) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

void AuditStore::execute(const std::string& sql) {
    char* error_message = nullptr;

    const int rc = sqlite3_exec(
        db_,
        sql.c_str(),
        nullptr,
        nullptr,
        &error_message
    );

    if (rc != SQLITE_OK) {
        std::string error = error_message ? error_message : "unknown SQLite error";
        sqlite3_free(error_message);
        throw std::runtime_error("SQLite execute failed: " + error);
    }
}

void AuditStore::initialize() {
    execute(
        "CREATE TABLE IF NOT EXISTS raw_events ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "event_id TEXT NOT NULL,"
        "event_type TEXT NOT NULL,"
        "timestamp TEXT,"
        "pid INTEGER,"
        "ppid INTEGER,"
        "uid INTEGER,"
        "process_name TEXT,"
        "process_path TEXT,"
        "command_line TEXT,"
        "file_path TEXT,"
        "dest_ip TEXT,"
        "dest_port INTEGER"
        ");"
    );

    execute(
        "CREATE TABLE IF NOT EXISTS incidents ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "incident_id TEXT NOT NULL,"
        "pid INTEGER,"
        "uid INTEGER,"
        "process_name TEXT,"
        "process_path TEXT,"
        "first_seen TEXT,"
        "last_seen TEXT,"
        "chain_summary TEXT,"
        "risk_score INTEGER,"
        "verdict TEXT"
        ");"
    );

    execute(
        "CREATE TABLE IF NOT EXISTS incident_rule_matches ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "incident_id TEXT NOT NULL,"
        "rule_id TEXT,"
        "rule_name TEXT,"
        "risk_points INTEGER,"
        "severity TEXT,"
        "reason TEXT"
        ");"
    );
}

std::string AuditStore::optionalStringValue(
    const std::optional<std::string>& value
) {
    return value.has_value() ? value.value() : "";
}

int AuditStore::optionalIntValue(
    const std::optional<int>& value
) {
    return value.has_value() ? value.value() : -1;
}

void AuditStore::insertRawEvent(const KernelEvent& event) {
    sqlite3_stmt* stmt = nullptr;

    const char* sql =
        "INSERT INTO raw_events ("
        "event_id, event_type, timestamp, pid, ppid, uid, "
        "process_name, process_path, command_line, file_path, dest_ip, dest_port"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error(
            "Failed to prepare raw_events insert: " +
            std::string(sqlite3_errmsg(db_))
        );
    }

    const std::string event_type = eventTypeToString(event.event_type);
    const std::string file_path = optionalStringValue(event.file_path);
    const std::string dest_ip = optionalStringValue(event.dest_ip);
    const int dest_port = optionalIntValue(event.dest_port);

    sqlite3_bind_text(stmt, 1, event.event_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, event_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, event.timestamp.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, event.pid);
    sqlite3_bind_int(stmt, 5, event.ppid);
    sqlite3_bind_int(stmt, 6, event.uid);
    sqlite3_bind_text(stmt, 7, event.process_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 8, event.process_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 9, event.command_line.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 10, file_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 11, dest_ip.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 12, dest_port);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::string error = sqlite3_errmsg(db_);
        sqlite3_finalize(stmt);
        throw std::runtime_error("Failed to insert raw event: " + error);
    }

    sqlite3_finalize(stmt);
}

void AuditStore::insertIncident(const Incident& incident) {
    sqlite3_stmt* stmt = nullptr;

    const char* sql =
        "INSERT INTO incidents ("
        "incident_id, pid, uid, process_name, process_path, "
        "first_seen, last_seen, chain_summary, risk_score, verdict"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error(
            "Failed to prepare incidents insert: " +
            std::string(sqlite3_errmsg(db_))
        );
    }

    const std::string chain_summary = buildChainSummary(incident);

    sqlite3_bind_text(stmt, 1, incident.incident_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, incident.pid);
    sqlite3_bind_int(stmt, 3, incident.uid);
    sqlite3_bind_text(stmt, 4, incident.process_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, incident.process_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, incident.first_seen.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, incident.last_seen.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 8, chain_summary.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 9, incident.total_risk_score);
    sqlite3_bind_text(stmt, 10, incident.verdict.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::string error = sqlite3_errmsg(db_);
        sqlite3_finalize(stmt);
        throw std::runtime_error("Failed to insert incident: " + error);
    }

    sqlite3_finalize(stmt);
}

void AuditStore::insertIncidentRuleMatches(const Incident& incident) {
    sqlite3_stmt* stmt = nullptr;

    const char* sql =
        "INSERT INTO incident_rule_matches ("
        "incident_id, rule_id, rule_name, risk_points, severity, reason"
        ") VALUES (?, ?, ?, ?, ?, ?);";

    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error(
            "Failed to prepare incident_rule_matches insert: " +
            std::string(sqlite3_errmsg(db_))
        );
    }

    for (const auto& match : incident.matched_rules) {
        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);

        sqlite3_bind_text(stmt, 1, incident.incident_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, match.rule_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, match.rule_name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 4, match.risk_points);
        sqlite3_bind_text(stmt, 5, match.severity.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 6, match.reason.c_str(), -1, SQLITE_TRANSIENT);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            std::string error = sqlite3_errmsg(db_);
            sqlite3_finalize(stmt);
            throw std::runtime_error(
                "Failed to insert incident rule match: " + error
            );
        }
    }

    sqlite3_finalize(stmt);
}

} // namespace kernelgate
