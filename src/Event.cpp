#include "Event.hpp"

#include <fstream>
#include <stdexcept>

namespace kernelgate {

std::string eventTypeToString(EventType type) {
    switch (type) {
        case EventType::EXEC:
            return "EXEC";
        case EventType::FILE_ACCESS:
            return "FILE_ACCESS";
        case EventType::NET_CONNECT:
            return "NET_CONNECT";
        default:
            return "UNKNOWN";
    }
}

EventType eventTypeFromString(const std::string& type) {
    if (type == "EXEC") {
        return EventType::EXEC;
    }

    if (type == "FILE_ACCESS") {
        return EventType::FILE_ACCESS;
    }

    if (type == "NET_CONNECT") {
        return EventType::NET_CONNECT;
    }

    return EventType::UNKNOWN;
}

KernelEvent eventFromJson(const nlohmann::json& j) {
    KernelEvent event;

    event.event_id = j.value("event_id", "");
    event.event_type = eventTypeFromString(j.value("event_type", "UNKNOWN"));
    event.timestamp = j.value("timestamp", "");

    event.pid = j.value("pid", -1);
    event.ppid = j.value("ppid", -1);
    event.uid = j.value("uid", -1);

    event.process_name = j.value("process_name", "");
    event.process_path = j.value("process_path", "");
    event.command_line = j.value("command_line", "");

    if (j.contains("file_path") && !j.at("file_path").is_null()) {
        event.file_path = j.at("file_path").get<std::string>();
    }

    if (j.contains("dest_ip") && !j.at("dest_ip").is_null()) {
        event.dest_ip = j.at("dest_ip").get<std::string>();
    }

    if (j.contains("dest_port") && !j.at("dest_port").is_null()) {
        event.dest_port = j.at("dest_port").get<int>();
    }

    return event;
}

nlohmann::json eventToJson(const KernelEvent& event) {
    nlohmann::json j;

    j["event_id"] = event.event_id;
    j["event_type"] = eventTypeToString(event.event_type);
    j["timestamp"] = event.timestamp;

    j["pid"] = event.pid;
    j["ppid"] = event.ppid;
    j["uid"] = event.uid;

    j["process_name"] = event.process_name;
    j["process_path"] = event.process_path;
    j["command_line"] = event.command_line;

    if (event.file_path.has_value()) {
        j["file_path"] = event.file_path.value();
    }

    if (event.dest_ip.has_value()) {
        j["dest_ip"] = event.dest_ip.value();
    }

    if (event.dest_port.has_value()) {
        j["dest_port"] = event.dest_port.value();
    }

    return j;
}

std::vector<KernelEvent> loadEventsFromFile(const std::string& file_path) {
    std::ifstream input(file_path);

    if (!input.is_open()) {
        throw std::runtime_error("Failed to open event file: " + file_path);
    }

    nlohmann::json root;
    input >> root;

    if (!root.is_array()) {
        throw std::runtime_error("Event file must contain a JSON array");
    }

    std::vector<KernelEvent> events;
    events.reserve(root.size());

    for (const auto& item : root) {
        events.push_back(eventFromJson(item));
    }

    return events;
}

} // namespace kernelgate
