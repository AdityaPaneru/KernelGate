#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace kernelgate {

enum class EventType {
    EXEC,
    FILE_ACCESS,
    NET_CONNECT,
    UNKNOWN
};

struct KernelEvent {
    std::string event_id;
    EventType event_type = EventType::UNKNOWN;
    std::string timestamp;

    int pid = -1;
    int ppid = -1;
    int uid = -1;

    std::string process_name;
    std::string process_path;
    std::string command_line;

    std::optional<std::string> file_path;
    std::optional<std::string> dest_ip;
    std::optional<int> dest_port;
};

std::string eventTypeToString(EventType type);
EventType eventTypeFromString(const std::string& type);

KernelEvent eventFromJson(const nlohmann::json& j);
nlohmann::json eventToJson(const KernelEvent& event);

std::vector<KernelEvent> loadEventsFromFile(const std::string& file_path);

} // namespace kernelgate
