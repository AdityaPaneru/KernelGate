#include "ProcEnricher.hpp"

#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <vector>

namespace kernelgate {

std::optional<ProcessInfo> ProcEnricher::inspectPid(int pid) {
    if (pid <= 0) {
        return std::nullopt;
    }

    const std::string proc_dir = "/proc/" + std::to_string(pid);
    const std::string status_path = proc_dir + "/status";
    const std::string cmdline_path = proc_dir + "/cmdline";
    const std::string exe_path = proc_dir + "/exe";

    ProcessInfo info;
    info.pid = pid;

    try {
        const std::string status_content = readFileToString(status_path);

        info.name = parseStringField(status_content, "Name");
        info.ppid = parseIntegerField(status_content, "PPid");
        info.uid = parseIntegerField(status_content, "Uid");

        const std::string raw_cmdline = readFileToString(cmdline_path);
        info.command_line = normalizeCmdline(raw_cmdline);

        info.exe_path = readSymlinkTarget(exe_path);
        info.found = true;

        return info;

    } catch (const std::exception&) {
        return std::nullopt;
    }
}

std::string ProcEnricher::readFileToString(const std::string& path) {
    std::ifstream input(path, std::ios::binary);

    if (!input.is_open()) {
        throw std::runtime_error("Failed to open file: " + path);
    }

    std::ostringstream buffer;
    buffer << input.rdbuf();

    return buffer.str();
}

std::string ProcEnricher::readSymlinkTarget(const std::string& path) {
    std::vector<char> buffer(4096);

    const ssize_t length = readlink(
        path.c_str(),
        buffer.data(),
        buffer.size() - 1
    );

    if (length == -1) {
        throw std::runtime_error("Failed to read symlink: " + path);
    }

    buffer[length] = '\0';
    return std::string(buffer.data());
}

std::string ProcEnricher::normalizeCmdline(const std::string& raw_cmdline) {
    std::string normalized = raw_cmdline;

    for (char& ch : normalized) {
        if (ch == '\0') {
            ch = ' ';
        }
    }

    while (!normalized.empty() && normalized.back() == ' ') {
        normalized.pop_back();
    }

    return normalized;
}

int ProcEnricher::parseIntegerField(
    const std::string& status_content,
    const std::string& field_name
) {
    const std::string prefix = field_name + ":";

    std::istringstream stream(status_content);
    std::string line;

    while (std::getline(stream, line)) {
        if (line.rfind(prefix, 0) == 0) {
            std::istringstream line_stream(line.substr(prefix.size()));
            int value = -1;
            line_stream >> value;
            return value;
        }
    }

    return -1;
}

std::string ProcEnricher::parseStringField(
    const std::string& status_content,
    const std::string& field_name
) {
    const std::string prefix = field_name + ":";

    std::istringstream stream(status_content);
    std::string line;

    while (std::getline(stream, line)) {
        if (line.rfind(prefix, 0) == 0) {
            std::string value = line.substr(prefix.size());

            while (!value.empty() && (value.front() == '\t' || value.front() == ' ')) {
                value.erase(value.begin());
            }

            return value;
        }
    }

    return "";
}

} // namespace kernelgate
