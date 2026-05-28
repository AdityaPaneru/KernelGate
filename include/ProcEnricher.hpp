#pragma once

#include <optional>
#include <string>

namespace kernelgate {

struct ProcessInfo {
    int pid = -1;
    int ppid = -1;
    int uid = -1;

    std::string name;
    std::string exe_path;
    std::string command_line;

    bool found = false;
};

class ProcEnricher {
public:
    static std::optional<ProcessInfo> inspectPid(int pid);

private:
    static std::string readFileToString(const std::string& path);
    static std::string readSymlinkTarget(const std::string& path);
    static std::string normalizeCmdline(const std::string& raw_cmdline);

    static int parseIntegerField(
        const std::string& status_content,
        const std::string& field_name
    );

    static std::string parseStringField(
        const std::string& status_content,
        const std::string& field_name
    );
};

} // namespace kernelgate
