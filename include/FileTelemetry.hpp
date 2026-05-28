#pragma once

#include <string>
#include <vector>

#include "Event.hpp"

namespace kernelgate {

struct FileWatchConfig {
    std::string watch_path = "/etc";
    std::string target_file = "/etc/passwd";
    int duration_seconds = 15;
    int max_events = 5;
};

class FanotifyFileSource {
public:
    static std::vector<KernelEvent> captureFileEvents(
        const FileWatchConfig& config
    );

private:
    static std::string pathFromFd(int fd);
    static std::string currentUtcTimestamp();

    static KernelEvent makeFileAccessEvent(
        int event_index,
        int pid,
        const std::string& file_path
    );
};

} // namespace kernelgate
