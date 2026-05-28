#include "FileTelemetry.hpp"

#include <cerrno>
#include <chrono>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <iomanip>
#include <poll.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/fanotify.h>
#include <unistd.h>
#include <vector>

#include "ProcEnricher.hpp"

#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif

namespace kernelgate {

std::vector<KernelEvent> FanotifyFileSource::captureFileEvents(
    const FileWatchConfig& config
) {
    const int fan_fd = fanotify_init(
        FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK,
        O_RDONLY | O_LARGEFILE
    );

    if (fan_fd == -1) {
        throw std::runtime_error(
            "fanotify_init failed: " + std::string(std::strerror(errno)) +
            ". Try running with sudo."
        );
    }

    const uint64_t mask = FAN_OPEN | FAN_ACCESS | FAN_EVENT_ON_CHILD;

    if (fanotify_mark(
            fan_fd,
            FAN_MARK_ADD,
            mask,
            AT_FDCWD,
            config.watch_path.c_str()
        ) == -1) {
        const std::string error = std::strerror(errno);
        close(fan_fd);
        throw std::runtime_error(
            "fanotify_mark failed for " + config.watch_path + ": " + error
        );
    }

    std::vector<KernelEvent> captured_events;

    const auto deadline =
        std::chrono::steady_clock::now() +
        std::chrono::seconds(config.duration_seconds);

    struct pollfd poll_fd {};
    poll_fd.fd = fan_fd;
    poll_fd.events = POLLIN;

    while (
        std::chrono::steady_clock::now() < deadline &&
        static_cast<int>(captured_events.size()) < config.max_events
    ) {
        const int poll_result = poll(&poll_fd, 1, 500);

        if (poll_result == -1) {
            if (errno == EINTR) {
                continue;
            }

            close(fan_fd);
            throw std::runtime_error(
                "poll failed: " + std::string(std::strerror(errno))
            );
        }

        if (poll_result == 0) {
            continue;
        }

        alignas(struct fanotify_event_metadata) char buffer[8192];

        ssize_t length = read(fan_fd, buffer, sizeof(buffer));

        if (length == -1) {
            if (errno == EAGAIN) {
                continue;
            }

            close(fan_fd);
            throw std::runtime_error(
                "read from fanotify fd failed: " +
                std::string(std::strerror(errno))
            );
        }

        auto* metadata =
            reinterpret_cast<struct fanotify_event_metadata*>(buffer);

        while (FAN_EVENT_OK(metadata, length)) {
            if (metadata->vers != FANOTIFY_METADATA_VERSION) {
                close(fan_fd);
                throw std::runtime_error("fanotify metadata version mismatch");
            }

            if (metadata->fd >= 0) {
                const std::string file_path = pathFromFd(metadata->fd);
                close(metadata->fd);

                if (
                    config.target_file.empty() ||
                    file_path == config.target_file
                ) {
                    captured_events.push_back(
                        makeFileAccessEvent(
                            static_cast<int>(captured_events.size()) + 1,
                            metadata->pid,
                            file_path
                        )
                    );
                }
            }

            metadata = FAN_EVENT_NEXT(metadata, length);
        }
    }

    close(fan_fd);
    return captured_events;
}

std::string FanotifyFileSource::pathFromFd(int fd) {
    const std::string fd_path = "/proc/self/fd/" + std::to_string(fd);

    std::vector<char> buffer(4096);

    const ssize_t length = readlink(
        fd_path.c_str(),
        buffer.data(),
        buffer.size() - 1
    );

    if (length == -1) {
        return "";
    }

    buffer[length] = '\0';
    return std::string(buffer.data());
}

std::string FanotifyFileSource::currentUtcTimestamp() {
    const auto now = std::chrono::system_clock::now();
    const auto time = std::chrono::system_clock::to_time_t(now);

    std::tm utc_snapshot {};
    gmtime_r(&time, &utc_snapshot);

    std::ostringstream timestamp;
    timestamp << std::put_time(&utc_snapshot, "%Y-%m-%dT%H:%M:%SZ");

    return timestamp.str();
}

KernelEvent FanotifyFileSource::makeFileAccessEvent(
    int event_index,
    int pid,
    const std::string& file_path
) {
    KernelEvent event;

    event.event_id = "REAL-FILE-" + std::to_string(event_index);
    event.event_type = EventType::FILE_ACCESS;
    event.timestamp = currentUtcTimestamp();

    event.pid = pid;
    event.file_path = file_path;

    const auto process_info = ProcEnricher::inspectPid(pid);

    if (process_info.has_value()) {
        const auto& info = process_info.value();

        event.ppid = info.ppid;
        event.uid = info.uid;
        event.process_name = info.name;
        event.process_path = info.exe_path;
        event.command_line = info.command_line;
    } else {
        event.ppid = -1;
        event.uid = -1;
        event.process_name = "unknown";
        event.process_path = "unknown";
        event.command_line = "";
    }

    return event;
}

} // namespace kernelgate
