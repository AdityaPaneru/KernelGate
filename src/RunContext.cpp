#include "RunContext.hpp"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace kernelgate {

std::string generateRunId() {
    const auto now = std::chrono::system_clock::now();
    const auto time = std::chrono::system_clock::to_time_t(now);

    std::tm tm_snapshot{};

#if defined(_WIN32)
    localtime_s(&tm_snapshot, &time);
#else
    localtime_r(&time, &tm_snapshot);
#endif

    std::ostringstream run_id;
    run_id << "RUN-"
           << std::put_time(&tm_snapshot, "%Y%m%d-%H%M%S");

    return run_id.str();
}

} // namespace kernelgate
