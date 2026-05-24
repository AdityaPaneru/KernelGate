#include <iostream>
#include <exception>

#include <nlohmann/json.hpp>
#include "Event.hpp"

int main() {
    try {
        nlohmann::json startup = {
            {"project", "KernelGate"},
            {"module", "phase-1A-event-replay"},
            {"status", "running"},
            {"goal", "C++ endpoint runtime policy engine"}
        };

        std::cout << startup.dump(4) << "\n\n";

        const std::string event_file = "sample_events/suspicious_chain.json";
        const auto events = kernelgate::loadEventsFromFile(event_file);

        std::cout << "Loaded " << events.size()
                  << " synthetic runtime events from "
                  << event_file << "\n\n";

        for (const auto& event : events) {
            const auto normalized = kernelgate::eventToJson(event);
            std::cout << normalized.dump(4) << "\n\n";
        }

        std::cout << "KernelGate Phase 1A event replay completed successfully.\n";
        return 0;

    } catch (const std::exception& ex) {
        std::cerr << "KernelGate error: " << ex.what() << "\n";
        return 1;
    }
}
