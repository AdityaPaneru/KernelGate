# KernelGate Claude Instructions

Project:
KernelGate is a C++ endpoint runtime policy engine for an Omnissa-targeted portfolio project.

Important:
- We are building only KernelGate.
- Do not create AccessGate files or unrelated projects.
- Do not turn this into a cron job, shell script, or simple process monitor.
- The project must stay endpoint-agent focused.
- Phase 1 uses synthetic runtime events and /proc enrichment.
- Phase 2 may add fanotify.
- Phase 3 may add eBPF if the environment supports it.
- Use C++20, CMake, SQLite, nlohmann/json, and modular class design.
- Never run sudo commands unless I explicitly approve.
- Before changing code, explain the files you plan to edit.
- Keep functions small, testable, and readable.
- Do not implement eBPF, fanotify, backend, or SQLite until the Phase 1 event pipeline works.

Phase 1 build order:
1. Event model
2. Sample event replay
3. Policy loader
4. Risk evaluator
5. Console incident output

Planned Phase 1 files:
- include/Event.hpp
- src/Event.cpp
- sample_events/suspicious_chain.json
- include/Policy.hpp
- src/PolicyLoader.cpp
- include/RiskEvaluator.hpp
- src/RiskEvaluator.cpp
