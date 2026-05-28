# KernelGate

KernelGate is a C++ Linux endpoint runtime policy engine prototype. It demonstrates endpoint event normalization, JSON policy evaluation, risk scoring, incident correlation, SQLite audit storage, Linux /proc process enrichment, and mock UEM-style incident upload.

It was built as an Omnissa-targeted systems project focused on endpoint visibility, compliance posture, incident reporting, and fleet-level risk awareness.

## Core Demo

KernelGate detects and correlates a suspicious behavior chain:

    EXEC -> FILE_ACCESS -> NET_CONNECT

Demo incident:

    bash executes a suspicious script
    same process accesses /etc/passwd
    same process attempts connection to port 4444
    final verdict: HIGH risk

## Current Capabilities

    C++20 endpoint agent
    JSON runtime policy loading
    Synthetic runtime event replay
    EXEC, FILE_ACCESS, and NET_CONNECT event support
    Risk scoring
    Incident correlation by PID
    SQLite local audit storage
    run_id-based audit grouping
    Linux /proc process inspection
    CLI support
    FastAPI mock UEM backend
    Incident upload using libcurl
    Final smoke test script
    Demo and interview documentation

## Architecture

    sample_events/*.json
            |
            v
    +-------------------+
    | Event Loader      |
    +-------------------+
            |
            v
    +-------------------+        config/runtime_policy.json
    | KernelEvent Model | <--------------+
    +-------------------+                |
            |                            |
            v                            v
    +-------------------+        +-------------------+
    | RiskEvaluator     | <------| PolicyLoader      |
    +-------------------+        +-------------------+
            |
            v
    +-------------------+
    | Correlator        |
    +-------------------+
            |
            v
    +-------------------+       +-----------------------+
    | Incident Model    | ----> | SQLite Audit Store    |
    +-------------------+       +-----------------------+
            |
            v
    +-------------------+
    | UEM Upload Client |
    +-------------------+
            |
            v
    +-----------------------------+
    | FastAPI Mock Control Plane  |
    +-----------------------------+

## Repository Structure

    backend/
        main.py
        requirements.txt

    config/
        runtime_policy.json

    docs/
        ARCHITECTURE.md
        DEMO_GUIDE.md
        INTERVIEW_NOTES.md
        PROJECT_STATUS.md
        SAMPLE_DEMO_OUTPUT.md
        TESTING_CHECKLIST.md
        RESUME_BULLETS.md
        FINAL_INTERVIEW_SCRIPT.md

    include/
        Event.hpp
        Policy.hpp
        RiskEvaluator.hpp
        Incident.hpp
        Correlator.hpp
        AuditStore.hpp
        ProcEnricher.hpp
        RunContext.hpp
        UemClient.hpp

    src/
        Event.cpp
        PolicyLoader.cpp
        RiskEvaluator.cpp
        Incident.cpp
        Correlator.cpp
        AuditStore.cpp
        ProcEnricher.cpp
        RunContext.cpp
        UemClient.cpp
        main.cpp

    scripts/
        generate_suspicious_events.sh
        run_phase5_demo.sh
        run_uem_upload_demo.sh
        final_smoke_test.sh

## Install Dependencies

C++ dependencies:

    sudo apt install -y \
      build-essential \
      cmake \
      ninja-build \
      nlohmann-json3-dev \
      libsqlite3-dev \
      libssl-dev \
      libcurl4-openssl-dev \
      sqlite3 \
      curl

Python backend:

    python3 -m venv backend/venv
    source backend/venv/bin/activate
    pip install -r backend/requirements.txt

## Build

    cmake -S . -B build -G Ninja
    cmake --build build

## Run Local Agent Demo

    ./build/kernelgate-agent --reset-db

Expected:

    INC-001
    Risk score: 80
    Verdict: HIGH
    Chain: EXEC -> FILE_ACCESS -> NET_CONNECT

## Inspect a Real Linux Process

    ./build/kernelgate-agent --inspect-pid $$

This reads process metadata from:

    /proc/<pid>/status
    /proc/<pid>/cmdline
    /proc/<pid>/exe

## Run Mock UEM Backend

Terminal 1:

    source backend/venv/bin/activate
    python3 backend/main.py

Health check:

    curl http://127.0.0.1:8000/health

## Upload Incident to Backend

Terminal 2:

    ./build/kernelgate-agent --reset-db --upload

Check backend:

    curl http://127.0.0.1:8000/incidents
    curl http://127.0.0.1:8000/fleet/summary

Expected fleet summary:

    status: HIGH_RISK

## One-Command UEM Demo

With backend running:

    ./scripts/run_uem_upload_demo.sh

## Final Smoke Test

    ./scripts/final_smoke_test.sh

Expected:

    Final smoke test passed

## CLI Options

    ./build/kernelgate-agent
    ./build/kernelgate-agent --events <event_json>
    ./build/kernelgate-agent --policy <policy_json>
    ./build/kernelgate-agent --db <sqlite_db>
    ./build/kernelgate-agent --reset-db
    ./build/kernelgate-agent --inspect-pid <pid>
    ./build/kernelgate-agent --upload
    ./build/kernelgate-agent --control-plane-url <url>
    ./build/kernelgate-agent --device-id <id>
    ./build/kernelgate-agent --help

## Why This Is Not Just a Log Parser

A log parser only reads existing text logs and finds patterns.

KernelGate has a structured endpoint pipeline:

    typed event model
    runtime policy model
    risk evaluator
    incident correlator
    SQLite audit store
    /proc process enrichment
    UEM upload path

The strongest feature is correlation:

    EXEC + FILE_ACCESS + NET_CONNECT -> one incident

## Current Limitations

KernelGate currently uses synthetic and controlled demo events. It does not yet capture all kernel-level runtime events.

Future event sources:

    fanotify for sensitive file access
    eBPF tracepoints for process execution
    eBPF hooks for network telemetry

## Interview Positioning

KernelGate is a modular C++ endpoint runtime policy engine that converts process, file, and network activity into correlated incidents, stores audit evidence locally, enriches process context through /proc, and reports high-risk incidents to a UEM-style control plane.
