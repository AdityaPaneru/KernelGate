# KernelGate Testing Checklist

## Build Test

Command:

    cmake -S . -B build -G Ninja
    cmake --build build

Expected:

    kernelgate-agent builds successfully

## CLI Test

Command:

    ./build/kernelgate-agent --help

Expected options:

    --events
    --policy
    --db
    --reset-db
    --inspect-pid
    --upload
    --control-plane-url
    --device-id

## Local Detection Pipeline Test

Command:

    ./build/kernelgate-agent --reset-db

Expected:

    INC-001
    Risk score: 80
    Verdict: HIGH
    Chain: EXEC -> FILE_ACCESS -> NET_CONNECT

## SQLite Audit Test

Command:

    sqlite3 kernelgate.db "SELECT incident_id, risk_score, verdict, chain_summary FROM incidents;"

Expected:

    INC-001|80|HIGH|EXEC -> FILE_ACCESS -> NET_CONNECT

## Process Inspection Test

Command:

    ./build/kernelgate-agent --inspect-pid $$

Expected:

    PID
    PPID
    UID
    Name
    Exe
    Cmdline

## Backend Health Test

Command:

    curl http://127.0.0.1:8000/health

Expected:

    status ok

## UEM Upload Test

Backend must be running first.

Command:

    ./build/kernelgate-agent --reset-db --upload
    curl http://127.0.0.1:8000/fleet/summary

Expected:

    HIGH_RISK

## Full Demo Script Test

Command:

    ./scripts/run_uem_upload_demo.sh

Expected:

    Demo completed successfully

## Final Smoke Test

Command:

    ./scripts/final_smoke_test.sh

Expected:

    Final smoke test passed
