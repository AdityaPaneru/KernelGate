# KernelGate Demo Guide

## Build

Run:

    cmake -S . -B build -G Ninja
    cmake --build build

## Local Agent Demo

Run:

    ./build/kernelgate-agent --reset-db

Expected result:

    INC-001
    Risk score: 80
    Verdict: HIGH
    Chain: EXEC -> FILE_ACCESS -> NET_CONNECT

This proves KernelGate can load events, load policy, score risk, correlate incidents, and store audit data locally.

## SQLite Audit Store

Show tables:

    sqlite3 kernelgate.db ".tables"

Expected tables:

    raw_events
    incidents
    incident_rule_matches

Query incidents:

    sqlite3 kernelgate.db "SELECT run_id, incident_id, risk_score, verdict, chain_summary FROM incidents;"

## Process Inspection

Run:

    ./build/kernelgate-agent --inspect-pid $$

This reads real Linux process metadata from /proc.

KernelGate reads:

    /proc/<pid>/status
    /proc/<pid>/cmdline
    /proc/<pid>/exe

## Start Backend

In Terminal 1:

    cd ~/omnissa-projects/kernelgate
    source backend/venv/bin/activate
    python3 backend/main.py

If port 8000 is already in use, the backend is already running.

## Reset Backend State

In Terminal 2:

    curl -X POST http://127.0.0.1:8000/reset

## Upload Incident

Run:

    ./build/kernelgate-agent --reset-db --upload

Expected output:

    [UPLOAD] Incident INC-001 uploaded to http://127.0.0.1:8000/incident

## Check Backend

Run:

    curl http://127.0.0.1:8000/incidents
    curl http://127.0.0.1:8000/fleet/summary

Expected fleet status:

    HIGH_RISK

## One-Command UEM Upload Demo

With backend running:

    ./scripts/run_uem_upload_demo.sh

Expected final line:

    Demo completed successfully
