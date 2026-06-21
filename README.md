# KernelGate

> **A C++20 Linux endpoint runtime policy engine prototype** that turns process, file-access, and network activity into explainable security incidents.

KernelGate is a systems-security project that models the core flow of an endpoint detection agent:

```text
Runtime activity → normalized event → policy evaluation → risk score
→ correlation by process → incident → local audit storage → optional backend reporting
```

It is designed as a learning-oriented, modular prototype—not a production endpoint protection product. Its emphasis is on clear event modeling, explainable detection decisions, incident correlation, and Linux-facing telemetry.

---

## Why KernelGate?

A single system action is often not enough to establish risk. For example, a process reading a file may be legitimate. But a **single process** that:

1. executes a script from `/tmp`,
2. accesses `/etc/passwd`, and
3. connects to a restricted port such as `4444`,

creates a much stronger suspicious behavior chain.

KernelGate detects this sequence and correlates it into one incident:

```text
EXEC → FILE_ACCESS → NET_CONNECT
```

---

## Features

- **C++20 endpoint agent** built with CMake and Ninja
- Common `KernelEvent` model for `EXEC`, `FILE_ACCESS`, and `NET_CONNECT`
- JSON-based runtime policy loading
- Rule-based, explainable risk scoring
- PID-based incident correlation
- SQLite audit storage with `run_id` grouping
- Linux `/proc` process inspection and enrichment
- Real file-access telemetry demo using **fanotify**
- Optional process-execution tracing demo using **eBPF/bpftrace**
- Optional incident upload to a FastAPI mock UEM control plane using `libcurl`
- CLI options for custom policy, events, database path, device ID, and backend URL

---

## Architecture

```text
                         config/runtime_policy.json
                                   │
                                   ▼
Sample JSON events ──► Event Loader ──► KernelEvent ──► RiskEvaluator
                                                     │        │
                                                     │        ▼
                                                     │   Rule matches + score
                                                     ▼
                                             Correlator (by PID)
                                                     │
                                                     ▼
                                                  Incident
                                                     │
                              ┌──────────────────────┴──────────────────────┐
                              ▼                                             ▼
                    SQLite AuditStore                             UemClient (optional)
           raw_events / incidents / rule_matches                         │
                                                                          ▼
                                                        FastAPI Mock UEM Backend

Real file access: fanotify ──► KernelEvent ──► same evaluation/correlation/audit flow

Optional exec tracing: eBPF/bpftrace ──► terminal telemetry proof-of-concept
```

### Main detection flow

```text
Event source
   ↓
KernelEvent
   ↓
RiskEvaluator checks JSON rules
   ↓
Each matching rule adds risk points
   ↓
Correlator groups related evaluated events by PID
   ↓
Incident is created with chain summary and final verdict
   ↓
SQLite stores evidence; optional UEM upload reports the incident
```

---

## Demo Scenario

The default controlled demo replays three events for the same `bash` process (`PID 3101`):

| Event | Activity | Rule | Score |
|---|---|---|---:|
| `EXEC` | Executes `bash /tmp/suspicious.sh` | `EXEC_TMP_001` | +30 |
| `FILE_ACCESS` | Accesses `/etc/passwd` | `SENSITIVE_FILE_001` | +25 |
| `NET_CONNECT` | Connects to port `4444` | `RESTRICTED_PORT_001` | +25 |

The individual events are below the warning threshold, but correlation produces:

```text
Incident: INC-001
Chain: EXEC → FILE_ACCESS → NET_CONNECT
Risk score: 80
Verdict: HIGH
```

---

## Policy Rules

Rules are configured in [`config/runtime_policy.json`](config/runtime_policy.json).

| Rule ID | Detects | Matching values | Risk points |
|---|---|---|---:|
| `EXEC_TMP_001` | Execution from temporary locations | `/tmp`, `/dev/shm`, `/var/tmp` | 30 |
| `SENSITIVE_FILE_001` | Access to sensitive files | `/etc/passwd`, `/etc/shadow`, `/etc/ssh/sshd_config` | 25 |
| `RESTRICTED_PORT_001` | Connection to restricted outbound ports | `4444`, `5555`, `6666` | 25 |

Default thresholds:

```text
WARNING  = 40
HIGH     = 70
CRITICAL = 90
```

The default mode is `REPORT_ONLY`: KernelGate reports suspicious activity but does not block it.

---

## Tech Stack

| Area | Technology |
|---|---|
| Core agent | C++20 |
| Build system | CMake + Ninja |
| JSON | nlohmann/json |
| Local audit database | SQLite3 |
| HTTP client | libcurl |
| Linux telemetry | `/proc`, fanotify, optional eBPF/bpftrace |
| Mock control plane | FastAPI + Uvicorn + Pydantic |
| Platform | Linux / WSL2-compatible environment |

---

## Repository Structure

```text
KernelGate/
├── backend/
│   ├── main.py                    # FastAPI mock UEM control plane
│   └── requirements.txt
├── config/
│   └── runtime_policy.json        # Detection rules and thresholds
├── include/
│   ├── Event.hpp                  # KernelEvent model
│   ├── Policy.hpp                 # Policy and rule models
│   ├── RiskEvaluator.hpp          # Rule evaluation interface
│   ├── Incident.hpp               # Incident model
│   ├── Correlator.hpp             # PID-based event correlation
│   ├── AuditStore.hpp             # SQLite persistence interface
│   ├── ProcEnricher.hpp           # /proc process inspection
│   ├── FileTelemetry.hpp          # fanotify file-event source
│   ├── RunContext.hpp             # Run ID generation
│   └── UemClient.hpp              # HTTP upload client
├── sample_events/
│   └── suspicious_chain.json      # Default controlled event chain
├── scripts/
│   ├── generate_suspicious_events.sh
│   ├── run_phase5_demo.sh
│   ├── run_uem_upload_demo.sh
│   ├── run_ebpf_exec_demo.sh
│   ├── trigger_exec_events.sh
│   └── ebpf_exec_monitor.bt
├── src/
│   ├── main.cpp                   # Main agent pipeline + CLI parsing
│   ├── Event.cpp
│   ├── PolicyLoader.cpp
│   ├── RiskEvaluator.cpp
│   ├── Incident.cpp
│   ├── Correlator.cpp
│   ├── AuditStore.cpp
│   ├── ProcEnricher.cpp
│   ├── FileTelemetry.cpp
│   ├── RunContext.cpp
│   ├── UemClient.cpp
│   └── fanotify_demo.cpp
├── CMakeLists.txt
└── README.md
```

---

## Prerequisites

Use Ubuntu, another Linux distribution, or WSL2 with a Linux kernel.

### System dependencies

```bash
sudo apt update
sudo apt install -y \
  build-essential \
  cmake \
  ninja-build \
  nlohmann-json3-dev \
  sqlite3 \
  libsqlite3-dev \
  libssl-dev \
  libcurl4-openssl-dev \
  python3 \
  python3-venv \
  python3-pip \
  curl
```

### Optional eBPF dependency

```bash
sudo apt install -y bpftrace
```

> eBPF support can depend on your Linux kernel and WSL configuration. The core JSON, SQLite, `/proc`, and backend demos do not depend on eBPF.

---

## Build

From the project root:

```bash
cmake -S . -B build -G Ninja
cmake --build build
```

The build creates:

```text
build/kernelgate-agent
build/kernelgate-fanotify-demo
```

---

## Quick Start: Default Detection Demo

Run the C++ agent with a fresh SQLite database:

```bash
./build/kernelgate-agent --reset-db
```

Expected final incident:

```text
[INCIDENT] INC-001
  Chain: EXEC -> FILE_ACCESS -> NET_CONNECT
  Risk score: 80
  Verdict: HIGH
```

Confirm that the incident was persisted locally:

```bash
sqlite3 kernelgate.db \
  "SELECT incident_id, risk_score, verdict, chain_summary FROM incidents;"
```

Expected output:

```text
INC-001|80|HIGH|EXEC -> FILE_ACCESS -> NET_CONNECT
```

### Optional local helper script

If you keep a local `run.sh` helper in the repository, you can use:

```bash
./run.sh
```

The portable commands above remain the official build-and-run path because `run.sh` is a local convenience wrapper.

---

## Inspect a Real Linux Process with `/proc`

Inspect the current shell process:

```bash
./build/kernelgate-agent --inspect-pid $$
```

KernelGate reads data from:

```text
/proc/<pid>/status
/proc/<pid>/cmdline
/proc/<pid>/exe
```

Example output fields:

```text
[PROC] PID: ...
[PROC] PPID: ...
[PROC] UID: ...
[PROC] Name: bash
[PROC] Exe: /usr/bin/bash
[PROC] Cmdline: ...
```

---

## Use a Custom Event File or Policy

```bash
./build/kernelgate-agent \
  --events sample_events/suspicious_chain.json \
  --policy config/runtime_policy.json \
  --db kernelgate.db \
  --reset-db
```

Useful CLI options:

```text
--events <event_json>             Use a custom event file
--policy <policy_json>            Use a custom runtime policy
--db <sqlite_db>                  Store audit records in a custom database file
--reset-db                        Delete the selected database before the run
--inspect-pid <pid>               Inspect a live Linux process through /proc
--upload                          Upload generated incidents to the control plane
--control-plane-url <url>         Override the default backend URL
--device-id <id>                  Set the endpoint identifier in uploaded data
--help                            Print usage information
```

---

## Controlled “Live” Event Generation Demo

This helper creates a controlled local script, executes it, and writes a new JSON event file with current timestamps and PID values. The main agent then replays that generated file through the normal policy pipeline.

Build once first, then run:

```bash
./scripts/run_phase5_demo.sh
```

Generated file:

```text
sample_events/live_demo_chain.json
```

This is still a controlled JSON replay for the main pipeline; it is useful for demonstrations because each execution produces a fresh event file.

---

## Real File-Access Telemetry with fanotify

KernelGate includes a separate C++ executable that captures real file-access activity through Linux `fanotify` and then uses the same policy evaluation, correlation, and SQLite audit flow.

### Terminal 1: Start the watcher

```bash
sudo ./build/kernelgate-fanotify-demo \
  --reset-db \
  --duration 30 \
  --db /tmp/kernelgate_fanotify.db
```

### Terminal 2: Access the watched file during the window

```bash
cat /etc/passwd > /dev/null
```

Expected behavior:

```text
[REAL_EVENT] ... | type=FILE_ACCESS | ... | file=/etc/passwd
[MATCH] SENSITIVE_FILE_001 | +25 | reason=sensitive file accessed: /etc/passwd
```

The demo requires `sudo` because fanotify interacts with kernel notification APIs.

---

## Optional Process-Execution Telemetry with eBPF

The eBPF demo uses `bpftrace` and attaches to:

```text
tracepoint:syscalls:sys_enter_execve
```

It prints real execution telemetry such as PID, UID, command name, and executable filename.

### Terminal 1: Start the monitor

```bash
./scripts/run_ebpf_exec_demo.sh
```

### Terminal 2: Generate safe example executions

```bash
./scripts/trigger_exec_events.sh
```

Expected style of output in Terminal 1:

```text
[EBPF_EXEC] pid=1234 uid=1000 comm=whoami filename=/usr/bin/whoami
[EBPF_EXEC] pid=1235 uid=1000 comm=ls filename=/usr/bin/ls
```

Stop the monitor with `Ctrl+C`.

> **Current scope:** eBPF is a telemetry proof-of-concept. It prints real `execve` observations but is not yet directly wired into the C++ `RiskEvaluator → Correlator → SQLite` pipeline.

---

## Mock UEM Backend and Incident Upload

The backend is a small FastAPI mock control plane. It receives incidents in memory and exposes simple health, incident, reset, and fleet-summary endpoints.

### Start backend — Terminal 1

```bash
python3 -m venv backend/venv
source backend/venv/bin/activate
pip install -r backend/requirements.txt
python3 backend/main.py
```

Expected server address:

```text
http://127.0.0.1:8000
```

Check backend health:

```bash
curl http://127.0.0.1:8000/health
```

### Upload incident — Terminal 2

```bash
./build/kernelgate-agent --reset-db --upload
```

Check backend data:

```bash
curl http://127.0.0.1:8000/incidents
curl http://127.0.0.1:8000/fleet/summary
```

Expected summary after the default HIGH-risk incident is uploaded:

```json
{
  "total_incidents": 1,
  "high_risk_incidents": 1,
  "status": "HIGH_RISK"
}
```

### Backend endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/` | Basic service status |
| `GET` | `/health` | Health check |
| `POST` | `/incident` | Receive one incident upload |
| `GET` | `/incidents` | List received incidents |
| `POST` | `/reset` | Clear in-memory incident list |
| `GET` | `/fleet/summary` | Return total and high-risk incident counts |

> The FastAPI backend intentionally stores received incidents **only in memory**. Restarting it clears the received incident list.

---

## SQLite Audit Data

The local `kernelgate.db` database contains three core tables:

| Table | Purpose |
|---|---|
| `raw_events` | Original normalized events received during a run |
| `incidents` | Correlated incidents with final score, verdict, and behavior chain |
| `incident_rule_matches` | Explainable evidence: which rules matched and why |

Example queries:

```bash
sqlite3 kernelgate.db ".tables"
```

```bash
sqlite3 kernelgate.db \
  "SELECT run_id, incident_id, risk_score, verdict, chain_summary FROM incidents;"
```

```bash
sqlite3 kernelgate.db \
  "SELECT incident_id, rule_id, risk_points, reason FROM incident_rule_matches;"
```

---

## What Makes This More Than a Log Parser?

A log parser usually reads already-written text logs and searches for patterns.

KernelGate instead uses a structured endpoint pipeline:

```text
typed event model
+ external JSON policy
+ per-event risk evaluation
+ correlation by process identity
+ SQLite evidence storage
+ Linux /proc enrichment
+ optional live fanotify capture
+ optional UEM-style reporting
```

The key value is **behavior correlation**:

```text
EXEC + FILE_ACCESS + NET_CONNECT → one explainable HIGH-risk incident
```

---

## Current Limitations

- Main `EXEC` and `NET_CONNECT` detection in the agent is currently demonstrated with controlled JSON event replay.
- Live `NET_CONNECT` kernel telemetry is planned, not yet implemented.
- The eBPF demo is currently separate from the C++ risk pipeline.
- Correlation is primarily PID-based; production systems would also consider process trees, timestamps, user sessions, command lines, and parent PID relationships.
- The agent is report-only; it does not block, quarantine, or kill processes.
- The mock backend stores incidents only in memory and has no authentication, persistent database, TLS, or retry queue.
- fanotify and eBPF depend on Linux permissions/kernel capability and may behave differently on WSL.

---

## Future Improvements

- Feed eBPF `execve` events directly into the C++ `KernelEvent` pipeline
- Add live network telemetry through eBPF or netlink
- Add time-window and process-tree correlation
- Add rule hot-reload and richer policy conditions
- Add secure backend authentication, HTTPS, retry queues, and persistent storage
- Add unit/integration tests and CI workflow
- Add response actions such as alerting, process isolation, or blocking modes

---

## Interview Summary

> KernelGate is a modular C++20 Linux endpoint monitoring prototype. It normalizes process, file, and network activity into a common event model; evaluates events against JSON policy rules; correlates suspicious events by PID into incidents; stores audit evidence in SQLite; enriches process context through `/proc`; captures real file access through fanotify; and can upload incidents to a FastAPI-based mock control plane.
