# KernelGate

> **C++20 Linux Endpoint Runtime Policy Engine**
> Detect. Correlate. Report. — Built for enterprise endpoint visibility.

---

```
 ██╗  ██╗███████╗██████╗ ███╗   ██╗███████╗██╗      ██████╗  █████╗ ████████╗███████╗
 ██║ ██╔╝██╔════╝██╔══██╗████╗  ██║██╔════╝██║     ██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝
 █████╔╝ █████╗  ██████╔╝██╔██╗ ██║█████╗  ██║     ██║  ███╗███████║   ██║   █████╗
 ██╔═██╗ ██╔══╝  ██╔══██╗██║╚██╗██║██╔══╝  ██║     ██║   ██║██╔══██║   ██║   ██╔══╝
 ██║  ██╗███████╗██║  ██║██║ ╚████║███████╗███████╗╚██████╔╝██║  ██║   ██║   ███████╗
 ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝
```

![Language](https://img.shields.io/badge/Language-C%2B%2B20-blue?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux-orange?style=flat-square)
![Backend](https://img.shields.io/badge/Backend-FastAPI-009688?style=flat-square)
![Database](https://img.shields.io/badge/Database-SQLite3-003B57?style=flat-square)
![Build](https://img.shields.io/badge/Build-CMake%20%2B%20Ninja-red?style=flat-square)


---

## What is KernelGate?

KernelGate is a modular **endpoint detection and response (EDR)** prototype that monitors Linux process behavior — tracking what a process executes, which sensitive files it accesses, and where it connects — then scores that behavior against a JSON policy to generate correlated, risk-ranked incidents.

**The key insight**: three individually "LOW" events (suspicious exec + /etc/passwd read + port 4444 connect) become a single **HIGH** incident when they're all from the same process. That's behavioral chain correlation, not log parsing.

---

## Core Demo: Behavior Chain Detection

```
bash /tmp/suspicious.sh          →  EXEC        +30 pts  (LOW)
    └─ reads /etc/passwd         →  FILE_ACCESS  +25 pts  (LOW)
    └─ connects to port 4444     →  NET_CONNECT  +25 pts  (LOW)
                                                 ─────────────
                                       INC-001 =  80 pts  HIGH  ⚠
```

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        Event Sources                             │
│   sample_events/*.json   │   fanotify (kernel)   │   eBPF        │
└──────────────┬───────────┴────────────┬──────────┴───────────────┘
               │                        │
               ▼                        ▼
┌─────────────────────────────────────────────────────────────────┐
│                    KernelGate C++ Agent                          │
│                                                                  │
│  ┌──────────────┐    ┌───────────────┐    ┌──────────────────┐  │
│  │ Event Loader │───▶│ RiskEvaluator │◀───│  PolicyLoader    │  │
│  │  Event.cpp   │    │   (scoring)   │    │  policy.json     │  │
│  └──────────────┘    └──────┬────────┘    └──────────────────┘  │
│                             │                                    │
│                             ▼                                    │
│                    ┌────────────────┐                            │
│                    │   Correlator   │  ← groups events by PID   │
│                    └───────┬────────┘                            │
│                            │                                     │
│              ┌─────────────┴──────────────┐                     │
│              ▼                             ▼                     │
│   ┌─────────────────┐         ┌──────────────────────┐          │
│   │   AuditStore    │         │     UemClient         │          │
│   │   SQLite DB     │         │  libcurl HTTP POST    │          │
│   └─────────────────┘         └──────────┬───────────┘          │
└──────────────────────────────────────────┼──────────────────────┘
                                           ▼
                               ┌─────────────────────┐
                               │  FastAPI Backend     │
                               │  POST /incident      │
                               │  GET  /fleet/summary │
                               └─────────────────────┘
```

---

## Capabilities

| Feature | Status |
|---|---|
| C++20 endpoint agent | Ready |
| JSON runtime policy loading | Ready |
| EXEC / FILE_ACCESS / NET_CONNECT events | Ready |
| Risk scoring with configurable thresholds | Ready |
| PID-based incident correlation | Ready |
| SQLite audit storage with run IDs | Ready |
| Linux `/proc` process enrichment | Ready |
| CLI with full option support | Ready |
| FastAPI mock UEM control plane | Ready |
| libcurl incident upload | Ready |
| fanotify real file monitoring | Demo |
| eBPF execution telemetry | Demo |

---

## Repository Structure

```
KernelGate-main/
├── CMakeLists.txt
├── config/
│   └── runtime_policy.json        ← detection rules & risk thresholds
├── sample_events/
│   └── suspicious_chain.json      ← demo: EXEC → FILE_ACCESS → NET_CONNECT
├── include/                       ← C++ headers (Event, Policy, Incident, ...)
├── src/                           ← C++ implementations
│   ├── main.cpp                   ← CLI entry point & pipeline orchestration
│   ├── RiskEvaluator.cpp          ← rule matching & risk scoring
│   ├── Correlator.cpp             ← PID grouping → incidents
│   ├── AuditStore.cpp             ← SQLite DDL/DML
│   ├── UemClient.cpp              ← libcurl HTTP upload
│   └── ...
├── backend/
│   ├── main.py                    ← FastAPI mock control plane
│   └── requirements.txt
└── scripts/
    ├── run_uem_upload_demo.sh     ← end-to-end demo
    └── final_smoke_test.sh        ← build + validate
```

---

## Quick Start

### 1. Install Dependencies

```bash
# C++ build dependencies
sudo apt install -y \
  build-essential cmake ninja-build \
  nlohmann-json3-dev libsqlite3-dev \
  libssl-dev libcurl4-openssl-dev \
  sqlite3 curl

# Python backend
python3 -m venv backend/venv
source backend/venv/bin/activate
pip install -r backend/requirements.txt
```

### 2. Build

```bash
cmake -S . -B build -G Ninja
cmake --build build
```

### 3. Run the Demo

```bash
./build/kernelgate-agent --reset-db
```

**Expected output:**
```
[INCIDENT] INC-001
  PID:     3101
  Process: bash (/usr/bin/bash)
  Chain:   EXEC -> FILE_ACCESS -> NET_CONNECT
  Score:   80
  Verdict: HIGH
```

---

## Run with UEM Backend Upload

**Terminal 1** — start the control plane:
```bash
source backend/venv/bin/activate
python3 backend/main.py
```

**Terminal 2** — run the agent with upload:
```bash
./build/kernelgate-agent --reset-db --upload
```

**Check fleet status:**
```bash
curl http://127.0.0.1:8000/fleet/summary
# → { "status": "HIGH_RISK", "incident_count": 1 }
```

**One-command demo** (with backend running):
```bash
./scripts/run_uem_upload_demo.sh
```

---

## Inspect a Real Linux Process

```bash
./build/kernelgate-agent --inspect-pid $$
```

Reads live metadata from `/proc/<pid>/status`, `/proc/<pid>/cmdline`, and `/proc/<pid>/exe`.

---

## CLI Options

```
./build/kernelgate-agent [options]

  --events <file>          Event JSON to replay (default: sample_events/suspicious_chain.json)
  --policy <file>          Policy JSON to load  (default: config/runtime_policy.json)
  --db <path>              SQLite path          (default: kernelgate.db)
  --reset-db               Drop and recreate the database
  --inspect-pid <pid>      Inspect a running process via /proc
  --upload                 Upload incidents to control plane
  --control-plane-url <u>  Control plane URL    (default: http://127.0.0.1:8000)
  --device-id <id>         Device ID for uploads (default: kernelgate-endpoint-01)
  --help                   Show this help
```

---

## Risk Score Reference

| Score | Verdict | Action |
|---|---|---|
| 0 | CLEAN | No risk, no action |
| 1 – 39 | LOW | Monitor |
| 40 – 69 | WARNING | Investigate |
| 70 – 89 | HIGH | Alert triggered |
| 90+ | CRITICAL | Immediate response |

---

## SQLite Audit Schema

KernelGate stores three tables per run, keyed by a `run_id` (`RUN-YYYYMMDD-HHMMSS`):

```sql
raw_events            -- every parsed event before scoring
incidents             -- one row per correlated incident
incident_rule_matches -- one row per matched rule per incident
```

Query results after a run:
```bash
sqlite3 kernelgate.db \
  "SELECT incident_id, risk_score, verdict, chain_summary FROM incidents;"

# INC-001|80|HIGH|EXEC -> FILE_ACCESS -> NET_CONNECT
```

---

## Smoke Test

```bash
./scripts/final_smoke_test.sh
# Expected: Final smoke test passed
```

Validates: project structure, build, CLI, event pipeline, SQLite output, /proc inspection.

---

## Why This Is Not Just a Log Parser

| Log Parser | KernelGate |
|---|---|
| Reads existing text files | Consumes typed event structs |
| Regex / pattern match | Policy rule engine with scoring |
| Per-line analysis | Cross-event PID correlation |
| No context | /proc process enrichment |
| File output | SQLite audit + HTTP upload |
| Flat results | Behavioral chain incidents |

The strongest feature is correlation: three separately low-risk events from the same process become one HIGH-severity incident that captures the full attack pattern.

---

## Future Event Sources

KernelGate currently uses synthetic and controlled demo events. Planned real kernel sources:

- `fanotify` — kernel-backed sensitive file access monitoring
- `eBPF tracepoints` — process execution via `sys_enter_execve`
- `eBPF socket hooks` — outbound network telemetry

---

## Optional: eBPF Exec Telemetry Demo

```bash
# Requires bpftrace installed
./scripts/run_ebpf_exec_demo.sh
```

Attaches to `tracepoint:syscalls:sys_enter_execve` and prints every process execution in real time.

---

## Documentation

| File | Contents |
|---|---|
| `PROJECT_EXPLANATION.md` | Deep-dive architecture, phase-by-phase flowcharts, component reference |
| `docs/ARCHITECTURE.md` | System design notes |
| `docs/DEMO_GUIDE.md` | Step-by-step demo walkthrough |
| `docs/PROJECT_STATUS.md` | Implementation status |

---

## Tech Stack

```
C++20          → Agent core, event model, risk engine
nlohmann/json  → JSON parsing and serialization
SQLite3        → Local audit database
libcurl        → HTTP incident upload
OpenSSL        → TLS support
FastAPI        → Mock UEM control plane
CMake + Ninja  → Build system
bpftrace       → Optional eBPF kernel telemetry
```

---

*KernelGate — Modular endpoint runtime policy enforcement with behavioral correlation, local auditability, and fleet-scale risk reporting.*

---

## Core Demo: Behavior Chain Detection

```
bash /tmp/suspicious.sh          →  EXEC        +30 pts  (LOW)
    └─ reads /etc/passwd         →  FILE_ACCESS  +25 pts  (LOW)
    └─ connects to port 4444     →  NET_CONNECT  +25 pts  (LOW)
                                                 ─────────────
                                       INC-001 =  80 pts  HIGH  ⚠
```

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        Event Sources                             │
│   sample_events/*.json   │   fanotify (kernel)   │   eBPF        │
└──────────────┬───────────┴────────────┬──────────┴───────────────┘
               │                        │
               ▼                        ▼
┌─────────────────────────────────────────────────────────────────┐
│                    KernelGate C++ Agent                          │
│                                                                  │
│  ┌──────────────┐    ┌───────────────┐    ┌──────────────────┐  │
│  │ Event Loader │───▶│ RiskEvaluator │◀───│  PolicyLoader    │  │
│  │  Event.cpp   │    │   (scoring)   │    │  policy.json     │  │
│  └──────────────┘    └──────┬────────┘    └──────────────────┘  │
│                             │                                    │
│                             ▼                                    │
│                    ┌────────────────┐                            │
│                    │   Correlator   │  ← groups events by PID   │
│                    └───────┬────────┘                            │
│                            │                                     │
│              ┌─────────────┴──────────────┐                     │
│              ▼                             ▼                     │
│   ┌─────────────────┐         ┌──────────────────────┐          │
│   │   AuditStore    │         │     UemClient         │          │
│   │   SQLite DB     │         │  libcurl HTTP POST    │          │
│   └─────────────────┘         └──────────┬───────────┘          │
└──────────────────────────────────────────┼──────────────────────┘
                                           ▼
                               ┌─────────────────────┐
                               │  FastAPI Backend     │
                               │  POST /incident      │
                               │  GET  /fleet/summary │
                               └─────────────────────┘
```

---

## Capabilities

| Feature | Status |
|---|---|
| C++20 endpoint agent | Ready |
| JSON runtime policy loading | Ready |
| EXEC / FILE_ACCESS / NET_CONNECT events | Ready |
| Risk scoring with configurable thresholds | Ready |
| PID-based incident correlation | Ready |
| SQLite audit storage with run IDs | Ready |
| Linux `/proc` process enrichment | Ready |
| CLI with full option support | Ready |
| FastAPI mock UEM control plane | Ready |
| libcurl incident upload | Ready |
| fanotify real file monitoring | Demo |
| eBPF execution telemetry | Demo |

---

## Repository Structure

```
KernelGate-main/
├── CMakeLists.txt
├── config/
│   └── runtime_policy.json        ← detection rules & risk thresholds
├── sample_events/
│   └── suspicious_chain.json      ← demo: EXEC → FILE_ACCESS → NET_CONNECT
├── include/                       ← C++ headers (Event, Policy, Incident, ...)
├── src/                           ← C++ implementations
│   ├── main.cpp                   ← CLI entry point & pipeline orchestration
│   ├── RiskEvaluator.cpp          ← rule matching & risk scoring
│   ├── Correlator.cpp             ← PID grouping → incidents
│   ├── AuditStore.cpp             ← SQLite DDL/DML
│   ├── UemClient.cpp              ← libcurl HTTP upload
│   └── ...
├── backend/
│   ├── main.py                    ← FastAPI mock control plane
│   └── requirements.txt
└── scripts/
    ├── run_uem_upload_demo.sh     ← end-to-end demo
    └── final_smoke_test.sh        ← build + validate
```

---

## Quick Start

### 1. Install Dependencies

```bash
# C++ build dependencies
sudo apt install -y \
  build-essential cmake ninja-build \
  nlohmann-json3-dev libsqlite3-dev \
  libssl-dev libcurl4-openssl-dev \
  sqlite3 curl

# Python backend
python3 -m venv backend/venv
source backend/venv/bin/activate
pip install -r backend/requirements.txt
```

### 2. Build

```bash
cmake -S . -B build -G Ninja
cmake --build build
```

### 3. Run the Demo

```bash
./build/kernelgate-agent --reset-db
```

**Expected output:**
```
[INCIDENT] INC-001
  PID:     3101
  Process: bash (/usr/bin/bash)
  Chain:   EXEC -> FILE_ACCESS -> NET_CONNECT
  Score:   80
  Verdict: HIGH
```

---

## Run with UEM Backend Upload

**Terminal 1** — start the control plane:
```bash
source backend/venv/bin/activate
python3 backend/main.py
```

**Terminal 2** — run the agent with upload:
```bash
./build/kernelgate-agent --reset-db --upload
```

**Check fleet status:**
```bash
curl http://127.0.0.1:8000/fleet/summary
# → { "status": "HIGH_RISK", "incident_count": 1 }
```

**One-command demo** (with backend running):
```bash
./scripts/run_uem_upload_demo.sh
```

---

## Inspect a Real Linux Process

```bash
./build/kernelgate-agent --inspect-pid $$
```

Reads live metadata from `/proc/<pid>/status`, `/proc/<pid>/cmdline`, and `/proc/<pid>/exe`.

---

## CLI Options

```
./build/kernelgate-agent [options]

  --events <file>          Event JSON to replay (default: sample_events/suspicious_chain.json)
  --policy <file>          Policy JSON to load  (default: config/runtime_policy.json)
  --db <path>              SQLite path          (default: kernelgate.db)
  --reset-db               Drop and recreate the database
  --inspect-pid <pid>      Inspect a running process via /proc
  --upload                 Upload incidents to control plane
  --control-plane-url <u>  Control plane URL    (default: http://127.0.0.1:8000)
  --device-id <id>         Device ID for uploads (default: kernelgate-endpoint-01)
  --help                   Show this help
```

---

## Risk Score Reference

| Score | Verdict | Action |
|---|---|---|
| 0 | CLEAN | No risk, no action |
| 1 – 39 | LOW | Monitor |
| 40 – 69 | WARNING | Investigate |
| 70 – 89 | HIGH | Alert triggered |
| 90+ | CRITICAL | Immediate response |

---

## SQLite Audit Schema

KernelGate stores three tables per run, keyed by a `run_id` (`RUN-YYYYMMDD-HHMMSS`):

```sql
raw_events            -- every parsed event before scoring
incidents             -- one row per correlated incident
incident_rule_matches -- one row per matched rule per incident
```

Query results after a run:
```bash
sqlite3 kernelgate.db \
  "SELECT incident_id, risk_score, verdict, chain_summary FROM incidents;"

# INC-001|80|HIGH|EXEC -> FILE_ACCESS -> NET_CONNECT
```

---

## Smoke Test

```bash
./scripts/final_smoke_test.sh
# Expected: Final smoke test passed
```

Validates: project structure, build, CLI, event pipeline, SQLite output, /proc inspection.

---

## Why This Is Not Just a Log Parser

| Log Parser | KernelGate |
|---|---|
| Reads existing text files | Consumes typed event structs |
| Regex / pattern match | Policy rule engine with scoring |
| Per-line analysis | Cross-event PID correlation |
| No context | /proc process enrichment |
| File output | SQLite audit + HTTP upload |
| Flat results | Behavioral chain incidents |

The strongest feature is correlation: three separately low-risk events from the same process become one HIGH-severity incident that captures the full attack pattern.

---

## Future Event Sources

KernelGate currently uses synthetic and controlled demo events. Planned real kernel sources:

- `fanotify` — kernel-backed sensitive file access monitoring
- `eBPF tracepoints` — process execution via `sys_enter_execve`
- `eBPF socket hooks` — outbound network telemetry

---

## Optional: eBPF Exec Telemetry Demo

```bash
# Requires bpftrace installed
./scripts/run_ebpf_exec_demo.sh
```

Attaches to `tracepoint:syscalls:sys_enter_execve` and prints every process execution in real time.

---

## Documentation

| File | Contents |
|---|---|
| `PROJECT_EXPLANATION.md` | Deep-dive architecture, phase-by-phase flowcharts, component reference |
| `docs/ARCHITECTURE.md` | System design notes |
| `docs/DEMO_GUIDE.md` | Step-by-step demo walkthrough |
| `docs/PROJECT_STATUS.md` | Implementation status |

---

## Tech Stack

```
C++20          → Agent core, event model, risk engine
nlohmann/json  → JSON parsing and serialization
SQLite3        → Local audit database
libcurl        → HTTP incident upload
OpenSSL        → TLS support
FastAPI        → Mock UEM control plane
CMake + Ninja  → Build system
bpftrace       → Optional eBPF kernel telemetry
```

---

*KernelGate — Modular endpoint runtime policy enforcement with behavioral correlation, local auditability, and fleet-scale risk reporting.*
