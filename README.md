# KernelGate

KernelGate is a C++20 endpoint runtime policy engine designed to simulate how a modern endpoint-management or endpoint-security agent can observe local system activity, evaluate runtime behavior against configurable policies, calculate risk, and generate structured endpoint posture signals.

The project is built around a practical systems question:

```text
Is this endpoint behaving safely and compliantly right now?
```

Instead of being a textbook OS simulator, KernelGate is designed as a realistic endpoint-agent style project. It focuses on runtime telemetry, policy evaluation, risk scoring, incident creation, and auditability.

---

## Project Overview

KernelGate is a Linux-focused C++ endpoint agent prototype.

The project aims to process runtime events such as:

```text
process execution
file access
network connection attempts
suspicious process chains
sensitive file access
execution from temporary directories
```

These events are evaluated against JSON-based runtime policies. If the activity violates a policy or looks suspicious, KernelGate assigns risk points, builds an incident record, and updates the endpoint posture.

---

## Core Idea

The core idea is to build a pipeline like this:

```text
Runtime Event
      |
      v
Event Normalizer
      |
      v
Policy Engine
      |
      v
Risk Scorer
      |
      v
Incident Correlator
      |
      v
Audit Store
      |
      v
Endpoint Posture Report
```

The final system should be able to answer:

```text
What happened?
Which process caused it?
Which policy was triggered?
How risky is it?
Should this endpoint be marked healthy, warning, non-compliant, or critical?
Can the event be stored and reviewed later?
```

---

## Why KernelGate Exists

A simple script can check one condition at a time:

```text
Is a process running?
Is a file present?
Is a service active?
```

KernelGate is different because it is designed to maintain a structured event-processing pipeline.

It does not only check one condition. It tries to connect runtime behavior with policy and risk.

Example:

```text
bash executed from /tmp
    -> accessed /etc/passwd
    -> attempted connection to restricted port
    -> policy violation detected
    -> risk score increased
    -> endpoint posture changed
```

This makes the project closer to a real endpoint-agent prototype than a simple shell-script monitor.

---

## Project Goals

The main goals of KernelGate are:

```text
Build a C++ endpoint-agent foundation
Represent runtime activity as structured events
Evaluate events using JSON-based policies
Assign risk scores based on policy hits
Correlate related events into incidents
Persist events and incidents in a local audit store
Prepare the architecture for real Linux telemetry sources
```

---

## What KernelGate Is

KernelGate is:

```text
C++20 systems project
Linux endpoint-agent prototype
Runtime policy evaluation engine
Endpoint posture simulator
Risk scoring and incident generation system
Audit-friendly telemetry processor
```

---

## What KernelGate Is Not

KernelGate is not:

```text
a cron job
a shell script wrapper
a basic log parser
a simple process monitor
a toy CPU scheduling simulator
an Ansible replacement
a dashboard-only project
```

The project is intentionally designed around endpoint runtime behavior and policy-based decision-making.

---

## Current Status

The project is currently in the foundation stage.

Completed baseline:

```text
C++20 project structure
CMake-based build system
starter endpoint agent binary
basic configuration layout
GitHub repository setup
initial README documentation
```

Current development focus:

```text
Phase 1: Event Model and Synthetic Event Replay
```

The project will be developed in phases to keep it realistic and demo-ready at every stage.

---

## High-Level Architecture

```text
+------------------------------------------------------+
|                    Linux Endpoint                    |
+------------------------------------------------------+
|                                                      |
|  Runtime Activity                                    |
|  - process execution                                 |
|  - file access                                       |
|  - network connection                                |
|  - suspicious behavior                               |
|                                                      |
|                  |                                   |
|                  v                                   |
|        +----------------------+                      |
|        | Runtime Event Source |                      |
|        +----------+-----------+                      |
|                   |                                  |
|                   v                                  |
|        +----------------------+                      |
|        | Event Normalizer     |                      |
|        +----------+-----------+                      |
|                   |                                  |
|                   v                                  |
|        +----------------------+                      |
|        | Policy Engine        |                      |
|        +----------+-----------+                      |
|                   |                                  |
|                   v                                  |
|        +----------------------+                      |
|        | Risk Scorer          |                      |
|        +----------+-----------+                      |
|                   |                                  |
|                   v                                  |
|        +----------------------+                      |
|        | Incident Correlator  |                      |
|        +----------+-----------+                      |
|                   |                                  |
|                   v                                  |
|        +----------------------+                      |
|        | SQLite Audit Store   |                      |
|        +----------+-----------+                      |
|                   |                                  |
|                   v                                  |
|        +----------------------+                      |
|        | Posture Reporter     |                      |
|        +----------------------+                      |
|                                                      |
+------------------------------------------------------+
```

---

## Runtime Event Example

A runtime event represents an action happening on the endpoint.

Example process execution event:

```json
{
  "event_type": "EXEC",
  "pid": 4312,
  "ppid": 811,
  "process_name": "bash",
  "executable_path": "/tmp/update.sh",
  "user": "root",
  "timestamp": "2026-05-24 10:30:00"
}
```

Example file access event:

```json
{
  "event_type": "FILE_ACCESS",
  "pid": 4312,
  "process_name": "bash",
  "file_path": "/etc/passwd",
  "access_type": "READ",
  "timestamp": "2026-05-24 10:30:05"
}
```

Example network connection event:

```json
{
  "event_type": "NETWORK_CONNECT",
  "pid": 4312,
  "process_name": "bash",
  "destination_ip": "192.168.1.50",
  "destination_port": 4444,
  "timestamp": "2026-05-24 10:30:10"
}
```

---

## Policy Example

KernelGate uses JSON policies to define suspicious or non-compliant behavior.

Example runtime policy:

```json
{
  "policy_version": "v1",
  "mode": "REPORT_ONLY",
  "rules": [
    {
      "rule_id": "EXEC_TEMP_DIR",
      "name": "Execution from temporary directory",
      "event_type": "EXEC",
      "path_prefixes": ["/tmp", "/dev/shm", "/var/tmp"],
      "risk_points": 30,
      "severity": "HIGH"
    },
    {
      "rule_id": "SENSITIVE_FILE_ACCESS",
      "name": "Sensitive file access",
      "event_type": "FILE_ACCESS",
      "sensitive_paths": [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/ssh/sshd_config"
      ],
      "risk_points": 25,
      "severity": "HIGH"
    },
    {
      "rule_id": "RESTRICTED_NETWORK_PORT",
      "name": "Restricted outbound connection",
      "event_type": "NETWORK_CONNECT",
      "restricted_ports": [4444, 5555, 6666],
      "risk_points": 20,
      "severity": "MEDIUM"
    }
  ]
}
```

---

## Risk Scoring Model

KernelGate uses a simple risk-scoring model.

Example scoring:

```text
Execution from temporary directory       +30
Sensitive file access                    +25
Restricted outbound connection           +20
Unexpected root execution                +15
Unknown binary                           +10
Suspicious parent-child process chain    +20
```

Possible score levels:

```text
0-30       LOW
31-60      MEDIUM
61-80      HIGH
81-100+    CRITICAL
```

Example final incident:

```json
{
  "incident_id": "INC-1001",
  "risk_score": 85,
  "severity": "HIGH",
  "verdict": "SUSPICIOUS",
  "reasons": [
    "execution_from_temp_directory",
    "sensitive_file_access",
    "restricted_network_connection"
  ]
}
```

---

## Endpoint Posture

Endpoint posture represents the current health or risk state of the device.

Possible posture states:

```text
HEALTHY
WARNING
NON_COMPLIANT
HIGH_RISK
CRITICAL
```

Example posture report:

```json
{
  "device_id": "aditya-endpoint-01",
  "policy_version": "v1",
  "runtime_risk_score": 72,
  "status": "NON_COMPLIANT",
  "recent_incidents": 3
}
```

---

## Development Phases

KernelGate is intentionally divided into phases. This keeps the project realistic, testable, and demo-ready after every milestone.

---

### Phase 0: Project Foundation

Status:

```text
Completed / Initial setup
```

Goal:

```text
Create the base C++ project and verify that the environment works.
```

Tasks:

```text
Create project directory
Set up CMake
Create starter main.cpp
Add JSON policy config folder
Add README
Initialize Git repository
Push to GitHub
```

Expected output:

```text
KernelGate agent boot successful
```

Purpose:

```text
This phase proves that the build system, folder structure, compiler, and GitHub setup are working.
```

---

### Phase 1: Event Model and Synthetic Event Replay

Status:

```text
Next
```

Goal:

```text
Create a structured runtime event model and replay sample events from JSON.
```

Planned files:

```text
include/Event.hpp
src/Event.cpp
sample_events/suspicious_chain.json
```

Tasks:

```text
Define RuntimeEvent structure
Support event types such as EXEC, FILE_ACCESS, NETWORK_CONNECT
Load sample JSON events
Print normalized event objects
Validate event parsing
```

Why this phase matters:

```text
It allows the core pipeline to be tested without depending on real kernel telemetry.
```

Example sample chain:

```text
nginx -> bash -> /tmp/script.sh -> /etc/passwd -> port 4444
```

---

### Phase 2: PolicyEngine

Status:

```text
Planned
```

Goal:

```text
Evaluate runtime events against JSON-based policy rules.
```

Planned files:

```text
include/PolicyEngine.hpp
src/PolicyEngine.cpp
config/runtime_policy.json
```

Tasks:

```text
Load policy JSON
Parse policy rules
Match event type
Match path prefixes
Match sensitive file paths
Match restricted network ports
Return policy hit results
```

Expected output:

```json
{
  "event_type": "EXEC",
  "matched_rule": "EXEC_TEMP_DIR",
  "risk_points": 30,
  "severity": "HIGH"
}
```

Purpose:

```text
This phase turns raw events into policy decisions.
```

---

### Phase 3: RiskScorer

Status:

```text
Planned
```

Goal:

```text
Convert policy hits into risk scores and severity levels.
```

Planned files:

```text
include/RiskScorer.hpp
src/RiskScorer.cpp
```

Tasks:

```text
Add risk points from matched policies
Calculate total event risk
Map numeric score to severity
Generate reason list
```

Expected output:

```json
{
  "risk_score": 75,
  "severity": "HIGH",
  "reasons": [
    "execution_from_temp_directory",
    "sensitive_file_access"
  ]
}
```

Purpose:

```text
This phase makes the project more than a rule matcher by adding measurable endpoint risk.
```

---

### Phase 4: IncidentCorrelator

Status:

```text
Planned
```

Goal:

```text
Connect multiple related events into one behavior chain.
```

Planned files:

```text
include/IncidentCorrelator.hpp
src/IncidentCorrelator.cpp
```

Tasks:

```text
Track PID and PPID relationships
Group events by process chain
Correlate process, file, and network events
Create incident IDs
Generate incident summary
```

Example behavior chain:

```text
nginx spawned bash
bash executed /tmp/script.sh
script accessed /etc/passwd
script connected to 192.168.1.50:4444
```

Expected incident:

```json
{
  "incident_id": "INC-1004",
  "chain": [
    "nginx -> bash",
    "bash -> /tmp/script.sh",
    "script -> /etc/passwd",
    "script -> 192.168.1.50:4444"
  ],
  "risk_score": 92,
  "severity": "CRITICAL"
}
```

Purpose:

```text
This is one of the strongest parts of the project because real endpoint systems care about behavior chains, not isolated events.
```

---

### Phase 5: SQLiteAuditStore

Status:

```text
Planned
```

Goal:

```text
Persist events, policy hits, incidents, and posture reports locally.
```

Planned files:

```text
include/SQLiteAuditStore.hpp
src/SQLiteAuditStore.cpp
```

Planned tables:

```text
events
policy_hits
incidents
posture_reports
```

Tasks:

```text
Create SQLite database
Create tables
Insert runtime events
Insert incidents
Query recent high-risk incidents
```

Purpose:

```text
Endpoint activity should be auditable. This phase makes KernelGate stateful instead of just printing output.
```

---

### Phase 6: Linux /proc Enrichment

Status:

```text
Planned
```

Goal:

```text
Use Linux /proc to enrich events with real process metadata.
```

Possible sources:

```text
/proc/<pid>/cmdline
/proc/<pid>/exe
/proc/<pid>/status
/proc/<pid>/fd
```

Tasks:

```text
Read process command line
Resolve executable path
Read parent PID
Read UID/user information
Attach metadata to runtime events
```

Purpose:

```text
This phase moves KernelGate closer to real endpoint telemetry.
```

---

### Phase 7: File Monitoring with inotify/fanotify

Status:

```text
Advanced planned
```

Goal:

```text
Monitor selected files or directories for runtime file activity.
```

Possible targets:

```text
/etc/passwd
/etc/ssh/sshd_config
/tmp
/var/tmp
/dev/shm
```

Tasks:

```text
Watch sensitive paths
Generate file-access or file-change events
Feed file events into the same policy pipeline
```

Purpose:

```text
This phase improves runtime visibility beyond synthetic events.
```

---

### Phase 8: eBPF Runtime Event Capture

Status:

```text
Advanced planned
```

Goal:

```text
Capture real kernel-level runtime events such as process execution and network connections.
```

Possible targets:

```text
execve
open/openat
connect
```

Tasks:

```text
Create eBPF probe for exec events
Receive event data in user-space C++ agent
Normalize eBPF events into RuntimeEvent format
Feed events into PolicyEngine and RiskScorer
```

Important note:

```text
eBPF is an advanced telemetry source, not the entire project.
The core project remains the policy, risk, and correlation pipeline.
```

Purpose:

```text
This phase gives the project kernel-level depth while keeping the architecture safe and modular.
```

---

### Phase 9: Mock UEM Control Plane

Status:

```text
Planned
```

Goal:

```text
Send endpoint posture and incidents to a lightweight backend.
```

Possible stack:

```text
FastAPI
REST API
simple dashboard
```

Planned API payload:

```json
{
  "device_id": "aditya-endpoint-01",
  "risk_score": 82,
  "status": "HIGH_RISK",
  "recent_incident": "INC-1004"
}
```

Purpose:

```text
This phase shows how the endpoint agent could report into a central management plane.
```

---

### Phase 10: Final Demo and Documentation

Status:

```text
Planned
```

Goal:

```text
Prepare a polished demo and interview-ready documentation.
```

Demo scenarios:

```text
Synthetic suspicious event chain
Policy hit and risk score
Incident correlation
SQLite audit query
Endpoint posture output
Optional real /proc or eBPF event
```

Final deliverables:

```text
README
architecture diagram
demo script
sample events
clear build instructions
interview explanation
```

---

## Repository Structure

Current/planned structure:

```text
kernelgate/
├── CMakeLists.txt
├── README.md
├── CLAUDE.md
├── config/
│   └── runtime_policy.json
├── include/
│   ├── Event.hpp
│   ├── PolicyEngine.hpp
│   ├── RiskScorer.hpp
│   ├── IncidentCorrelator.hpp
│   └── SQLiteAuditStore.hpp
├── src/
│   ├── main.cpp
│   ├── Event.cpp
│   ├── PolicyEngine.cpp
│   ├── RiskScorer.cpp
│   ├── IncidentCorrelator.cpp
│   └── SQLiteAuditStore.cpp
├── sample_events/
│   └── suspicious_chain.json
├── scripts/
├── backend/
├── docs/
└── tests/
```

---

## Build Instructions

### Configure

```bash
cmake -S . -B build -G Ninja
```

### Build

```bash
cmake --build build
```

### Run

```bash
./build/kernelgate-agent
```

---

## Development Environment

```text
Operating System: Ubuntu / WSL2
Editor: VS Code
Language: C++20
Build System: CMake + Ninja
Version Control: Git + GitHub
```

---

## Tech Stack

### C++20

Used for the endpoint agent and runtime event-processing pipeline.

### CMake

Used for project configuration and dependency management.

### Ninja

Used as the fast build backend.

### nlohmann/json

Used for JSON policies, sample events, and structured output.

### SQLite

Planned for local audit storage.

### Linux /proc

Planned for process metadata enrichment.

### inotify/fanotify

Planned for file-event monitoring.

### eBPF

Planned as an advanced kernel telemetry source.

### FastAPI

Possible future backend for mock control-plane reporting.

---

## Demo Strategy

KernelGate will support multiple demo levels.

### Demo Level 1: Synthetic Event Replay

```text
Replay sample JSON events
Show policy hits
Show risk score
Show incident output
```

### Demo Level 2: Event Correlation

```text
Replay process-file-network chain
Generate one correlated incident
Show endpoint posture change
```

### Demo Level 3: Local Audit Store

```text
Store events and incidents in SQLite
Query recent incidents
Show audit history
```

### Demo Level 4: Real Linux Telemetry

```text
Use /proc, fanotify, or eBPF
Capture actual endpoint events
Feed real events into same pipeline
```

---

## Example Final Demo

Input event chain:

```text
nginx spawned bash
bash executed /tmp/script.sh
script accessed /etc/passwd
script connected to 192.168.1.50:4444
```

Expected KernelGate output:

```json
{
  "incident_id": "INC-1007",
  "risk_score": 92,
  "severity": "CRITICAL",
  "endpoint_status": "HIGH_RISK",
  "chain": [
    "nginx -> bash",
    "bash -> /tmp/script.sh",
    "script -> /etc/passwd",
    "script -> 192.168.1.50:4444"
  ]
}
```

---

## Honest Current Limitations

KernelGate does not currently claim to have completed:

```text
real eBPF telemetry
real fanotify monitoring
real network event interception
full process-file-network correlation
backend dashboard
fleet simulation
```

These are planned phases.

The current goal is to build the core C++ endpoint-agent pipeline first.

---

## Interview Explanation

KernelGate is a C++ endpoint runtime policy engine.

The project simulates how an endpoint agent can process runtime behavior, evaluate it against security/compliance policies, compute risk scores, and generate structured incidents.

I designed it in phases so the core logic can be tested first using synthetic events, then enhanced later with Linux runtime telemetry such as `/proc`, fanotify, and eBPF.

The main idea is not just to capture events, but to turn endpoint behavior into meaningful posture and risk signals.

---

## Author

```text
Aditya Paneru
GitHub: AdityaPaneru
Email: paneruaditya8@gmail.com
```
