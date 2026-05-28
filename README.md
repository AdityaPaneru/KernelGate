# KernelGate

KernelGate is a C++ endpoint runtime policy engine built for Linux endpoint visibility, behavior correlation, local auditability, and mock UEM-style incident reporting.

The project is designed as an Omnissa-targeted portfolio project. It demonstrates core concepts behind endpoint management and endpoint security platforms: runtime telemetry, policy evaluation, risk scoring, incident correlation, audit storage, process metadata enrichment, and control-plane reporting.

---

## Why KernelGate Exists

Most beginner OS projects stop at basic process monitoring or log parsing. KernelGate is designed to go further.

It models how an endpoint agent can:

1. collect runtime events,
2. normalize them into a typed event model,
3. evaluate them against policy,
4. score risk,
5. correlate behavior into incidents,
6. store audit records locally,
7. enrich process context using `/proc`,
8. upload incidents to a control plane.

The current version uses synthetic and controlled demo events. The architecture is intentionally built so future phases can replace synthetic sources with fanotify or eBPF-based runtime telemetry.

---

## Current Capabilities

- C++20 endpoint agent
- JSON-based runtime policy loading
- Synthetic runtime event replay
- Event types:
  - `EXEC`
  - `FILE_ACCESS`
  - `NET_CONNECT`
- Policy rule matching
- Risk scoring
- Incident correlation by process ID
- SQLite audit storage
- Run ID tracking for audit grouping
- Linux `/proc` process inspection
- CLI options for demo control
- Mock UEM backend using FastAPI
- Incident upload to control plane using libcurl

---

## Architecture Overview

```text
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
