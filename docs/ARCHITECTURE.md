# KernelGate Architecture

KernelGate is a modular C++ endpoint runtime policy engine.

## Runtime Pipeline

```text
Event Source
    ↓
Event Loader
    ↓
KernelEvent Model
    ↓
PolicyLoader
    ↓
RiskEvaluator
    ↓
Correlator
    ↓
SQLite AuditStore
    ↓
Optional UEM Upload
