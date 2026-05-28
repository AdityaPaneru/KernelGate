# KernelGate Interview Notes

## One-Minute Pitch

KernelGate is a C++ Linux endpoint agent prototype. It takes runtime events such as process execution, sensitive file access, and suspicious network connection attempts, evaluates them against policy, scores risk, correlates related events into incidents, stores local audit records in SQLite, enriches process metadata using /proc, and uploads incidents to a mock UEM control plane.

## Why It Fits Omnissa

Omnissa works around endpoint management, device visibility, compliance posture, and fleet control.

KernelGate maps to those ideas through:

    endpoint telemetry
    risk scoring
    incident reporting
    local audit storage
    process enrichment
    UEM-style backend upload
    fleet risk summary

## Strongest Demo

The strongest demo is the behavior chain:

    EXEC -> FILE_ACCESS -> NET_CONNECT

KernelGate correlates these events into one incident:

    INC-001
    Risk score: 80
    Verdict: HIGH

That is stronger than showing three unrelated logs.

## Why Not Just Shell Scripts?

Shell scripts can check individual conditions.

KernelGate provides:

    typed event model
    runtime policy abstraction
    risk scoring
    stateful incident correlation
    SQLite audit storage
    HTTP upload path
    modular C++ architecture

A shell script can imitate one check. It cannot cleanly model the full endpoint-policy pipeline.

## Why C++?

Endpoint agents often need native system access, low overhead, predictable deployment, and OS-level integration.

KernelGate uses C++ with:

    /proc
    SQLite C API
    libcurl
    CMake

## Why SQLite?

SQLite provides lightweight local audit storage without requiring a separate database server.

It is useful for:

    local evidence
    offline incident records
    debugging
    forensic review

## Why /proc?

Linux exposes process metadata through /proc.

KernelGate reads:

    /proc/<pid>/status
    /proc/<pid>/cmdline
    /proc/<pid>/exe

This gives process identity, parent process, UID, executable path, and command line.

## Current Limitation

KernelGate currently uses synthetic and controlled demo telemetry.

It does not yet perform full kernel-level event capture.

Future work:

    fanotify for sensitive file access
    eBPF for process execution telemetry
    eBPF for network telemetry
    backend persistence
    dashboard UI

## Honest Explanation

I first built the stable user-space policy pipeline. That was intentional. The core value is not only event capture; it is the event-to-policy-to-risk-to-incident-to-control-plane pipeline. Once this pipeline is stable, fanotify or eBPF can be added as event sources.
