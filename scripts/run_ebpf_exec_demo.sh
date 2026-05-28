#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v bpftrace >/dev/null 2>&1; then
    echo "[ERROR] bpftrace is not installed."
    echo "Install it with:"
    echo "  sudo apt install -y bpftrace"
    exit 1
fi

echo "================ KernelGate eBPF Exec Demo ================"
echo
echo "This demo uses bpftrace to attach to:"
echo "  tracepoint:syscalls:sys_enter_execve"
echo
echo "Open another terminal and run:"
echo "  ./scripts/trigger_exec_events.sh"
echo
echo "Stop this monitor with Ctrl+C."
echo

sudo bpftrace scripts/ebpf_exec_monitor.bt
