#!/usr/bin/env bash
set -euo pipefail

echo "[TRIGGER] Generating exec events..."

whoami >/dev/null
ls >/dev/null
bash -c "echo kernelgate-ebpf-demo >/dev/null"

echo "[TRIGGER] Done."
