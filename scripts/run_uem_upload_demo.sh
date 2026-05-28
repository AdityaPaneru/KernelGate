#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

BACKEND_URL="${BACKEND_URL:-http://127.0.0.1:8000}"

echo "================ KernelGate UEM Upload Demo ================"

echo "[1/6] Checking backend health..."
if ! curl -fsS "$BACKEND_URL/health" >/dev/null; then
    echo "[ERROR] Backend is not running at $BACKEND_URL"
    echo "Start backend in another terminal with:"
    echo "  cd ~/omnissa-projects/kernelgate"
    echo "  source backend/venv/bin/activate"
    echo "  python3 backend/main.py"
    exit 1
fi

echo "[2/6] Resetting backend incident memory..."
curl -fsS -X POST "$BACKEND_URL/reset" >/dev/null

echo "[3/6] Building KernelGate..."
cmake --build build

echo "[4/6] Running KernelGate with UEM upload..."
./build/kernelgate-agent \
    --reset-db \
    --upload \
    --control-plane-url "$BACKEND_URL"

echo "[5/6] Querying local SQLite incident..."
sqlite3 kernelgate.db \
    "SELECT run_id, incident_id, risk_score, verdict, chain_summary FROM incidents;"

echo "[6/6] Querying backend fleet summary..."
curl -s "$BACKEND_URL/fleet/summary"
echo

echo "================ Demo completed successfully ================"
