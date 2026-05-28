#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

EVENT_FILE="sample_events/live_demo_chain.json"
DB_FILE="kernelgate.db"

echo "================ KernelGate Phase 5 Demo ================"
echo "[1/5] Generating controlled suspicious event chain..."
./scripts/generate_suspicious_events.sh "$EVENT_FILE"

echo
echo "[2/5] Building KernelGate..."
cmake --build build

echo
echo "[3/5] Running KernelGate with generated event file..."
./build/kernelgate-agent --reset-db --events "$EVENT_FILE" --db "$DB_FILE"

echo
echo "[4/5] SQLite tables..."
sqlite3 "$DB_FILE" ".tables"

echo
echo "[5/5] Stored incident..."
sqlite3 "$DB_FILE" "SELECT incident_id, risk_score, verdict, chain_summary FROM incidents;"

echo
echo "================ Demo completed successfully ================"
