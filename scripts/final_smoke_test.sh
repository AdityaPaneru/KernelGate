#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "================ KernelGate Final Smoke Test ================"

echo "[1/7] Checking project structure..."
test -f CMakeLists.txt
test -f src/main.cpp
test -f include/Event.hpp
test -f include/RiskEvaluator.hpp
test -f include/AuditStore.hpp
test -f include/UemClient.hpp
test -f backend/main.py
test -f backend/requirements.txt
test -f config/runtime_policy.json
test -f sample_events/suspicious_chain.json
test -f docs/ARCHITECTURE.md
test -f docs/DEMO_GUIDE.md
test -f docs/INTERVIEW_NOTES.md
test -f docs/TESTING_CHECKLIST.md
test -f docs/PROJECT_STATUS.md

echo "[2/7] Building KernelGate..."
cmake -S . -B build -G Ninja
cmake --build build

echo "[3/7] Checking CLI help..."
./build/kernelgate-agent --help | grep -F -- "--upload"
./build/kernelgate-agent --help | grep -F -- "--inspect-pid"
./build/kernelgate-agent --help | grep -F -- "--reset-db"

echo "[4/7] Running local policy/risk/correlation pipeline..."
./build/kernelgate-agent --reset-db

echo "[5/7] Checking SQLite incident output..."
sqlite3 kernelgate.db \
  "SELECT incident_id, risk_score, verdict, chain_summary FROM incidents;" \
  | grep -F "INC-001|80|HIGH|EXEC -> FILE_ACCESS -> NET_CONNECT"

echo "[6/7] Checking /proc inspection..."
./build/kernelgate-agent --inspect-pid $$ | grep -F "[PROC] PID"

echo "[7/7] Checking documentation files..."
test -f README.md
test -f docs/ARCHITECTURE.md
test -f docs/DEMO_GUIDE.md
test -f docs/INTERVIEW_NOTES.md
test -f docs/TESTING_CHECKLIST.md
test -f docs/PROJECT_STATUS.md

echo "================ Final smoke test passed ====================="
