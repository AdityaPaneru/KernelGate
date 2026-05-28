#!/usr/bin/env bash
set -euo pipefail

OUT_FILE="${1:-sample_events/live_demo_chain.json}"

mkdir -p "$(dirname "$OUT_FILE")"

DEMO_DIR="/tmp/kernelgate-demo"
SCRIPT_PATH="$DEMO_DIR/suspicious.sh"
BASH_PATH="$(command -v bash)"

mkdir -p "$DEMO_DIR"

cat > "$SCRIPT_PATH" <<'SCRIPT'
#!/usr/bin/env bash

cat /etc/passwd > /tmp/kernelgate-demo/passwd.copy 2>/dev/null || true

timeout 1 bash -c 'cat < /dev/null > /dev/tcp/127.0.0.1/4444' 2>/dev/null || true
SCRIPT

chmod +x "$SCRIPT_PATH"

bash "$SCRIPT_PATH" &
DEMO_PID=$!
DEMO_PPID=$$
DEMO_UID=$(id -u)

wait "$DEMO_PID" || true

T1=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
T2=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
T3=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

cat > "$OUT_FILE" <<JSON
[
  {
    "event_id": "LIVE-001",
    "event_type": "EXEC",
    "timestamp": "$T1",
    "pid": $DEMO_PID,
    "ppid": $DEMO_PPID,
    "uid": $DEMO_UID,
    "process_name": "bash",
    "process_path": "$BASH_PATH",
    "command_line": "bash $SCRIPT_PATH"
  },
  {
    "event_id": "LIVE-002",
    "event_type": "FILE_ACCESS",
    "timestamp": "$T2",
    "pid": $DEMO_PID,
    "ppid": $DEMO_PPID,
    "uid": $DEMO_UID,
    "process_name": "bash",
    "process_path": "$BASH_PATH",
    "command_line": "bash $SCRIPT_PATH",
    "file_path": "/etc/passwd"
  },
  {
    "event_id": "LIVE-003",
    "event_type": "NET_CONNECT",
    "timestamp": "$T3",
    "pid": $DEMO_PID,
    "ppid": $DEMO_PPID,
    "uid": $DEMO_UID,
    "process_name": "bash",
    "process_path": "$BASH_PATH",
    "command_line": "bash $SCRIPT_PATH",
    "dest_ip": "127.0.0.1",
    "dest_port": 4444
  }
]
JSON

echo "[DEMO] Generated suspicious event chain: $OUT_FILE"
echo "[DEMO] Simulated process PID: $DEMO_PID"
echo "[DEMO] Demo script path: $SCRIPT_PATH"
