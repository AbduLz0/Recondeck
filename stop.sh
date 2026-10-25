#!/usr/bin/env bash
# Stop the local ReconDeck server started by start.sh.
set -u

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${RECONDECK_DATA_DIR:-${ROOT}/data}"
PID_FILE="${DATA_DIR}/recondeck.pid"

if [[ ! -f "$PID_FILE" ]]; then
  echo "ReconDeck does not appear to be running (no PID file)."
  exit 0
fi

PID="$(cat "$PID_FILE" 2>/dev/null || true)"
if [[ ! "$PID" =~ ^[0-9]+$ ]]; then
  echo "Invalid PID file; removing it."
  rm -f "$PID_FILE"
  exit 0
fi

if ! kill -0 "$PID" 2>/dev/null; then
  echo "ReconDeck is not running (stale PID file)."
  rm -f "$PID_FILE"
  exit 0
fi

CMDLINE="$(tr '\0' ' ' < "/proc/${PID}/cmdline" 2>/dev/null || true)"
if [[ "$CMDLINE" != *"${ROOT}/app.py"* ]]; then
  echo "Refusing to stop PID ${PID}: it is not the ReconDeck process recorded for this folder." >&2
  echo "Remove ${PID_FILE} manually if you are sure it is stale." >&2
  exit 1
fi

kill -TERM "$PID" 2>/dev/null || true
for _ in $(seq 1 30); do
  if ! kill -0 "$PID" 2>/dev/null; then
    rm -f "$PID_FILE"
    echo "ReconDeck stopped."
    exit 0
  fi
  sleep 0.2
done
kill -KILL "$PID" 2>/dev/null || true
rm -f "$PID_FILE"
echo "ReconDeck force-stopped."
