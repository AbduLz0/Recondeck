#!/usr/bin/env bash
# Launch ReconDeck in a local browser app window.
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PORT="${RECONDECK_PORT:-8777}"
HOST="127.0.0.1"
URL="http://${HOST}:${PORT}"
DATA_DIR="${RECONDECK_DATA_DIR:-${ROOT}/data}"
LOG_FILE="${DATA_DIR}/recondeck.log"
PID_FILE="${DATA_DIR}/recondeck.pid"
PYTHON="${RECONDECK_PYTHON:-python3}"

mkdir -p "$DATA_DIR"
chmod 700 "$DATA_DIR" 2>/dev/null || true

EXPECTED_VERSION="1.0.0"

is_recondeck() {
  local health
  health="$(curl -fsS --max-time 1 "${URL}/healthz" 2>/dev/null || true)"
  [[ "$health" == *'"app":"ReconDeck"'* ]]
}

is_current_version() {
  local health
  health="$(curl -fsS --max-time 1 "${URL}/healthz" 2>/dev/null || true)"
  [[ "$health" == *'"app":"ReconDeck"'* && "$health" == *'"version":"'"${EXPECTED_VERSION}"'"'* ]]
}

open_app() {
  if [[ "${RECONDECK_NO_BROWSER:-0}" =~ ^(1|true|yes|on)$ ]]; then
    echo "Browser launch disabled. Open ${URL}"
    return 0
  fi
  if [[ "${RECONDECK_APP_WINDOW:-1}" =~ ^(0|false|no|off)$ ]]; then
    xdg-open "$URL" >/dev/null 2>&1 || echo "Open ${URL} in your browser."
    return 0
  fi
  local candidate
  for candidate in brave-browser chromium chromium-browser google-chrome; do
    if command -v "$candidate" >/dev/null 2>&1; then
      if command -v setsid >/dev/null 2>&1; then
        setsid "$candidate" --app="$URL" >/dev/null 2>&1 &
      else
        "$candidate" --app="$URL" >/dev/null 2>&1 &
      fi
      disown 2>/dev/null || true
      return 0
    fi
  done
  if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$URL" >/dev/null 2>&1 &
    disown 2>/dev/null || true
    return 0
  fi
  echo "Open ${URL} in your browser."
}

if is_recondeck; then
  if is_current_version; then
    echo "ReconDeck is already running at ${URL}"
    open_app
    exit 0
  fi

  echo "An older ReconDeck build is running at ${URL}. Replacing it with ${EXPECTED_VERSION}…"
  if [[ -f "$PID_FILE" ]]; then
    RECONDECK_DATA_DIR="$DATA_DIR" "$ROOT/stop.sh" >/dev/null 2>&1 || true
  fi
  for _ in $(seq 1 30); do
    is_recondeck || break
    sleep 0.2
  done
  if is_recondeck; then
    echo "The older instance could not be stopped." >&2
    echo "Run ${ROOT}/stop.sh manually, then launch ReconDeck again." >&2
    exit 1
  fi
fi

if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "Python 3 was not found. Install Python 3.10+ and try again." >&2
  exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required by the ReconDeck launcher. Install curl and try again." >&2
  exit 1
fi
if ! "$PYTHON" -c "import flask" >/dev/null 2>&1; then
  echo "Flask is not available for ${PYTHON}." >&2
  echo "Install it with:  ${PYTHON} -m pip install -r \"${ROOT}/requirements.txt\"" >&2
  exit 1
fi
if ! command -v nmap >/dev/null 2>&1; then
  echo "Nmap was not found. Install nmap before launching ReconDeck." >&2
  exit 1
fi

if (exec 3<>"/dev/tcp/${HOST}/${PORT}") 2>/dev/null; then
  if ! is_recondeck; then
    echo "Port ${PORT} is already in use by another application." >&2
    echo "Set RECONDECK_PORT to another port, for example: RECONDECK_PORT=8778 ./start.sh" >&2
    exit 1
  fi
fi

# Keep the local scan log from growing without bound.
if [[ -f "$LOG_FILE" ]] && [[ "$(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)" -gt 5242880 ]]; then
  mv -f "$LOG_FILE" "${LOG_FILE}.1"
fi

if [[ "${RECONDECK_FOREGROUND:-0}" =~ ^(1|true|yes|on)$ ]]; then
  echo "ReconDeck starting at ${URL}"
  exec "$PYTHON" "$ROOT/app.py" --port "$PORT" --data-dir "$DATA_DIR" --open
fi

cd "$ROOT"
nohup "$PYTHON" "$ROOT/app.py" --port "$PORT" --data-dir "$DATA_DIR" >>"$LOG_FILE" 2>&1 &
APP_PID=$!
printf '%s\n' "$APP_PID" > "$PID_FILE"
chmod 600 "$PID_FILE" 2>/dev/null || true

READY=0
for _ in $(seq 1 80); do
  if is_recondeck; then
    READY=1
    break
  fi
  if ! kill -0 "$APP_PID" 2>/dev/null; then
    break
  fi
  sleep 0.15
done

if [[ "$READY" != "1" ]]; then
  echo "ReconDeck did not start. Recent server output:" >&2
  tail -n 30 "$LOG_FILE" 2>/dev/null >&2 || true
  rm -f "$PID_FILE"
  exit 1
fi

echo "ReconDeck is running at ${URL}"
echo "Scan database: ${DATA_DIR}/recondeck.db"
echo "Stop it with:   ${ROOT}/stop.sh"
open_app
