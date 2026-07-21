#!/usr/bin/env bash
# Copyright 2026 Query Farm LLC - https://query.farm
#
# Run this repo's sqllogictest suite (test/sql/*.test) against the vgi-evtx
# VGI worker, using a prebuilt standalone `haybarn-unittest` and the signed
# community `vgi` extension — no C++ build from source. See ci/README.md.
#
# Parameterized by TRANSPORT (default: subprocess), exercising the SAME suite
# over each transport the vgi extension supports — the only thing that changes
# is what LOCATION (VGI_EVTX_WORKER) the .test files ATTACH:
#
#   subprocess  VGI_EVTX_WORKER = the stdio worker command (DuckDB spawns it).
#   http        start `evtx-worker --http` (auto port; advertises `PORT:<n>`
#               on stdout), VGI_EVTX_WORKER = http://127.0.0.1:<port>.
#   unix        start `evtx-worker --unix <sock>` (advertises `UNIX:<sock>`
#               on stdout), VGI_EVTX_WORKER = unix://<sock>.
#
# Required environment:
#   HAYBARN_UNITTEST  path to the haybarn-unittest binary
#   WORKER_BIN        path to the compiled evtx-worker binary (used to launch
#                     the http/unix servers, and the stdio LOCATION). Falls back
#                     to VGI_EVTX_WORKER when that is a bare command (subprocess).
# Optional:
#   TRANSPORT         subprocess | http | unix   (default: subprocess)
#   STAGE             scratch dir for the preprocessed test tree (default: mktemp)
set -euo pipefail

TRANSPORT="${TRANSPORT:-subprocess}"

: "${HAYBARN_UNITTEST:?path to the haybarn-unittest binary}"

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
STAGE="${STAGE:-$(mktemp -d)}"

# For http/unix we must launch the worker binary ourselves; for subprocess the
# binary IS the LOCATION. WORKER_BIN names the compiled binary; default to the
# release build in this repo.
WORKER_BIN="${WORKER_BIN:-$REPO/target/release/evtx-worker}"

SERVER_PID=""
SOCK_PATH=""
cleanup() {
  local rc=$?
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  [[ -n "$SOCK_PATH" ]] && rm -f "$SOCK_PATH" 2>/dev/null || true
  return "$rc"
}
trap cleanup EXIT

# Bring up the out-of-band server for http/unix and resolve VGI_EVTX_WORKER.
# Both transports announce their endpoint on stdout (`PORT:<n>` / `UNIX:<path>`),
# which we poll for in the log before running the suite (readiness gate).
start_server_and_set_location() {
  local kind="$1"
  : "${WORKER_BIN:?path to the evtx-worker binary (WORKER_BIN)}"
  [[ -x "$WORKER_BIN" ]] || { echo "ERROR: worker binary not executable: $WORKER_BIN" >&2; exit 1; }

  # Launch the worker with cwd = $STAGE so the VARCHAR-path overload of
  # evtx_records()/the scalars resolve the staged relative-path fixtures
  # (test/sql/data/*.evtx) server-side, exactly as the subprocess runner does.
  local log="$STAGE/.worker-$kind.log"
  case "$kind" in
    http)
      ( cd "$STAGE" && exec "$WORKER_BIN" --http ) >"$log" 2>&1 &
      SERVER_PID=$!
      local port=""
      for _ in $(seq 1 60); do
        if ! kill -0 "$SERVER_PID" 2>/dev/null; then
          echo "ERROR: worker (--http) exited during startup. Log:" >&2; cat "$log" >&2; exit 1
        fi
        port=$(sed -n 's/.*PORT:\([0-9][0-9]*\).*/\1/p' "$log" 2>/dev/null | head -1)
        [[ -n "$port" ]] && break
        sleep 0.5
      done
      [[ -n "$port" ]] || { echo "ERROR: timed out waiting for PORT:<n>. Log:" >&2; cat "$log" >&2; exit 1; }
      export VGI_EVTX_WORKER="http://127.0.0.1:$port"
      echo "HTTP worker ready on 127.0.0.1:$port (pid $SERVER_PID)"
      ;;
    unix)
      SOCK_PATH="${VGI_EVTX_SOCK:-/tmp/evtx.$$.sock}"
      rm -f "$SOCK_PATH" 2>/dev/null || true
      ( cd "$STAGE" && exec "$WORKER_BIN" --unix "$SOCK_PATH" ) >"$log" 2>&1 &
      SERVER_PID=$!
      local ready=""
      for _ in $(seq 1 60); do
        if ! kill -0 "$SERVER_PID" 2>/dev/null; then
          echo "ERROR: worker (--unix) exited during startup. Log:" >&2; cat "$log" >&2; exit 1
        fi
        if grep -q "UNIX:$SOCK_PATH" "$log" 2>/dev/null && [[ -S "$SOCK_PATH" ]]; then
          ready=1; break
        fi
        sleep 0.5
      done
      [[ -n "$ready" ]] || { echo "ERROR: timed out waiting for UNIX socket. Log:" >&2; cat "$log" >&2; exit 1; }
      export VGI_EVTX_WORKER="unix://$SOCK_PATH"
      echo "Unix worker ready on $SOCK_PATH (pid $SERVER_PID)"
      ;;
  esac
}

# Stage the preprocessed tests + fixtures FIRST, so the http/unix worker (which
# we launch next with cwd = $STAGE) resolves the staged relative-path fixtures.
echo "Staging preprocessed tests into $STAGE ..."
mkdir -p "$STAGE/test/sql"
# Pass the transport to the preprocessor: the http leg additionally needs DuckDB's
# `httpfs` extension loaded (the vgi extension's HTTP client is built on it), so
# the awk injects a signed INSTALL/LOAD httpfs after each `LOAD vgi;`. Without it
# the http ATTACH fails with a "HTTP"-containing error that the sqllogictest
# runner *silently auto-skips* (default ignore_error_messages), masking the gap.
for f in "$REPO"/test/sql/*.test; do
  awk -v transport="$TRANSPORT" -f "$HERE/preprocess-require.awk" "$f" > "$STAGE/test/sql/$(basename "$f")"
done

# The .test files read committed fixtures by relative path (test/sql/data/*.evtx).
# Subprocess: DuckDB spawns the worker with the runner's cwd (= $STAGE). http/unix:
# we launch the worker with cwd = $STAGE (see start_server_and_set_location). Stage
# the fixtures so both resolve them either way.
cp -R "$REPO/test/sql/data" "$STAGE/test/sql/"

case "$TRANSPORT" in
  subprocess)
    # The binary itself is the stdio LOCATION DuckDB spawns. Honor an explicit
    # VGI_EVTX_WORKER (e.g. a bare command) if the caller set one.
    export VGI_EVTX_WORKER="${VGI_EVTX_WORKER:-$WORKER_BIN}"
    ;;
  http)
    # Honor a pre-launched HTTP worker (e.g. a running container in the docker
    # image_test): if VGI_EVTX_WORKER already points at an http(s) URL, use it
    # as-is and skip spawning a local binary. Otherwise launch evtx-worker
    # --http ourselves (with cwd = $STAGE, so the VARCHAR-path fixtures resolve).
    if [[ "${VGI_EVTX_WORKER:-}" =~ ^https?:// ]]; then
      echo "Using pre-launched HTTP worker at $VGI_EVTX_WORKER"
    else
      start_server_and_set_location http
    fi
    ;;
  unix)  start_server_and_set_location unix ;;
  *) echo "ERROR: unknown TRANSPORT '$TRANSPORT' (want subprocess|http|unix)" >&2; exit 1 ;;
esac

: "${VGI_EVTX_WORKER:?worker LOCATION (stdio command, http:// URL, or unix:// socket)}"

cd "$STAGE"

# Warm the extension cache once: vgi from the signed community channel. A miss
# here is only a warning — the per-test LOAD vgi; (the .test files load it
# explicitly) is what actually gates each file, and that LOAD only succeeds once
# vgi has been INSTALLed from community.
echo "Warming the extension cache (vgi from community) ..."
mkdir -p "$STAGE/test"
cat > "$STAGE/test/_warm.test" <<'EOF'
# name: test/_warm.test
# group: [warm]
statement ok
INSTALL vgi FROM community;
EOF
"$HAYBARN_UNITTEST" "test/_warm.test" >/dev/null 2>&1 || echo "::warning::extension warm step did not fully succeed"
rm -f "$STAGE/test/_warm.test"

# Run the whole suite in one invocation, streaming the runner's native
# sqllogictest report. Any failed assertion exits non-zero and fails the job.
#
# Guard against the silent-skip trap: DuckDB's sqllogictest runner auto-skips
# any test whose error message contains "HTTP" (default ignore_error_messages),
# so a broken http leg can report "All tests were skipped" with exit 0 and look
# green. Tee the report and fail if NOTHING actually ran. (For subprocess/unix
# there is no skip path, so this only ever bites a genuinely broken http leg.)
echo "Running suite (transport: $TRANSPORT, worker: $VGI_EVTX_WORKER) ..."
REPORT="$STAGE/.report.txt"
set +e
"$HAYBARN_UNITTEST" "test/sql/*" 2>&1 | tee "$REPORT"
status="${PIPESTATUS[0]}"
set -e
if grep -qiE "All tests were skipped|total skipped [1-9]" "$REPORT"; then
  echo "ERROR: tests were SKIPPED — almost certainly an ATTACH/transport error whose" >&2
  echo "       message matched the runner's default ignore list (e.g. \"HTTP\"). A skip" >&2
  echo "       is NOT a pass. Transport=$TRANSPORT worker=$VGI_EVTX_WORKER." >&2
  exit 1
fi
exit "$status"
