#!/usr/bin/env bash
# cases_idle.sh: the cost of running. The daemon runs in dry-run with a short
# poll and must stay within a CPU budget, so a full /proc scan per poll does
# not quietly grow into a visible load.
# Usage: tests/cases_idle.sh path/to/oom-freezer
set -u
BIN=${1:?usage: cases_idle.sh path/to/oom-freezer}
WIN=10 BUDGET_MS=500

if [ ! -r /sys/fs/cgroup/cgroup.controllers ]; then
  echo "SKIP: idle budget needs cgroup v2"; exit 0
fi
dir=$(mktemp -d "${TMPDIR:-/tmp}/oom-freezer-idle-XXXXXX") || exit 1
printf 'FREEZE_DRYRUN=1\nFREEZE_POLL_S=2\nFREEZE_INTERVAL_S=1\n' > "$dir/conf"

OOM_FREEZER_STATE="$dir" "$BIN" --conf "$dir/conf" daemon 2>"$dir/log" &
pid=$!
cleanup() { kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; find "$dir" -mindepth 1 -delete; rmdir "$dir"; }
trap cleanup EXIT

cpu_ms() {
  local hz; hz=$(getconf CLK_TCK 2>/dev/null || echo 100)
  awk -v hz="$hz" '{ sub(/.*\) /, ""); print int((($12 + $13) * 1000) / hz) }' "/proc/$1/stat" 2>/dev/null
}

sleep 1
t0=$(cpu_ms "$pid")
[ -n "$t0" ] || { echo "FAIL: daemon exited at start: $(cat "$dir/log")"; exit 1; }
sleep "$WIN"
t1=$(cpu_ms "$pid")
[ -n "$t1" ] || { echo "FAIL: daemon exited during the measurement: $(cat "$dir/log")"; exit 1; }
spent=$(( t1 - t0 ))
if ! grep -q '^mode dry-run' "$dir/freeze.state" 2>/dev/null; then
  echo "FAIL: no freeze.state written in dry-run"; exit 1
fi
if [ "$spent" -le "$BUDGET_MS" ]; then
  echo "OK: ${spent} ms CPU in ${WIN} s with a 2 s poll (budget ${BUDGET_MS} ms)"
else
  echo "FAIL: ${spent} ms CPU in ${WIN} s with a 2 s poll, budget ${BUDGET_MS} ms"; exit 1
fi
