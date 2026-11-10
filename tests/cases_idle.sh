#!/usr/bin/env bash
# cases_idle.sh: the cost of idling. The daemon must stay quiet when nothing
# happens: a full /proc scan exists only to pick a victim, and the decision
# "kill or not" is made from two cheap files.
#
# The measurement is not decoration: without it "idle = ~0%" would quietly
# stop being true a few features later, and nobody would notice.

IDLE_STATE=""; IDLE_WATCH=""; IDLE_PID=""

idle_env() {   # thresholds far away on purpose, so the daemon surely considers itself idle
  IDLE_STATE="$STATE_DIR/idle.state"
  IDLE_WATCH="$STATE_DIR/idle.watch"
  export FREEZE_OOM_WATCH="$IDLE_WATCH"
  export FREEZE_OOM_AVAIL_SOFT_MB=1 FREEZE_OOM_AVAIL_HARD_MB=1
  export FREEZE_OOM_PSI_SOFT=99 FREEZE_OOM_PSI_HARD=99
  export FREEZE_OOM_IDLE_MS=1000 FREEZE_OOM_REFRESH_MS=500 FREEZE_OOM_IDLE_SCAN_S=3600
}

idle_start() {
  "$OOM_BIN" --dry-run --no-arm --no-conf --no-learn --state "$IDLE_STATE" --protect __none__ \
      >"$STATE_DIR/idle.out" 2>&1 &
  IDLE_PID=$!
  sleep 1
}
idle_stop() { [ -n "$IDLE_PID" ] && kill "$IDLE_PID" 2>/dev/null; wait "$IDLE_PID" 2>/dev/null; IDLE_PID=""; }

idle_field() { awk -v k="$1" '$1==k{print $2; exit}' "$IDLE_STATE" 2>/dev/null; }

# process CPU time in milliseconds (utime+stime from /proc/<pid>/stat)
idle_cpu_ms() {
  local hz; hz=$(getconf CLK_TCK 2>/dev/null || echo 100)
  awk -v hz="$hz" '{print int((($14+$15)*1000)/hz)}' "/proc/$1/stat" 2>/dev/null || echo 0
}

# ---- while idle /proc is not scanned ----------------------------------------
idle_no_scan_quiet() {
  local f=0 age
  idle_env; idle_start
  sleep 8
  age=$(idle_field scan_age_s)
  if [ -n "$age" ] && [ "$age" -ge 5 ] 2>/dev/null; then
    sub_ok "no scan while idle: snapshot is $age s old"
  else
    sub_bad "scanning while idle (scan_age_s=${age:-none}): /proc polling is back"; f=1
  fi
  # the state MUST still refresh: memory and PSI are always read
  local avail; avail=$(idle_field mem_avail_kb)
  if [ -n "$avail" ] && [ "$avail" -gt 0 ] 2>/dev/null; then
    sub_ok "memory is tracked while idle too (avail=${avail}kB)"
  else
    sub_bad "memory metrics stopped refreshing while idle: starvation would be missed"; f=1
  fi
  idle_stop; return $f
}

# ---- monitor open -> fresh snapshot ------------------------------------------
idle_watcher_wakes() {
  local f=0 age i
  idle_env; idle_start
  for i in 1 2 3 4 5 6; do : >"$IDLE_WATCH" 2>/dev/null; sleep 1; done
  age=$(idle_field scan_age_s)
  if [ -n "$age" ] && [ "$age" -le 2 ] 2>/dev/null; then
    sub_ok "snapshot is fresh with the monitor open ($age s)"
  else
    sub_bad "the monitor is open but the data is stale (scan_age_s=${age:-none})"; f=1
  fi
  local procs; procs=$(grep -c '^proc ' "$IDLE_STATE" 2>/dev/null || echo 0)
  if [ "$procs" -gt 0 ]; then sub_ok "process table is filled ($procs)"
  else sub_bad "process table is empty with the monitor open"; f=1; fi
  idle_stop; return $f
}

# ---- CPU budget while idle ---------------------------------------------------
idle_cpu_budget() {
  local f=0 t0 t1 spent win=10 budget=60
  idle_env; idle_start
  t0=$(idle_cpu_ms "$IDLE_PID")
  sleep "$win"
  t1=$(idle_cpu_ms "$IDLE_PID")
  spent=$(( t1 - t0 ))
  local pct; pct=$(awk -v s="$spent" -v w="$win" 'BEGIN{printf "%.2f", s/(w*10)}')
  if [ "$spent" -le "$budget" ]; then
    sub_ok "idle: ${spent} ms CPU in ${win} s = ${pct}% of a core (budget ${budget} ms)"
  else
    sub_bad "idle uses ${spent} ms in ${win} s = ${pct}% of a core, budget ${budget} ms"; f=1
  fi
  idle_stop; return $f
}

register_idle() {
  add_case fast idle "idle:no-scan"     "no /proc scan while idle, memory still tracked" 'idle_no_scan_quiet'
  add_case fast idle "idle:watcher"     "an open monitor wakes the hot cycle"            'idle_watcher_wakes'
  add_case fast idle "idle:cpu-budget"  "CPU budget while idle"                          'idle_cpu_budget'
}
