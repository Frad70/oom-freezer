# oom-freezer

A small Linux daemon and CLI that freezes idle, memory-heavy background
processes and thaws them on demand. A frozen process tree is moved into its own
cgroup v2 leaf, stopped with `cgroup.freeze`, and its pages are pushed to swap
with `process_madvise(MADV_PAGEOUT)` and `memory.reclaim`. Everything is
reversible: `oom-freezer thaw` resumes the process and moves it back to its
original cgroup, and its pages fault back in as it touches them.

## Why

A desktop or a development machine tends to collect long-running processes
nobody uses any more: a test server started hours ago, a forgotten JVM, a
Gradle daemon. They hold gigabytes of RAM and push the machine towards swap
storms and the OOM killer. Killing them loses state; freezing them keeps the
state and gives the memory back.

oom-freezer shares the idea of a protect list with aegis-oom (a PSI based OOM
guard, https://github.com/Frad70/aegis-oom) but needs no code from it; the
protect list parsing follows the same rules as aegis-oom.

## Build

    make            # builds ./oom-freezer
    make test       # offline tests, no root needed

Requirements: a C11 compiler and Linux headers. `make test` also needs bash and
runs the daemon in dry-run for ten seconds.

## Install

    sudo ./install.sh                  # PREFIX defaults to /usr/local
    sudo PREFIX=/opt/oom-freezer ./install.sh

The script builds the binary, installs it to `$PREFIX/bin/oom-freezer`,
installs `/etc/oom-freezer/oom-freezer.conf` (an existing config is kept and
the new default goes to `oom-freezer.conf.default`), writes
`/etc/systemd/system/oom-freezer.service` with the prefix substituted, and
enables and restarts the service. The service runs as root with
`Type=notify` and a 120 s watchdog.

To uninstall: `systemctl disable --now oom-freezer`, then remove the unit, the
binary and `/etc/oom-freezer`.

## Start in dry-run

The shipped config has `FREEZE_DRYRUN=1`. In this mode every decision is made
and logged, but nothing is frozen:

    journalctl -t oom-freezer -f       # "dry-run: would freeze ..."
    cat /run/oom-freezer/freeze.state  # every candidate with its verdict

Each `cand` line in `freeze.state` shows the kind, RSS, CPU, idle minutes, age
and verdict of one candidate. When the verdicts look right for a few days, set
`FREEZE_DRYRUN=0` and `systemctl reload oom-freezer`.

## CLI

    oom-freezer [--conf FILE] [COMMAND]
      daemon        run the freezer loop (default)
      once          run one scan and exit
      list          show frozen processes
      freeze PID    freeze a process tree now, ignoring the idle thresholds
      thaw SPEC     thaw by name, pid, cgroup name or all

`once` starts without a CPU sample, so it only writes `freeze.state` with
`no-sample` verdicts and never acts. `list` needs only read access to
`/run/oom-freezer/frozen`. `freeze` and
`thaw` need root. One-shot commands print their log lines to stderr as well.
The environment variables `OOM_FREEZER_CONF` and `OOM_FREEZER_STATE` override
the config path and the state directory.

## Configuration

`/etc/oom-freezer/oom-freezer.conf` is parsed as `KEY=value` lines; no shell
code is evaluated. Unknown keys are logged. Reload with
`systemctl reload oom-freezer` (SIGHUP).

| Key | Default | Meaning |
|-----|---------|---------|
| FREEZE_DRYRUN | 1 | 1 logs decisions only, 0 acts |
| FREEZE_ENABLE | 1 | 0 disables scanning entirely |
| FREEZE_INTERVAL_S | 15 | main loop tick, seconds |
| FREEZE_POLL_S | 60 | seconds between /proc scans |
| FREEZE_MIN_UPTIME_MIN | 60 | minimum process age |
| FREEZE_IDLE_MIN | 30 | minutes the process must stay below the CPU threshold |
| FREEZE_CPU_IDLE_PCT | 12 | CPU percent of one core that counts as idle |
| FREEZE_MIN_RSS_MB | 128 | smaller processes are ignored |
| FREEZE_BIG_JAVA_MB | 1024 | a java process this large is a java-big candidate |
| FREEZE_JAVA_BIG | 0 | 1 lets java-big candidates be frozen |
| FREEZE_GRADLE | 1 | 1 sends SIGTERM to idle Gradle daemons |
| FREEZE_WATCH | empty | substrings that make any process a candidate |
| FREEZE_SERVER_JARS | server | jar name prefixes of game server jars |
| FREEZE_SERVER_MAIN | empty | main class names of game servers |
| FREEZE_EXCLUDE | empty | substrings never frozen automatically |
| FREEZE_NEVER | empty | substrings never frozen, not even manually |
| FREEZE_IGNORE | empty | substrings not even evaluated |
| FREEZE_PROTECT | see below | exact process names protected with their descendants |
| FREEZE_ACTIVE_CMD | empty | absolute path of an activity check program |
| FREEZE_ACTIVE_TIMEOUT_S | 10 | time limit for the activity check |
| FREEZE_RECLAIM_MB | 256 | chunk written to memory.reclaim |
| FREEZE_RECLAIM_MAX_S | 60 | time budget for reclaim |

Substring lists match the command line, the working directory and the
executable path, case-insensitive, comma-separated, at most 32 entries of up
to 31 bytes; extra entries are dropped with a warning. An unquoted value ends
at `#`, so quote a value that contains `#`.

## How it decides

Every `FREEZE_POLL_S` seconds the daemon reads `/proc`. For each process the
checks run in this order; the first one that fails ends the evaluation.

1. RSS is at least `FREEZE_MIN_RSS_MB`.
2. Classification. The first match sets the kind:
   - `watched`: the command line, cwd or exe contains an entry of `FREEZE_WATCH`;
   - `gradle-daemon`: the command line names the Gradle daemon;
   - `game-server`: the executable is java and a jar argument starts with an
     entry of `FREEZE_SERVER_JARS`, or the command line contains an entry of
     `FREEZE_SERVER_MAIN`;
   - `java-big`: the executable is java and RSS is at least `FREEZE_BIG_JAVA_MB`.

   Anything else is not a candidate.
3. `FREEZE_IGNORE` matches: skipped silently.
4. Already frozen: skipped.
5. CPU is sampled as the average since the previous poll. A sample below
   `FREEZE_CPU_IDLE_PCT` starts or continues the idle period, a sample above
   ends it.

The verdict written to `freeze.state` then follows this order:

| Verdict | Meaning |
|---------|---------|
| `excluded:<entry>` | `FREEZE_EXCLUDE` matched |
| `never:<reason>` | protected, see the next section |
| `young` | younger than `FREEZE_MIN_UPTIME_MIN` |
| `no-sample` | first poll, no CPU sample yet |
| `busy` | the last sample was above the CPU threshold |
| `active-cmd` | the activity check said the process is in use |
| `idle-N-of-M-min` | idle, but not for `FREEZE_IDLE_MIN` yet |
| `FORGOTTEN-opt-in-off` | would qualify, but its kind is disabled (java-big without `FREEZE_JAVA_BIG`, gradle-daemon without `FREEZE_GRADLE`) |
| `FORGOTTEN` | will be acted on |

For a `FORGOTTEN` process:

1. If `FREEZE_ACTIVE_CMD` is set, it runs (at most once per poll). Exit status
   1 permits the freeze. Exit 0 means the process is in use and resets its idle
   period. Any other exit status, a crash, a timeout or a missing program also
   blocks the freeze and is logged.
2. At most one action per poll, and at most one per process every 15 minutes.
3. Dry-run logs `dry-run: would freeze`. Otherwise a Gradle daemon gets SIGTERM
   (a frozen Gradle daemon hangs the next build, and a new daemon starts by
   itself), and everything else is frozen.

Freezing a process:

1. Re-read the process; cancel if its start time changed or it is now protected.
2. Collect the whole process tree (at most 256 processes). Cancel if the tree
   cannot be read completely or any member is protected or holds a GPU node.
3. Create `/sys/fs/cgroup/oom-freezer/<name>-<pid>-<start>`, enable the memory
   controller, move every task, write `cgroup.freeze` and wait up to 5 s for
   `frozen 1` in `cgroup.events`.
4. Append a recovery record to `/run/oom-freezer/frozen` before anything slow.
5. Page out every task, then reclaim what is still charged to the leaf, in
   chunks, within `FREEZE_RECLAIM_MAX_S`.
6. Replace the record with the final PSS and swap figures.

If any step from 3 to 4 fails, the leaf is thawed, the tasks are moved back to
their original cgroup and the leaf is removed. A failure to move back is logged
with a pointer to `oom-freezer thaw`.

## What is never frozen

- PID 1, the daemon itself, its parent and ancestors, and its session leader,
  whatever the config says.
- Processes whose name contains a built-in system name: pipewire, wireplumber,
  pulse, kwin, plasma, Xorg, Xwayland, mutter, gnome-shell, sddm, gdm, systemd,
  dbus, sshd, init, NetworkManager, wayland, polkit, sway, weston, aegis-oom,
  aegis-reaper.
- `FREEZE_NEVER` matches.
- `FREEZE_PROTECT` names (exact comm or label), and every descendant of a
  protected process up to the next shell, terminal multiplexer, login or
  compositor boundary. The default list is systemd, init, sshd, dbus-daemon,
  pipewire, wireplumber, Xorg, Xwayland, gnome-shell, kwin_wayland, sway and
  weston. Processes with `oom_score_adj` of -1000 are protected the same way.
- Any process with a `/dev/dri` node open (a GUI or a game), and any tree that
  contains one.
- `FREEZE_EXCLUDE` matches are not frozen automatically, but can be frozen by
  hand.

## Why did my server stop responding?

A frozen process looks hung: connections reach the kernel backlog but are
never answered, and it uses no CPU at all. If a
service that sat idle for a while suddenly stops answering, check whether it
was frozen:

    oom-freezer list
    cat /sys/fs/cgroup/oom-freezer/*/cgroup.events   # "frozen 1"
    journalctl -t oom-freezer | grep frozen

Thaw it:

    sudo oom-freezer thaw paper.jar      # by name from the list
    sudo oom-freezer thaw 12345          # by pid
    sudo oom-freezer thaw all

Exempt it permanently with `FREEZE_EXCLUDE` (automatic freezing off, manual
freeze still possible) or `FREEZE_NEVER` (never), using a substring of its
command line or working directory, then `systemctl reload oom-freezer`.

### Worked example: a game server with players

A game server started with `java -jar paper-1.21.jar` in `/srv/game` matches
`FREEZE_SERVER_JARS=paper`. With a few players online and nothing happening it
can use less than 12 % of one core for half an hour, and it gets frozen while
people are connected.

Two ways out:

1. Exclude it: `FREEZE_EXCLUDE=/srv/game`. It is never frozen automatically,
   even when nobody has played for a week.
2. Keep it eligible, but only when it is empty. Add an activity check:

       #!/bin/sh
       # /usr/local/libexec/server-has-players <pid> <kind> <name>
       # Exit 0 when someone is connected to the game port, 1 otherwise.
       n=$(ss -Htn state established '( sport = :25565 )' | wc -l)
       [ "$n" -gt 0 ] && exit 0
       exit 1

   and set `FREEZE_ACTIVE_CMD=/usr/local/libexec/server-has-players`. While
   players are connected the verdict is `active-cmd` and the idle period starts
   over. Once the server has been empty and idle for `FREEZE_IDLE_MIN`, it is
   frozen. The program runs as root without a shell, so give it an absolute
   path and keep it owned by root.

## Tests

`make test` runs:

- `test_freezer.c`, offline, no root: config parsing and defaults, the verdict
  order, the dry-run switch, the recovery registry (atomic replace, refusal of
  symlinks, partial and oversized files, path traversal), thaw failure paths,
  label privacy, process tree completeness, rollback at each failure point of a
  freeze (migration, partial migration of a two process tree, freeze write,
  freeze not confirmed, registry) on a fake cgroup tree, the scan loop end to
  end in dry-run with two idle fixtures and an activity check, the activity check (exit 0, exit 1, other status, timeout,
  missing program), game server jar configuration, `list` output, strict pid
  parsing, list overflow warnings, pageout on a kernel without
  `process_madvise`, the own-tree protection and the start-up support checks.
  The rollback tests print a SKIP line when `/proc/self/cgroup` has no cgroup v2
  path.
- `tests/cases_idle.sh`: runs the daemon in dry-run with a 2 s poll for ten
  seconds and fails above 500 ms of CPU.

`make test-live` runs `tests/test_freeze_live.py`, which needs root or
`sudo -n` and cgroup v2, and prints SKIP otherwise. It creates its own cgroup
tree under `/sys/fs/cgroup/oom-freezer-test-<pid>`, freezes a 32 MiB fixture
process, checks that the recovery record exists before the first pageout,
breaks the original cgroup and the registry to check that thaw keeps the
record and a retry completes, and checks that the fixture's data is intact.

Not covered by tests: the scan loop freezing real candidates in live mode, the
Gradle SIGTERM path, GPU detection, the ancestry walk of the protect list on a real
desktop, and reclaim on large processes.

This README was written from the code. The behaviour described in "How it
decides" and "What is never frozen" follows the source; the parts listed above
are the ones exercised by tests.

## Limits

- Linux with cgroup v2 only. The binary exits with a message when
  `/sys/fs/cgroup/cgroup.controllers` is missing (cgroup v1), when the kernel
  has no `cgroup.freeze` (before 5.2), or when it would act without write
  access to `/sys/fs/cgroup` (an unprivileged container). It exits with status
  78 in these cases and the unit does not restart on it. Dry-run works without
  write access.
- Memory pressure (PSI) is not read. The freezer acts on idleness and size,
  not on pressure; reacting to pressure is the job of an OOM killer such as
  aegis-oom.
- Pageout needs `process_madvise` (Linux 5.10); without it the freeze still
  works, pageout is disabled with one log line, and `memory.reclaim`
  (Linux 5.19) is the only way memory is returned. Freed memory goes to swap or
  zram; without swap, freezing stops the CPU use but frees little RAM.
- The raw syscall numbers fall back to 434 and 440 only on architectures with
  the unified syscall table; elsewhere the build needs headers that define them.
- A frozen process keeps its sockets open. Clients see timeouts, not refused
  connections.
- Idle samples live in memory. After a daemon restart every candidate starts
  its idle period again.
- At most 64 candidates are tracked between polls, one action per poll, trees
  of at most 256 processes, a recovery registry of at most 64 KiB.
- The registry lives in `/run` and does not survive a reboot; neither do the
  frozen processes.

## License

MIT, see LICENSE.
