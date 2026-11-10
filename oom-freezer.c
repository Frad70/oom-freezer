/* oom-freezer: freezes idle, memory-heavy background processes into a
 * cgroup v2 leaf and pushes their pages to swap.
 */
#define _GNU_SOURCE
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include <syslog.h>
#include <time.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/file.h>
#include <ctype.h>
#include <limits.h>

#define MAXPROC   4096

/* ================================ config ================================= */

typedef struct {
    const char *state_dir;
    int dryrun, interval;
    int enable, poll_s, uptime_min, idle_min;
    int cpu_idle_pct, min_rss_mb, big_java_mb, java_big, gradle;
    int reclaim_mb, reclaim_max_s;
    int active_timeout_s;
    char active_cmd[PATHMAX];
    namelist watch, exclude, never, ignore, server_jars, server_main;
    protect_list protect;
} fz_config;

static volatile sig_atomic_t g_stop = 0, g_reload = 0;

static void on_term(int s) { (void)s; g_stop = 1; }
static void on_hup(int s)  { (void)s; g_reload = 1; }

/* ============================= config parsing ============================ */

#define DEFAULT_PROTECT "systemd,init,sshd,dbus-daemon,pipewire,wireplumber,Xorg,Xwayland,gnome-shell,kwin_wayland,sway,weston"

static void cfg_defaults(fz_config *c) {
    const char *dir = c->state_dir;
    memset(c, 0, sizeof *c);
    c->state_dir = dir ? dir : "/run/oom-freezer";
    protect_parse(DEFAULT_PROTECT, &c->protect);
    c->dryrun = 1; c->interval = 15;
    c->enable = 1; c->poll_s = 60;
    c->uptime_min = 60; c->idle_min = 30; c->cpu_idle_pct = 12;
    c->min_rss_mb = 128; c->big_java_mb = 1024;
    c->java_big = 0; c->gradle = 1;
    c->reclaim_mb = 256; c->reclaim_max_s = 60;
    list_parse(&c->server_jars, "server");
    c->active_timeout_s = 10;
}

static int cfg_integer(const char *value, int *out) {
    char *end; errno = 0; long n = strtol(value, &end, 10);
    if (errno || end == value || *end || n < 0 || n > INT_MAX) return 0;
    *out = (int)n; return 1;
}

static void cfg_apply(fz_config *c, const char *key, const char *val) {
    if (!strcmp(key, "FREEZE_PROTECT")) { protect_parse(val, &c->protect); return; }
    if (!strcmp(key, "FREEZE_ACTIVE_CMD")) {
        if (!val[0] || val[0] == '/') xcpy(c->active_cmd, sizeof c->active_cmd, val);
        else lg(LOG_WARNING, "config: %s must be an absolute path, ignored", key);
        return;
    }
    #define I(name, field) if (!strcmp(key, name)) { int n; if (cfg_integer(val, &n)) c->field = n; else lg(LOG_WARNING, "config: invalid numeric value for %s, default kept", key); return; }
    #define L(name, field) if (!strcmp(key, name)) { if (list_parse(&c->field, val)) lg(LOG_WARNING, "config: %s keeps %d entries of at most %d bytes, the rest is ignored", key, MAXLIST, MAXNAME - 1); return; }
    I("FREEZE_DRYRUN", dryrun) I("FREEZE_INTERVAL_S", interval)
    I("FREEZE_ENABLE", enable)
    I("FREEZE_POLL_S", poll_s) I("FREEZE_MIN_UPTIME_MIN", uptime_min)
    I("FREEZE_IDLE_MIN", idle_min) I("FREEZE_CPU_IDLE_PCT", cpu_idle_pct)
    I("FREEZE_MIN_RSS_MB", min_rss_mb) I("FREEZE_BIG_JAVA_MB", big_java_mb)
    I("FREEZE_JAVA_BIG", java_big) I("FREEZE_GRADLE", gradle)
    I("FREEZE_ACTIVE_TIMEOUT_S", active_timeout_s)
    I("FREEZE_RECLAIM_MB", reclaim_mb) I("FREEZE_RECLAIM_MAX_S", reclaim_max_s)
    L("FREEZE_WATCH", watch) L("FREEZE_EXCLUDE", exclude)
    L("FREEZE_NEVER", never) L("FREEZE_IGNORE", ignore)
    L("FREEZE_SERVER_JARS", server_jars) L("FREEZE_SERVER_MAIN", server_main)
    #undef I
    #undef L
    /* A mistyped exemption key must not pass silently. */
    lg(LOG_WARNING, "config: unknown key %s ignored", key);
}

static void cfg_load(fz_config *c, const char *path) {
    cfg_defaults(c);
    static char buf[64 * 1024];
    if (read_file(path, buf, sizeof buf) < 0) return;
    char *line = buf;
    while (line && *line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        char key[64], value[1024];
        if (config_assignment(line, key, sizeof key, value, sizeof value)) cfg_apply(c, key, value);
        line = nl ? nl + 1 : 0;
    }
    if (c->interval < 1) c->interval = 15;
}

/* ============================ process helpers ============================ */

/* Our own process tree: whoever started us and its ancestors. Freezing them
 * would freeze the shell or service manager that has to undo it. */
#define FZ_ANCESTOR_HOPS 24
static int fz_is_ancestor(int pid) {
    int cur = (int)getppid();
    for (int hop = 0; hop < FZ_ANCESTOR_HOPS && cur > 1; hop++) {
        if (cur == pid) return 1;
        char p[64], b[512];
        snprintf(p, sizeof p, "/proc/%d/stat", cur);
        if (read_file(p, b, sizeof b) < 0) break;
        char *rp = strrchr(b, ')');
        if (!rp) break;
        int st_pid = 0;
        if (sscanf(rp + 2, "%*c %d", &st_pid) != 1) break;
        cur = st_pid;
    }
    return 0;
}

/* PID 1, this process, its parent chain and its session leader are never
 * touched, whatever the config says. */
static int fz_own(int pid) {
    return pid <= 1 || pid == getpid() || pid == getppid() || pid == getsid(0) || fz_is_ancestor(pid);
}

static int fz_sacred(const char *comm, int pid) {
    static const char *sacred[] = {
        "pipewire", "wireplumber", "pulse", "kwin", "plasma", "Xorg", "Xwayland",
        "mutter", "gnome-shell", "sddm", "gdm", "systemd", "dbus", "sshd", "init",
        "NetworkManager", "wayland", "polkit", "sway", "weston", "aegis-oom", "aegis-reaper", 0
    };
    for (int i = 0; sacred[i]; i++) if (strstr(comm, sacred[i])) return 1;
    if (pid > 0 && fz_own(pid)) return 1;
    return 0;
}

/* A process with a /dev/dri node open draws on the GPU: a GUI or a game.
 * WAYLAND_DISPLAY cannot tell this, every descendant of a session inherits it. */
static int holds_gpu(int pid) {
    char dir[64];
    snprintf(dir, sizeof dir, "/proc/%d/fd", pid);
    DIR *d = opendir(dir);
    if (!d) return 0;
    struct dirent *e;
    int found = 0;
    while (!found && (e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        char p[PATHMAX], link[256];
        if (snprintf(p, sizeof p, "%s/%s", dir, e->d_name) >= (int)sizeof p) continue;
        ssize_t n = readlink(p, link, sizeof link - 1);
        if (n <= 0) continue;
        link[n] = 0;
        if (!strncmp(link, "/dev/dri/", 9)) found = 1;
    }
    closedir(d);
    return found;
}

/* ====================== FREEZING IDLE BACKGROUND PROCESSES ============== */
/* An idle background process is frozen rather than killed: cgroup.freeze stops the
 * whole tree, process_madvise(MADV_PAGEOUT) pushes its pages to swap. All of it
 * is reversible: oom-freezer thaw resumes the process, pages fault back in.
 *
 * Why MADV_PAGEOUT rather than a single memory.reclaim: in cgroup v2 memory
 * charges do not move with a process. A fresh cgroup after moving the pid
 * shows memory.current=0, and memory.reclaim returns EAGAIN without freeing
 * anything (RSS was measured unchanged before and after). Reclaim stays
 * the second step: after a thaw, pages come back charged to our cgroup, and
 * the next freeze makes use of that. */

#ifndef FZ_MNT
#define FZ_MNT      "/sys/fs/cgroup"
#endif
#ifndef FZ_ROOT
#define FZ_ROOT     "/sys/fs/cgroup/oom-freezer"
#endif
#define FZ_MAXCAND  64              /* candidates tracked between polls */
#define FZ_RATE_S   900             /* one action per process per 15 minutes */
#define FZ_REG_MAX  (64 * 1024)     /* registry size every reader accepts */
#define FZ_IOV_MAX  256             /* ranges per process_madvise call */
#define FZ_RECLAIM_FLOOR   (4L * 1024 * 1024)  /* stop reclaim below this */
#define FZ_RECLAIM_STALL   (1L * 1024 * 1024)  /* progress smaller than this is a stall */
#define FZ_RECLAIM_PAUSE_US 100000
#define FZ_POLL_STEP_MS    50
#define FZ_MAXTREE  256             /* processes in one frozen tree */
#define FZ_KEYLEN   40
#define FZ_NAMELEN  64
#define FZ_CMDLEN   16384

/* Old libc headers may lack these. 434 and 440 are the numbers of the unified
 * syscall table shared by the architectures listed; others (alpha, mips, x32)
 * use offsets, so they must come from the headers. */
#if !defined(SYS_pidfd_open) || !defined(SYS_process_madvise)
# if (defined(__x86_64__) && !defined(__ILP32__)) || defined(__i386__) || defined(__aarch64__) || \
     defined(__arm__) || defined(__riscv) || defined(__powerpc__) || defined(__s390__) || defined(__loongarch__)
#  ifndef SYS_pidfd_open
#   define SYS_pidfd_open 434
#  endif
#  ifndef SYS_process_madvise
#   define SYS_process_madvise 440
#  endif
# else
#  error "unknown architecture: use kernel headers that define SYS_pidfd_open and SYS_process_madvise"
# endif
#endif
#ifndef MADV_PAGEOUT
#define MADV_PAGEOUT 21
#endif

typedef struct {
    int  pid, ppid;
    unsigned long long start, ticks;
    long rss_kb;
    char comm[MAXNAME];
    char raw[FZ_CMDLEN];
    int  rawlen;
    char cmd[FZ_CMDLEN];
    char exe[PATHMAX];
    char cwd[PATHMAX];
    char hay[FZ_CMDLEN + 2 * PATHMAX];
} fz_proc;

typedef struct {
    char key[FZ_KEYLEN];
    long last_seen, idle_since;
    unsigned long long ticks;
    double cpu_pct;
    int  sampled;
} fz_slot;

typedef struct {
    fz_slot slots[FZ_MAXCAND];
    long    last;
} fz_state;

static int fz_write_file(const char *path, const char *val) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = write(fd, val, strlen(val));
    int e = errno;
    close(fd);
    errno = e;
    return n == (ssize_t)strlen(val) ? 0 : -1;
}

/* Every cgroup control write goes through this pointer so tests can inject failures. */
static int (*fz_write)(const char *path, const char *val) = fz_write_file;
static int fz_wait_ms = 5000;

static void fz_sanitize(char *s) {
    for (; *s; s++)
        if (!((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') ||
              (*s >= '0' && *s <= '9') || *s == '.' || *s == '_' || *s == '-')) *s = '_';
}

static const char *fz_base(const char *p) {
    const char *s = strrchr(p, '/');
    return s ? s + 1 : p;
}

static int fz_server_jar(const fz_config *c, const char *b) {
    size_t n = strlen(b);
    if (n <= 4 || strcasecmp(b + n - 4, ".jar")) return 0;
    for (int i = 0; i < c->server_jars.n; i++)
        if (!strncasecmp(b, c->server_jars.v[i], strlen(c->server_jars.v[i]))) return 1;
    return 0;
}

static const char *fz_list_hit(const namelist *l, const char *hay) {
    for (int i = 0; i < l->n; i++)
        if (l->v[i][0] && strcasestr(hay, l->v[i])) return l->v[i];
    return 0;
}

static int fz_read(int pid, fz_proc *p) {
    char path[64], buf[1024];
    memset(p, 0, sizeof *p);
    p->pid = pid;

    snprintf(path, sizeof path, "/proc/%d/stat", pid);
    if (read_file(path, buf, sizeof buf) < 0) return -1;
    char *lp = strchr(buf, '('), *rp = strrchr(buf, ')');
    if (!lp || !rp || rp <= lp) return -1;
    size_t cl = (size_t)(rp - lp - 1);
    if (cl >= sizeof p->comm) cl = sizeof p->comm - 1;
    memcpy(p->comm, lp + 1, cl);
    const char *q = rp + 2;
    unsigned long long ut = 0, st = 0;
    long rss_pages = 0;
    for (int f = 3; *q && f <= 24; f++) {
        if (f == 4)  p->ppid = (int)strtol(q, 0, 10);
        if (f == 14) ut = strtoull(q, 0, 10);
        if (f == 15) st = strtoull(q, 0, 10);
        if (f == 22) p->start = strtoull(q, 0, 10);
        if (f == 24) rss_pages = strtol(q, 0, 10);
        while (*q && *q != ' ') q++;
        while (*q == ' ') q++;
    }
    p->ticks = ut + st;
    p->rss_kb = rss_pages * (sysconf(_SC_PAGESIZE) / 1024);

    snprintf(path, sizeof path, "/proc/%d/cmdline", pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = read(fd, p->raw, sizeof p->raw - 1);
    close(fd);
    if (n <= 0) return -1;
    p->raw[n] = 0;
    p->rawlen = (int)n;
    memcpy(p->cmd, p->raw, (size_t)n);
    p->cmd[n] = 0;
    for (ssize_t i = 0; i < n; i++) if (!p->cmd[i]) p->cmd[i] = ' ';
    while (n > 0 && p->cmd[n - 1] == ' ') p->cmd[--n] = 0;

    snprintf(path, sizeof path, "/proc/%d/exe", pid);
    ssize_t k = readlink(path, p->exe, sizeof p->exe - 1);
    p->exe[k > 0 ? k : 0] = 0;
    snprintf(path, sizeof path, "/proc/%d/cwd", pid);
    k = readlink(path, p->cwd, sizeof p->cwd - 1);
    p->cwd[k > 0 ? k : 0] = 0;

    snprintf(p->hay, sizeof p->hay, "%s %s %s", p->cmd, p->cwd, p->exe);
    return 0;
}

static const char *fz_classify(const fz_config *c, const fz_proc *p, long rss_mb) {
    if (fz_list_hit(&c->watch, p->hay)) return "watched";
    if (strstr(p->cmd, "GradleDaemon") || strstr(p->cmd, "org.gradle.launcher.daemon"))
        return "gradle-daemon";
    if (strncmp(fz_base(p->exe[0] ? p->exe : p->raw), "java", 4)) return 0;
    for (int off = 0; off < p->rawlen; ) {
        const char *tok = p->raw + off;
        size_t tl = strlen(tok);
        off += (int)tl + 1;
        if (!tl) continue;
        if (!strcmp(tok, "-jar")) {
            if (off < p->rawlen && fz_server_jar(c, fz_base(p->raw + off))) return "game-server";
        } else if (fz_server_jar(c, fz_base(tok))) return "game-server";
    }
    if (fz_list_hit(&c->server_main, p->cmd)) return "game-server";
    if (rss_mb >= c->big_java_mb) return "java-big";
    return 0;
}

static void fz_label(const fz_config *c, const fz_proc *p, const char *kind, char *out, size_t cap) {
    if (!strcmp(kind, "gradle-daemon")) { xcpy(out, cap, "GradleDaemon"); return; }
    if (strncmp(fz_base(p->exe), "java", 4)) {
        xcpy(out, cap, p->comm[0] ? p->comm : fz_base(p->exe)); return;
    }
    for (int off = 0; off < p->rawlen; ) {
        const char *tok = p->raw + off;
        size_t tl = strlen(tok);
        off += (int)tl + 1;
        if (!tl) continue;
        if (!strcmp(tok, "-jar") && off < p->rawlen) { xcpy(out, cap, fz_base(p->raw + off)); return; }
        if (fz_server_jar(c, fz_base(tok))) { xcpy(out, cap, fz_base(tok)); return; }
    }
    /* Generic arguments can contain source code, credentials or private text.
     * Keep only comm/executable identity outside the explicit jar cases. */
    xcpy(out, cap, p->comm[0] ? p->comm : fz_base(p->exe));
}

/* Never touched: our own tree, built-in system names, the protect list, the explicit
 * never list and anything holding a /dev/dri node open (a GUI app such as a
 * game launcher with a running game is also a large java process). */
static const char *fz_never(const fz_config *c, const fz_proc *p, const char *label) {
    if (fz_own(p->pid)) return "own-tree";
    if (fz_sacred(p->comm, p->pid)) return "sacred";
    const char *hit = fz_list_hit(&c->never, p->hay);
    if (hit) return hit;
    for (int i = 0; i < c->protect.count; i++)
        if (!strcmp(p->comm, c->protect.names[i]) || !strcmp(label, c->protect.names[i]))
            return c->protect.names[i];
    if (holds_gpu(p->pid)) return "gui-dri";
    return 0;
}

static void fz_cgroup_of(int pid, char *out, size_t cap) {
    char path[64], buf[PATHMAX + 64];
    out[0] = 0;
    snprintf(path, sizeof path, "/proc/%d/cgroup", pid);
    if (read_file(path, buf, sizeof buf) < 0) return;
    char *p = strstr(buf, "0::");
    if (!p) return;
    p += 3;
    char *nl = strchr(p, '\n');
    if (!nl || (size_t)(nl - p) >= cap) return;
    *nl = 0;
    xcpy(out, cap, p);
}

/* cgroup-relative path of FZ_ROOT, compared by its own length */
static int fz_in_root(const char *cg) {
    const char *mnt = FZ_MNT, *root = FZ_ROOT;
    size_t m = strlen(mnt);
    if (strncmp(root, mnt, m)) return 0;
    root += m;
    size_t n = strlen(root);
    return n && !strncmp(cg, root, n) && cg[n] == '/';
}

/* Whether the pid is frozen right now. Being inside the freezer root is not
 * enough: after a thaw without a move back the process stays there, and it must
 * become a candidate again. */
static int fz_is_frozen(int pid) {
    char cg[PATHMAX], p[PATHMAX + 32], b[32];
    fz_cgroup_of(pid, cg, sizeof cg);
    if (!fz_in_root(cg)) return 0;
    snprintf(p, sizeof p, "%s%s/cgroup.freeze", FZ_MNT, cg);
    if (read_file(p, b, sizeof b) < 0) return 0;
    return b[0] == '1' && (b[1] == '\n' || !b[1]);
}

static int fz_tree(int root, int *pids, int cap) {
    static int lp[MAXPROC], lpp[MAXPROC];
    if (root <= 1 || cap < 1) return -1;
    int ln = 0, n = 1; pids[0] = root;
    DIR *d = opendir("/proc"); if (!d) return -1;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] < '1' || e->d_name[0] > '9') continue;
        int pid; if (!parse_pid(e->d_name, &pid)) continue;
        if (ln == MAXPROC) { closedir(d); errno = EOVERFLOW; return -1; }
        char path[64], buf[1024]; snprintf(path, sizeof path, "/proc/%d/stat", pid);
        if (read_file(path, buf, sizeof buf) < 0) continue;
        char *rp = strrchr(buf, ')'); int ppid = 0;
        if (!rp || sscanf(rp + 2, "%*c %d", &ppid) != 1) continue;
        lp[ln] = pid; lpp[ln++] = ppid;
    }
    closedir(d);
    for (int pass = 0, changed = 1; changed && pass < cap; pass++) {
        changed = 0;
        for (int i = 0; i < ln; i++) {
            int seen = 0, child = 0;
            for (int k = 0; k < n; k++) {
                if (pids[k] == lp[i]) { seen = 1; break; }
                if (pids[k] == lpp[i]) child = 1;
            }
            if (!seen && child) {
                if (n == cap) { errno = EOVERFLOW; return -1; }
                pids[n++] = lp[i]; changed = 1;
            }
        }
    }
    return n;
}

static void fz_footprint(const int *pids, int n, long *rss_kb, long *swap_kb) {
    long r = 0, s = 0;
    for (int i = 0; i < n; i++) {
        char path[64], buf[8192];
        snprintf(path, sizeof path, "/proc/%d/smaps_rollup", pids[i]);
        if (read_file(path, buf, sizeof buf) < 0) continue;
        long v = field_kb(buf, "Pss:");
        if (v > 0) r += v;
        v = field_kb(buf, "SwapPss:");
        if (v > 0) s += v;
    }
    *rss_kb = r;
    *swap_kb = s;
}

/* Push a process's pages to swap. This is what frees RAM: the kernel decides
 * where the pages go (zram before disk); what matters is that they leave the
 * resident set of the frozen process. */
static int sys_pidfd_open(int pid) { return (int)syscall(SYS_pidfd_open, pid, 0); }
static long sys_process_madvise(int pidfd, const struct iovec *iov, size_t n) {
    return syscall(SYS_process_madvise, pidfd, iov, n, MADV_PAGEOUT, 0U);
}
static int (*fz_pidfd_open)(int) = sys_pidfd_open;
static long (*fz_madvise)(int, const struct iovec *, size_t) = sys_process_madvise;
static int fz_no_pageout;

/* Kernels before 5.10 lack process_madvise: freeze without pageout and say so
 * once; memory.reclaim still runs where the kernel has it. */
static int fz_nosys(const char *what) {
    if (errno != ENOSYS) return 0;
    if (!fz_no_pageout) lg(LOG_WARNING, "freeze: %s is not supported by this kernel, pageout disabled", what);
    fz_no_pageout = 1;
    return 1;
}

static long fz_pageout(int pid) {
    if (fz_no_pageout) return -1;
    int pidfd = fz_pidfd_open(pid);
    if (pidfd < 0) { fz_nosys("pidfd_open"); return -1; }
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/maps", pid);
    FILE *f = fopen(path, "re");
    if (!f) { close(pidfd); return -1; }

    struct iovec iov[FZ_IOV_MAX];
    int nv = 0;
    long done = 0;
    char line[512];
    while (fgets(line, sizeof line, f)) {
        unsigned long a = 0, b = 0;
        char perms[8] = "", tail[256] = "";
        if (sscanf(line, "%lx-%lx %7s %*s %*s %*s %255[^\n]", &a, &b, perms, tail) < 3) continue;
        const char *pth = tail;
        while (*pth == ' ') pth++;
        if (!strncmp(pth, "[vvar", 5) || !strcmp(pth, "[vdso]") || !strcmp(pth, "[vsyscall]")) continue;
        if (!strncmp(pth, "/dev/", 5)) continue;
        if (b <= a) continue;
        iov[nv].iov_base = (void *)a;
        iov[nv].iov_len  = b - a;
        if (++nv == FZ_IOV_MAX) {
            long r = fz_madvise(pidfd, iov, (size_t)nv);
            if (r > 0) done += r;
            else if (r < 0 && fz_nosys("process_madvise")) break;
            nv = 0;
        }
    }
    if (nv && !fz_no_pageout) {
        long r = fz_madvise(pidfd, iov, (size_t)nv);
        if (r > 0) done += r;
        else if (r < 0) fz_nosys("process_madvise");
    }
    fclose(f);
    close(pidfd);
    return done;
}

/* Second pass: whatever is still charged to our cgroup (pages faulted in after
 * the last thaw, and its page cache). In chunks with pauses: reclaiming a
 * multi-gigabyte process in one go raises PSI to a level aegis-oom would
 * react to. */
static long fz_reclaim(const fz_config *c, const char *cg, long *out_current) {
    char p_cur[PATHMAX + 32], p_rec[PATHMAX + 32];
    snprintf(p_cur, sizeof p_cur, "%s/memory.current", cg);
    snprintf(p_rec, sizeof p_rec, "%s/memory.reclaim", cg);
    long start = read_long_file(p_cur, 0), cur = start;
    long chunk = (long)c->reclaim_mb * 1024 * 1024;
    long deadline = mono_s() + c->reclaim_max_s;
    int stall = 0;
    while (cur > FZ_RECLAIM_FLOOR && stall < 2 && mono_s() < deadline) {
        char v[32];
        snprintf(v, sizeof v, "%ld", cur < chunk ? cur : chunk);
        fz_write(p_rec, v);
        long now = read_long_file(p_cur, cur);
        if (cur - now < FZ_RECLAIM_STALL) stall++; else stall = 0;
        cur = now;
        usleep(FZ_RECLAIM_PAUSE_US);
    }
    *out_current = cur;
    return start - cur;
}

static int fz_wait_frozen(const char *cg, int want, int max_ms) {
    char p[PATHMAX + 32], buf[256];
    snprintf(p, sizeof p, "%s/cgroup.events", cg);
    for (int i = 0; i < max_ms / FZ_POLL_STEP_MS; i++) {
        if (read_file(p, buf, sizeof buf) >= 0) {
            const char *f = strstr(buf, "frozen ");
            if (f && f[7] == '0' + want && (f[8] == '\n' || !f[8])) return 0;
        }
        usleep(FZ_POLL_STEP_MS * 1000);
    }
    return -1;
}

static int fz_valid_original(const char *path);

static int fz_move_back(const char *cg, const char *orig) {
    if (!orig || !orig[0] || fz_in_root(orig)) return 0;
    if (!fz_valid_original(orig)) return -1;
    char src[PATHMAX + 32], dst[PATHMAX + 32], buf[8192];
    snprintf(src, sizeof src, "%s/cgroup.procs", cg);
    snprintf(dst, sizeof dst, "%s%s/cgroup.procs", FZ_MNT, orig);
    int length = read_file(src, buf, sizeof buf);
    if (length < 0 && errno == ENOENT) return 0;
    if (length < 0 || length == (int)sizeof buf - 1) return -1;
    int moved = 0;
    for (char *p = buf, *nl; *p; p = nl + 1) {
        nl = strchr(p, '\n');
        if (nl) *nl = 0;
        int pid;
        if (!parse_pid(p, &pid)) return -1;
        if (fz_write(dst, p) == 0) moved++;
        else if (errno != ESRCH) return -1;
        if (!nl) break;
    }
    return moved;
}

static void fz_reg_path(const fz_config *c, char *out, size_t cap) { snprintf(out, cap, "%s/frozen", c->state_dir); }

static int fz_registry_lock(const fz_config *c) {
    char path[PATHMAX];
    if (snprintf(path, sizeof path, "%s/frozen.lock", c->state_dir) >= (int)sizeof path) return -1;
    int fd = open(path, O_WRONLY | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd >= 0 && flock(fd, LOCK_EX | LOCK_NB) == 0) return fd;
    if (fd >= 0) close(fd);
    return -1;
}

static int fz_reg_append(const fz_config *c, const char *line) {
    int lock = fz_registry_lock(c); if (lock < 0) return -1;
    char reg[PATHMAX]; fz_reg_path(c, reg, sizeof reg);
    int fd = open(reg, O_RDWR | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0644);
    int ok = 0;
    if (fd >= 0) {
        off_t before = lseek(fd, 0, SEEK_END);
        size_t length = strlen(line);
        char last = '\n';
        int complete = before == 0 || (before > 0 && pread(fd, &last, 1, before-1) == 1 && last == '\n');
        /* Readers reject a full/truncated 64 KiB buffer. Never create a
         * recovery file they cannot consume, or extend a partial record. */
        ok = before >= 0 && complete && length < FZ_REG_MAX-1 &&
             before < (off_t)(FZ_REG_MAX-1-length) && write(fd, line, length) == (ssize_t)length;
        if (!ok && before >= 0) (void)ftruncate(fd, before);
        close(fd);
    }
    close(lock);
    return ok ? 0 : -1;
}

/* Replace final metrics atomically; any error preserves the recovery record. */
static int fz_reg_replace(const fz_config *c, const char *key, const char *replacement) {
    int lock = fz_registry_lock(c); if (lock < 0) return -1;
    char reg[PATHMAX], tmp[PATHMAX+32], prefix[FZ_KEYLEN+16];
    fz_reg_path(c, reg, sizeof reg);
    snprintf(tmp, sizeof tmp, "%s.tmp", reg);
    snprintf(prefix, sizeof prefix, "frozen %s ", key);
    static char input[FZ_REG_MAX], output[FZ_REG_MAX];
    int n = read_file_whole(reg, input, sizeof input), matches = 0, ok = 0;
    size_t used = 0;
    if (n <= 0 || input[n-1] != '\n') goto out;
    for (char *line = input; *line;) {
        char *next = strchr(line, '\n'); if (!next) goto out;
        size_t length = (size_t)(next + 1 - line);
        const char *value = line;
        if (!strncmp(line, prefix, strlen(prefix))) {
            value = replacement; length = strlen(value); matches++;
        }
        if (length >= sizeof output-1-used) goto out;
        memcpy(output+used, value, length); used += length;
        line = next + 1;
    }
    if (matches != 1) goto out;
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0644);
    if (fd < 0) goto out;
    ok = write(fd, output, used) == (ssize_t)used;
    close(fd);
    if (ok) ok = rename(tmp, reg) == 0;
    if (!ok) unlink(tmp);
out:
    close(lock);
    return ok ? 0 : -1;
}

static int fz_valid_component(const char *name) {
    if (!*name || !strcmp(name, ".") || !strcmp(name, "..")) return 0;
    for (; *name; name++) if (!(isalnum((unsigned char)*name) || *name == '_' || *name == '-' || *name == '.')) return 0;
    return 1;
}

static int fz_valid_original(const char *path) {
    if (path[0] != '/') return 0;
    if (!strcmp(path, "/")) return 1;
    for (const char *p = path + 1; *p;) {
        const char *slash = strchr(p, '/'); size_t length = slash ? (size_t)(slash-p) : strlen(p);
        if (!length || (length == 1 && p[0] == '.') || (length == 2 && p[0] == '.' && p[1] == '.')) return 0;
        for (size_t i = 0; i < length; i++) if ((unsigned char)p[i] <= 32 || p[i] == '\\' || p[i] == 127) return 0;
        if (!slash) return 1;
        p = slash + 1; if (!*p) return 0;
    }
    return 0;
}

static int fz_field(const char *line, const char *key, char *out, size_t cap) {
    char pat[32];
    snprintf(pat, sizeof pat, " %s", key);
    const char *p = strstr(line, pat);
    out[0] = 0;
    if (!p) return -1;
    p += strlen(pat);
    size_t i = 0;
    while (*p && *p != ' ' && *p != '\n' && i + 1 < cap) out[i++] = *p++;
    out[i] = 0;
    if (*p && *p != ' ' && *p != '\n') { out[0] = 0; return -1; }
    return 0;
}

/* Fills pids with the whole tree of p, or refuses: a stale pid, a protected
 * process or descendant, or a tree that could not be read completely. */
static int fz_collect(const fz_config *c, const fz_proc *p, const char *label, int *pids, int cap) {
    static fz_proc live;
    if (fz_read(p->pid, &live) || live.start != p->start || fz_never(c, &live, label) || pid_protected(p->pid, &c->protect)) {
        lg(LOG_WARNING, "freeze cancelled: stale or protected process %d", p->pid); return -1;
    }
    int n = fz_tree(p->pid, pids, cap);
    if (n < 1) { lg(LOG_WARNING, "freeze cancelled: incomplete process tree"); return -1; }
    for (int i = 0; i < n; i++) if (pid_protected(pids[i], &c->protect) || holds_gpu(pids[i])) {
        lg(LOG_WARNING, "freeze cancelled: protected descendant"); return -1;
    }
    return n;
}

static int fz_make_leaf(const char *name, char *cg, size_t cap) {
    if (mkdir(FZ_ROOT, 0755) != 0 && errno != EEXIST) {
        lg(LOG_ERR, "freeze: cannot create %s: %s", FZ_ROOT, strerror(errno));
        return -1;
    }
    /* Without this the leaf has neither memory.current nor memory.reclaim: the
     * parent grants the controller to a child, not the hierarchy root. */
    char subtree[PATHMAX+32];
    snprintf(subtree, sizeof subtree, "%s/cgroup.subtree_control", FZ_ROOT);
    if (fz_write(subtree, "+memory") != 0 && errno != EEXIST)
        lg(LOG_INFO, "freeze: memory controller not enabled on %s: %s", FZ_ROOT, strerror(errno));
    snprintf(cg, cap, "%s/%s", FZ_ROOT, name);
    if (mkdir(cg, 0755) != 0 && errno != EEXIST) {
        lg(LOG_ERR, "freeze: cannot create %s: %s", cg, strerror(errno));
        return -1;
    }
    return 0;
}

static int fz_migrate(const char *cg, const int *pids, int n) {
    char pf[PATHMAX + 32];
    snprintf(pf, sizeof pf, "%s/cgroup.procs", cg);
    int moved = 0;
    for (int i = 0; i < n; i++) {
        char v[16];
        snprintf(v, sizeof v, "%d", pids[i]);
        if (fz_write(pf, v) == 0) moved++;
    }
    return moved;
}

/* Undo a partial freeze: thaw, move every task back, remove the leaf. */
static int fz_rollback(const char *cg, const char *orig, const char *label, int pid, const char *why) {
    char ff[PATHMAX + 32];
    snprintf(ff, sizeof ff, "%s/cgroup.freeze", cg);
    lg(LOG_ERR, "freeze: %s(%d) %s, rolling back", label, pid, why);
    if (fz_write(ff, "0") != 0 && errno != ENOENT)
        lg(LOG_ERR, "freeze: rollback could not thaw %s: %s", cg, strerror(errno));
    if (fz_move_back(cg, orig) < 0)
        lg(LOG_ERR, "freeze: rollback left tasks in %s; run oom-freezer thaw", cg);
    rmdir(cg);
    return -1;
}

static int fz_record(char *out, size_t cap, const char *key, int pid, const char *kind,
                     const char *name, const char *orig, long pss0, long pss1, long swap1,
                     long ts, int ntasks, const char *label, const char *phase) {
    int w = snprintf(out, cap,
        "frozen %s pid=%d kind=%s cg=%s orig=%s pss_before_kb=%ld pss_after_kb=%ld "
        "swap_kb=%ld ts=%ld ntasks=%d name=%s phase=%s\n",
        key, pid, kind, name, orig[0] ? orig : "-", pss0, pss1, swap1, ts, ntasks, label, phase);
    return w < 0 || w >= (int)cap ? -1 : 0;
}

static int fz_freeze(const fz_config *c, const fz_proc *p, const char *kind, const char *label, const char *why) {
    int pids[FZ_MAXTREE];
    int n = fz_collect(c, p, label, pids, FZ_MAXTREE);
    if (n < 1) return -1;

    char name[FZ_NAMELEN + 16], cg[PATHMAX], orig[PATHMAX];
    snprintf(name, sizeof name, "%.32s-%d-%llu", label, p->pid, p->start);
    fz_sanitize(name);
    if (fz_make_leaf(name, cg, sizeof cg) != 0) return -1;

    fz_cgroup_of(p->pid, orig, sizeof orig);
    if (!fz_valid_original(orig)) { rmdir(cg); lg(LOG_ERR, "freeze: original cgroup is unknown"); return -1; }
    if (fz_in_root(orig)) orig[0] = 0;

    long rss0, swap0;
    fz_footprint(pids, n, &rss0, &swap0);

    int moved = fz_migrate(cg, pids, n);
    if (moved != n) return fz_rollback(cg, orig, label, p->pid, "incomplete migration");

    char ff[PATHMAX + 32];
    snprintf(ff, sizeof ff, "%s/cgroup.freeze", cg);
    if (fz_write(ff, "1") != 0) return fz_rollback(cg, orig, label, p->pid, "freeze write failed");
    if (fz_wait_frozen(cg, 1, fz_wait_ms) != 0) return fz_rollback(cg, orig, label, p->pid, "cgroup did not freeze");

    /* Reclaim may block longer than the systemd watchdog. Save recovery first,
     * with explicit unknown metrics until the final atomic update. */
    char reg[2*PATHMAX+512], safe_label[FZ_NAMELEN], key[FZ_KEYLEN];
    xcpy(safe_label, sizeof safe_label, label); fz_sanitize(safe_label);
    snprintf(key, sizeof key, "%d:%llu", p->pid, p->start);
    long frozen_at = (long)time(0);
    if (fz_record(reg, sizeof reg, key, p->pid, kind, name, orig, rss0, -1, -1,
                  frozen_at, moved, safe_label, "reclaiming") != 0 || fz_reg_append(c, reg) != 0)
        return fz_rollback(cg, orig, label, p->pid, "recovery registry unavailable");

    long advised = 0;
    for (int i = 0; i < n; i++) {
        long a = fz_pageout(pids[i]);
        if (a > 0) advised += a;
    }
    long cur = 0, reclaimed = fz_reclaim(c, cg, &cur);

    long rss1, swap1;
    fz_footprint(pids, n, &rss1, &swap1);
    if (fz_record(reg, sizeof reg, key, p->pid, kind, name, orig, rss0, rss1, swap1,
                  frozen_at, moved, safe_label, "frozen") != 0 || fz_reg_replace(c, key, reg) != 0)
        lg(LOG_ERR, "freeze: final metrics unavailable; earlier recovery record retained");

    lg(LOG_WARNING, "frozen: %s(%d) kind=%s PSS %ld -> %ld kB, SwapPSS %ld -> %ld kB "
                    "(pageout %ld B, reclaim %ld B, left %ld B) | %s",
       label, p->pid, kind, rss0, rss1, swap0, swap1, advised, reclaimed, cur, why);
    return 0;
}

static int fz_thaw(const fz_config *c, const char *spec) {
    int lock = fz_registry_lock(c);
    if (lock < 0) { perror("freeze registry lock"); return -1; }
    char reg[PATHMAX]; fz_reg_path(c, reg, sizeof reg);
    static char buf[FZ_REG_MAX], keep[FZ_REG_MAX];
    int len = read_file(reg, buf, sizeof buf);
    if (len <= 0) {
        int missing = errno == ENOENT || len == 0; close(lock);
        if (missing) { puts("Nothing is frozen."); return 0; }
        return -1;
    }
    if (len >= (int)sizeof buf-1 || buf[len-1] != '\n') {
        close(lock); fputs("Incomplete freeze registry; kept unchanged.\n", stderr); return -1;
    }
    size_t klen = 0; int done = 0, failed = 0;
    char *line = buf;
    while (line && *line) {
        char *nl = strchr(line, '\n'); if (nl) *nl = 0;
        char key[FZ_KEYLEN] = "", name[FZ_NAMELEN] = "", cgn[FZ_NAMELEN+16] = "";
        char orig[PATHMAX] = "", pidb[16] = "";
        int match = 0, remove = 0;
        if (!strncmp(line, "frozen ", 7) && sscanf(line, "frozen %39s", key) == 1) {
            fz_field(line, "name=", name, sizeof name);
            fz_field(line, "cg=", cgn, sizeof cgn);
            fz_field(line, "orig=", orig, sizeof orig);
            fz_field(line, "pid=", pidb, sizeof pidb);
            match = !strcmp(spec, "all") || !strcmp(spec, key) || !strcmp(spec, name) || !strcmp(spec, cgn) || !strcmp(spec, pidb);
        }
        if (match) {
            if (!fz_valid_component(cgn) || (strcmp(orig, "-") && !fz_valid_original(orig))) {
                lg(LOG_ERR, "thaw: invalid registry path; entry retained"); failed = 1;
            } else {
                char cg[PATHMAX], ff[PATHMAX+32];
                snprintf(cg, sizeof cg, "%s/%s", FZ_ROOT, cgn);
                snprintf(ff, sizeof ff, "%s/cgroup.freeze", cg);
                /* A prior thaw may have removed the cgroup, then failed to
                 * replace the registry. Only accept ENOENT beneath an existing
                 * freezer root; an unavailable hierarchy is not recovery. */
                int rootfd = open(FZ_ROOT, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
                struct stat st;
                int absent = rootfd >= 0 && fstatat(rootfd, cgn, &st, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT;
                if (rootfd >= 0) close(rootfd);
                int ok = !absent && fz_write(ff, "0") == 0 && fz_wait_frozen(cg, 0, fz_wait_ms) == 0;
                if (absent) {
                    remove = 1; done++;
                    printf("Recovery completed for absent cgroup %s\n", cgn);
                } else if (ok) {
                    int back = fz_move_back(cg, strcmp(orig, "-") ? orig : "");
                    if (back >= 0 && rmdir(cg) == 0) {
                        remove = 1; done++;
                        printf("Thawed %s (pid %s), moved back: %d task(s)\n", name[0] ? name : cgn, pidb, back);
                        lg(LOG_NOTICE, "thawed: %s, moved back: %d task(s)", cgn, back);
                    } else {
                        fputs("Thawed, but cgroup restoration is incomplete; recovery entry retained.\n", stderr);
                        failed = 1;
                    }
                } else { fputs("Thaw not confirmed; recovery entry retained.\n", stderr); failed = 1; }
            }
        }
        if (!remove && line[0]) {
            int written = snprintf(keep+klen, sizeof keep-klen, "%s\n", line);
            if (written < 0 || written >= (int)(sizeof keep-klen)) { close(lock); return -1; }
            klen += (size_t)written;
        }
        line = nl ? nl+1 : NULL;
    }
    char tmp[PATHMAX+32]; snprintf(tmp, sizeof tmp, "%s.tmp", reg);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0644);
    int saved = fd >= 0 && write(fd, keep, klen) == (ssize_t)klen;
    if (fd >= 0) close(fd);
    if (!saved || rename(tmp, reg)) { unlink(tmp); failed = 1; }
    close(lock);
    if (!done && !failed) printf("No frozen entry matches \"%s\".\n", spec);
    return failed ? -1 : done;
}

static int fz_freeze_pid(const fz_config *c, int pid) {
    static fz_proc p;
    if (fz_read(pid, &p) != 0) { printf("No such process: %d\n", pid); return 1; }
    if (fz_own(p.pid)) {
        printf("Refused: %d belongs to the daemon's own process tree.\n", pid);
        return 1;
    }
    if (fz_is_frozen(pid)) { printf("Already frozen: %d\n", pid); return 1; }
    char label[FZ_NAMELEN];
    const char *kind = fz_classify(c, &p, p.rss_kb / 1024);
    fz_label(c, &p, kind ? kind : "process", label, sizeof label);
    return fz_freeze(c, &p, kind ? kind : "process", label, "manual request") == 0 ? 0 : 1;
}

static fz_slot *fz_slot_get(fz_state *st, const char *key) {
    int free_i = -1;
    for (int i = 0; i < FZ_MAXCAND; i++) {
        if (!strcmp(st->slots[i].key, key)) return &st->slots[i];
        if (free_i < 0 && !st->slots[i].key[0]) free_i = i;
    }
    if (free_i < 0) return 0;
    memset(&st->slots[free_i], 0, sizeof st->slots[free_i]);
    xcpy(st->slots[free_i].key, sizeof st->slots[free_i].key, key);
    return &st->slots[free_i];
}

static int fz_live(const fz_config *c) { return !c->dryrun; }

typedef struct {
    const char *kind, *excluded, *never;
    char   key[FZ_KEYLEN], label[FZ_NAMELEN];
    double cpu_pct, age_min, idle_min;
    int    sampled, idle, forgotten, optout, active;
    fz_slot *slot;
} fz_cand;

/* Classify one process and update its CPU sample. Returns 0 when it is not a
 * candidate at all, so it gets neither a state line nor a slot. */
static int fz_evaluate(const fz_config *c, fz_state *fs, const fz_proc *p,
                       long now, double dt, long hz, double up, fz_cand *k) {
    memset(k, 0, sizeof *k);
    long rss_mb = p->rss_kb / 1024;
    if (rss_mb < c->min_rss_mb) return 0;
    k->kind = fz_classify(c, p, rss_mb);
    if (!k->kind) return 0;
    if (fz_list_hit(&c->ignore, p->hay)) return 0;
    if (rss_mb < (!strcmp(k->kind, "java-big") ? c->big_java_mb : c->min_rss_mb)) return 0;
    if (fz_is_frozen(p->pid)) return 0;

    snprintf(k->key, sizeof k->key, "%d:%llu", p->pid, p->start);
    fz_slot *s = fz_slot_get(fs, k->key);
    if (!s) return 0;
    if (dt > 0 && s->last_seen && p->ticks >= s->ticks) {
        s->cpu_pct = (double)(p->ticks - s->ticks) * 100.0 / ((double)hz * dt);
        s->sampled = 1;
        if (s->cpu_pct < c->cpu_idle_pct) { if (!s->idle_since) s->idle_since = now; }
        else s->idle_since = 0;
    }
    s->ticks = p->ticks;
    s->last_seen = now;
    k->slot = s;

    fz_label(c, p, k->kind, k->label, sizeof k->label);
    k->cpu_pct = s->cpu_pct;
    k->sampled = s->sampled;
    k->idle = s->idle_since != 0;
    k->age_min = (up - (double)p->start / (double)hz) / 60.0;
    k->idle_min = s->idle_since ? (double)(now - s->idle_since) / 60.0 : 0;
    k->excluded = fz_list_hit(&c->exclude, p->hay);
    k->never = k->excluded ? 0 : fz_never(c, p, k->label);
    k->forgotten = !k->excluded && !k->never && k->age_min >= c->uptime_min &&
                   k->idle && k->idle_min >= c->idle_min;
    k->optout = k->forgotten && ((!strcmp(k->kind, "java-big") && !c->java_big) ||
                                 (!strcmp(k->kind, "gradle-daemon") && !c->gradle));
    return 1;
}

static void fz_verdict(const fz_config *c, const fz_cand *k, char *out, size_t cap) {
    if (k->excluded)                  snprintf(out, cap, "excluded:%s", k->excluded);
    else if (k->never)                snprintf(out, cap, "never:%s", k->never);
    else if (k->age_min < c->uptime_min) snprintf(out, cap, "young");
    else if (!k->sampled)             snprintf(out, cap, "no-sample");
    else if (!k->idle)                snprintf(out, cap, "busy");
    else if (k->active)               snprintf(out, cap, "active-cmd");
    else if (!k->forgotten)           snprintf(out, cap, "idle-%.0f-of-%d-min", k->idle_min, c->idle_min);
    else if (k->optout)               snprintf(out, cap, "FORGOTTEN-opt-in-off");
    else                              snprintf(out, cap, "FORGOTTEN");
}

/* FREEZE_ACTIVE_CMD: exit 1 permits the freeze. Exit 0 means the process is
 * in use; any other outcome (exec failure, timeout, signal) also blocks the
 * freeze, so a broken check never freezes the service it guards. */
static int fz_active(const fz_config *c, const fz_proc *p, const fz_cand *k) {
    char pid[16];
    snprintf(pid, sizeof pid, "%d", p->pid);
    const char *argv[] = { c->active_cmd, pid, k->kind, k->label, 0 };
    int st = run_cmd_timeout(argv, c->active_timeout_s);
    if (st == 1) return 0;
    if (st != 0)
        lg(LOG_WARNING, "freeze: activity check for %s(%d) %s (status %d), not freezing",
           k->label, p->pid, st == -2 ? "timed out" : "failed", st);
    return 1;
}

static void fz_rate_key(const fz_cand *k, char *out, size_t cap) { snprintf(out, cap, "fz:%s", k->key); }

/* Returns 1 when an action was taken (or would be, in dry-run). Every attempt
 * is rate limited, so a freeze that keeps failing is not retried each poll. */
static int fz_act(const fz_config *c, const fz_proc *p, const fz_cand *k) {
    char why[96], rl[64];
    snprintf(why, sizeof why, "idle %.0f min, CPU %.1f%%, uptime %.0f min",
             k->idle_min, k->cpu_pct, k->age_min);
    fz_rate_key(k, rl, sizeof rl);
    rate_mark(rl);

    if (!fz_live(c)) {
        lg(LOG_NOTICE, "dry-run: would freeze %s(%d) kind=%s %ld MB | %s",
           k->label, p->pid, k->kind, p->rss_kb / 1024, why);
        return 1;
    }

    /* GradleDaemon is not frozen: a frozen daemon silently hangs the next
     * build because the client waits on its socket. The daemon is a cache and
     * a new one starts by itself, so a forgotten one gets a regular SIGTERM. */
    if (!strcmp(k->kind, "gradle-daemon")) {
        if (kill(p->pid, SIGTERM) != 0) {
            lg(LOG_ERR, "freeze: SIGTERM to GradleDaemon(%d) failed: %s", p->pid, strerror(errno));
            return 0;
        }
        lg(LOG_WARNING, "terminated: gradle daemon(%d) rss %ld kB | %s", p->pid, p->rss_kb, why);
        return 1;
    }

    return fz_freeze(c, p, k->kind, k->label, why) == 0;
}

static void fz_state_write(const fz_config *c, const char *buf, size_t len) {
    char sp[PATHMAX], tmp[PATHMAX + 32];
    snprintf(sp, sizeof sp, "%s/freeze.state", c->state_dir);
    snprintf(tmp, sizeof tmp, "%s.tmp", sp);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) return;
    ssize_t w = write(fd, buf, len);
    close(fd);
    if (w == (ssize_t)len) rename(tmp, sp); else unlink(tmp);
}

static void freeze_check(const fz_config *c, fz_state *fs) {
    if (!c->enable) return;
    long now = mono_s();
    if (fs->last && now - fs->last < c->poll_s) return;
    double dt = fs->last ? (double)(now - fs->last) : 0;
    fs->last = now;

    long hz = sysconf(_SC_CLK_TCK);
    if (hz <= 0) hz = 100;
    double up = 0;
    { char b[64]; if (read_file("/proc/uptime", b, sizeof b) >= 0) up = atof(b); }

    DIR *d = opendir("/proc");
    if (!d) return;
    static fz_proc p;
    static char st[16 * 1024];
    size_t stlen = 0;
    appendf(st, sizeof st, &stlen,
            "# oom-freezer state v1\nmode %s\nthreshold_uptime_min %d\nthreshold_idle_min %d\n"
            "threshold_cpu_pct %d\njava_big_optin %d\n",
            fz_live(c) ? "live" : "dry-run",
            c->uptime_min, c->idle_min, c->cpu_idle_pct, c->java_big);
    struct dirent *e;
    int acted = 0, checked = 0;
    while ((e = readdir(d))) {
        if (e->d_name[0] < '1' || e->d_name[0] > '9') continue;
        int pid;
        if (!parse_pid(e->d_name, &pid) || fz_read(pid, &p) != 0) continue;
        fz_cand k;
        if (!fz_evaluate(c, fs, &p, now, dt, hz, up, &k)) continue;
        int act = k.forgotten && !k.optout && !acted;
        char rl[64];
        fz_rate_key(&k, rl, sizeof rl);
        if (act && !rate_ok(rl, FZ_RATE_S)) act = 0;
        /* At most one check per tick keeps a slow command inside the watchdog. */
        if (act && c->active_cmd[0]) {
            if (checked) act = 0;
            else if ((checked = 1, fz_active(c, &p, &k))) {
                k.slot->idle_since = 0;
                k.active = 1; k.forgotten = 0; act = 0;
            }
        }
        char verdict[96];
        fz_verdict(c, &k, verdict, sizeof verdict);
        appendf(st, sizeof st, &stlen,
                "cand %d kind=%s rss_kb=%ld cpu=%.1f idle_min=%.0f age_min=%.0f verdict=%s name=%s\n",
                pid, k.kind, p.rss_kb, k.cpu_pct, k.idle_min, k.age_min, verdict, k.label);
        if (act) acted = fz_act(c, &p, &k);
    }
    closedir(d);
    for (int i = 0; i < FZ_MAXCAND; i++)
        if (fs->slots[i].key[0] && fs->slots[i].last_seen != now) fs->slots[i].key[0] = 0;
    fz_state_write(c, st, stlen);
}

/* Refuse to start on a system that cannot freeze: no cgroup v2, a kernel
 * without cgroup.freeze (before 5.2), or no write access when acting. */
static int fz_support(int need_write) {
    char p[PATHMAX + 64], self[PATHMAX];
    snprintf(p, sizeof p, "%s/cgroup.controllers", FZ_MNT);
    if (access(p, F_OK) != 0) {
        lg(LOG_ERR, "cgroup v2 is required: %s is missing (cgroup v1 or no /sys/fs/cgroup)", p);
        return -1;
    }
    fz_cgroup_of((int)getpid(), self, sizeof self);
    if (self[0] && strcmp(self, "/")) {
        snprintf(p, sizeof p, "%s%s/cgroup.freeze", FZ_MNT, self);
        if (access(p, F_OK) != 0) { lg(LOG_ERR, "the kernel has no cgroup freezer (%s is missing, needs Linux 5.2)", p); return -1; }
    }
    if (need_write && access(FZ_MNT, W_OK) != 0) {
        lg(LOG_ERR, "no write access to %s: run as root on a writable cgroup hierarchy, or set FREEZE_DRYRUN=1", FZ_MNT);
        return -1;
    }
    return 0;
}

/* CLI "list": the recovery registry with the live state of each cgroup. */
static int fz_list(const fz_config *c) {
    char reg[PATHMAX];
    fz_reg_path(c, reg, sizeof reg);
    static char buf[FZ_REG_MAX];
    int len = read_file(reg, buf, sizeof buf);
    if (len < 0 && errno != ENOENT) { fprintf(stderr, "%s: %s\n", reg, strerror(errno)); return 1; }
    if (len <= 0 || !strstr(buf, "frozen ")) { puts("Nothing is frozen."); return 0; }
    printf("%-24s %-8s %-12s %10s %10s %10s  %-16s %s\n",
           "NAME", "PID", "KIND", "PSS_BEFORE", "PSS_AFTER", "SWAP", "SINCE", "STATE");
    for (char *line = buf, *nl; line && *line; line = nl ? nl + 1 : 0) {
        nl = strchr(line, '\n');
        if (nl) *nl = 0;
        if (strncmp(line, "frozen ", 7)) continue;
        char name[FZ_NAMELEN] = "", pid[16] = "", kind[24] = "", cg[FZ_NAMELEN + 16] = "";
        char before[24] = "", after[24] = "", swap[24] = "", ts[24] = "";
        fz_field(line, "name=", name, sizeof name); fz_field(line, "pid=", pid, sizeof pid);
        fz_field(line, "kind=", kind, sizeof kind); fz_field(line, "cg=", cg, sizeof cg);
        fz_field(line, "pss_before_kb=", before, sizeof before);
        fz_field(line, "pss_after_kb=", after, sizeof after);
        fz_field(line, "swap_kb=", swap, sizeof swap); fz_field(line, "ts=", ts, sizeof ts);
        char since[32] = "-";
        time_t t = (time_t)atol(ts);
        struct tm tm;
        if (t > 0 && localtime_r(&t, &tm)) strftime(since, sizeof since, "%Y-%m-%d %H:%M", &tm);
        const char *state = "missing";
        char ff[PATHMAX + FZ_NAMELEN + 32], v[8];
        if (fz_valid_component(cg)) {
            snprintf(ff, sizeof ff, "%s/%s/cgroup.freeze", FZ_ROOT, cg);
            if (read_file(ff, v, sizeof v) > 0) state = v[0] == '1' ? "frozen" : "thawed";
        }
        int p;
        if (parse_pid(pid, &p) && kill(p, 0) != 0 && errno == ESRCH) state = "dead";
        printf("%-24s %-8s %-12s %7ld MiB %7ld MiB %7ld MiB  %-16s %s\n", name, pid, kind,
               atol(before) / 1024, atol(after) / 1024, atol(swap) / 1024, since, state);
    }
    return 0;
}

static void usage(FILE *f) {
    fputs("Usage: oom-freezer [--conf FILE] [COMMAND]\n"
          "  daemon        run the freezer loop (default)\n"
          "  once          run one scan and exit\n"
          "  list          show frozen processes\n"
          "  freeze PID    freeze a process tree now, ignoring the idle thresholds\n"
          "  thaw SPEC     thaw by name, pid, cgroup name or all\n", f);
}

/* ================================= main ================================== */

int main(int argc, char **argv) {
    static fz_config cfg;
    static fz_state state;
    const char *conf_path = "/etc/oom-freezer/oom-freezer.conf";
    const char *conf = getenv("OOM_FREEZER_CONF");
    if (conf && *conf) conf_path = conf;
    const char *sd = getenv("OOM_FREEZER_STATE");
    if (sd && *sd) cfg.state_dir = sd;
    int i = 1;
    for (; i < argc && !strncmp(argv[i], "--", 2); i++) {
        if (!strcmp(argv[i], "--conf") && i + 1 < argc) conf_path = argv[++i];
        else if (!strcmp(argv[i], "--help")) { usage(stdout); return 0; }
        else { fprintf(stderr, "oom-freezer: unknown option \"%s\"\n", argv[i]); usage(stderr); return 2; }
    }
    const char *cmd = i < argc ? argv[i++] : "daemon";
    const char *arg = i < argc ? argv[i++] : 0;
    int needs_arg = !strcmp(cmd, "freeze") || !strcmp(cmd, "thaw");
    if (i < argc || (needs_arg && !arg) || (!needs_arg && arg) ||
        (!needs_arg && strcmp(cmd, "daemon") && strcmp(cmd, "once") && strcmp(cmd, "list"))) {
        usage(stderr); return 2;
    }
    int freeze_pid = 0;
    if (!strcmp(cmd, "freeze") && !parse_pid(arg, &freeze_pid)) {
        fprintf(stderr, "oom-freezer: invalid pid \"%s\"\n", arg); return 2;
    }

    /* One-shot commands also print their log lines, so a refusal is visible. */
    openlog("oom-freezer", LOG_PID | (strcmp(cmd, "daemon") ? LOG_PERROR : 0), LOG_DAEMON);
    cfg_load(&cfg, conf_path);
    if (!strcmp(cmd, "list")) return fz_list(&cfg);
    mkdir(cfg.state_dir, 0755);

    signal(SIGTERM, on_term);
    signal(SIGINT, on_term);
    signal(SIGHUP, on_hup);
    signal(SIGPIPE, SIG_IGN);

    if (fz_support(needs_arg || !cfg.dryrun) != 0) return 1;
    if (!strcmp(cmd, "thaw")) return fz_thaw(&cfg, arg) >= 0 ? 0 : 1;
    if (!strcmp(cmd, "freeze")) return fz_freeze_pid(&cfg, freeze_pid);
    if (!strcmp(cmd, "once")) { freeze_check(&cfg, &state); return 0; }

    notify_init();
    lg(LOG_NOTICE, "started dryrun=%d interval=%d s", cfg.dryrun, cfg.interval);
    notify("READY=1\nSTATUS=Watching");

    while (!g_stop) {
        if (g_reload) {
            g_reload = 0;
            cfg_load(&cfg, conf_path);
            lg(LOG_INFO, "config reloaded on SIGHUP");
        }
        freeze_check(&cfg, &state);
        notify("WATCHDOG=1");

        for (int i = 0; i < cfg.interval && !g_stop && !g_reload; i++) sleep(1);
    }

    lg(LOG_NOTICE, "stopped cleanly");
    notify("STATUS=Stopped");
    closelog();
    return 0;
}
