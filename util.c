#define _GNU_SOURCE
#include "util.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>

/* ================================ log ===================================== */

/* Bounded append to a buffer. snprintf returns the length it would have
 * written, so a plain len += snprintf(...) lets (cap - len) underflow once the
 * buffer is full and the next write lands past the array. */
void appendf(char *buf, size_t cap, size_t *len, const char *fmt, ...) {
    if (*len >= cap - 1) return;
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(buf + *len, cap - *len, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    *len = (n >= (int)(cap - *len)) ? cap - 1 : *len + (size_t)n;
}

void lg(int pri, const char *fmt, ...) {
    char buf[1024];
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    syslog(pri, "%s", buf);
}

/* ============================== utilities ================================ */

/* Bounded string copy. Truncation is intentional here (process names,
 * config keys), so not snprintf: it rightly warns about truncation. */
void xcpy(char *dst, size_t cap, const char *src) {
    if (!cap) return;
    size_t n = strnlen(src, cap - 1);
    memcpy(dst, src, n);
    dst[n] = 0;
}

long mono_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec;
}

int read_file(const char *path, char *buf, size_t cap) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, cap - 1);
    close(fd);
    if (n < 0) return -1;
    buf[n] = 0;
    return (int)n;
}

long read_long_file(const char *path, long dflt) {
    char b[64];
    if (read_file(path, b, sizeof b) < 0) return dflt;
    return atol(b);
}

/* "Name: value" field from /proc-style text */
long field_kb(const char *buf, const char *key) {
    const char *p = strstr(buf, key);
    if (!p) return -1;
    p += strlen(key);
    while (*p == ' ' || *p == '\t') p++;
    return atol(p);
}


int list_parse(namelist *l, const char *csv) {
    l->n = 0;
    int dropped = 0;
    const char *p = csv;
    while (*p) {
        while (*p == ' ' || *p == ',') p++;
        if (!*p) break;
        const char *e = p;
        while (*e && *e != ',' && *e != ' ') e++;
        size_t len = (size_t)(e - p);
        if (len >= MAXNAME || l->n == MAXLIST) dropped++;
        else { memcpy(l->v[l->n], p, len); l->v[l->n][len] = 0; l->n++; }
        p = e;
    }
    return dropped;
}

/* =========================== systemd watchdog ============================ */
/* The protocol is simple: one datagram to $NOTIFY_SOCKET. Pulling in
 * libsystemd for it is not worth it: twenty lines instead of a dependency. */

static int g_notify_fd = -1;
static struct sockaddr_un g_notify_addr;
static socklen_t g_notify_len = 0;

void notify_init(void) {
    const char *s = getenv("NOTIFY_SOCKET");
    if (!s || !*s) return;
    g_notify_fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (g_notify_fd < 0) return;
    memset(&g_notify_addr, 0, sizeof g_notify_addr);
    g_notify_addr.sun_family = AF_UNIX;
    size_t n = strlen(s);
    if (n >= sizeof g_notify_addr.sun_path) { close(g_notify_fd); g_notify_fd = -1; return; }
    memcpy(g_notify_addr.sun_path, s, n + 1);
    if (g_notify_addr.sun_path[0] == '@') g_notify_addr.sun_path[0] = 0;  /* abstract */
    g_notify_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + n);
}

void notify(const char *msg) {
    if (g_notify_fd < 0) return;
    sendto(g_notify_fd, msg, strlen(msg), MSG_NOSIGNAL,
           (struct sockaddr *)&g_notify_addr, g_notify_len);
}

/* ============================== rate-limit =============================== */
/* In memory on purpose: a limit that survived a restart would block the first
 * action after it. */

typedef struct { char key[112]; long at; } rl_slot;
static rl_slot g_rl[64];

int rate_ok(const char *key, int secs) {
    long now = mono_s();
    for (int i = 0; i < 64; i++)
        if (!strcmp(g_rl[i].key, key))
            return (now - g_rl[i].at) >= secs;
    return 1;
}
void rate_mark(const char *key) {
    long now = mono_s();
    int free_i = -1;
    for (int i = 0; i < 64; i++) {
        if (!strcmp(g_rl[i].key, key)) { g_rl[i].at = now; return; }
        if (free_i < 0 && !g_rl[i].key[0]) free_i = i;
    }
    if (free_i >= 0) { snprintf(g_rl[free_i].key, sizeof g_rl[free_i].key, "%s", key); g_rl[free_i].at = now; }
}

/* Declarative KEY=value only. Never evaluates shell, expansion or commands. */
int config_assignment(const char *line, char *key, size_t kn,
                                        char *value, size_t vn) {
    while (*line == ' ' || *line == '\t') line++;
    size_t k = 0, n = 0;
    while ((*line >= 'A' && *line <= 'Z') || (*line >= '0' && *line <= '9') || *line == '_') {
        if (k + 1 >= kn) return 0;
        key[k++] = *line++;
    }
    key[k] = 0;
    while (*line == ' ' || *line == '\t') line++;
    if (!k || *line++ != '=') return 0;
    while (*line == ' ' || *line == '\t') line++;
    char quote = (*line == '\'' || *line == '"') ? *line++ : 0;
    while (*line && *line != '\n' && *line != '\r') {
        if ((quote && *line == quote) || (!quote && *line == '#')) break;
        if (n + 1 >= vn) return 0;
        value[n++] = *line++;
    }
    if (quote) {
        if (*line++ != quote) return 0;
        while (*line == ' ' || *line == '\t') line++;
        if (*line && *line != '#' && *line != '\r' && *line != '\n') return 0;
    } else {
        while (n && (value[n-1] == ' ' || value[n-1] == '\t')) n--;
    }
    value[n] = 0;
    return 1;
}

int protect_parse(const char *csv, protect_list *pl) {
    pl->count = 0;
    if (!csv) return 0;
    const char *p = csv;
    while (*p && pl->count < MAXPROTECT) {
        while (*p == ',' || *p == ' ' || *p == '\t') p++;
        const char *start = p;
        while (*p && *p != ',') p++;
        size_t len = (size_t)(p - start);
        while (len > 0 && (start[len-1] == ' ' || start[len-1] == '\t')) len--;
        if (len > 0) {
            if (len >= MAXNAME) len = MAXNAME - 1;
            memcpy(pl->names[pl->count], start, len);
            pl->names[pl->count][len] = 0;
            pl->count++;
        }
    }
    return pl->count;
}

int protect_has(const char *comm, const protect_list *pl) {
    for (int i = 0; i < pl->count; i++)
        if (strcmp(comm, pl->names[i]) == 0) return 1;
    return 0;
}

int ancestry_boundary(const char *comm) {
    static const char *const names[] = {"systemd", "init", "login", "sshd",
                                       "bash", "zsh", "sh", "fish", "tmux", "screen",
                                       "Xorg", "Xwayland", "gnome-shell", "kwin_wayland",
                                       "sway", "weston"};
    for (unsigned i = 0; i < sizeof names / sizeof names[0]; i++)
        if (!strcmp(comm, names[i])) return 1;
    return 0;
}

static const char *line_find(const char *buf, const char *key) {
    size_t kl = strlen(key);
    const char *p = buf;
    while (p && *p) {
        if (strncmp(p, key, kl) == 0) return p + kl;
        const char *nl = strchr(p, '\n');
        p = nl ? nl + 1 : 0;
    }
    return 0;
}

static long status_field(const char *buf, const char *key) {
    const char *p = line_find(buf, key);
    if (!p) return 0;
    while (*p && (*p < '0' || *p > '9')) { if (*p == '\n') return 0; p++; }
    long v = 0; while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; }
    return v;
}

int parse_status(const char *buf, proc_status *p) {
    const char *n = line_find(buf, "Name:");
    p->comm[0] = 0;
    if (n) {
        while (*n == ' ' || *n == '\t') n++;
        int i = 0; while (*n && *n != '\n' && i < MAXNAME - 1) p->comm[i++] = *n++;
        p->comm[i] = 0;
    }
    p->ppid = (int)status_field(buf, "PPid:");
    return 0;
}

int read_file_whole(const char *path, char *buf, size_t size) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return -1;
    ssize_t n;
    do { n = read(fd, buf, size - 1); } while (n < 0 && errno == EINTR);
    int saved = errno;
    close(fd);
    if (n < 0 || n == (ssize_t)size - 1) { errno = n < 0 ? saved : EOVERFLOW; return -1; }
    buf[n] = 0;
    return (int)n;
}

/* A protected application includes its descendants, regardless of comm. */
int pid_protected(int pid, const protect_list *pl) {
    for (int depth = 0; depth < 64; depth++) {
        if (pid <= 1) return depth == 0;
        char path[64], buf[8192];
        snprintf(path, sizeof path, "/proc/%d/status", pid);
        if (read_file_whole(path, buf, sizeof buf) < 0) return errno == ENOENT ? 0 : 1;
        proc_status p = {0};
        parse_status(buf, &p);
        if (!p.comm[0]) return 1;
        if (depth > 0 && ancestry_boundary(p.comm)) return 0;
        if (pl && protect_has(p.comm, pl)) return 1;
        snprintf(path, sizeof path, "/proc/%d/oom_score_adj", pid);
        if (read_file_whole(path, buf, sizeof buf) < 0) return errno == ENOENT ? 0 : 1;
        if (atoi(buf) <= OOM_ADJ_IMMUNE) return 1;
        if (p.ppid == pid || p.ppid < 0) return 1;
        pid = p.ppid;
    }
    return 1; /* incomplete ancestry is not permission to kill */
}


/* Runs argv[0] (an absolute path, no shell) with stdio on /dev/null. Returns
 * the exit status, -1 when it could not run or died by a signal, -2 on timeout.
 * The child gets its own process group so a timeout kills its helpers too. */
int run_cmd_timeout(const char *const argv[], int timeout_s) {
    pid_t p = fork();
    if (p < 0) return -1;
    if (p == 0) {
        setpgid(0, 0);
        int fd = open("/dev/null", O_RDWR);
        if (fd >= 0) { dup2(fd, 0); dup2(fd, 1); dup2(fd, 2); if (fd > 2) close(fd); }
        execv(argv[0], (char *const *)argv);
        _exit(127);
    }
    long deadline = mono_s() + timeout_s;
    int st = 0;
    for (;;) {
        pid_t r = waitpid(p, &st, WNOHANG);
        if (r == p) break;
        if (r < 0 && errno != EINTR) return -1;
        if (mono_s() >= deadline) {
            kill(-p, SIGKILL); kill(p, SIGKILL);
            while (waitpid(p, &st, 0) < 0 && errno == EINTR) {}
            return -2;
        }
        usleep(20000);
    }
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

/* Strict decimal pid: digits only, no sign, no trailing text, 1..INT_MAX. */
int parse_pid(const char *s, int *out) {
    if (!s || *s < '1' || *s > '9') return 0;
    long v = 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9') return 0;
        v = v * 10 + (*s - '0');
        if (v > INT_MAX) return 0;
    }
    *out = (int)v;
    return 1;
}
