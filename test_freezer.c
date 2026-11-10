static char *test_freezer_root = "/proc/oom-freezer-tests-never-created";
#define FZ_ROOT test_freezer_root
#define main oom_freezer_main
#include "oom-freezer.c"
#undef main
#include <sys/wait.h>

static int failures;
#define EXPECT(c, message) do { if (!(c)) { fprintf(stderr, "FAIL: %s\n", message); failures++; } } while (0)

static void registry_text(const char *path, const char *value) {
    FILE *f = fopen(path, "w"); if (!f) exit(2);
    fputs(value, f); fclose(f);
}

int main(void) {
    static fz_config cfg; fz_config *c = &cfg;
    cfg_defaults(c);
    EXPECT(c->dryrun == 1, "missing config starts main daemon in dry-run");
    cfg_apply(c, "FREEZE_INTERVAL_S", "garbage");
    EXPECT(c->interval == 15, "malformed numeric value cannot create a busy loop");
    cfg_apply(c, "FREEZE_DRYRUN", "false");
    EXPECT(c->dryrun == 1, "malformed dryrun cannot arm the daemon");
    cfg_apply(c, "FREEZE_PROTECT", "java,firefox");
    EXPECT(protect_has("java", &c->protect) && c->protect.count == 2,
           "configured protect list replaces the default");
    EXPECT(fz_valid_component("paper-123-456"), "safe freezer name");
    EXPECT(!fz_valid_component("../escape"), "freezer traversal rejected");
    EXPECT(!fz_valid_component("name\nfrozen"), "registry newline rejected");
    EXPECT(fz_valid_original("/user.slice/user-1000.slice/session-5.scope"), "valid original cgroup");
    EXPECT(!fz_valid_original("/user.slice/../system.slice"), "original traversal rejected");
    EXPECT(!fz_valid_original("/user.slice//job"), "empty path component rejected");
    char field[4];
    EXPECT(fz_field("frozen 1:2 cg=toolong", "cg=", field, sizeof field) < 0, "truncated registry field rejected");
    fz_proc label_source = {0}; char safe_label[FZ_NAMELEN];
    const char arguments[] = "python3\0-c\0sensitive.example.argument\0";
    memcpy(label_source.raw, arguments, sizeof arguments);
    label_source.rawlen = sizeof arguments - 1;
    xcpy(label_source.comm, sizeof label_source.comm, "python3");
    xcpy(label_source.exe, sizeof label_source.exe, "/usr/bin/python3");
    fz_label(&label_source, "watched", safe_label, sizeof safe_label);
    EXPECT(!strcmp(safe_label, "python3"), "generic process label must not copy an arbitrary command argument");

    fz_cand cand = {.kind = "watched", .age_min = 90, .sampled = 1, .idle = 1, .idle_min = 10};
    char verdict[96];
    fz_verdict(c, &cand, verdict, sizeof verdict);
    EXPECT(!strcmp(verdict, "idle-10-of-30-min"), "idle but below the idle threshold");
    cand.idle_min = 45; cand.forgotten = 1;
    fz_verdict(c, &cand, verdict, sizeof verdict);
    EXPECT(!strcmp(verdict, "FORGOTTEN"), "idle long enough is forgotten");
    cand.excluded = "server"; cand.never = "sshd";
    fz_verdict(c, &cand, verdict, sizeof verdict);
    EXPECT(!strcmp(verdict, "excluded:server"), "exclusion is reported before every other check");
    cand.excluded = 0;
    fz_verdict(c, &cand, verdict, sizeof verdict);
    EXPECT(!strcmp(verdict, "never:sshd"), "never list is reported before age and idleness");
    cand.never = 0; cand.age_min = 5;
    fz_verdict(c, &cand, verdict, sizeof verdict);
    EXPECT(!strcmp(verdict, "young"), "young processes are not frozen");
    c->monitor = 0; c->dryrun = 1;
    EXPECT(!fz_live(c), "dry-run never acts");
    c->dryrun = 0;
    EXPECT(fz_live(c), "live only with dry-run, monitor and autopilot all permitting");
    c->dryrun = 1;

    int pipes[2]; EXPECT(!pipe(pipes), "pipe"); pid_t child = fork();
    if (!child) { close(pipes[1]); char b; (void)read(pipes[0], &b, 1); _exit(0); }
    close(pipes[0]); EXPECT(child > 0, "child fixture");
    if (child > 0) {
        int pids[8];
        EXPECT(fz_tree((int)getpid(), pids, 1) < 0, "partial tree is rejected instead of freezing just the parent");
        EXPECT(fz_tree((int)getpid(), pids, 8) >= 2, "complete owned process tree");
        close(pipes[1]); waitpid(child, NULL, 0);
    } else close(pipes[1]);

    char state[] = "/tmp/oom-freezer-registry-XXXXXX";
    EXPECT(mkdtemp(state), "registry fixture"); c->state_dir = state;
    char path[PATHMAX], actual[2048]; snprintf(path, sizeof path, "%s/frozen", state);
    registry_text(path, "frozen 1:2 pid=123 phase=reclaiming\nfrozen 3:4 pid=456 phase=reclaiming\n");
    EXPECT(!fz_reg_replace(c, "1:2", "frozen 1:2 pid=123 phase=frozen\n"), "final metrics replace exactly one record");
    EXPECT(read_file(path, actual, sizeof actual) >= 0 &&
           !strcmp(actual, "frozen 1:2 pid=123 phase=frozen\nfrozen 3:4 pid=456 phase=reclaiming\n"),
           "metric update preserves unrelated recovery records");
    EXPECT(fz_reg_replace(c, "9:9", "unexpected\n") < 0, "missing recovery identity is never inserted");
    const char *malicious = "frozen 1:2 pid=123 cg=../../escape orig=/user.slice name=fixture\n";
    registry_text(path, malicious);
    EXPECT(fz_thaw(c, "all") < 0, "invalid registry entry cannot trigger a thaw");
    EXPECT(read_file(path, actual, sizeof actual) >= 0 && !strcmp(actual, malicious), "invalid recovery entry retained");
    const char *pending = "frozen 1:2 pid=123 cg=fixture-123-456 orig=/user.slice name=fixture\n";
    registry_text(path, pending);
    EXPECT(fz_thaw(c, "all") < 0, "failed thaw is reported");
    EXPECT(read_file(path, actual, sizeof actual) >= 0 && !strcmp(actual, pending), "failed thaw retains recovery entry");
    registry_text(path, "incomplete record");
    EXPECT(fz_thaw(c, "all") < 0, "incomplete registry is never rewritten");
    EXPECT(read_file(path, actual, sizeof actual) >= 0 && !strcmp(actual, "incomplete record"), "partial registry preserved");
    EXPECT(fz_reg_append(c, "frozen 1:2\n") < 0, "append never extends an incomplete recovery registry");
    static char full_registry[64*1024];
    memset(full_registry, 'x', sizeof full_registry-2);
    full_registry[sizeof full_registry-2] = '\n';
    full_registry[sizeof full_registry-1] = 0;
    registry_text(path, full_registry);
    EXPECT(fz_reg_append(c, "frozen 1:2\n") < 0, "writer cannot grow beyond the recovery reader limit");
    unlink(path);
    EXPECT(!symlink("/dev/full", path), "symlink fixture");
    EXPECT(fz_reg_append(c, "frozen 1:2\n") < 0, "registry writer refuses symlinks");
    unlink(path);
    char root[] = "/tmp/oom-freezer-thaw-XXXXXX", leaf[PATHMAX], control[PATHMAX+32];
    EXPECT(mkdtemp(root), "fake cgroup filesystem"); test_freezer_root = root;
    snprintf(leaf, sizeof leaf, "%s/fixture-123-456", root);
    EXPECT(!mkdir(leaf, 0700), "fake leaf");
    snprintf(control, sizeof control, "%s/cgroup.freeze", leaf); registry_text(control, "1");
    snprintf(control, sizeof control, "%s/cgroup.events", leaf); registry_text(control, "populated 1\nfrozen 0\n");
    const char *unrestored = "frozen 123:456 pid=123 cg=fixture-123-456 orig=- name=fixture\n";
    registry_text(path, unrestored);
    EXPECT(fz_thaw(c, "all") < 0, "thaw cannot report full recovery while the cgroup cannot be removed");
    EXPECT(read_file(path, actual, sizeof actual) >= 0 && !strcmp(actual, unrestored),
           "failed cgroup removal must retain recovery");
    /* A previous attempt may remove the leaf but fail to commit the registry.
     * A retry must be able to finish that bookkeeping, without acting on a PID. */
    unlink(control); snprintf(control, sizeof control, "%s/cgroup.freeze", leaf); unlink(control); rmdir(leaf);
    registry_text(path, unrestored);
    EXPECT(fz_thaw(c, "all") == 1, "retry finishes recovery for a confirmed absent leaf");
    EXPECT(read_file(path, actual, sizeof actual) == 0, "completed recovery is removed on retry");
    rmdir(root);
    unlink(path); snprintf(path, sizeof path, "%s/frozen.lock", state); unlink(path); rmdir(state);
    if (failures) return 1;
    puts("OK: freezer safety"); return 0;
}
