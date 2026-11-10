#ifndef OOM_FREEZER_UTIL_H
#define OOM_FREEZER_UTIL_H
#include <stddef.h>

#define MAXNAME     32
#define MAXLIST     16
#define MAXPROTECT  32
#define PATHMAX     512
#define OOM_ADJ_IMMUNE (-1000)

typedef struct { char v[MAXLIST][MAXNAME]; int n; } namelist;
typedef struct { char names[MAXPROTECT][MAXNAME]; int count; } protect_list;
typedef struct { int ppid; char comm[MAXNAME]; } proc_status;

void appendf(char *buf, size_t cap, size_t *len, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));
void lg(int pri, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void xcpy(char *dst, size_t cap, const char *src);
long mono_s(void);
int  read_file(const char *path, char *buf, size_t cap);
int  read_file_whole(const char *path, char *buf, size_t size);
long read_long_file(const char *path, long dflt);
long field_kb(const char *buf, const char *key);
void list_parse(namelist *l, const char *csv);

int  rate_ok(const char *key, int secs);
void rate_mark(const char *key);

void notify_init(void);
void notify(const char *msg);

int  config_assignment(const char *line, char *key, size_t kn, char *value, size_t vn);

int  protect_parse(const char *csv, protect_list *pl);
int  protect_has(const char *comm, const protect_list *pl);
int  ancestry_boundary(const char *comm);
int  parse_status(const char *buf, proc_status *p);
int  pid_protected(int pid, const protect_list *pl);
#endif
