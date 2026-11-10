#!/usr/bin/env python3
"""Bounded live freeze/thaw test, confined to its own unique cgroup tree."""
import ctypes
import os
from pathlib import Path
import select
import subprocess
import tempfile
import concurrent.futures
import time

ROOT = Path(__file__).resolve().parent.parent


def privileged(*args, **kwargs):
    prefix = [] if os.geteuid() == 0 else ['sudo', '-n']
    return subprocess.run([*prefix, *map(str, args)], check=True, **kwargs)


def write(path, value):
    privileged('tee', path, input=value, text=True, stdout=subprocess.DEVNULL)


def main():
    cg = Path('/sys/fs/cgroup') / f'oom-freezer-test-{os.getpid()}'
    if cg.exists():
        raise RuntimeError('test cgroup already exists; refusing to reuse it')
    child = None
    try:
        privileged('mkdir', cg)
        write(cg / 'memory.max', str(192 * 1024 * 1024))
        write(cg / 'pids.max', '32')
        write(cg / 'cgroup.subtree_control', '+memory +pids')
        privileged('mkdir', cg / 'origin.scope')
        with tempfile.TemporaryDirectory(prefix='oom-freezer-live-') as directory:
            directory = Path(directory)
            state = directory / 'state'; state.mkdir()
            conf = directory / 'oom-freezer.conf'
            conf.write_text('FREEZE_PROTECT=__none__\nFREEZE_ENABLE=0\nFREEZE_RECLAIM_MAX_S=2\n'
                            'FREEZE_RECLAIM_MB=8\n')
            helper = directory / 'oom-freezer-test'
            subprocess.run(['cc', '-O2', '-Wall', '-Wextra', '-std=c11',
                            '-DFZ_ROOT="' + str(cg / 'frozen') + '"',
                            '-o', str(helper), str(ROOT / "oom-freezer.c"), str(ROOT / "util.c")], check=True)
            # Observe the first pageout boundary while the child is frozen.
            # Recovery must already exist if reclaim later stalls or crashes.
            observer = directory / 'observer.c'
            observer.write_text(r'''
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
FILE *fopen(const char *path, const char *mode) {
  static FILE *(*next)(const char *, const char *);
  if (!next) next = dlsym(RTLD_NEXT, "fopen");
  const char *dir = getenv("FREEZER_TEST_OBSERVER");
  if (dir && strstr(path, "/maps")) {
    char marker[4096], reg[4096], resume[4096]; struct stat st;
    snprintf(reg, sizeof reg, "%s/state/frozen", dir);
    snprintf(marker, sizeof marker, "%s/observed", dir);
    snprintf(resume, sizeof resume, "%s/continue", dir);
    char value = stat(reg, &st) == 0 && st.st_size > 0 ? '1' : '0';
    int fd = open(marker, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) { (void)write(fd, &value, 1); close(fd); }
    for (int i=0; i<500 && access(resume, F_OK); i++) usleep(10000);
  }
  return next(path, mode);
}
''')
            preload = directory / 'observer.so'
            subprocess.run(['cc', '-shared', '-fPIC', '-O2', '-Wall', '-Wextra', '-o', str(preload), str(observer), '-ldl'], check=True)
            code = r'''
import sys, resource, ctypes
resource.setrlimit(resource.RLIMIT_AS, (128*1024*1024, 128*1024*1024))
ctypes.CDLL(None).prctl(15, b'fz-fixture', 0, 0, 0)
data = bytearray(32*1024*1024)
for i in range(0, len(data), 4096): data[i] = 1
print('READY', flush=True)
for line in sys.stdin: print(sum(data[::4096]), flush=True)
'''
            child = subprocess.Popen(['python3', '-u', '-c', code], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            assert select.select([child.stdout], [], [], 5)[0] and child.stdout.readline().strip() == 'READY'
            write(cg / 'origin.scope/cgroup.procs', str(child.pid))
            env = ['env', 'OOM_FREEZER_STATE=' + str(state)]
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(privileged, *env, 'LD_PRELOAD=' + str(preload),
                                     'FREEZER_TEST_OBSERVER=' + str(directory), helper,
                                     '--conf', conf, '--freeze', child.pid, timeout=20)
                try:
                    deadline = time.monotonic() + 10
                    observed = directory / 'observed'
                    while (not observed.exists() or observed.stat().st_size == 0) and not future.done() and time.monotonic() < deadline:
                        time.sleep(0.01)
                    assert observed.read_text() == '1', 'recovery must be saved before pageout/reclaim'
                    print('PASS: recovery exists before the first pageout syscall', flush=True)
                finally:
                    (directory / 'continue').touch()
                    future.result(timeout=25)
            record = (state / 'frozen').read_text()
            values = dict(part.split('=', 1) for part in record.split() if '=' in part)
            leaf = cg / 'frozen' / values['cg']
            assert 'frozen 1' in (leaf / 'cgroup.events').read_text()
            assert values['pid'] == str(child.pid) and values['orig'] == str(cg / 'origin.scope').removeprefix('/sys/fs/cgroup')
            assert 'cmd=' not in record
            assert values['phase'] == 'frozen'
            assert values['name'] == 'fz-fixture'
            print('PASS: owned fixture frozen; recovery registry saved; original cgroup retained', flush=True)
            print(record, end='', flush=True)
            # The original leaf can disappear while the application is frozen.
            # A partial thaw must keep the registry, allowing a later retry.
            privileged('rmdir', cg / 'origin.scope')
            try:
                privileged(*env, helper, '--conf', conf, '--thaw', child.pid, timeout=10)
                raise AssertionError('missing destination must fail thaw')
            except subprocess.CalledProcessError:
                pass
            assert (state / 'frozen').read_text() == record
            assert leaf.exists() and 'frozen 0' in (leaf / 'cgroup.events').read_text()
            print('PASS: failed migration retains the recovery entry after unfreezing', flush=True)
            privileged('mkdir', cg / 'origin.scope')

            # Force an atomic registry replacement failure *after* cgroup
            # removal. No writes follow this symlink (O_NOFOLLOW).
            privileged('ln', '-s', '/dev/full', state / 'frozen.tmp')
            try:
                privileged(*env, helper, '--conf', conf, '--thaw', child.pid, timeout=10)
                raise AssertionError('blocked registry commit must fail thaw')
            except subprocess.CalledProcessError:
                pass
            assert not leaf.exists() and (state / 'frozen').read_text() == record
            if (state / 'frozen.tmp').is_symlink():
                privileged('rm', state / 'frozen.tmp')
            privileged(*env, helper, '--conf', conf, '--thaw', child.pid, timeout=10)
            assert not (state / 'frozen').read_text()
            print('PASS: retry completes registry cleanup after cgroup removal', flush=True)
            assert str(child.pid) in (cg / 'origin.scope/cgroup.procs').read_text().splitlines()
            child.stdin.write('verify\n'); child.stdin.flush()
            assert select.select([child.stdout], [], [], 5)[0] and child.stdout.readline().strip() == '8192'
            print('PASS: thaw confirmed, original cgroup restored, all 32 MiB of data intact', flush=True)
            child.stdin.close(); child.wait(timeout=3)
    finally:
        if cg.exists():
            # Only this test's unique root is ever killed or removed.
            write(cg / 'cgroup.kill', '1')
            if child is not None:
                child.wait(timeout=5)
            privileged('find', cg, '-depth', '-type', 'd', '-exec', 'rmdir', '{}', '+')
        elif child is not None and child.poll() is None:
            child.kill(); child.wait(timeout=3)
    print('OK: live freeze/thaw', flush=True)


if __name__ == '__main__':
    main()
