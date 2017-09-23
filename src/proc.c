/*
 * tbstack -- fast stack trace utility
 *
 * Copyright (c) 2014, Tbricks AB
 * All rights reserved.
 */

#include "mem_map.h"
#include "proc.h"

#include <ctype.h>
#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SYS_process_vm_readv
#define SYS_process_vm_readv 310
#endif

#define SLEEP_WAIT 500

int attached_pid = 0;

/* timeout on waiting for process to stop (us) */
extern int stop_timeout;
static int sleep_time = 0;

/* for summary */
int sleep_count = 0;
size_t total_length = 0;

extern struct timeval freeze_time;
extern struct timeval unfreeze_time;

extern int opt_proc_mem;
extern int opt_use_waitpid_timeout;
extern int opt_verbose;

int proc_stopped(int pid)
{
    FILE *f;
    char buf[128];
    char c;
    int rc = -1;

    sprintf(buf, "/proc/%d/status", pid);
    if ((f = fopen(buf, "r")) == NULL) {
        fprintf(stderr, "cannot open %s: %s\n", buf, strerror(errno));
        return -1;
    }

    while (fgets(buf, sizeof(buf), f)) {
        if (sscanf(buf, "State:\t%c", &c) == 1) {
            rc = (c == 't' || c == 'T');
            break;
        }
    }

    fclose(f);
    return rc;
}

struct mem_map *create_maps(int pid)
{
    FILE *f;
    char *buf = NULL, *str = NULL;
    size_t total_read, capacity;

    size_t addr_start, addr_end, offset, len;
    char r, w, x, p;
    int dev_major, dev_minor, inode;
    char path[PATH_MAX];

    struct mem_map *map = NULL;
    struct mem_region *region;

    capacity = 0x100000;
    buf = calloc(1, capacity);

    sprintf(buf, "/proc/%d/maps", pid);
    if ((f = fopen(buf, "r")) == NULL) {
        fprintf(stderr, "cannot open %s: %s\n", buf, strerror(errno));
        return NULL;
    }

    map = malloc(sizeof(struct mem_map));
    mem_map_init(map);

    memset(buf, 0, capacity);
    total_read = 0;
    while (!feof(f)) {
        fread(&buf[total_read], capacity - total_read - 1, 1, f);
        if (errno) {
            perror("maps");
            mem_map_destroy(map);
            map = NULL;
            goto create_maps_end;
        }

        total_read = strlen(buf);
        if ((total_read + 1) == capacity) {
            capacity *= 2;
            buf = realloc(buf, capacity);
            memset(&buf[total_read], 0, capacity - total_read);
        } else {
            buf[total_read] = '\0';
        }
    }

    str = &buf[0];
    while (*str) {
        int scan;
        char *next;

        next = strchr(str, '\n');
        if (next != NULL)
            *next = '\0';

        scan = sscanf(str, "%lx-%lx %c%c%c%c %lx %x:%x %d %[^\t\n]",
                &addr_start, &addr_end,
                &r, &w, &x, &p,
                &offset,
                &dev_major, &dev_minor,
                &inode,
                path);

        if (scan < 10) {
            fprintf(stderr, "warning: unable to parse maps "
                    "entry '%s' (read %d)\n", str, scan);
            break;
        }

        region = malloc(sizeof(struct mem_region));
        mem_region_init(region);

        region->start = (void *)addr_start;
        region->length = addr_end - addr_start;
        region->offset = offset;
        if (scan > 10 && path[0] != '\0') {
            if (!strcmp(path, "[vdso]")) {
                region->type = MEM_REGION_TYPE_VDSO;
            } else if (!strcmp(path, "[vsyscall]")) {
                region->type = MEM_REGION_TYPE_VSYSCALL;
            } else if ((len = strlen(path)) > 10 &&
                    !strcmp(path + len - 10, " (deleted)")) {
                *(path + len - 10) = '\0';
                region->path = strdup(path);
                region->type = MEM_REGION_TYPE_DELETED;
            } else {
                region->path = strdup(path);
                region->type = MEM_REGION_TYPE_MMAP;
            }
        }

        if (mem_map_add_region(map, region) != 0) {
            mem_map_destroy(map);
            map = NULL;
            break;
        }

        if (next != NULL)
            str = next + 1;
    }

    if (map != NULL)
        mem_map_create_region_index(map);

create_maps_end:
    fclose(f);
    free(buf);
    return map;
}

int print_proc_maps(int pid)
{
    char cmd[32];
    sprintf(cmd, "cat /proc/%d/maps 1>&2", pid);
    return system(cmd);
}

/*
 * filter for scandir(). choose only thread identifiers
 */
static int dir_select(const struct dirent *entry)
{
    const char *c = entry->d_name;
    while (*c)
        if (!isdigit(*c++))
            return 0;
    return 1;
}

int get_threads(int pid, int **tids)
{
    char buf[32];
    struct dirent **namelist;
    int cur, i, n;

    snprintf(buf, sizeof(buf), "/proc/%d/task", pid);

    n = scandir(buf, &namelist, dir_select, NULL);
    if (n < 0) {
        perror(buf);
        return -1;
    } else {
        *tids = malloc(sizeof(int)*n);
        i = 0;
        while (i < n) {
            cur = atoi(namelist[i]->d_name);
            (*tids)[i] = cur;
            free(namelist[i++]);
        }
        free(namelist);
    }

    return n;
}

int adjust_threads(int *tids, int nr_tids, int *user_tids,
        int *index, int nr_user)
{
    int i, j, n = 0;
    for (i = 0; i < nr_user; ++i) {
        int found = 0;
        for (j = 0; j < nr_tids; ++j) {
            if (tids[j] == user_tids[i]) {
                found = 1;
                break;
            }
        }
        if (!found) {
            if (n || (user_tids[i] > nr_tids) || (user_tids[i] <= 0)) {
                fprintf(stderr, "unexpected thread %d\n", user_tids[i]);
                return -1;
            }
        } else {
            ++n;
            index[i] = j + 1;
        }
    }
    if (!n) {
        for (i = 0; i < nr_user; ++i) {
            index[i] = user_tids[i];
            user_tids[i] = tids[user_tids[i]-1];
        }
    }
    return 0;
}

int attach_process(int pid)
{
    int status = 0;

    gettimeofday(&freeze_time, NULL);

    attached_pid = pid;
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        perror("attach");
        detach_process(pid);
        return -1;
    }
    if (!proc_stopped(pid)) {
        struct itimerval tm;

        if (opt_use_waitpid_timeout) {
            /* setup alarm to avoid long waiting on waitpid */
            tm.it_interval.tv_sec = 0;
            tm.it_interval.tv_usec = 0;
            tm.it_value.tv_sec = 1;
            tm.it_value.tv_usec = stop_timeout % 1000000;
            setitimer(ITIMER_REAL, &tm, NULL);
        }

        if (waitpid(pid, &status, WUNTRACED) < 0) {
            if (errno == EINTR) {
                fprintf(stderr, "timeout on waitpid\n");
                detach_process(pid);
                return -1;
            }
            fprintf(stderr, "waitpid %d: %s\n", pid, strerror(errno));
            detach_process(pid);
            return -1;
        }

        if (opt_use_waitpid_timeout) {
            tm.it_value.tv_sec = 0;
            tm.it_value.tv_usec = 0;
            setitimer(ITIMER_REAL, &tm, NULL);
        }

        if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP)
            fprintf(stderr, "warning: waitpid(%d) WIFSTOPPED=%d WSTOPSIG=%d\n",
                    pid, WIFSTOPPED(status), WSTOPSIG(status));
    }
    if (kill(pid, SIGSTOP) < 0) {
        perror("send SIGSTOP");
        return -1;
    }
    return 0;
}

int attach_thread(int tid)
{
    if (ptrace(PTRACE_ATTACH, tid, NULL, NULL) < 0) {
        perror("PTRACE_ATTACH");
        return -1;
    }
    if (wait_thread(tid) < 0)
        return -1;
    return 0;
}

int detach_process(int pid)
{
    int rc = 0;
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
        perror("detach");
        rc = -1;
    }
    if (kill(pid, SIGCONT) < 0) {
        perror("send SIGCONT");
        rc = -1;
    }

    attached_pid = 0;
    gettimeofday(&unfreeze_time, NULL);
    return rc;
}

int detach_thread(int tid)
{
    long rc = ptrace(PTRACE_DETACH, tid, NULL, NULL);
    if (rc < 0) {
        perror("PTRACE_DETACH");
        return -1;
    }
    return 0;
}

int wait_thread(int tid)
{
    int rc;
    while (!(rc = proc_stopped(tid))) {
        if (stop_timeout && sleep_time > stop_timeout) {
            fprintf(stderr, "timeout waiting for thread %d to stop", tid);
            return -1;
        }
        usleep(SLEEP_WAIT);
        sleep_time += SLEEP_WAIT;
        sleep_count++;
    }
    return (rc == -1 ? -1 : 0);
}

/*
 * copy memory contents using process_vm_readv(). reduces number
 * of system calls comparing to /proc/pid/mem
 *
 * return values:
 *      0  success
 *     -1  fail
 * ENOSYS  process_vm_readv() is not supported
 */
static int copy_memory_process_vm_readv(int pid,
        struct mem_data_chunk **frames, int n_frames)
{
    struct iovec *local_iov, *remote_iov;
    ssize_t *frame_bytes;
    int i, rc = -1;
    ssize_t bytes_total = 0;
    int seg_count = 0;

    local_iov = malloc(sizeof(struct iovec)*n_frames);
    remote_iov = malloc(sizeof(struct iovec)*n_frames);
    frame_bytes = malloc(sizeof(ssize_t)*n_frames);

    for (i = 0; i < n_frames; ++i) {
        local_iov[i].iov_base = frames[i]->data;
        local_iov[i].iov_len = frames[i]->length;
        remote_iov[i].iov_base = frames[i]->start;
        remote_iov[i].iov_len = frames[i]->length;

        bytes_total += frames[i]->length;
        frame_bytes[i] = bytes_total;
    }

    bytes_total = 0;
    while (1) {
        ssize_t bytes_read;
        int frames_to_read = n_frames - seg_count;
        if (frames_to_read > IOV_MAX)
            frames_to_read = IOV_MAX;

        bytes_read = syscall(SYS_process_vm_readv,
                pid,
                local_iov + seg_count,
                frames_to_read,
                remote_iov + seg_count,
                frames_to_read,
                0ULL);

        if (bytes_read < 0) {
            if (errno == ENOSYS)
                rc = ENOSYS;
            else
                perror("process_vm_readv");

            goto process_vm_readv_end;
        }

        bytes_total += bytes_read;
        total_length = bytes_total;
        for (seg_count = n_frames-1; seg_count >= 0; --seg_count) {
            if (frame_bytes[seg_count] == bytes_total)
                break;
        }

        if (seg_count < 0) {
            fprintf(stderr, "unknown number of bytes returned by "
                    "process_vm_readv: bytes_read=%ld "
                    "bytes_total=%ld seg_count=%d\n",
                    bytes_read, bytes_total, seg_count);
            goto process_vm_readv_end;
        }

        if (seg_count == (n_frames-1))
            break;

        ++seg_count;
    }

    rc = 0;

process_vm_readv_end:
    free(local_iov);
    free(remote_iov);
    free(frame_bytes);
    return rc;
}

/*
 * read the file /proc/<pid>/mem
 */
static int copy_memory_proc_mem(int pid, struct mem_data_chunk **frames,
        int n_frames)
{
    int i = 0;
    char fname[32];
    int fd;
    int rc = -1;

    sprintf(fname, "/proc/%d/mem", pid);
    if ((fd = open(fname, O_RDONLY)) == -1) {
        fprintf(stderr, "cannot open %s\n", fname);
        perror(fname);
        return -1;
    }

    for (i = 0; i < n_frames; ++i) {
        off_t from = (off_t)frames[i]->start;
        char *to = frames[i]->data;
        size_t count = frames[i]->length;

        while (count > 0) {
            ssize_t rd = pread(fd, to, count, from);

            if (rd == -1) {
                fprintf(stderr, "pread() at %s:0x%lx (#%d) failed: %s [%d]\n",
                        fname, from, i, strerror(errno), errno);
                goto proc_mem_end;
            }

            from += rd;
            to += rd;
            count -= rd;
        }

        total_length += frames[i]->length;
    }

    rc = 0;

proc_mem_end:
    close(fd);
    return rc;
}

int copy_memory(int pid, struct mem_data_chunk **frames, int n_frames)
{
    if (!opt_proc_mem) {
        int rc = copy_memory_process_vm_readv(pid, frames, n_frames);
        if (rc == ENOSYS) {
            if (opt_verbose) {
                fprintf(stderr, "process_vm_readv is not supported, falling "
                                "back to /proc/pid/mem\n");
            }
        } else {
            return rc;
        }
    }

    return copy_memory_proc_mem(pid, frames, n_frames);
}

void *get_vdso()
{
    static const char *auxv = "/proc/self/auxv";
    FILE *f;
    long entry[2];

    f = fopen(auxv, "r");
    if (f == NULL) {
        perror(auxv);
        return NULL;
    }

    while (!feof(f)) {
        if (fread(entry, sizeof(entry), 1, f) != 1)
            goto get_vdso_fail;

        if (entry[0] == AT_SYSINFO_EHDR) {
            fclose(f);
            return (void *)entry[1];
        }
    }

get_vdso_fail:
    perror(auxv);
    fclose(f);
    return NULL;
}

void quit_handler(int signum)
{
    /*
     * We can't call PTRACE_DETACH here because we are in a signal handler.
     * Additionally ptrace will automatically detach when this process exits at
     * the end of this function. We do however always need to send the SIGCONT
     * if we have ptrace attached because when the ptrace automatically
     * detaches it will leave the process in a stopped state even if we had not
     * yet sent SIGSTOP to it.
     */
    if (attached_pid)
        kill(attached_pid, SIGCONT);
    if (signum == SIGSEGV) {
        static volatile int *n = NULL;
        *n = 1969;
    }
    _exit(1);
}
