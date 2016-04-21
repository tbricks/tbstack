/*
 * tbstack -- fast stack trace utility
 *
 * Copyright (c) 2014, Tbricks AB
 * All rights reserved.
 */

#include "mem_map.h"
#include "proc.h"
#include "snapshot.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <elf.h>

extern int opt_proc_mem;
extern int opt_process_vm_readv;
extern size_t stack_size;
extern int opt_verbose;

void snapshot_destroy(struct snapshot *snap)
{
    if (snap == NULL)
        return;

    if (snap->map != NULL)
        mem_map_destroy(snap->map);

    free(snap->regs);
    free(snap->tids);
    free(snap);
}

static int get_kernel_version(int *major, int *minor)
{
    struct utsname name;
    char *chr1, *chr2;

    if (uname(&name) < 0) {
        perror("uname");
        return -1;
    }

    if ((chr1 = strchr(name.release, '.')) != NULL) {
        *chr1 = '\0';
        if ((chr2 = strchr(++chr1, '.')) != NULL)
            *chr2 = '\0';

        *major = atoi(name.release);
        *minor = atoi(chr1);
        return 0;
    }

    fprintf(stderr, "invalid kernel release: %s\n", name.release);
    return -1;
}

/*
 * save process' memory maps, stack contents, thread identifiers and registers
 */
struct snapshot *get_snapshot(int pid, int *tids, int *index, int nr_tids)
{
    struct snapshot *res;
    int i, attached_tid, n_frames;
    long page, label, rc;
    struct mem_data_chunk **stacks_cover = NULL;
    int v_major, v_minor;
    int use_process_vm_readv = 0;

    if ((page = sysconf(_SC_PAGESIZE)) < 0) {
        perror("get pagesize");
        return NULL;
    }
    --page;

    res = calloc(1, sizeof(struct snapshot));

    /*
     * create memory_map structure corresponding to process' maps
     */
    res->map = create_maps(pid);
    if (res->map == NULL)
        goto get_snapshot_fail;

    /*
     * get process' threads
     */
    res->num_threads = get_threads(pid, &res->tids);
    if (res->num_threads < 0 || res->tids == NULL)
        goto get_snapshot_fail;

    /*
     * user-provided list of threads
     */
    if (tids != NULL) {
        if (adjust_threads(res->tids, res->num_threads, tids, index, nr_tids) < 0)
            goto get_snapshot_fail;

        free(res->tids);
        res->num_threads = nr_tids;
        res->tids = tids;
    }

    res->cur_thr = 0;

    res->regs = malloc(sizeof(res->regs[0])*res->num_threads);
    if (res->regs == NULL) {
        perror("malloc");
        goto get_snapshot_fail;
    }

    /*
     * decide how to copy memory contents of the process. on newer kernels
     * proc_vm_readv() is used by default. on older kernels or when the option
     * --proc-mem is specified read the file /proc/<pid>/mem
     */
    if (!opt_proc_mem) {
        if (get_kernel_version(&v_major, &v_minor) < 0)
            goto get_snapshot_fail;
        if (((v_major << 16) | v_minor) >= 0x30002)
            use_process_vm_readv = 1;
    } else {
        use_process_vm_readv = 0;
    }

    /* FREEZE PROCESS */
    if (attach_process(pid) < 0)
        goto get_snapshot_fail;

    for (i = 0; i < res->num_threads; ++i) {
        struct iovec iov;

        /*
         * we have already attached to main thread. call attach_thread()
         * for other ones
         */
        attached_tid = res->tids[i];
        if (res->tids[i] != pid && attach_thread(res->tids[i]) < 0)
            goto get_snapshot_fail_attached;

        /*
         * save thread's registers
         */
        iov.iov_len = sizeof(res->regs[0]);
        iov.iov_base = &res->regs[i];
        rc = ptrace(PTRACE_GETREGSET, res->tids[i], NT_PRSTATUS, &iov);
        if (rc < 0) {
            perror("PTRACE_GETREGSET");
            goto get_snapshot_fail_attached;
        }

        /*
         * save label on memory region. it will indicate that memory contents
         * upper than this point (%rsp) will needed to unwind stacks
         */
        label = SP_REG(&res->regs[i]) & ~page;
        rc = mem_map_add_label(res->map, (void *)label, res->num_threads);

        if (rc < 0) {
            fprintf(stderr, "failed to add label 0x%lx [rsp 0x%llx thread %d]\n",
                    label, (long long unsigned int)SP_REG(&res->regs[i]), res->tids[i]);
            goto get_snapshot_fail_attached;
        }

        /*
         * detach from thread. it will still be frozen due to SIGSTOP
         */
        if (res->tids[i] != pid && detach_thread(res->tids[i]) < 0)
            goto get_snapshot_fail_attached;
    }

    /*
     * arrange data chunks to copy memory contents. in most cases the chunks
     * will start from %rsp pointing somewhere in thread's stack
     * to the end of the stack region
     */
    stacks_cover = malloc(sizeof(struct mem_data_chunk*) * res->num_threads);

    n_frames = mem_map_build_label_cover(res->map, stack_size,
            stacks_cover, page + 1);

    if (stacks_cover == NULL) {
        fprintf(stderr, "error: stacks cover == NULL, n_frames=%d\n", n_frames);
        goto get_snapshot_fail_attached;
    }

    /*
     * copy memory contents
     */
    rc = use_process_vm_readv ?
        copy_memory_process_vm_readv(pid, stacks_cover, n_frames) :
        copy_memory_proc_mem(pid, stacks_cover, n_frames);

    if (rc < 0)
        goto get_snapshot_fail_attached;

    /* UNFREEZE PROCESS */
    if (detach_process(pid) < 0)
        goto get_snapshot_fail;

    if (opt_verbose) {
        for (i = 0; i < n_frames; ++i) {
            struct mem_data_chunk *chunk = stacks_cover[i];
            printf("chunk #%d: 0x%lx-0x%lx length: %ldK\n",
                    i, (size_t)chunk->start,
                    (size_t)chunk->start + chunk->length,
                    chunk->length >> 10);
        }
    }

    free(stacks_cover);

    return res;

get_snapshot_fail_attached:
    if (attached_tid)
        detach_thread(attached_tid);

    detach_process(pid);

get_snapshot_fail:
    if (opt_verbose) {
        fprintf(stderr, "maps of %d:\n", pid);
        print_proc_maps(pid);
    }

    free(stacks_cover);
    snapshot_destroy(res);
    return NULL;
}
