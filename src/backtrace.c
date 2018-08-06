/*
 * tbstack -- fast stack trace utility
 *
 * Copyright (c) 2014, Tbricks AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL TBRICKS
 * AB BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THISS OFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include <assert.h>
#include <libunwind.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined (NO_LIBUNWIND_PTRACE)
#include <libunwind-ptrace.h>
#endif

#include "backtrace.h"
#include "proc.h"
#include "snapshot.h"

extern unw_accessors_t snapshot_addr_space_accessors;

extern int opt_show_rsp;
extern int opt_show_state;
extern int opt_verbose;
extern char *opt_thread_states;

static int backtrace_thread(unw_accessors_t *accessors, void *arg)
{
    unw_addr_space_t addr_space;
    unw_cursor_t cursor;
    int rc = 0, n = 0;

    if ((addr_space = unw_create_addr_space(accessors, 0)) == NULL) {
        fprintf(stderr, "failed to create address space for unwinding\n");
        return -1;
    }

    if ((rc = unw_init_remote(&cursor, addr_space, arg)) < 0) {
        fprintf(stderr, "failed to init cursor for unwinding: rc=%d\n", rc);
        return -1;
    }

    do {
        unw_word_t ip, sp = -1, off;
        static char buf[512];
        size_t len;
        int is_sig;

        if ((rc = unw_get_reg(&cursor, UNW_REG_IP, &ip)) < 0) {
            fprintf(stderr, "failed to get IP: rc=%d\n", rc);
            break;
        }

        buf[0] = '\0';
        unw_get_proc_name(&cursor, buf, sizeof(buf), &off);

        if (buf[0] == '\0') {
            buf[0] = '?';
            buf[1] = '\0';
            len = 1;
        } else {
            len = strlen(buf);
        }

        if (len >= sizeof(buf) - 32)
            len = sizeof(buf) - 32;

        if (!ip)
            break;

        is_sig = unw_is_signal_frame(&cursor);
        if (is_sig > 0) {
            printf(" <signal handler called>\n");
        }

        if (off) {
            sprintf(buf + len, " + 0x%lx", (unsigned long)off);
        }
        if (!opt_show_rsp) {
            printf(" %016lx  %s\n", (long)ip, buf);
        } else {
            unw_get_reg(&cursor, UNW_REG_SP, &sp);
            printf(" %016lx  %016lx  %s\n", (long)ip, (long)sp, buf);
        }

        if ((rc = unw_step(&cursor)) < 0) {
            if (!opt_show_rsp)
                printf(" ????????????????  <stack breaks here>\n");
            else
                printf(" ????????????????  ????????????????  <stack breaks here>\n");

            if (opt_verbose) {
                fprintf(stderr, "unwind step failed: n=%d rc=%d\n", n, rc);
            }
            break;
        }

        if (++n == 64 && rc) {
            puts(" ????????????????  <stack is too long>\n");
            break;
        }
    } while (rc > 0);

    unw_destroy_addr_space(addr_space);

    return rc;
}

void print_thread_heading(const int *index, const int *tids,
        const char states[], int i)
{
    int ind = (index != NULL ? index[i] : i+1);
    if (opt_show_state) {
        assert(states != NULL);
        printf("--------------------  thread %d (%d) (%c) "
               "--------------------\n",
               ind, tids[i], states[i]);
    } else {
        printf("--------------------  thread %d (%d)  --------------------\n",
               ind, tids[i]);
    }
}

int backtrace_snapshot(int pid, int *tids, int *index, int nr_tids)
{
    int i, rc = 0;
    struct snapshot *snap;
    
    if ((snap = get_snapshot(pid, tids, index, nr_tids)) == NULL)
        return -1;

    for (i = 0; i < snap->num_threads; ++i) {
        print_thread_heading(index, snap->tids, snap->states, i);

        snap->cur_thr = i;
        if (backtrace_thread(&snapshot_addr_space_accessors, snap) < 0)
            rc = -1;
    }

    snapshot_destroy(snap);
    return rc;
}

int backtrace_ptrace(int pid, int *tids, int *index, int nr_tids)
{
#if !defined (NO_LIBUNWIND_PTRACE)
    int i, count, rc = 0;
    int *threads = NULL;
    char *states = NULL;

    count = get_threads(pid, &threads);
    if (!count || threads == NULL)
        return -1;

    if (tids != NULL) {
        if (adjust_threads(threads, count, tids, index, nr_tids) < 0)
            return -1;

        free(threads);
        count = nr_tids;
        threads = tids;
    }

    if (opt_show_state || opt_thread_states)
        states = get_thread_states(threads, count);

    if (opt_thread_states)
        count = filter_threads(threads, index, states, count, opt_thread_states);

    if (attach_process(pid) < 0)
        return -1;

    for (i = 0; i < count; ++i) {
        void *upt_info;

        print_thread_heading(index, threads, states, i);

        if (threads[i] != pid && attach_thread(threads[i]) < 0) {
            rc = -1;
            break;
        }

        upt_info = _UPT_create(threads[i]);

        if (backtrace_thread(&_UPT_accessors, upt_info) < 0)
            rc = -1;

        _UPT_destroy(upt_info);

        if (threads[i] != pid && detach_thread(threads[i]))
            rc = -1;
        if (rc < 0)
            break;
    }

    free(threads);

    if (detach_process(pid) < 0)
        return -1;

    free(states);

    return rc;

#else
    return -1;
#endif /* NO_LIBUNWIND_PTRACE */
}
