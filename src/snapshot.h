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

#ifndef __d235bb20_9af6_11e3_8ab0_50ba7047f67f
#define __d235bb20_9af6_11e3_8ab0_50ba7047f67f

struct mem_map;

#if defined(__arm__)
struct user_regs;
typedef struct user_regs regs_t;
#else
struct user_regs_struct;
typedef struct user_regs_struct regs_t;
#endif

#if defined(__arm__)
#define SP_REG(regs) ((regs)->uregs[13])
#elif defined(__aarch64__)
#define SP_REG(r) ((r)->sp)
#elif defined(__i386)
#define SP_REG(regs) ((regs)->esp)
#elif defined(__x86_64)
#define SP_REG(regs) ((regs)->rsp)
#else
#error Need porting
#endif

struct snapshot
{
    /* memory mapping, copied contents, open mmapped files */
    struct mem_map *map;
    /* thread identifiers */
    int *tids;
    /* thread states */
    char *states;
    /* number of threads */
    int num_threads;
    /* current thread (used when unwinding stack) */
    int cur_thr;
    /* per-thread registers */
    regs_t *regs;
};

/*
 * fill up snapshot structure for a process
 */
struct snapshot *get_snapshot(int pid, int *tids, int *index, int nr_tids);

/*
 * free resources
 */
void snapshot_destroy(struct snapshot *snap);

#endif

