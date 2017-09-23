/*
 * tbstack -- fast stack trace utility
 *
 * Copyright (c) 2014, Tbricks AB
 * All rights reserved.
 */

#ifndef __d235bb20_9af6_11e3_8ab0_50ba7047f67f
#define __d235bb20_9af6_11e3_8ab0_50ba7047f67f

struct mem_map;
struct user_regs_struct;

struct snapshot
{
    /* memory mapping, copied contents, open mmapped files */
    struct mem_map *map;
    /* thread identifiers */
    int *tids;
    /* number of threads */
    int num_threads;
    /* current thread (used when unwinding stack) */
    int cur_thr;
    /* per-thread registers */
    struct user_regs_struct *regs;
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

