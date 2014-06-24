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
    struct mem_map *map;
    int *tids;
    int num_threads;
    int cur_thr;
    struct user_regs_struct *regs;
};

struct snapshot *get_snapshot(int pid);

void snapshot_destroy(struct snapshot *snap);

#endif

