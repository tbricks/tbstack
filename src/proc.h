/*
 * tbstack -- fast stack trace utility
 *
 * Copyright (c) 2014, Tbricks AB
 * All rights reserved.
 */

#ifndef __0383eba0_9883_11e3_82d0_c1c5dc4afb95
#define __0383eba0_9883_11e3_82d0_c1c5dc4afb95

struct mem_data_chunk;
struct mem_map;

int proc_stopped(int pid);

struct mem_map *create_maps(int pid);

int print_proc_maps(int pid);

int get_threads(int pid, int **tids);

int attach_process(int pid);
int attach_thread(int tid);
int detach_process(int pid);
int detach_thread(int tid);
int wait_thread(int tid);

int copy_memory_process_vm_readv(int pid,
        struct mem_data_chunk **frames, int n_frames);

int copy_memory_proc_mem(int pid,
        struct mem_data_chunk **frames, int n_frames);

void *get_vdso(void);

void quit_handler(int signum);

#endif

