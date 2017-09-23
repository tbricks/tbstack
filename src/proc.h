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

/*
 * get process state (R, S, D, T, ...)
 */
char proc_state(int pid);

/*
 * parse /proc/<pid>/maps file and create mem_map structure
 */
struct mem_map *create_maps(int pid);

/*
 * simple routine to print process maps for
 * debugging or advanced error reporting
 */
int print_proc_maps(int pid);

/*
 * get thread identifiers of the process
 */
int get_threads(int pid, int **tids);

/*
 * get thread states
 */
char *get_thread_states(const int *tids, int n);

/*
 * translate thread numbers to system lwp ids
 */
int adjust_threads(int *tids, int nr_tids, int *user_tids,
        int *index, int nr_user);

/*
 * attach to the process, wait until it's stopped,
 * send SIGSTOP to make all threads frozen
 */
int attach_process(int pid);

/*
 * attach to process' thread
 */
int attach_thread(int tid);

/*
 * detach from process, send SIGCONT
 */
int detach_process(int pid);

/*
 * detach from process' thread
 */
int detach_thread(int tid);

/*
 * wait for thread to stop. we cannot use waitpid() here because non-leader
 * group members don't become children of tracer
 */
int wait_thread(int tid);

/*
 * copy process' memory contents
 */
int copy_memory(int pid, struct mem_data_chunk **frames, int n_frames);

/*
 * resolve VDSO mapping address
 */
void *get_vdso(void);

/*
 * detach from process and send SIGCONT when interrupt/termination occurs
 */
void quit_handler(int signum);

#endif

