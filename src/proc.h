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

#ifndef __0383eba0_9883_11e3_82d0_c1c5dc4afb95
#define __0383eba0_9883_11e3_82d0_c1c5dc4afb95

struct mem_data_chunk;
struct mem_map;

/*
 * returns process state (R, S, D, T, ...) or -1 on error
 */
int proc_state(int pid);

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
 * returns a pointer to dynamically allocated array of characters representing
 * thread states as found in /proc/<pid>/status
 */
char *get_thread_states(const int *tids, int n);

/*
 * translate thread numbers to system lwp ids
 */
int adjust_threads(int *tids, int nr_tids, int *user_tids,
        int *index, int nr_user);

/*
 * filter threads by state. returns new number of threads
 */
int filter_threads(int tids[], int index[], char states[], int nr_tids,
        const char *user_states);

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

