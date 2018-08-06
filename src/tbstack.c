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
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <libelf.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <unistd.h>

#include "backtrace.h"
#include "proc.h"

#define GENERIC_STACK_SIZE 0xa00000

struct timeval freeze_time = {0, 0};
struct timeval unfreeze_time = {0, 0};

extern int sleep_count;
extern size_t total_length;

static int pid = 0;
static int nr_tids = 0;
static int *tid_list = NULL;
static int *tid_index = NULL;
size_t stack_size = 0;
int opt_proc_mem = 0;
int opt_ptrace = 0;
int opt_show_rsp = 0;
int opt_show_state = 0;
int opt_verbose = 0;
int stop_timeout = 1000000;
int opt_ignore_deleted = 0;
int opt_use_waitpid_timeout = 0;
char *opt_thread_states = NULL;

static int usage(const char *name)
{
    fprintf(stderr,
"usage:    %s <pid>\n"
"          %s <pid>/<tid1>,...,<tidn>\n"
"          %s <pid>/RS\n\n"
"options:  --help                show this\n"
"          --ignore-deleted      try to open shared objects marked as deleted\n"
"          --use-waitpid-timeout set alarm to interrupt waitpid\n"
"          --proc-mem            prefer reading /proc/pid/mem. default flavor\n"
"                                is process_vm_readv\n"
#if !defined (NO_LIBUNWIND_PTRACE)
"          --ptrace              use libunwind-ptrace interface (slower)\n"
#endif
"          --show-rsp            show %%rsp in second column\n"
"          --show-state          show thread states\n"
"          --stack-size <size>   maximum stack size to copy (default is current\n"
"                                RLIMIT_STACK)\n"
"          --stop-timeout        timeout for waiting the process to freeze, in\n"
"                                milliseconds. default value is %d\n"
"          --verbose             verbose error messages\n"
"          --version             output version information and exit\n",
        name, name, name, stop_timeout/1000);
    return 2;
}

static void parse_pid_arg(const char *prog, char *arg)
{
    char *tstr, *pos;
    int nr_commas = 0;
    char c, prev = '\0';
    int i = 0, j;
    int is_state_list = 1;

    tstr = strchr(arg, '/');
    if (tstr != NULL) {
        *tstr++ = '\0';
        if (*tstr == '\0') {
            fprintf(stderr, "empty thread list\n");
            exit(usage(prog));
        }
    }

    pid = atoi(arg);
    if (pid <= 0) {
        fprintf(stderr, "invalid pid %s\n", arg);
        exit(usage(prog));
    }

    if (tstr == NULL)
        return;

    /* check if state list is provided */
    pos = tstr;
    while ((c = *pos++)) {
        if (!isalpha(c)) {
            is_state_list = 0;
            break;
        }
    }

    if (is_state_list) {
        opt_thread_states = strdup(tstr);
        return;
    }

    pos = tstr;
    if (*pos == ',')
        goto parse_pid_arg_invalid_list;
    while ((c = *pos++)) {
        if (c == ',') {
            if (prev == ',' || prev == '\0')
                goto parse_pid_arg_invalid_list;
            ++nr_commas;
        } else if (!isdigit(c)) {
            goto parse_pid_arg_invalid_list;
        }
        prev = c;
    }
    if (prev == ',')
        goto parse_pid_arg_invalid_list;

    nr_tids = nr_commas + 1;
    tid_list = malloc(sizeof(int) * nr_tids);
    tid_index = malloc(sizeof(int) * nr_tids);

    tstr = strtok(tstr, ",");
    do {
        assert(i < nr_tids);
        tid_list[i++] = atoi(tstr);
    } while ((tstr = strtok(NULL, ",")) != NULL);


    for (i = 0; i < nr_tids; ++i) {
        for (j = i + 1; j < nr_tids; ++j) {
            if (tid_list[i] == tid_list[j]) {
                fprintf(stderr, "duplicate thread %d\n", tid_list[i]);
                exit(usage(prog));
            }
        }
    }

    return;

parse_pid_arg_invalid_list:
    fprintf(stderr, "invalid thread list string '%s'\n", tstr);
    exit(usage(prog));
}

static void parse_options(int argc, char **argv)
{
    char *endptr = "";

    while (1) {
        int option_index = 0, c;
        static struct option long_options[] = {
            { "proc-mem", 0, NULL, 0 },
            { "ptrace", 0, NULL, 0 },
            { "stack-size", 1, NULL, 0},
            { "show-rsp", 0, NULL, 0},
            { "verbose", 0, NULL, 0},
            { "help", 0, NULL, 0},
            { "stop-timeout", 1, NULL, 0},
            { "ignore-deleted", 0, NULL, 0},
            { "use-waitpid-timeout", 0, NULL, 0 },
            { "show-state", 0, NULL, 0 },
            { "version", 0, NULL, 0 },
            { 0, 0, 0, 0 }
        };

        c = getopt_long(argc, argv, "", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 0:
            switch (option_index) {
            case 0:
                opt_proc_mem = 1;
                break;

            case 1:
#if defined (NO_LIBUNWIND_PTRACE)
                fprintf(stderr, "support for libunwind-ptrace is disabled\n");
                exit(1);
#endif
                opt_ptrace = 1;
                break;

            case 2:
                if (optarg[0] == '0' && optarg[1] == 'x') {
                    stack_size = strtol(optarg+2, &endptr, 16);
                } else {
                    stack_size = strtol(optarg, &endptr, 10);
                }
                if (*endptr != '\0') {
                    fprintf(stderr, "invalid value of option stack-size: %s\n",
                            optarg);
                    exit(2);
                }
                break;

            case 3:
                opt_show_rsp = 1;
                break;

            case 4:
                opt_verbose = 1;
                break;

            case 5:
                usage(argv[0]);
                exit(0);

            case 6:
                if ((stop_timeout = atoi(optarg) * 1000) < 0) {
                    fprintf(stderr, "invalid value of stop-timeout: %s\n",
                            optarg);
                    exit(2);
                }
                break;

            case 7:
                opt_ignore_deleted = 1;
                break;

            case 8:
                opt_use_waitpid_timeout = 1;
                break;

            case 9:
                opt_show_state = 1;
                break;

            case 10:
                puts(PACKAGE_STRING);
                exit(0);

            default:
                break;
            }
            break;

        case '?':
            exit(usage(argv[0]));
            break;

        default:
            printf("?? getopt returned character code 0%o ??\n", c);
        }
    }

    if (optind == argc)
        exit(usage(argv[0]));

    parse_pid_arg(argv[0], argv[optind]);

    if (++optind < argc) {
        fprintf(stderr, "unknown command line argument %s\n", argv[optind]);
        exit(usage(argv[0]));
    }
}

static void check_libelf_version()
{
    if (elf_version(EV_CURRENT) == EV_NONE) {
        fprintf(stderr, "elf initialization failed: %s\n",
                elf_errmsg(elf_errno()));
        exit(1);
    }
}

static void alarm_handler(int signo)
{
    (void) signo;
};

static void setup_signals()
{
    sigset_t mask;
    struct sigaction act;

    sigemptyset(&mask);
    act.sa_handler = quit_handler;
    act.sa_mask = mask;
    act.sa_flags = 0;
    act.sa_restorer = NULL;

    if (sigaction(SIGINT, &act, NULL) < 0 ||
            sigaction(SIGQUIT, &act, NULL) < 0 ||
            sigaction(SIGPIPE, &act, NULL) < 0 ||
            sigaction(SIGTERM, &act, NULL) < 0 ||
            sigaction(SIGTSTP, &act, NULL) < 0 ||
            sigaction(SIGABRT, &act, NULL) < 0 ||
            sigaction(SIGSEGV, &act, NULL) < 0)
        goto sigaction_fail;

    act.sa_handler = alarm_handler;
    if (sigaction(SIGALRM, &act, NULL) < 0)
        goto sigaction_fail;

    return;

sigaction_fail:
    perror("sigaction");
    exit(1);
}

static void setup_stack_size()
{
    struct rlimit lim;
    if (getrlimit(RLIMIT_STACK, &lim) < 0) {
        perror("getrlimit");
        exit(1);
    }

    if (lim.rlim_cur == RLIM_INFINITY) {
        stack_size = GENERIC_STACK_SIZE;
    } else {
        stack_size = lim.rlim_cur;
    }
}

static void check_process()
{
    if (kill(pid, 0) < 0) {
        fprintf(stderr, "%s\n", strerror(errno));
        exit(1);
    }
}

static void summary()
{
    long tm;

    if (!freeze_time.tv_sec)
        return;

    tm = unfreeze_time.tv_sec * 1000000 + unfreeze_time.tv_usec;
    tm -= freeze_time.tv_sec * 1000000 + freeze_time.tv_usec;

    printf("-----------------------  summary  --------------------------\n"
           " time the process was frozen: %ldms %ldus\n"
           " sleep count: %d\n"
           " total bytes copied: 0x%zx (%zdK)\n",
           tm/1000, tm%1000, sleep_count, total_length, total_length>>10);
}

int main(int argc, char **argv)
{
    int rc = 0;

    parse_options(argc, argv);
    check_process();
    check_libelf_version();
    setup_signals();

    if (!stack_size)
        setup_stack_size();

    rc = !opt_ptrace ?
        backtrace_snapshot(pid, tid_list, tid_index, nr_tids) :
        backtrace_ptrace(pid, tid_list, tid_index, nr_tids);

    summary();

    return (rc != 0);
}
