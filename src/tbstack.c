/*
 * tbstack -- fast stack trace utility
 *
 * Copyright (c) 2014, Tbricks AB
 * All rights reserved.
 */

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
size_t stack_size = 0;
int opt_proc_mem = 0;
int opt_ptrace = 0;
int opt_show_rsp = 0;
int opt_verbose = 0;
int stop_timeout = 1000000;
int opt_ignore_deleted = 0;

static int usage(const char *name)
{
    fprintf(stderr,
"usage:    %s <pid>\n\n"
"options:  --help               show this\n"
"          --ignore-deleted     try to open shared objects marked as deleted\n"
"          --proc-mem           prefer reading /proc/pid/mem (default on systems\n"
"                               with kernel older than 3.2. on modern kernels\n"
"                               default flavor is process_vm_readv)\n"
"          --ptrace             use libunwind-ptrace interface (slower)\n"
"          --show-rsp           show %%rsp in second column\n"
"          --stack-size <size>  maximum stack size to copy (default is current\n"
"                               RLIMIT_STACK)\n"
"          --stop-timeout       timeout for waiting the process to freeze, in\n"
"                               milliseconds. default value is %d\n"
"          --verbose            verbose error messages\n",
        name, stop_timeout/1000);
    return 2;
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

            default:
                break;
            }
            break;

        case '?':
            break;

        default:
            printf("?? getopt returned character code 0%o ??\n", c);
        }
    }

    if (optind == argc)
        exit(usage(argv[0]));

    pid = atoi(argv[optind]);
    if (pid <= 0) {
        fprintf(stderr, "invalid pid %s\n", argv[optind]);
        exit(usage(argv[0]));
    }

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
            sigaction(SIGSEGV, &act, NULL) < 0) {
        perror("sigaction");
        exit(1);
    }
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

static void check_process(int pid)
{
    if (kill(pid, 0) < 0) {
        fprintf(stderr, "%d: %s\n", pid, strerror(errno));
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
           " total bytes copied: 0x%lx (%ldK)\n",
           tm/1000, tm%1000, sleep_count, total_length, total_length>>10);
}

int main(int argc, char **argv)
{
    int rc = 0;

    parse_options(argc, argv);
    check_libelf_version();
    setup_signals();

    if (!stack_size)
        setup_stack_size();

    rc = !opt_ptrace ?
        backtrace_snapshot(pid) :
        backtrace_ptrace(pid);

    summary();

    return (rc != 0);
}
