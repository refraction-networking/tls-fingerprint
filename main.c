#define _GNU_SOURCE
#include <signal.h>
#include <sys/sysinfo.h>
#include <sys/wait.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>

#include "pfring_zc.h"
#define pfring_maybezc_stat pfring_zc_stat
#define pfring_maybezc_stats pfring_zc_stats

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

#include "rust-src/rust_ffi.h"

// Once we are receiving filtered, 443-only traffic, we might need a lower
// PKT_BURST_SIZE! Although, given all of the non-443 junk that gets quickly
// discarded, maybe we could have a much larger burst size now, and the current
// burst size is appropriate for 443-only. We will have to experiment.
// Should probably keep PKT_BURST_SIZE a multiple of PF_BURST_SIZE.
#define PF_BURST_SIZE 16
#define PKT_BURST_SIZE 800
// When our last recv burst got nothing, we want to wait at least this long
// before doing another recv burst. If the Rust eloop tick doesn't take this
// long, do a sleep to make up the difference. (However, since minimum sleep is
// like 50us, the pause dur will overshoot. It's fine, though).
#define DESIRED_PAUSE_DUR_NS 10000

#define NO_ZC_BUFFER_LEN 9000
#define MAX_NUM_FORKED_PROCS 256
pid_t g_forked_pids[MAX_NUM_FORKED_PROCS];
pfring_zc_queue* g_ring = 0;
pfring_zc_buffer_pool* g_pool = 0;
pfring_zc_pkt_buff* g_buf[PF_BURST_SIZE];
int g_num_worker_procs = 0;
void* g_rust_cli_conf_proto_ptr = 0;
void* g_rust_failed_map = 0;
int g_update_cli_conf_when_convenient = 0;
int g_update_overloaded_decoys_when_convenient = 0;

#define TIMESPEC_DIFF(a, b) ((a.tv_sec - b.tv_sec)*1000000000LL + \
                             ((int64_t)a.tv_nsec - (int64_t)b.tv_nsec))
void the_program(uint8_t core_id, unsigned int log_interval, char* db_source_name, int gre_offset, int log_client_hello) {
    struct RustGlobalsStruct rust_globals = rust_init(core_id, g_num_worker_procs, db_source_name, gre_offset, log_client_hello);
    void* rust_ptr = (void*) &rust_globals;

    printf("Zero-copy TLS ClientHello Analyzer child proc started on core %d!\n", core_id);

    int recvd_pkts = 0;

    struct timespec prev_cleanup;
    struct timespec prev_status_report;
    clock_gettime(CLOCK_MONOTONIC, &prev_cleanup);
    clock_gettime(CLOCK_MONOTONIC, &prev_status_report);
    struct timespec cur_time_ns;
    int64_t ns_since_status_report;
    int64_t ns_since_cleanup;
    // log_interval is milliseconds
    int64_t log_interval_ns = log_interval * 1000LL * 1000LL;
    int64_t cleanup_interval_ns = 10LL*1000LL*1000LL*1000LL; // 10s
    pfring_maybezc_stat stats;
    pfring_maybezc_stats(g_ring, &stats);
    unsigned long drops_prev = stats.drop;
    unsigned long drops_cur = stats.drop;

    while(1)
    {
        while(recvd_pkts < PKT_BURST_SIZE)
        {
            int cur_recvd_pkts;
            if((cur_recvd_pkts =
                pfring_zc_recv_pkt_burst(g_ring, g_buf, PF_BURST_SIZE, 0)) > 0)
            {
                for(int i=0; i< cur_recvd_pkts; i++)
                {
                    rust_process_packet(
                        rust_ptr, pfring_zc_pkt_buff_data(g_buf[i], g_ring),
                        g_buf[i]->len);
                }
                recvd_pkts += cur_recvd_pkts;
            }
            else
                break;
        }

        recvd_pkts = 0;

        clock_gettime(CLOCK_MONOTONIC, &cur_time_ns);
        ns_since_status_report = TIMESPEC_DIFF(cur_time_ns, prev_status_report);
        ns_since_cleanup = TIMESPEC_DIFF(cur_time_ns, prev_cleanup);
        if(unlikely(ns_since_cleanup > cleanup_interval_ns))
        {
            prev_cleanup = cur_time_ns;
            rust_periodic_cleanup(rust_ptr);
            rust_print_avg_stats(rust_ptr);
        }
        if(unlikely(ns_since_status_report > log_interval_ns))
        {
            prev_status_report = cur_time_ns;
            pfring_maybezc_stats(g_ring, &stats);
            drops_cur = stats.drop;

            printf("drop %lu %lu\n", (drops_cur - drops_prev), drops_cur);

            drops_prev = drops_cur;
        }
    }
}

void ignore_sigpipe(int sig)
{
    printf("received a SIGPIPE, ignoring\n");
}


void sigproc_child(int sig)
{
    static char called = 0;
    if(called) return; else called = 1;

    pfring_zc_queue_breakloop(g_ring);
    for (int i=0; i<PF_BURST_SIZE; i++)
        pfring_zc_release_packet_handle_to_pool(g_pool, g_buf[i]);
    pfring_zc_ipc_detach_queue(g_ring);
    pfring_zc_ipc_detach_buffer_pool(g_pool);
    fprintf(stderr, "PF_RING zero-copy TLS ClientHello Analyzer child process shut down\n");
    exit(0);
}

void sigproc_parent(int sig)
{
    static char called = 0;
    if(called) return; else called = 1;

    fprintf(stderr, "PF_RING TLS ClientHello Analyzer shutting down...\n");

    int i, junk;
    for(i=0; i<g_num_worker_procs; i++)
        kill(g_forked_pids[i], SIGTERM);
    for(i=0; i<g_num_worker_procs; i++)
        waitpid(g_forked_pids[i], &junk, 0);
    fprintf(stderr, "PF_RING TLS ClientHello Analyzer done shutting down!\n");
    exit(0);
}

void set_affinity(int id)
{
    cpu_set_t cpuset;
    u_long core_id = id;
    int s;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    if((s = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset)))
        fprintf(stderr, "Error binding to core %ld: errno=%i\n", core_id, s);
}

void startup_pfring_maybezc(unsigned int cluster_id, int proc_ind, int cluster_queue_offset)
{
    char cluster_iface_id[200];
    sprintf(cluster_iface_id, "zc:%d@%d", cluster_id, proc_ind + cluster_queue_offset);
    if(!(g_ring = pfring_zc_ipc_attach_queue(cluster_id, proc_ind + cluster_queue_offset, rx_only)))
    {
        fprintf(stderr, "pfring_zc_ipc_attach_queue error [%s] opening %s "
                        "(%d, %d)\n",
                strerror(errno), cluster_iface_id, cluster_id, proc_ind);
        exit(-1);
    }

    if(!(g_pool = pfring_zc_ipc_attach_buffer_pool(cluster_id, proc_ind + cluster_queue_offset)))
    {
        fprintf(stderr,
                "pfring_zc_ipc_attach_buffer_pool error [%s] opening %s\n",
                strerror(errno), cluster_iface_id);
        exit(-1);
    }

    for (int i=0; i<PF_BURST_SIZE; i++)
    {
        if(!(g_buf[i] = pfring_zc_get_packet_handle_from_pool(g_pool)))
        {
            fprintf(stderr,
                    "pfring_zc_get_packet_handle_from_pool error [%s] "
                    "opening %s\n", strerror(errno), cluster_iface_id);
            exit(-1);
        }
    }
}

pid_t start_process(int core_affinity, unsigned int cluster_id,
                             int proc_ind, unsigned int log_interval, char* db_source_name, int cluster_queue_offset, int gre_offset, int log_client_hello)
{
    pid_t the_pid = fork();
    if(the_pid == 0)
    {
        startup_pfring_maybezc(cluster_id, proc_ind, cluster_queue_offset);
        printf("Child proc %d created\n", core_affinity);

        set_affinity(core_affinity);
        signal(SIGINT, sigproc_child);
        signal(SIGTERM, sigproc_child);
        signal(SIGPIPE, ignore_sigpipe);
        the_program(proc_ind, log_interval, db_source_name, gre_offset, log_client_hello);
    }
    printf("Core %d: PID %d, lcore %d\n", proc_ind, the_pid, core_affinity);
    return the_pid;
}

struct cmd_options
{
    // Number of cores to spread across.
    uint8_t         cpu_procs;

    // An integer that works as a handle to a PF_RING "cluster". These don't
    // need to be allocated or whatever; just pick one to pass as the -c arg to
    // zbalance_ipc, and pass the same one as the -c of this program. Can be
    // 1, 99, probably whatever.
    unsigned int    cluster_id;
    unsigned int    cluster_queue_offset;

    // Instead of starting at core 0 to core $cpu_procs, we'll do core
    // $core_affinity_offset to core $core_affinity_offset+$cpu_procs.
    // This allows us to run debug/production pf_rings on different cores
    // entirely (which rust likes), and with different cluster_ids.
    uint8_t         core_affinity_offset;

    // In seconds, interval between logging of bandwidth, tag checks/s, etc.
    unsigned int    log_interval;
    int             skip_core;    // -1 if not skipping any core, otherwise the core to skip

    char*           db_source_name; // DSN for SQL database

    size_t          gre_offset; // Offset to drop packet headers (GRE, ERSPAN, etc)
    size_t          log_client_hello; // Rate of logging of ClientHello packets to PCAP 0 is no logging 100 is full
};

void parse_cmd_args(int argc, char* argv[], struct cmd_options* options)
{
    // Defaults, development
    int32_t cpu_procs_i32 = 1; // struct member is a u8! catch overflow!
    options->cluster_id = 987654321;
    options->core_affinity_offset = 0;
    options->log_interval = 1000; // milliseconds
    options->gre_offset = 0;
    options->log_client_hello = 0;
    int skip_core = -1; // If >0, skip this core when incrementing

    char c;
    while ((c = getopt(argc,argv,"n:m:c:d:o:l:s:g:p:")) != -1)
    {
        switch (c)
        {
            case 'm':
                options->cluster_queue_offset = atoi(optarg);
                break;
            case 'n':
                cpu_procs_i32 = atoi(optarg);
                break;
            case 'd':
                options->db_source_name = optarg;
                break;
            case 'c':
                options->cluster_id = atoi(optarg);
                break;
            case 'o':
                options->core_affinity_offset = atoi(optarg);
                break;
            case 'l':
                options->log_interval = 1000*atoi(optarg);
                break;
            case 's':
                skip_core = atoi(optarg);
                break;
            case 'g':
		        options->gre_offset = atoi(optarg);
		        break;
            case 'p':
                options->log_client_hello = atoi(optarg);
                break;
            default:
                fprintf(stderr, "Unknown option %c\n", c);
                break;
        }
    }
    if (options->cluster_id == 987654321)
    {
        fprintf(stderr, "Error: required -c cluster_id\n");
        exit(-1);
    }

    int last_core_id_requested = (options->core_affinity_offset +
                                 cpu_procs_i32) - 1;
    if (skip_core > 0) last_core_id_requested++;
    if (last_core_id_requested >= MAX_NUM_FORKED_PROCS)
    {
        fprintf(stderr,
            "Error: highest requested core ID %d is too high of a core ID to\n"
            "ask for. This program can only use 0 through %d inclusive (even\n"
            "if your machine has more).\n",
            last_core_id_requested, MAX_NUM_FORKED_PROCS-1);
        if(options->core_affinity_offset != 0)
        {
            fprintf(stderr, "Hint: you specified a non-zero core offset (-o).\n"
                            "Try again without that argument.\n");
        }
        exit(-1);
    }
    int cores_online = get_nprocs_conf();
    if(last_core_id_requested >= cores_online)
    {
        fprintf(stderr,
            "Error: highest requested core ID %d is beyond the range of core\n"
            "IDs currently available on this machine. Cores 0 to %d inclusive\n"
            "are available.\n", last_core_id_requested, cores_online - 1);
        if(options->core_affinity_offset != 0)
        {
            fprintf(stderr, "Hint: you specified a non-zero core offset (-o).\n"
                            "Try again without that argument.\n");
        }
        exit(-1);
    }
    options->cpu_procs = cpu_procs_i32;
    options->skip_core = skip_core;
}

int main(int argc, char* argv[]) {
    struct cmd_options options;
    parse_cmd_args(argc, argv, &options);

    g_num_worker_procs = options.cpu_procs;

    int i;
    int core_num = options.core_affinity_offset;
    for (i=0; i<g_num_worker_procs; i++)
    {
        printf("Starting process %d...\n", i);

        if (core_num == options.skip_core) core_num++;
        g_forked_pids[i] = start_process(core_num, options.cluster_id, i,
            options.log_interval, options.db_source_name, options.cluster_queue_offset, options.gre_offset, options.log_client_hello);
        core_num++;
    }
    signal(SIGINT, sigproc_parent);
    signal(SIGTERM, sigproc_parent);

    int wait_status = 0, wait_ret = 0, wait_errno = 0;
    for(i=0; i<g_num_worker_procs; i++)
    {
        do
        {
            wait_ret = waitpid(g_forked_pids[i], &wait_status, 0);
            wait_errno = errno;
            if (wait_ret == -1 && wait_errno != EINTR)
                perror("waitpid");
        } while (wait_ret == -1 && wait_errno == EINTR);

        printf("child proc %d ", i);
        if (WIFEXITED(wait_status))
            printf("exited, status=%d\n", WEXITSTATUS(wait_status));
        else if (WIFSIGNALED(wait_status))
            printf("killed by signal %d\n", WTERMSIG(wait_status));
        else if (WIFSTOPPED(wait_status))
            printf("stopped by signal %d\n", WSTOPSIG(wait_status));
        else if (WIFCONTINUED(wait_status))
            printf("continued\n");
        else
            printf("...not sure what happened!\n");
    }
    sigproc_parent(SIGTERM);
    return 0;
}
