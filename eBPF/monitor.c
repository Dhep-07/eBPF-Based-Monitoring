// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/utsname.h>
#include <net/if.h>
#include <gelf.h>
#include <libelf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sqlite3.h>

#include "monitor.skel.h"
#include "sampler.h"

#define TASK_COMM_LEN 16
#define EVENT_NCCL_AR 1
#define EVENT_CUDA_DEV_SYNC 2
#define EVENT_CUDA_STR_SYNC 3
#define EVENT_CU_CTX_SYNC 4

struct collective_event {
    unsigned long long start_ns;
    unsigned long long end_ns;
    unsigned long long host_call_ns;
    unsigned long long cgroup_id;
    unsigned long long count;
    unsigned long long comm_ptr;
    unsigned long long seq_num;
    unsigned int pid;
    unsigned int tid;
    unsigned int type;
    unsigned int datatype;
    char comm[TASK_COMM_LEN];
};

struct agg_counters {
    unsigned long long vic_cpu_switches;
    unsigned long long sys_cpu_switches;
    unsigned long long vic_preempt_ns;
    unsigned long long vic_runnable_wait_ns;
    unsigned long long vic_tcp_send_bytes;
    unsigned long long vic_tcp_send_calls;
    unsigned long long sys_net_xmit_pkts;
    unsigned long long sys_net_xmit_bytes;
    unsigned long long sys_tcp_retrans;
    unsigned long long vic_disk_reqs;
    unsigned long long sys_disk_reqs;
    unsigned long long vic_mem_allocs;
    unsigned long long sys_mem_allocs;
    unsigned long long ringbuf_drops;
    unsigned long long sys_disk_rd_bytes;
    unsigned long long sys_disk_wr_bytes;
    unsigned long long vic_disk_rd_bytes;
    unsigned long long vic_disk_wr_bytes;
    unsigned long long vic_cuda_launches;
    unsigned long long vic_cuda_memcpys;
};

struct monitor_cfg {
    unsigned long long target_cgroup_id;
    int target_ifindex;
    int system_only_mode;
};

struct psi_totals {
    unsigned long long cpu_some_us;
    unsigned long long io_some_us;
    unsigned long long io_full_us;
    unsigned long long mem_some_us;
    unsigned long long mem_full_us;
};

static volatile int exiting = 0;
static sqlite3 *db = NULL;
static sqlite3_stmt *stmt_win = NULL;
static sqlite3_stmt *stmt_col = NULL;
static sqlite3_stmt *stmt_clk = NULL;
static sqlite3_stmt *stmt_sys = NULL;
static sqlite3_stmt *stmt_gpu = NULL;
static long long mono_to_real_offset_ns = 0;
static unsigned long long sqlite_step_errors = 0;

static void sig_handler(int sig)
{
    (void)sig;
    exiting = 1;
}

static unsigned long long get_time_ns(clockid_t clk)
{
    struct timespec ts;
    clock_gettime(clk, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ULL + (unsigned long long)ts.tv_nsec;
}

/* Sandwich sample: MONO -> REAL -> MONO */
static void sample_clock_sandwich(long long *offset_out, unsigned long long *uncertainty_out,
                                  unsigned long long *mono_mid_out, unsigned long long *real_out)
{
    unsigned long long m1 = get_time_ns(CLOCK_MONOTONIC);
    unsigned long long r  = get_time_ns(CLOCK_REALTIME);
    unsigned long long m2 = get_time_ns(CLOCK_MONOTONIC);
    unsigned long long mid = m1 + (m2 - m1) / 2;
    *offset_out = (long long)(r - mid);
    *uncertainty_out = (m2 - m1) / 2;
    *mono_mid_out = mid;
    *real_out = r;
}

static void read_psi_file(const char *path, unsigned long long *some_us, unsigned long long *full_us)
{
    *some_us = 0;
    if (full_us)
        *full_us = 0;
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return;
    char buf[512];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return;
    buf[n] = '\0';

    char *p = strstr(buf, "some ");
    if (p) {
        char *t = strstr(p, "total=");
        if (t)
            *some_us = strtoull(t + 6, NULL, 10);
    }
    if (full_us) {
        p = strstr(buf, "full ");
        if (p) {
            char *t = strstr(p, "total=");
            if (t)
                *full_us = strtoull(t + 6, NULL, 10);
        }
    }
}

static void sample_psi(struct psi_totals *psi)
{
    read_psi_file("/proc/pressure/cpu", &psi->cpu_some_us, NULL);
    read_psi_file("/proc/pressure/io", &psi->io_some_us, &psi->io_full_us);
    read_psi_file("/proc/pressure/memory", &psi->mem_some_us, &psi->mem_full_us);
}

static void record_meta_kv(const char *k, const char *v)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "INSERT INTO run_meta (key, val) VALUES (?, ?);", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, k, -1, SQLITE_STATIC);
        sqlite3_bind_text(st, 2, v, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) != SQLITE_DONE)
            sqlite_step_errors++;
        sqlite3_finalize(st);
    }
}

static void capture_cmd_meta(const char *key, const char *cmd)
{
    FILE *fp = popen(cmd, "r");
    if (!fp)
        return;
    char buf[2048];
    size_t total = fread(buf, 1, sizeof(buf) - 1, fp);
    buf[total] = '\0';
    pclose(fp);
    record_meta_kv(key, buf);
}

static long get_elf_func_offset(const char *path, const char *func_name)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    if (elf_version(EV_CURRENT) == EV_NONE) {
        close(fd);
        return -1;
    }
    Elf *e = elf_begin(fd, ELF_C_READ, NULL);
    if (!e) {
        close(fd);
        return -1;
    }

    Elf_Scn *scn = NULL;
    GElf_Shdr shdr;
    long offset = -1;

    while ((scn = elf_nextscn(e, scn)) != NULL) {
        if (gelf_getshdr(scn, &shdr) != &shdr)
            continue;
        if (shdr.sh_type != SHT_DYNSYM && shdr.sh_type != SHT_SYMTAB)
            continue;

        Elf_Data *data = elf_getdata(scn, NULL);
        if (!data || shdr.sh_entsize == 0)
            continue;

        int count = shdr.sh_size / shdr.sh_entsize;
        for (int i = 0; i < count; i++) {
            GElf_Sym sym;
            if (!gelf_getsym(data, i, &sym))
                continue;
            const char *name = elf_strptr(e, shdr.sh_link, sym.st_name);
            if (name && strcmp(name, func_name) == 0 && sym.st_value != 0) {
                size_t phnum = 0;
                elf_getphdrnum(e, &phnum);
                for (size_t p = 0; p < phnum; p++) {
                    GElf_Phdr phdr;
                    if (!gelf_getphdr(e, p, &phdr))
                        continue;
                    if (phdr.p_type == PT_LOAD &&
                        sym.st_value >= phdr.p_vaddr &&
                        sym.st_value < phdr.p_vaddr + phdr.p_memsz) {
                        offset = (long)(sym.st_value - phdr.p_vaddr + phdr.p_offset);
                        break;
                    }
                }
                if (offset < 0)
                    offset = (long)sym.st_value;
                break;
            }
        }
        if (offset >= 0)
            break;
    }

    elf_end(e);
    close(fd);
    return offset;
}

static void check_link(struct bpf_link *link, const char *name)
{
    long err = libbpf_get_error(link);
    if (err != 0 || !link) {
        fprintf(stderr, "FATAL: Failed to attach BPF program '%s' (err=%ld)\n", name, err);
        exit(1);
    }
}

static int init_db(const char *path)
{
    /* Remove stale database files so runs never mix */
    unlink(path);
    char wal_path[512], shm_path[512];
    snprintf(wal_path, sizeof(wal_path), "%s-wal", path);
    snprintf(shm_path, sizeof(shm_path), "%s-shm", path);
    unlink(wal_path);
    unlink(shm_path);

    if (sqlite3_open(path, &db) != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    /* Use MEMORY journal & synchronous=OFF on /dev/shm so no external -wal files exist */
    sqlite3_exec(db, "PRAGMA journal_mode=MEMORY; PRAGMA synchronous=OFF;", NULL, NULL, NULL);

    const char *schema =
        "CREATE TABLE run_meta ("
        "  key TEXT NOT NULL,"
        "  val TEXT NOT NULL"
        ");"
        "CREATE TABLE clock_sync ("
        "  ts_mono_ns INTEGER NOT NULL,"
        "  ts_real_ns INTEGER NOT NULL,"
        "  mono_to_real_offset_ns INTEGER NOT NULL,"
        "  uncertainty_ns INTEGER NOT NULL"
        ");"
        "CREATE TABLE window_metrics ("
        "  ts_mono_ns INTEGER NOT NULL,"
        "  ts_real_ns INTEGER NOT NULL,"
        "  dt_ns INTEGER NOT NULL,"
        "  vic_cpu_sw INTEGER, sys_cpu_sw INTEGER,"
        "  vic_preempt_ns INTEGER, vic_runnable_wait_ns INTEGER,"
        "  vic_tcp_bytes INTEGER, vic_tcp_calls INTEGER,"
        "  sys_net_xmit_pkts INTEGER, sys_net_xmit_bytes INTEGER, sys_tcp_retrans INTEGER,"
        "  vic_disk_reqs INTEGER, sys_disk_reqs INTEGER,"
        "  vic_mem_allocs INTEGER, sys_mem_allocs INTEGER,"
        "  ringbuf_drops INTEGER,"
        "  psi_cpu_some_us INTEGER, psi_io_some_us INTEGER, psi_io_full_us INTEGER,"
        "  psi_mem_some_us INTEGER, psi_mem_full_us INTEGER,"
        "  sys_disk_rd_bytes INTEGER, sys_disk_wr_bytes INTEGER,"
        "  vic_disk_rd_bytes INTEGER, vic_disk_wr_bytes INTEGER,"
        "  vic_cuda_launches INTEGER, vic_cuda_memcpys INTEGER"
        ");"
        "CREATE TABLE system_metrics ("
        "  ts_mono_ns INTEGER NOT NULL,"
        "  ts_real_ns INTEGER NOT NULL,"
        "  cpu_util_pct REAL,"
        "  cpu_temp_mc INTEGER,"
        "  mem_total_kb INTEGER, mem_avail_kb INTEGER, mem_free_kb INTEGER, cached_kb INTEGER,"
        "  swap_total_kb INTEGER, swap_free_kb INTEGER"
        ");"
        "CREATE TABLE gpu_metrics ("
        "  ts_mono_ns INTEGER NOT NULL,"
        "  ts_real_ns INTEGER NOT NULL,"
        "  gpu_index INTEGER NOT NULL,"
        "  util_gpu_pct INTEGER, util_mem_pct INTEGER,"
        "  temp_c INTEGER, power_mw INTEGER,"
        "  mem_used_bytes INTEGER, mem_total_bytes INTEGER"
        ");"
        "CREATE TABLE collectives ("
        "  start_mono_ns INTEGER NOT NULL,"
        "  end_mono_ns INTEGER NOT NULL,"
        "  start_real_ns INTEGER NOT NULL,"
        "  end_real_ns INTEGER NOT NULL,"
        "  host_call_ns INTEGER NOT NULL,"
        "  seq_num INTEGER,"
        "  count INTEGER,"
        "  datatype INTEGER,"
        "  comm_ptr INTEGER,"
        "  cgroup_id INTEGER,"
        "  pid INTEGER, tid INTEGER, type TEXT, comm TEXT"
        ");"
        "CREATE INDEX idx_win_ts ON window_metrics(ts_mono_ns);"
        "CREATE INDEX idx_col_start ON collectives(start_mono_ns);"
        "CREATE INDEX idx_sys_ts ON system_metrics(ts_mono_ns);"
        "CREATE INDEX idx_gpu_ts ON gpu_metrics(ts_mono_ns, gpu_index);";

    if (sqlite3_exec(db, schema, NULL, NULL, NULL) != SQLITE_OK) {
        fprintf(stderr, "Schema error: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    if (sqlite3_prepare_v2(db,
        "INSERT INTO window_metrics VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);",
        -1, &stmt_win, NULL) != SQLITE_OK)
        return -1;

    if (sqlite3_prepare_v2(db,
        "INSERT INTO system_metrics VALUES (?,?,?,?,?,?,?,?,?,?);",
        -1, &stmt_sys, NULL) != SQLITE_OK)
        return -1;

    if (sqlite3_prepare_v2(db,
        "INSERT INTO gpu_metrics VALUES (?,?,?,?,?,?,?,?,?);",
        -1, &stmt_gpu, NULL) != SQLITE_OK)
        return -1;

    if (sqlite3_prepare_v2(db,
        "INSERT INTO collectives VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?);",
        -1, &stmt_col, NULL) != SQLITE_OK)
        return -1;

    if (sqlite3_prepare_v2(db,
        "INSERT INTO clock_sync VALUES (?,?,?,?);",
        -1, &stmt_clk, NULL) != SQLITE_OK)
        return -1;

    return 0;
}

static void record_clock_sync_row(void)
{
    long long off = 0;
    unsigned long long unc = 0, mono = 0, real = 0;
    sample_clock_sandwich(&off, &unc, &mono, &real);
    mono_to_real_offset_ns = off;

    sqlite3_bind_int64(stmt_clk, 1, (sqlite3_int64)mono);
    sqlite3_bind_int64(stmt_clk, 2, (sqlite3_int64)real);
    sqlite3_bind_int64(stmt_clk, 3, (sqlite3_int64)off);
    sqlite3_bind_int64(stmt_clk, 4, (sqlite3_int64)unc);
    if (sqlite3_step(stmt_clk) != SQLITE_DONE)
        sqlite_step_errors++;
    sqlite3_reset(stmt_clk);
}

static int handle_event(void *ctx, void *data, size_t size)
{
    (void)ctx;
    if (size < sizeof(struct collective_event))
        return 0;

    struct collective_event *e = data;
    const char *tname = "unknown";
    if (e->type == EVENT_NCCL_AR) tname = "ncclAllReduce";
    else if (e->type == EVENT_CUDA_DEV_SYNC) tname = "cudaDeviceSynchronize";
    else if (e->type == EVENT_CUDA_STR_SYNC) tname = "cudaStreamSynchronize";
    else if (e->type == EVENT_CU_CTX_SYNC) tname = "cuCtxSynchronize";

    sqlite3_bind_int64(stmt_col, 1, (sqlite3_int64)e->start_ns);
    sqlite3_bind_int64(stmt_col, 2, (sqlite3_int64)e->end_ns);
    sqlite3_bind_int64(stmt_col, 3, (sqlite3_int64)(e->start_ns + mono_to_real_offset_ns));
    sqlite3_bind_int64(stmt_col, 4, (sqlite3_int64)(e->end_ns + mono_to_real_offset_ns));
    sqlite3_bind_int64(stmt_col, 5, (sqlite3_int64)e->host_call_ns);
    sqlite3_bind_int64(stmt_col, 6, (sqlite3_int64)e->seq_num);
    sqlite3_bind_int64(stmt_col, 7, (sqlite3_int64)e->count);
    sqlite3_bind_int(stmt_col, 8, (int)e->datatype);
    sqlite3_bind_int64(stmt_col, 9, (sqlite3_int64)e->comm_ptr);
    sqlite3_bind_int64(stmt_col, 10, (sqlite3_int64)e->cgroup_id);
    sqlite3_bind_int(stmt_col, 11, (int)e->pid);
    sqlite3_bind_int(stmt_col, 12, (int)e->tid);
    sqlite3_bind_text(stmt_col, 13, tname, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt_col, 14, e->comm, -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt_col) != SQLITE_DONE)
        sqlite_step_errors++;
    sqlite3_reset(stmt_col);
    return 0;
}

static void sum_percpu_stats(int map_fd, int ncpus, struct agg_counters *percpu_buf, struct agg_counters *total)
{
    unsigned int zero = 0;
    memset(total, 0, sizeof(*total));
    if (bpf_map_lookup_elem(map_fd, &zero, percpu_buf) != 0)
        return;

    for (int i = 0; i < ncpus; i++) {
        total->vic_cpu_switches     += percpu_buf[i].vic_cpu_switches;
        total->sys_cpu_switches     += percpu_buf[i].sys_cpu_switches;
        total->vic_preempt_ns       += percpu_buf[i].vic_preempt_ns;
        total->vic_runnable_wait_ns += percpu_buf[i].vic_runnable_wait_ns;
        total->vic_tcp_send_bytes   += percpu_buf[i].vic_tcp_send_bytes;
        total->vic_tcp_send_calls   += percpu_buf[i].vic_tcp_send_calls;
        total->sys_net_xmit_pkts    += percpu_buf[i].sys_net_xmit_pkts;
        total->sys_net_xmit_bytes   += percpu_buf[i].sys_net_xmit_bytes;
        total->sys_tcp_retrans      += percpu_buf[i].sys_tcp_retrans;
        total->vic_disk_reqs        += percpu_buf[i].vic_disk_reqs;
        total->sys_disk_reqs        += percpu_buf[i].sys_disk_reqs;
        total->vic_mem_allocs       += percpu_buf[i].vic_mem_allocs;
        total->sys_mem_allocs       += percpu_buf[i].sys_mem_allocs;
        total->ringbuf_drops        += percpu_buf[i].ringbuf_drops;
        total->sys_disk_rd_bytes    += percpu_buf[i].sys_disk_rd_bytes;
        total->sys_disk_wr_bytes    += percpu_buf[i].sys_disk_wr_bytes;
        total->vic_disk_rd_bytes    += percpu_buf[i].vic_disk_rd_bytes;
        total->vic_disk_wr_bytes    += percpu_buf[i].vic_disk_wr_bytes;
        total->vic_cuda_launches    += percpu_buf[i].vic_cuda_launches;
        total->vic_cuda_memcpys     += percpu_buf[i].vic_cuda_memcpys;
    }
}

static void record_system_and_gpu(unsigned long long mono, unsigned long long real)
{
    struct sys_sample s;
    sampler_sample_sys(&s);
    sqlite3_bind_int64(stmt_sys, 1, (sqlite3_int64)mono);
    sqlite3_bind_int64(stmt_sys, 2, (sqlite3_int64)real);
    sqlite3_bind_double(stmt_sys, 3, s.cpu_util_pct);
    sqlite3_bind_int64(stmt_sys, 4, (sqlite3_int64)s.cpu_temp_mc);
    sqlite3_bind_int64(stmt_sys, 5, (sqlite3_int64)s.mem_total_kb);
    sqlite3_bind_int64(stmt_sys, 6, (sqlite3_int64)s.mem_avail_kb);
    sqlite3_bind_int64(stmt_sys, 7, (sqlite3_int64)s.mem_free_kb);
    sqlite3_bind_int64(stmt_sys, 8, (sqlite3_int64)s.cached_kb);
    sqlite3_bind_int64(stmt_sys, 9, (sqlite3_int64)s.swap_total_kb);
    sqlite3_bind_int64(stmt_sys, 10, (sqlite3_int64)s.swap_free_kb);
    if (sqlite3_step(stmt_sys) != SQLITE_DONE)
        sqlite_step_errors++;
    sqlite3_reset(stmt_sys);

    struct gpu_sample g[MAX_GPUS];
    int n = sampler_sample_gpus(g, MAX_GPUS);
    for (int i = 0; i < n; i++) {
        sqlite3_bind_int64(stmt_gpu, 1, (sqlite3_int64)mono);
        sqlite3_bind_int64(stmt_gpu, 2, (sqlite3_int64)real);
        sqlite3_bind_int(stmt_gpu, 3, g[i].index);
        sqlite3_bind_int(stmt_gpu, 4, (int)g[i].util_gpu_pct);
        sqlite3_bind_int(stmt_gpu, 5, (int)g[i].util_mem_pct);
        sqlite3_bind_int(stmt_gpu, 6, (int)g[i].temp_c);
        sqlite3_bind_int(stmt_gpu, 7, (int)g[i].power_mw);
        sqlite3_bind_int64(stmt_gpu, 8, (sqlite3_int64)g[i].mem_used_bytes);
        sqlite3_bind_int64(stmt_gpu, 9, (sqlite3_int64)g[i].mem_total_bytes);
        if (sqlite3_step(stmt_gpu) != SQLITE_DONE)
            sqlite_step_errors++;
        sqlite3_reset(stmt_gpu);
    }
}

static unsigned long long env_ull(const char *name, unsigned long long def)
{
    const char *v = getenv(name);
    if (!v || !*v)
        return def;
    unsigned long long x = strtoull(v, NULL, 10);
    return x ? x : def;
}

static unsigned long long db_size_bytes(void)
{
    sqlite3_stmt *st = NULL;
    unsigned long long sz = 0;
    if (sqlite3_prepare_v2(db, "SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size();",
                           -1, &st, NULL) == SQLITE_OK) {
        if (sqlite3_step(st) == SQLITE_ROW)
            sz = (unsigned long long)sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
    }
    return sz;
}

int main(int argc, char **argv)
{
    /* Usage: sudo ./monitor <db_path> <target_cgroup_inode | --system-only> [ifname] [nccl_so] [cudart_so] [cuda_drv_so] */
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <db_path> <target_cgroup_inode | --system-only> [ifname] [nccl_so] [cudart_so] [cuda_drv_so]\n", argv[0]);
        return 1;
    }

    const char *db_path = argv[1];
    int system_only = (strcmp(argv[2], "--system-only") == 0) ? 1 : 0;
    unsigned long long target_cg = system_only ? 0 : strtoull(argv[2], NULL, 10);

    if (!system_only && target_cg == 0) {
        fprintf(stderr, "ERROR: target_cgroup_inode cannot be 0 (pass --system-only for standalone smoke tests).\n");
        return 1;
    }

    const char *ifname = argc > 3 ? argv[3] : "eno1";
    const char *nccl_so = argc > 4 ? argv[4] :
        "/home/iot/nccl-eye-venv/lib/python3.10/site-packages/nvidia/nccl/lib/libnccl.so.2";
    const char *cudart_so = argc > 5 ? argv[5] :
        "/home/iot/nccl-eye-venv/lib/python3.10/site-packages/nvidia/cuda_runtime/lib/libcudart.so.12";
    const char *cuda_drv_so = argc > 6 ? argv[6] :
        "/usr/lib/x86_64-linux-gnu/libcuda.so.1";

    int ifindex = (int)if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "WARNING: Interface '%s' not found; NIC filter disabled.\n", ifname);
    }

    int ncpus = libbpf_num_possible_cpus();
    if (ncpus <= 0) {
        fprintf(stderr, "Failed to query possible CPUs\n");
        return 1;
    }
    struct agg_counters *percpu_buf = calloc((size_t)ncpus, sizeof(struct agg_counters));
    if (!percpu_buf)
        return 1;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    if (init_db(db_path) < 0)
        return 1;

    struct utsname uts;
    if (uname(&uts) == 0) {
        record_meta_kv("hostname", uts.nodename);
        record_meta_kv("kernel", uts.release);
    }
    record_meta_kv("ifname", ifname);
    capture_cmd_meta("chrony_start", "chronyc tracking 2>&1");

    record_clock_sync_row();

    struct monitor_bpf *skel = monitor_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    unsigned int zero = 0;
    struct monitor_cfg cfg = {
        .target_cgroup_id = target_cg,
        .target_ifindex = ifindex,
        .system_only_mode = system_only,
    };
    if (bpf_map_update_elem(bpf_map__fd(skel->maps.cfg_map), &zero, &cfg, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to update cfg_map\n");
        return 1;
    }

    /* Attach and strictly check kernel tracepoints and kprobes */
    skel->links.trace_schedule = bpf_program__attach(skel->progs.trace_schedule);
    check_link(skel->links.trace_schedule, "trace_schedule");

    skel->links.trace_tcp_send = bpf_program__attach(skel->progs.trace_tcp_send);
    check_link(skel->links.trace_tcp_send, "trace_tcp_send");

    skel->links.trace_net_xmit = bpf_program__attach(skel->progs.trace_net_xmit);
    check_link(skel->links.trace_net_xmit, "trace_net_xmit");

    skel->links.trace_tcp_retrans = bpf_program__attach(skel->progs.trace_tcp_retrans);
    check_link(skel->links.trace_tcp_retrans, "trace_tcp_retrans");

    skel->links.trace_disk_issue = bpf_program__attach(skel->progs.trace_disk_issue);
    check_link(skel->links.trace_disk_issue, "trace_disk_issue");

    skel->links.trace_page_alloc = bpf_program__attach(skel->progs.trace_page_alloc);
    check_link(skel->links.trace_page_alloc, "trace_page_alloc");

    /* Attach and check userspace uprobes */
    long nccl_off = get_elf_func_offset(nccl_so, "ncclAllReduce");
    if (nccl_off > 0) {
        skel->links.uprobe_nccl_enter = bpf_program__attach_uprobe(
            skel->progs.uprobe_nccl_enter, false, -1, nccl_so, (size_t)nccl_off);
        check_link(skel->links.uprobe_nccl_enter, "uprobe_nccl_enter");
        skel->links.uretprobe_nccl_exit = bpf_program__attach_uprobe(
            skel->progs.uretprobe_nccl_exit, true, -1, nccl_so, (size_t)nccl_off);
        check_link(skel->links.uretprobe_nccl_exit, "uretprobe_nccl_exit");
    } else {
        fprintf(stderr, "FATAL: Could not resolve ncclAllReduce in %s\n", nccl_so);
        return 1;
    }

    long dsync_off = get_elf_func_offset(cudart_so, "cudaDeviceSynchronize");
    if (dsync_off > 0) {
        skel->links.uprobe_dev_sync_enter = bpf_program__attach_uprobe(
            skel->progs.uprobe_dev_sync_enter, false, -1, cudart_so, (size_t)dsync_off);
        check_link(skel->links.uprobe_dev_sync_enter, "uprobe_dev_sync_enter");
        skel->links.uretprobe_dev_sync_exit = bpf_program__attach_uprobe(
            skel->progs.uretprobe_dev_sync_exit, true, -1, cudart_so, (size_t)dsync_off);
        check_link(skel->links.uretprobe_dev_sync_exit, "uretprobe_dev_sync_exit");
    }

    long ssync_off = get_elf_func_offset(cudart_so, "cudaStreamSynchronize");
    if (ssync_off > 0) {
        skel->links.uprobe_str_sync_enter = bpf_program__attach_uprobe(
            skel->progs.uprobe_str_sync_enter, false, -1, cudart_so, (size_t)ssync_off);
        check_link(skel->links.uprobe_str_sync_enter, "uprobe_str_sync_enter");
        skel->links.uretprobe_str_sync_exit = bpf_program__attach_uprobe(
            skel->progs.uretprobe_str_sync_exit, true, -1, cudart_so, (size_t)ssync_off);
        check_link(skel->links.uretprobe_str_sync_exit, "uretprobe_str_sync_exit");
    }

    long launch_off = get_elf_func_offset(cudart_so, "cudaLaunchKernel");
    if (launch_off > 0) {
        skel->links.uprobe_cuda_launch = bpf_program__attach_uprobe(
            skel->progs.uprobe_cuda_launch, false, -1, cudart_so, (size_t)launch_off);
        check_link(skel->links.uprobe_cuda_launch, "uprobe_cuda_launch");
    }

    long memcpy_off = get_elf_func_offset(cudart_so, "cudaMemcpyAsync");
    if (memcpy_off > 0) {
        skel->links.uprobe_cuda_memcpy = bpf_program__attach_uprobe(
            skel->progs.uprobe_cuda_memcpy, false, -1, cudart_so, (size_t)memcpy_off);
        check_link(skel->links.uprobe_cuda_memcpy, "uprobe_cuda_memcpy");
    }

    long csync_off = get_elf_func_offset(cuda_drv_so, "cuCtxSynchronize");
    if (csync_off > 0) {
        skel->links.uprobe_ctx_sync_enter = bpf_program__attach_uprobe(
            skel->progs.uprobe_ctx_sync_enter, false, -1, cuda_drv_so, (size_t)csync_off);
        check_link(skel->links.uprobe_ctx_sync_enter, "uprobe_ctx_sync_enter");
        skel->links.uretprobe_ctx_sync_exit = bpf_program__attach_uprobe(
            skel->progs.uretprobe_ctx_sync_exit, true, -1, cuda_drv_so, (size_t)csync_off);
        check_link(skel->links.uretprobe_ctx_sync_exit, "uretprobe_ctx_sync_exit");
    }

    struct ring_buffer *rb = ring_buffer__new(
        bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "FATAL: Failed to create BPF ring buffer\n");
        return 1;
    }

    printf("NCCL-Eye Monitor active | DB: %s | Cgroup: %llu (sys_only=%d) | IF: %s (idx=%d) | CPUs: %d\n",
           db_path, target_cg, system_only, ifname, ifindex, ncpus);

    struct agg_counters prev = {0}, curr = {0};
    struct psi_totals psi_prev = {0}, psi_curr = {0};
    int stats_fd = bpf_map__fd(skel->maps.stats_map);

    unsigned long long win_interval_ns = env_ull("WIN_MS", 100) * 1000000ULL;
    unsigned long long max_db_bytes = env_ull("MAX_DB_MB", 256) * 1024ULL * 1024ULL;
    printf("Sampling: window=%llu ms, sensors=%llu ms, db cap=%llu MB\n",
           win_interval_ns / 1000000ULL, env_ull("SYS_MS", 1000), max_db_bytes >> 20);
    unsigned long long commit_interval_ns = 1000000000ULL; /* 1 s commit & clock sync */
    unsigned long long prev_win_mono = get_time_ns(CLOCK_MONOTONIC);
    unsigned long long next_win_mono = prev_win_mono + win_interval_ns;
    unsigned long long last_commit_mono = prev_win_mono;

    unsigned long long sys_interval_ns = env_ull("SYS_MS", 1000) * 1000000ULL;
    unsigned long long next_sys_mono = prev_win_mono;

    int ngpu = sampler_init();
    printf("Sampler: %d NVIDIA GPU(s) via NVML\n", ngpu);
    if (ngpu == 0)
        fprintf(stderr, "WARNING: no NVML GPUs found; gpu_metrics will be empty.\n");

    sum_percpu_stats(stats_fd, ncpus, percpu_buf, &prev);
    sample_psi(&psi_prev);

    sqlite3_exec(db, "BEGIN TRANSACTION;", NULL, NULL, NULL);

    while (!exiting) {
        unsigned long long now_mono = get_time_ns(CLOCK_MONOTONIC);
        int timeout_ms = 0;
        if (next_win_mono > now_mono) {
            timeout_ms = (int)((next_win_mono - now_mono) / 1000000ULL);
            if (timeout_ms < 1)
                timeout_ms = 1;
        }

        int err = ring_buffer__poll(rb, timeout_ms);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Ring buffer poll error: %d\n", err);
            break;
        }

        now_mono = get_time_ns(CLOCK_MONOTONIC);
        if (now_mono >= next_win_mono) {
            unsigned long long dt_ns = now_mono - prev_win_mono;
            unsigned long long now_real = (unsigned long long)((long long)now_mono + mono_to_real_offset_ns);

            sum_percpu_stats(stats_fd, ncpus, percpu_buf, &curr);
            sample_psi(&psi_curr);

            sqlite3_bind_int64(stmt_win, 1, (sqlite3_int64)now_mono);
            sqlite3_bind_int64(stmt_win, 2, (sqlite3_int64)now_real);
            sqlite3_bind_int64(stmt_win, 3, (sqlite3_int64)dt_ns);
            sqlite3_bind_int64(stmt_win, 4, (sqlite3_int64)(curr.vic_cpu_switches - prev.vic_cpu_switches));
            sqlite3_bind_int64(stmt_win, 5, (sqlite3_int64)(curr.sys_cpu_switches - prev.sys_cpu_switches));
            sqlite3_bind_int64(stmt_win, 6, (sqlite3_int64)(curr.vic_preempt_ns - prev.vic_preempt_ns));
            sqlite3_bind_int64(stmt_win, 7, (sqlite3_int64)(curr.vic_runnable_wait_ns - prev.vic_runnable_wait_ns));
            sqlite3_bind_int64(stmt_win, 8, (sqlite3_int64)(curr.vic_tcp_send_bytes - prev.vic_tcp_send_bytes));
            sqlite3_bind_int64(stmt_win, 9, (sqlite3_int64)(curr.vic_tcp_send_calls - prev.vic_tcp_send_calls));
            sqlite3_bind_int64(stmt_win, 10, (sqlite3_int64)(curr.sys_net_xmit_pkts - prev.sys_net_xmit_pkts));
            sqlite3_bind_int64(stmt_win, 11, (sqlite3_int64)(curr.sys_net_xmit_bytes - prev.sys_net_xmit_bytes));
            sqlite3_bind_int64(stmt_win, 12, (sqlite3_int64)(curr.sys_tcp_retrans - prev.sys_tcp_retrans));
            sqlite3_bind_int64(stmt_win, 13, (sqlite3_int64)(curr.vic_disk_reqs - prev.vic_disk_reqs));
            sqlite3_bind_int64(stmt_win, 14, (sqlite3_int64)(curr.sys_disk_reqs - prev.sys_disk_reqs));
            sqlite3_bind_int64(stmt_win, 15, (sqlite3_int64)(curr.vic_mem_allocs - prev.vic_mem_allocs));
            sqlite3_bind_int64(stmt_win, 16, (sqlite3_int64)(curr.sys_mem_allocs - prev.sys_mem_allocs));
            sqlite3_bind_int64(stmt_win, 17, (sqlite3_int64)(curr.ringbuf_drops - prev.ringbuf_drops));
            sqlite3_bind_int64(stmt_win, 18, (sqlite3_int64)(psi_curr.cpu_some_us - psi_prev.cpu_some_us));
            sqlite3_bind_int64(stmt_win, 19, (sqlite3_int64)(psi_curr.io_some_us - psi_prev.io_some_us));
            sqlite3_bind_int64(stmt_win, 20, (sqlite3_int64)(psi_curr.io_full_us - psi_prev.io_full_us));
            sqlite3_bind_int64(stmt_win, 21, (sqlite3_int64)(psi_curr.mem_some_us - psi_prev.mem_some_us));
            sqlite3_bind_int64(stmt_win, 22, (sqlite3_int64)(psi_curr.mem_full_us - psi_prev.mem_full_us));
            sqlite3_bind_int64(stmt_win, 23, (sqlite3_int64)(curr.sys_disk_rd_bytes - prev.sys_disk_rd_bytes));
            sqlite3_bind_int64(stmt_win, 24, (sqlite3_int64)(curr.sys_disk_wr_bytes - prev.sys_disk_wr_bytes));
            sqlite3_bind_int64(stmt_win, 25, (sqlite3_int64)(curr.vic_disk_rd_bytes - prev.vic_disk_rd_bytes));
            sqlite3_bind_int64(stmt_win, 26, (sqlite3_int64)(curr.vic_disk_wr_bytes - prev.vic_disk_wr_bytes));
            sqlite3_bind_int64(stmt_win, 27, (sqlite3_int64)(curr.vic_cuda_launches - prev.vic_cuda_launches));
            sqlite3_bind_int64(stmt_win, 28, (sqlite3_int64)(curr.vic_cuda_memcpys - prev.vic_cuda_memcpys));

            if (sqlite3_step(stmt_win) != SQLITE_DONE)
                sqlite_step_errors++;
            sqlite3_reset(stmt_win);

            prev = curr;
            psi_prev = psi_curr;
            prev_win_mono = now_mono;
            while (next_win_mono <= now_mono)
                next_win_mono += win_interval_ns;
        }

        /* Slow sensors (temps, NVML, meminfo): every 200 ms, off the 20 ms hot path */
        if (now_mono >= next_sys_mono) {
            record_system_and_gpu(now_mono,
                (unsigned long long)((long long)now_mono + mono_to_real_offset_ns));
            while (next_sys_mono <= now_mono)
                next_sys_mono += sys_interval_ns;
        }

        if (now_mono - last_commit_mono >= commit_interval_ns) {
            record_clock_sync_row();
            sqlite3_exec(db, "COMMIT; BEGIN TRANSACTION;", NULL, NULL, NULL);
            last_commit_mono = now_mono;
            if (db_size_bytes() >= max_db_bytes) {
                fprintf(stderr, "DB reached cap (%llu MB); stopping cleanly.\n",
                        max_db_bytes >> 20);
                exiting = 1;
            }
        }
    }

    capture_cmd_meta("chrony_end", "chronyc tracking 2>&1");
    char err_buf[64];
    snprintf(err_buf, sizeof(err_buf), "%llu", sqlite_step_errors);
    record_meta_kv("sqlite_step_errors", err_buf);

    sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL);
    ring_buffer__free(rb);
    monitor_bpf__destroy(skel);
    sqlite3_finalize(stmt_win);
    sqlite3_finalize(stmt_col);
    sqlite3_finalize(stmt_clk);
    sqlite3_finalize(stmt_sys);
    sqlite3_finalize(stmt_gpu);
    sampler_close();
    sqlite3_close(db);
    free(percpu_buf);

    printf("\nMonitor stopped cleanly (sqlite_errors=%llu).\n", sqlite_step_errors);
    return 0;
}