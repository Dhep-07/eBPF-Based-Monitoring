// SPDX-License-Identifier: GPL-2.0-only OR MIT
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16

enum event_type {
    EVENT_NCCL_AR = 1,
    EVENT_CUDA_DEV_SYNC = 2,
    EVENT_CUDA_STR_SYNC = 3,
    EVENT_CU_CTX_SYNC = 4,
};

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
};

struct monitor_cfg {
    unsigned long long target_cgroup_id;
    int target_ifindex;
    int system_only_mode;
};

struct uprobe_entry_val {
    unsigned long long start_ns;
    unsigned long long count;
    unsigned long long comm_ptr;
    unsigned int datatype;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, unsigned int);
    __type(value, struct agg_counters);
} stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, unsigned int);
    __type(value, struct monitor_cfg);
} cfg_map SEC(".maps");

struct preempt_val {
    unsigned long long ts_ns;
    int was_preempted;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, unsigned int);
    __type(value, struct preempt_val);
} preempt_ts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2048);
    __type(key, unsigned long long);
    __type(value, struct uprobe_entry_val);
} uprobe_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, unsigned int);
    __type(value, unsigned long long);
} seq_map SEC(".maps");

static __always_inline struct agg_counters *get_stats(void)
{
    unsigned int zero = 0;
    return bpf_map_lookup_elem(&stats_map, &zero);
}

static __always_inline struct monitor_cfg *get_cfg(void)
{
    unsigned int zero = 0;
    return bpf_map_lookup_elem(&cfg_map, &zero);
}

static __always_inline int is_victim_cgroup(void)
{
    struct monitor_cfg *cfg = get_cfg();
    if (!cfg)
        return 0;
    if (cfg->system_only_mode)
        return 1;
    if (cfg->target_cgroup_id == 0)
        return 0;
    return bpf_get_current_cgroup_id() == cfg->target_cgroup_id;
}

/* 1. CPU: Scheduler context switch & involuntary preemption wait */
SEC("tracepoint/sched/sched_switch")
int trace_schedule(struct trace_event_raw_sched_switch *ctx)
{
    struct agg_counters *st = get_stats();
    if (!st)
        return 0;

    unsigned long long now = bpf_ktime_get_ns();
    unsigned int prev_tid = ctx->prev_pid;
    unsigned int next_tid = ctx->next_pid;

    /* sys_cpu_switches counts ALL context switches on the CPU (including victim) */
    st->sys_cpu_switches += 1;

    if (is_victim_cgroup()) {
        st->vic_cpu_switches += 1;
        /* Lower 7 bits == 0 means task is still TASK_RUNNING (yielded R or preempted R+).
         * Bit 0x100 (or 0x80 depending on kernel TASK_REPORT_MAX) marks involuntary preemption (R+). */
        if ((ctx->prev_state & 0x7f) == 0) {
            struct preempt_val pv = {};
            pv.ts_ns = now;
            pv.was_preempted = (ctx->prev_state & 0x180) ? 1 : 0;
            bpf_map_update_elem(&preempt_ts, &prev_tid, &pv, BPF_ANY);
        }
    }

    struct preempt_val *pv = bpf_map_lookup_elem(&preempt_ts, &next_tid);
    if (pv) {
        if (now > pv->ts_ns) {
            unsigned long long delta = now - pv->ts_ns;
            st->vic_runnable_wait_ns += delta;
            if (pv->was_preempted)
                st->vic_preempt_ns += delta;
        }
        bpf_map_delete_elem(&preempt_ts, &next_tid);
    }
    return 0;
}

/* 2. Network: Process-context TCP send (Victim attribution) */
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(trace_tcp_send, struct sock *sk, struct msghdr *msg, size_t size)
{
    if (!is_victim_cgroup())
        return 0;
    struct agg_counters *st = get_stats();
    if (!st)
        return 0;
    st->vic_tcp_send_calls += 1;
    st->vic_tcp_send_bytes += size;
    return 0;
}

/* 3. Network: NIC transmit filtered to target interface (eno1) & TCP Retransmissions */
SEC("tracepoint/net/net_dev_xmit")
int trace_net_xmit(struct trace_event_raw_net_dev_xmit *ctx)
{
    struct monitor_cfg *cfg = get_cfg();
    if (cfg && cfg->target_ifindex > 0) {
        struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
        int ifindex = BPF_CORE_READ(skb, dev, ifindex);
        if (ifindex != cfg->target_ifindex)
            return 0;
    }

    struct agg_counters *st = get_stats();
    if (st) {
        st->sys_net_xmit_pkts += 1;
        st->sys_net_xmit_bytes += ctx->len;
    }
    return 0;
}

SEC("tracepoint/tcp/tcp_retransmit_skb")
int trace_tcp_retrans(void *ctx)
{
    struct agg_counters *st = get_stats();
    if (st)
        st->sys_tcp_retrans += 1;
    return 0;
}

/* 4. Disk: Block I/O requests issued (sys includes victim) */
SEC("tracepoint/block/block_rq_issue")
int trace_disk_issue(void *ctx)
{
    struct agg_counters *st = get_stats();
    if (!st)
        return 0;
    st->sys_disk_reqs += 1;
    if (is_victim_cgroup())
        st->vic_disk_reqs += 1;
    return 0;
}

/* 5. Memory: Page allocations (sys includes victim) */
SEC("tracepoint/kmem/mm_page_alloc")
int trace_page_alloc(void *ctx)
{
    struct agg_counters *st = get_stats();
    if (!st)
        return 0;
    st->sys_mem_allocs += 1;
    if (is_victim_cgroup())
        st->vic_mem_allocs += 1;
    return 0;
}

/* 6. Userspace Uprobes (Victim-filtered) */
static __always_inline int record_uprobe_enter(unsigned int type_id,
                                               unsigned long long count,
                                               unsigned int datatype,
                                               unsigned long long comm_ptr)
{
    if (!is_victim_cgroup())
        return 0;
    unsigned int tid = (unsigned int)bpf_get_current_pid_tgid();
    unsigned long long key = ((unsigned long long)tid) | (((unsigned long long)type_id) << 32);
    struct uprobe_entry_val val = {};
    val.start_ns = bpf_ktime_get_ns();
    val.count = count;
    val.comm_ptr = comm_ptr;
    val.datatype = datatype;
    bpf_map_update_elem(&uprobe_start, &key, &val, BPF_ANY);
    return 0;
}

static __always_inline int record_uprobe_exit(unsigned int type_id)
{
    if (!is_victim_cgroup())
        return 0;
    unsigned long long pid_tgid = bpf_get_current_pid_tgid();
    unsigned int tid = (unsigned int)pid_tgid;
    unsigned long long key = ((unsigned long long)tid) | (((unsigned long long)type_id) << 32);

    struct uprobe_entry_val *val = bpf_map_lookup_elem(&uprobe_start, &key);
    if (!val)
        return 0;

    unsigned long long end_ts = bpf_ktime_get_ns();
    unsigned long long seq = 0;

    if (type_id == EVENT_NCCL_AR) {
        unsigned long long *cur_seq = bpf_map_lookup_elem(&seq_map, &tid);
        if (cur_seq) {
            seq = *cur_seq + 1;
            *cur_seq = seq;
        } else {
            seq = 1;
            bpf_map_update_elem(&seq_map, &tid, &seq, BPF_ANY);
        }
    }

    struct collective_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->start_ns = val->start_ns;
        e->end_ns = end_ts;
        e->host_call_ns = end_ts - val->start_ns;
        e->cgroup_id = bpf_get_current_cgroup_id();
        e->count = val->count;
        e->comm_ptr = val->comm_ptr;
        e->seq_num = seq;
        e->pid = pid_tgid >> 32;
        e->tid = tid;
        e->type = type_id;
        e->datatype = val->datatype;
        bpf_get_current_comm(e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    } else {
        struct agg_counters *st = get_stats();
        if (st)
            st->ringbuf_drops += 1;
    }

    bpf_map_delete_elem(&uprobe_start, &key);
    return 0;
}

/* ncclAllReduce(sendbuff, recvbuff, count, datatype, op, comm, stream) */
SEC("uprobe/ncclAllReduce")
int uprobe_nccl_enter(struct pt_regs *ctx)
{
    unsigned long long count = (unsigned long long)PT_REGS_PARM3(ctx);
    unsigned int datatype = (unsigned int)PT_REGS_PARM4(ctx);
    unsigned long long comm_ptr = (unsigned long long)PT_REGS_PARM6(ctx);
    return record_uprobe_enter(EVENT_NCCL_AR, count, datatype, comm_ptr);
}

SEC("uretprobe/ncclAllReduce")
int uretprobe_nccl_exit(struct pt_regs *ctx)
{
    return record_uprobe_exit(EVENT_NCCL_AR);
}

SEC("uprobe/cudaDeviceSynchronize")
int uprobe_dev_sync_enter(struct pt_regs *ctx)
{
    return record_uprobe_enter(EVENT_CUDA_DEV_SYNC, 0, 0, 0);
}

SEC("uretprobe/cudaDeviceSynchronize")
int uretprobe_dev_sync_exit(struct pt_regs *ctx)
{
    return record_uprobe_exit(EVENT_CUDA_DEV_SYNC);
}

SEC("uprobe/cudaStreamSynchronize")
int uprobe_str_sync_enter(struct pt_regs *ctx)
{
    return record_uprobe_enter(EVENT_CUDA_STR_SYNC, 0, 0, 0);
}

SEC("uretprobe/cudaStreamSynchronize")
int uretprobe_str_sync_exit(struct pt_regs *ctx)
{
    return record_uprobe_exit(EVENT_CUDA_STR_SYNC);
}

SEC("uprobe/cuCtxSynchronize")
int uprobe_ctx_sync_enter(struct pt_regs *ctx)
{
    return record_uprobe_enter(EVENT_CU_CTX_SYNC, 0, 0, 0);
}

SEC("uretprobe/cuCtxSynchronize")
int uretprobe_ctx_sync_exit(struct pt_regs *ctx)
{
    return record_uprobe_exit(EVENT_CU_CTX_SYNC);
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
