#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define TASK_COMM_LEN 16

enum metric_type {
    METRIC_CPU = 1,
    METRIC_NET,
    METRIC_DISK,
    METRIC_MEM,
};

struct event {
    unsigned long long timestamp_ns;
    unsigned int pid;
    unsigned int type;
    char comm[TASK_COMM_LEN];
    unsigned long long value;
    unsigned int extra;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* CPU: scheduler context switch */
SEC("tracepoint/sched/sched_switch")
int trace_schedule(void *ctx)
{
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->type = METRIC_CPU;
    e->value = 1;
    e->extra = bpf_get_smp_processor_id();

    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* Network: packet transmission */
SEC("tracepoint/net/net_dev_xmit")
int trace_net_xmit(void *ctx)
{
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->type = METRIC_NET;
    e->value = 1;
    e->extra = 0;

    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* Disk: request issued */
SEC("tracepoint/block/block_rq_issue")
int trace_disk_issue(void *ctx)
{
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->type = METRIC_DISK;
    e->value = 1;
    e->extra = 0;

    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* Memory: page allocation */
SEC("tracepoint/kmem/mm_page_alloc")
int trace_page_alloc(void *ctx)
{
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->type = METRIC_MEM;
    e->value = 1;
    e->extra = 0;

    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
