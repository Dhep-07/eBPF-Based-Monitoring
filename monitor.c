#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sqlite3.h>

#include "monitor.skel.h"

#define METRIC_CPU 1
#define METRIC_NET 2
#define METRIC_DISK 3
#define METRIC_MEM 4

#define TASK_COMM_LEN 16

struct event {
    unsigned long long timestamp_ns;
    unsigned int pid;
    unsigned int type;
    char comm[TASK_COMM_LEN];
    unsigned long long value;
    unsigned int extra;
};

static volatile int exiting = 0;
static sqlite3 *db = NULL;
static sqlite3_stmt *stmt = NULL;

static void sig_handler(int sig)
{
    exiting = 1;
}

static int init_db(const char *path)
{
    int rc = sqlite3_open(path, &db);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n",
                sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_exec(db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);

    rc = sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS metrics ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "ts INTEGER NOT NULL,"
        "subsystem TEXT NOT NULL,"
        "metric TEXT NOT NULL,"
        "value REAL NOT NULL,"
        "pid INTEGER,"
        "comm TEXT"
        ");",
        NULL, NULL, NULL);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to create table: %s\n",
                sqlite3_errmsg(db));
        return -1;
    }

    rc = sqlite3_prepare_v2(db,
        "INSERT INTO metrics "
        "(ts,subsystem,metric,value,pid,comm) "
        "VALUES (?,?,?,?,?,?);",
        -1, &stmt, NULL);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare SQL: %s\n",
                sqlite3_errmsg(db));
        return -1;
    }

    printf("SQLite database initialized: %s\n", path);
    return 0;
}

static void insert_metric(unsigned long long ts,
                          const char *sub,
                          const char *metric,
                          double value,
                          int pid,
                          const char *comm)
{
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)ts);
    sqlite3_bind_text(stmt, 2, sub, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, metric, -1, SQLITE_TRANSIENT);
    sqlite3_bind_double(stmt, 4, value);
    sqlite3_bind_int(stmt, 5, pid);
    sqlite3_bind_text(stmt, 6, comm, -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_DONE)
        fprintf(stderr, "SQLite insert failed: %s\n",
                sqlite3_errmsg(db));

    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);
}

static int handle_event(void *ctx, void *data, size_t size)
{
    struct event *e = data;

    switch (e->type) {
    case METRIC_CPU:
        printf("CPU  | PID:%-6u | %-16s | Core:%u\n",
               e->pid, e->comm, e->extra);

        insert_metric(e->timestamp_ns,
                      "cpu",
                      "context_switch",
                      1.0,
                      e->pid,
                      e->comm);
        break;

    case METRIC_NET:
        printf("NET  | PID:%-6u | %-16s | TCP send\n",
               e->pid, e->comm);

        insert_metric(e->timestamp_ns,
                      "network",
                      "tcp_send",
                      1.0,
                      e->pid,
                      e->comm);
        break;

    case METRIC_MEM:
        printf("MEM  | PID:%-6u | %-16s | Page alloc\n",
               e->pid, e->comm);

        insert_metric(e->timestamp_ns,
                      "memory",
                      "page_alloc",
                      1.0,
                      e->pid,
                      e->comm);
        break;

    default:
        break;
    }

    return 0;
}

int main(int argc, char **argv)
{
    struct monitor_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    const char *db_path = argc > 1 ? argv[1] : "monitor.db";
    int err = 0;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("=== eBPF Monitor ===\n");
    printf("Database: %s\n", db_path);

    if (init_db(db_path) < 0)
        return 1;

    skel = monitor_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        err = 1;
        goto cleanup;
    }

    err = monitor_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF: %d\n", err);
        goto cleanup;
    }

    err = monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(
        bpf_map__fd(skel->maps.events),
        handle_event,
        NULL,
        NULL);

    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = 1;
        goto cleanup;
    }

    printf("Monitoring... Press Ctrl+C to stop.\n\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);

        if (err == -EINTR) {
            err = 0;
            break;
        }

        if (err < 0) {
            fprintf(stderr, "Ring buffer error: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    monitor_bpf__destroy(skel);
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    printf("\nMonitor stopped.\n");
    return err < 0 ? 1 : err;
}
