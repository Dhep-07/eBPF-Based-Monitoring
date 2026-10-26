// SPDX-License-Identifier: MIT
/* shipper: copies new rows from the local monitor SQLite DB to central Postgres.
 *
 * Usage:  PG_CONNINFO="host=10.0.0.5 dbname=nccl_eye user=ebpf_writer password=..." \
 *         ./shipper /dev/shm/run.db
 *
 * - Resumable: asks Postgres for the last src_rowid it has for this
 *   (machine_ip, run_id) and sends only newer rows. No local state file.
 * - Safe to retry: inserts use ON CONFLICT DO NOTHING.
 * - If Postgres is down, it keeps retrying; the local DB is the buffer.
 * Env: PG_CONNINFO (required), SHIP_SEC (default 5), BATCH_ROWS (default 5000)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sqlite3.h>
#include <libpq-fe.h>

static volatile sig_atomic_t stop_flag = 0;
static void on_sig(int s) { (void)s; stop_flag = 1; }

static const char *TABLES[] = {
    "clock_sync", "window_metrics", "system_metrics", "gpu_metrics", "collectives"
};

static int pg_simple(PGconn *pg, const char *sql)
{
    PGresult *r = PQexec(pg, sql);
    ExecStatusType s = PQresultStatus(r);
    int ok = (s == PGRES_COMMAND_OK || s == PGRES_TUPLES_OK);
    if (!ok)
        fprintf(stderr, "PG error: %s", PQerrorMessage(pg));
    PQclear(r);
    return ok ? 0 : -1;
}

static int get_meta(sqlite3 *db, const char *key, char *out, size_t n)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;
    if (sqlite3_prepare_v2(db, "SELECT val FROM run_meta WHERE key=? LIMIT 1;", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, key, -1, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *v = sqlite3_column_text(st, 0);
        if (v) {
            snprintf(out, n, "%s", (const char *)v);
            rc = 0;
        }
    }
    sqlite3_finalize(st);
    return rc;
}

static long long pg_last_rowid(PGconn *pg, const char *table, const char *ip, const char *run)
{
    char sql[256];
    snprintf(sql, sizeof(sql),
             "SELECT COALESCE(MAX(src_rowid),0) FROM %s WHERE machine_ip=$1::inet AND run_id=$2::bigint", table);
    const char *vals[2] = { ip, run };
    PGresult *r = PQexecParams(pg, sql, 2, NULL, vals, NULL, NULL, 0);
    long long v = -1;
    if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1)
        v = atoll(PQgetvalue(r, 0, 0));
    else
        fprintf(stderr, "PG error (last rowid, %s): %s", table, PQerrorMessage(pg));
    PQclear(r);
    return v;
}

/* Returns rows sent (>=0) or -1 on error */
static long ship_table(PGconn *pg, sqlite3 *db, const char *table,
                       const char *ip, const char *run, int batch)
{
    long long last = pg_last_rowid(pg, table, ip, run);
    if (last < 0)
        return -1;

    char sql[256];
    snprintf(sql, sizeof(sql), "SELECT rowid, * FROM %s WHERE rowid > ? ORDER BY rowid LIMIT %d;", table, batch);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return 0;                         /* table not there yet */
    sqlite3_bind_int64(st, 1, (sqlite3_int64)last);

    int ncols = sqlite3_column_count(st); /* col 0 = rowid */
    int nparams = ncols + 2;              /* machine_ip, run_id + all columns */

    /* INSERT INTO t (machine_ip, run_id, src_rowid, c1, c2, ...) VALUES ($1,$2,$3,$4,...) */
    char ins[4096];
    size_t off = (size_t)snprintf(ins, sizeof(ins), "INSERT INTO %s (machine_ip, run_id, src_rowid", table);
    for (int i = 1; i < ncols; i++)
        off += (size_t)snprintf(ins + off, sizeof(ins) - off, ", %s", sqlite3_column_name(st, i));
    off += (size_t)snprintf(ins + off, sizeof(ins) - off, ") VALUES (");
    for (int i = 1; i <= nparams; i++)
        off += (size_t)snprintf(ins + off, sizeof(ins) - off, "%s$%d", i > 1 ? "," : "", i);
    snprintf(ins + off, sizeof(ins) - off, ") ON CONFLICT DO NOTHING;");

    /* BEGIN must come first: a simple-query command (like BEGIN) destroys the
     * unnamed prepared statement, so prepare AFTER it. */
    if (pg_simple(pg, "BEGIN") != 0) {
        sqlite3_finalize(st);
        return -1;
    }

    PGresult *pr = PQprepare(pg, "", ins, nparams, NULL);
    if (PQresultStatus(pr) != PGRES_COMMAND_OK) {
        fprintf(stderr, "PG prepare error (%s): %s", table, PQerrorMessage(pg));
        PQclear(pr);
        pg_simple(pg, "ROLLBACK");
        sqlite3_finalize(st);
        return -1;
    }
    PQclear(pr);

    const char *vals[64];
    char rowid_txt[32];
    long sent = 0;
    int rc, failed = 0;

    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        snprintf(rowid_txt, sizeof(rowid_txt), "%lld", (long long)sqlite3_column_int64(st, 0));
        vals[0] = ip;
        vals[1] = run;
        vals[2] = rowid_txt;
        for (int i = 1; i < ncols && (i + 2) < 64; i++)
            vals[i + 2] = (sqlite3_column_type(st, i) == SQLITE_NULL)
                              ? NULL : (const char *)sqlite3_column_text(st, i);

        PGresult *er = PQexecPrepared(pg, "", nparams, vals, NULL, NULL, 0);
        if (PQresultStatus(er) != PGRES_COMMAND_OK) {
            fprintf(stderr, "PG insert error (%s): %s", table, PQerrorMessage(pg));
            PQclear(er);
            failed = 1;
            break;
        }
        PQclear(er);
        sent++;
    }
    if (!failed && rc != SQLITE_DONE) {
        /* e.g. SQLITE_BUSY: not fatal, retry next cycle */
        failed = 1;
    }
    sqlite3_finalize(st);

    if (failed) {
        pg_simple(pg, "ROLLBACK");
        return -1;
    }
    if (pg_simple(pg, "COMMIT") != 0)
        return -1;
    return sent;
}

static void ship_meta(PGconn *pg, sqlite3 *db, const char *ip, const char *run)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "SELECT key, val FROM run_meta;", -1, &st, NULL) != SQLITE_OK)
        return;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *vals[4] = {
            ip, run,
            (const char *)sqlite3_column_text(st, 0),
            (const char *)sqlite3_column_text(st, 1)
        };
        PGresult *r = PQexecParams(pg,
            "INSERT INTO run_meta (machine_ip, run_id, key, val) "
            "VALUES ($1::inet, $2::bigint, $3, $4) "
            "ON CONFLICT (machine_ip, run_id, key) DO UPDATE SET val = EXCLUDED.val",
            4, NULL, vals, NULL, NULL, 0);
        if (PQresultStatus(r) != PGRES_COMMAND_OK)
            fprintf(stderr, "PG error (run_meta): %s", PQerrorMessage(pg));
        PQclear(r);
    }
    sqlite3_finalize(st);
}

static void ship_cycle(PGconn *pg, const char *db_path, int batch)
{
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return;                           /* monitor not started yet */
    }
    sqlite3_busy_timeout(db, 3000);

    char ip[64], run[32];
    if (get_meta(db, "machine_ip", ip, sizeof(ip)) != 0 ||
        get_meta(db, "run_id", run, sizeof(run)) != 0) {
        sqlite3_close(db);
        return;
    }

    ship_meta(pg, db, ip, run);
    for (size_t i = 0; i < sizeof(TABLES) / sizeof(TABLES[0]); i++) {
        long n;
        /* keep draining while a full batch comes back */
        do {
            n = ship_table(pg, db, TABLES[i], ip, run, batch);
            if (n > 0)
                printf("shipped %ld rows -> %s (machine %s, run %s)\n", n, TABLES[i], ip, run);
        } while (n >= batch && !stop_flag);
    }
    sqlite3_close(db);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: PG_CONNINFO=\"host=... dbname=nccl_eye user=... password=...\" %s <sqlite_db>\n", argv[0]);
        return 1;
    }
    const char *conninfo = getenv("PG_CONNINFO");
    if (!conninfo || !*conninfo) {
        fprintf(stderr, "ERROR: set PG_CONNINFO\n");
        return 1;
    }
    int interval = getenv("SHIP_SEC") ? atoi(getenv("SHIP_SEC")) : 5;
    int batch = getenv("BATCH_ROWS") ? atoi(getenv("BATCH_ROWS")) : 5000;
    if (interval < 1) interval = 5;
    if (batch < 1) batch = 5000;

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    PGconn *pg = NULL;
    while (!stop_flag) {
        if (!pg || PQstatus(pg) != CONNECTION_OK) {
            if (pg) PQfinish(pg);
            pg = PQconnectdb(conninfo);
            if (PQstatus(pg) != CONNECTION_OK) {
                fprintf(stderr, "Postgres not reachable (%s) - retrying in %ds\n",
                        PQerrorMessage(pg), interval);
                sleep((unsigned)interval);
                continue;
            }
            printf("Connected to Postgres.\n");
        }
        ship_cycle(pg, argv[1], batch);
        sleep((unsigned)interval);
    }

    /* final drain so the last rows (and end-of-run meta) are not lost */
    if (pg && PQstatus(pg) == CONNECTION_OK)
        ship_cycle(pg, argv[1], batch);
    if (pg) PQfinish(pg);
    printf("Shipper stopped.\n");
    return 0;
}