// SPDX-License-Identifier: MIT
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <dlfcn.h>
#include "sampler.h"

/* ---------- minimal NVML ABI (avoids needing the CUDA toolkit headers) ---------- */
typedef void *nvmlDevice_t;
typedef struct { unsigned int gpu; unsigned int memory; } nvmlUtilization_t;
typedef struct { unsigned long long total, free, used; } nvmlMemory_t;

static void *nvml_lib;
static int (*p_Init)(void);
static int (*p_Shutdown)(void);
static int (*p_Count)(unsigned int *);
static int (*p_Handle)(unsigned int, nvmlDevice_t *);
static int (*p_Util)(nvmlDevice_t, nvmlUtilization_t *);
static int (*p_Temp)(nvmlDevice_t, int, unsigned int *);  /* sensor 0 = GPU */
static int (*p_Mem)(nvmlDevice_t, nvmlMemory_t *);
static int (*p_Power)(nvmlDevice_t, unsigned int *);
static nvmlDevice_t gpu_dev[MAX_GPUS];
static int ngpus;

/* ---------- hwmon CPU temperature inputs ---------- */
#define MAX_TEMP_FILES 64
static char temp_files[MAX_TEMP_FILES][320];
static int ntemp;

/* ---------- /proc/stat state ---------- */
static unsigned long long prev_busy, prev_total;

static int read_cpu_jiffies(unsigned long long *busy, unsigned long long *total)
{
    FILE *f = fopen("/proc/stat", "r");
    if (!f)
        return -1;
    unsigned long long u, n, s, i, io, irq, sirq, st;
    int r = fscanf(f, "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
                   &u, &n, &s, &i, &io, &irq, &sirq, &st);
    fclose(f);
    if (r < 8)
        return -1;
    *busy = u + n + s + irq + sirq + st;
    *total = *busy + i + io;
    return 0;
}

static void discover_cpu_temps(void)
{
    DIR *d = opendir("/sys/class/hwmon");
    if (!d)
        return;
    struct dirent *de;
    while ((de = readdir(d)) != NULL && ntemp < MAX_TEMP_FILES) {
        if (strncmp(de->d_name, "hwmon", 5) != 0)
            continue;
        char p[300], name[64] = "";
        snprintf(p, sizeof(p), "/sys/class/hwmon/%s/name", de->d_name);
        FILE *f = fopen(p, "r");
        if (!f)
            continue;
        if (!fgets(name, sizeof(name), f))
            name[0] = '\0';
        fclose(f);
        /* Intel: coretemp, AMD: k10temp, some ARM/servers: cpu_thermal */
        if (!strstr(name, "coretemp") && !strstr(name, "k10temp") &&
            !strstr(name, "cpu_thermal"))
            continue;
        for (int i = 1; i <= 64 && ntemp < MAX_TEMP_FILES; i++) {
            snprintf(temp_files[ntemp], sizeof(temp_files[0]),
                     "/sys/class/hwmon/%s/temp%d_input", de->d_name, i);
            FILE *t = fopen(temp_files[ntemp], "r");
            if (!t)
                continue;
            fclose(t);
            ntemp++;
        }
    }
    closedir(d);
}

static long read_cpu_temp_mc(void)
{
    long max = -1;
    for (int i = 0; i < ntemp; i++) {
        FILE *f = fopen(temp_files[i], "r");
        if (!f)
            continue;
        long v;
        if (fscanf(f, "%ld", &v) == 1 && v > max)
            max = v;
        fclose(f);
    }
    return max;
}

int sampler_init(void)
{
    discover_cpu_temps();
    read_cpu_jiffies(&prev_busy, &prev_total);

    nvml_lib = dlopen("libnvidia-ml.so.1", RTLD_NOW);
    if (!nvml_lib)
        return 0;
    p_Init     = dlsym(nvml_lib, "nvmlInit_v2");
    p_Shutdown = dlsym(nvml_lib, "nvmlShutdown");
    p_Count    = dlsym(nvml_lib, "nvmlDeviceGetCount_v2");
    p_Handle   = dlsym(nvml_lib, "nvmlDeviceGetHandleByIndex_v2");
    p_Util     = dlsym(nvml_lib, "nvmlDeviceGetUtilizationRates");
    p_Temp     = dlsym(nvml_lib, "nvmlDeviceGetTemperature");
    p_Mem      = dlsym(nvml_lib, "nvmlDeviceGetMemoryInfo");
    p_Power    = dlsym(nvml_lib, "nvmlDeviceGetPowerUsage");
    if (!p_Init || !p_Count || !p_Handle || p_Init() != 0)
        return 0;

    unsigned int n = 0;
    if (p_Count(&n) != 0)
        return 0;
    for (unsigned int i = 0; i < n && ngpus < MAX_GPUS; i++)
        if (p_Handle(i, &gpu_dev[ngpus]) == 0)
            ngpus++;
    return ngpus;
}

void sampler_sample_sys(struct sys_sample *s)
{
    memset(s, 0, sizeof(*s));

    unsigned long long busy, total;
    if (read_cpu_jiffies(&busy, &total) == 0 && total > prev_total)
        s->cpu_util_pct = 100.0 * (double)(busy - prev_busy) / (double)(total - prev_total);
    prev_busy = busy;
    prev_total = total;

    s->cpu_temp_mc = read_cpu_temp_mc();

    FILE *f = fopen("/proc/meminfo", "r");
    if (f) {
        char line[128];
        while (fgets(line, sizeof(line), f)) {
            unsigned long long v;
            if (sscanf(line, "MemTotal: %llu", &v) == 1) s->mem_total_kb = v;
            else if (sscanf(line, "MemFree: %llu", &v) == 1) s->mem_free_kb = v;
            else if (sscanf(line, "MemAvailable: %llu", &v) == 1) s->mem_avail_kb = v;
            else if (sscanf(line, "Cached: %llu", &v) == 1) s->cached_kb = v;
            else if (sscanf(line, "SwapTotal: %llu", &v) == 1) s->swap_total_kb = v;
            else if (sscanf(line, "SwapFree: %llu", &v) == 1) s->swap_free_kb = v;
        }
        fclose(f);
    }
}

int sampler_sample_gpus(struct gpu_sample *out, int max)
{
    int n = 0;
    for (int i = 0; i < ngpus && n < max; i++) {
        struct gpu_sample *g = &out[n];
        memset(g, 0, sizeof(*g));
        g->index = i;
        nvmlUtilization_t u;
        nvmlMemory_t m;
        unsigned int t = 0, pw = 0;
        if (p_Util && p_Util(gpu_dev[i], &u) == 0) {
            g->util_gpu_pct = u.gpu;
            g->util_mem_pct = u.memory;
        }
        if (p_Temp && p_Temp(gpu_dev[i], 0, &t) == 0)
            g->temp_c = t;
        if (p_Power && p_Power(gpu_dev[i], &pw) == 0)
            g->power_mw = pw;
        if (p_Mem && p_Mem(gpu_dev[i], &m) == 0) {
            g->mem_used_bytes = m.used;
            g->mem_total_bytes = m.total;
        }
        n++;
    }
    return n;
}

void sampler_close(void)
{
    if (nvml_lib) {
        if (p_Shutdown)
            p_Shutdown();
        dlclose(nvml_lib);
        nvml_lib = NULL;
    }
}
