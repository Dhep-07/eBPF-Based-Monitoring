/* SPDX-License-Identifier: MIT
 * Sampler for data sources that eBPF cannot provide:
 *  - temperatures (hwmon sysfs)
 *  - NVIDIA GPU utilisation / memory / temperature / power (NVML via dlopen)
 *  - RAM usage (/proc/meminfo) and CPU utilisation (/proc/stat)
 */
#ifndef SAMPLER_H
#define SAMPLER_H

#define MAX_GPUS 16

struct sys_sample {
    /* CPU utilisation over the interval since the previous call, percent */
    double cpu_util_pct;
    /* Temperatures in milli-degrees C; -1 if unavailable */
    long cpu_temp_mc;
    /* RAM in kB */
    unsigned long long mem_total_kb, mem_avail_kb, mem_free_kb, cached_kb;
    unsigned long long swap_total_kb, swap_free_kb;
};

struct gpu_sample {
    int index;
    unsigned int util_gpu_pct;
    unsigned int util_mem_pct;
    unsigned int temp_c;
    unsigned int power_mw;
    unsigned long long mem_used_bytes;
    unsigned long long mem_total_bytes;
};

int  sampler_init(void);   /* returns number of GPUs found (0 if NVML missing) */
void sampler_sample_sys(struct sys_sample *s);
int  sampler_sample_gpus(struct gpu_sample *out, int max); /* returns count */
void sampler_close(void);

#endif
