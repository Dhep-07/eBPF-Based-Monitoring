# eBPF System Monitor

A lightweight Linux system-monitoring application using **eBPF**, **libbpf**, and **SQLite**.

The monitor collects kernel events through eBPF tracepoints, sends them to userspace through a BPF ring buffer, and stores the collected metrics in a SQLite database.

## Features

The current implementation monitors:

* CPU scheduler context switches
* Network transmit events
* Disk I/O request events
* Memory page allocation events
* Process ID and command name
* CPU core information
* Event values and timestamps
* Persistent storage using SQLite

## Project Structure

```text
eBPF-Based-Monitoring/
├── monitor.bpf.c       # eBPF kernel-side program
├── monitor.c           # Userspace monitoring program
├── Makefile            # Build configuration
├── README.md           # Project documentation
├── .gitignore          # Git ignore rules
├── LICENSE
├── vmlinux.h           # Generated kernel BTF definitions
├── monitor.bpf.o       # Generated eBPF object
├── monitor.skel.h      # Generated libbpf skeleton
├── monitor             # Generated executable
└── monitor.db          # Generated SQLite database
```

The files `monitor.bpf.o`, `monitor.skel.h`, `monitor`, and `monitor.db` are generated and should not normally be committed to Git.

---

## Requirements

This project requires:

* Linux
* Clang/LLVM
* GCC or another C compiler
* libbpf
* bpftool
* SQLite3 development libraries
* Linux kernel BTF support
* Linux kernel headers
* `make`

The monitor normally needs to be run as root because it loads and attaches eBPF programs.

---

## Installation

### Debian / Ubuntu / Kali Linux

Install the required packages:

```bash
sudo apt update
sudo apt install -y \
    clang \
    llvm \
    gcc \
    make \
    libbpf-dev \
    libelf-dev \
    zlib1g-dev \
    libsqlite3-dev \
    bpftool \
    linux-headers-$(uname -r)
```

Check the installed tools:

```bash
clang --version
gcc --version
bpftool version
make --version
```

---

## Generate `vmlinux.h`

The eBPF program uses the kernel's BTF information.

Check whether BTF is available:

```bash
ls -l /sys/kernel/btf/vmlinux
```

If the file exists, generate `vmlinux.h`:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

Verify:

```bash
ls -lh vmlinux.h
```

`vmlinux.h` is generated from the running kernel and can therefore differ between kernel versions.

---

## Build the Project

From the project directory:

```bash
cd ~/eBPF-Based-Monitoring
```

Build everything:

```bash
make
```

The Makefile performs these steps:

```text
monitor.bpf.c
      │
      │ clang
      ▼
monitor.bpf.o
      │
      │ bpftool
      ▼
monitor.skel.h
      │
      │ gcc
      ▼
monitor
```

After a successful build, verify:

```bash
ls -lh monitor monitor.bpf.o monitor.skel.h
```

You should have:

```text
monitor
monitor.bpf.o
monitor.skel.h
```

Warnings generated from `vmlinux.h` may appear during compilation. If Clang continues and the `bpftool` and compiler stages complete successfully, the build has succeeded.

---

## Run the Monitor

Run the program from the project directory:

```bash
sudo ./monitor
```

Expected startup output:

```text
=== eBPF Monitor ===
Database: monitor.db
SQLite database initialized: monitor.db
Monitoring... Press Ctrl+C to stop.
```

The default database is:

```text
~/eBPF-Based-Monitoring/monitor.db
```

The database is automatically created if it does not already exist.

### Specify a custom database

You can provide a database path as the first argument:

```bash
sudo ./monitor /tmp/monitor.db
```

This creates:

```text
/tmp/monitor.db
```

---

## Stop the Monitor

Press:

```text
Ctrl+C
```

The program handles `SIGINT` and exits cleanly.

If necessary, you can stop it from another terminal:

```bash
sudo pkill monitor
```

---

## Check the SQLite Database

Check that the database exists:

```bash
ls -lh monitor.db
```

Open the database:

```bash
sqlite3 monitor.db
```

List the tables:

```sql
.tables
```

The monitor creates:

```text
metrics
```

View the table structure:

```sql
.schema metrics
```

View collected metrics:

```sql
SELECT * FROM metrics LIMIT 10;
```

Exit SQLite:

```sql
.quit
```

You can also query directly from the shell:

```bash
sqlite3 monitor.db "SELECT * FROM metrics LIMIT 10;"
```

### Useful queries

Count collected events:

```bash
sqlite3 monitor.db \
"SELECT COUNT(*) FROM metrics;"
```

Show events grouped by subsystem:

```bash
sqlite3 monitor.db \
"SELECT subsystem, COUNT(*) FROM metrics GROUP BY subsystem;"
```

Show the most recent events:

```bash
sqlite3 monitor.db \
"SELECT id, subsystem, metric, value, pid, comm FROM metrics ORDER BY id DESC LIMIT 20;"
```

---

## Clean the Build

To remove generated build files:

```bash
make clean
```

The provided Makefile should remove:

```text
monitor
monitor.bpf.o
monitor.skel.h
```

The SQLite database should be preserved.

If you want to manually remove the database:

```bash
rm -f monitor.db
```

---

## Rebuild From Scratch

If you change `monitor.bpf.c` or `monitor.c`, rebuild with:

```bash
make clean
make
```

Then run:

```bash
sudo ./monitor
```

---

## Troubleshooting

### `sqlite3.h: No such file or directory`

Install the SQLite development package:

```bash
sudo apt install -y libsqlite3-dev
```

Then rebuild:

```bash
make clean
make
```

### `asm/types.h: No such file or directory`

The project uses `vmlinux.h` to avoid depending directly on architecture-specific kernel UAPI headers.

Regenerate it:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

Then:

```bash
make clean
make
```

### `bpftool: command not found`

Install:

```bash
sudo apt install -y bpftool
```

### BPF program fails to attach

eBPF attachment points depend on the running kernel. Check:

```bash
uname -a
```

Check available scheduler tracepoints:

```bash
sudo ls /sys/kernel/debug/tracing/events/sched/
```

Check available network tracepoints:

```bash
sudo ls /sys/kernel/debug/tracing/events/net/
```

Check available block tracepoints:

```bash
sudo ls /sys/kernel/debug/tracing/events/block/
```

Check available memory tracepoints:

```bash
sudo ls /sys/kernel/debug/tracing/events/kmem/
```

If a tracepoint is not available on your kernel, the corresponding eBPF program must be adjusted.

### Permission errors

Run the monitor as root:

```bash
sudo ./monitor
```

---

## Architecture

The application consists of two parts.

### Kernel-side eBPF program

`monitor.bpf.c` runs inside the kernel through eBPF.

It:

1. Attaches to kernel tracepoints.
2. Collects event information.
3. Creates an event structure.
4. Sends events through a BPF ring buffer.

### Userspace program

`monitor.c`:

1. Loads the generated BPF skeleton.
2. Loads and attaches the eBPF programs.
3. Reads events from the ring buffer.
4. Displays events in the terminal.
5. Inserts events into SQLite.

The data flow is:

```text
Linux Kernel
     │
     ▼
eBPF Tracepoints
     │
     ▼
BPF Ring Buffer
     │
     ▼
monitor
     │
     ├── Terminal output
     │
     ▼
SQLite
     │
     ▼
monitor.db
```

---

## Database Schema

The monitor creates the following table:

```sql
CREATE TABLE metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    subsystem TEXT NOT NULL,
    metric TEXT NOT NULL,
    value REAL NOT NULL,
    pid INTEGER,
    comm TEXT
);
```

Example records may contain:

```text
cpu       context_switch
network   tcp_send
disk      io_request
memory    page_alloc
```

---

## Notes

* `monitor.bpf.o` is generated by Clang.
* `monitor.skel.h` is generated by `bpftool`.
* `monitor` is the compiled userspace executable.
* `monitor.db` is created automatically when the program starts.
* `vmlinux.h` is generated from the running kernel's BTF information.
* eBPF tracepoints and kernel behavior can vary between Linux kernel versions.
* The monitor should be tested on the target kernel where it will be deployed.

## License

This project is licensed under the GNU General Public License v2.0.
