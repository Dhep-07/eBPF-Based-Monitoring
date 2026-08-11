CLANG ?= clang
CC ?= gcc

ARCH := $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/')

all: monitor

monitor.bpf.o: monitor.bpf.c
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -c $< -o $@

monitor.skel.h: monitor.bpf.o
	bpftool gen skeleton $< > $@

monitor: monitor.c monitor.skel.h
	$(CC) -g -O2 -o $@ monitor.c -lbpf -lelf -lz -lsqlite3

clean:
	rm -f monitor monitor.bpf.o monitor.skel.h

.PHONY: all clean
