CLANG ?= clang
CC ?= gcc
BPFTOOL ?= bpftool

ARCH := $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/')
LIBBPF ?= $(HOME)/libbpf-inst/usr
INCS := -I$(LIBBPF)/include -I.

all: monitor

monitor.bpf.o: monitor.bpf.c vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCS) -c $< -o $@

monitor.skel.h: monitor.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

monitor: monitor.c sampler.c sampler.h monitor.skel.h
	$(CC) -g -O2 $(INCS) -o $@ monitor.c sampler.c $(LIBBPF)/lib64/libbpf.a -lelf -lz -lsqlite3 -ldl

clean:
	rm -f monitor monitor.bpf.o monitor.skel.h

.PHONY: all clean
