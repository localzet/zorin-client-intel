CLANG ?= clang
CC ?= cc
BPFTOOL ?= bpftool
UNAME_M := $(shell uname -m)
ARCH ?= $(if $(filter aarch64 arm64,$(UNAME_M)),arm64,x86)
CFLAGS ?= -O2 -g -Wall -Wextra
BPF_CFLAGS ?= -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH)

.PHONY: all clean vmlinux

all: tcp-sensor

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

tcp_sensor.bpf.o: tcp_sensor.bpf.c tcp_sensor.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -I. -c tcp_sensor.bpf.c -o $@

tcp_sensor.skel.h: tcp_sensor.bpf.o
	$(BPFTOOL) gen skeleton tcp_sensor.bpf.o > tcp_sensor.skel.h

tcp-sensor: tcp_sensor.c tcp_sensor.h tcp_sensor.skel.h
	$(CC) $(CFLAGS) -I. tcp_sensor.c -o $@ $$(pkg-config --cflags --libs libbpf) -lelf -lz

clean:
	rm -f tcp-sensor tcp_sensor.bpf.o tcp_sensor.skel.h vmlinux.h
