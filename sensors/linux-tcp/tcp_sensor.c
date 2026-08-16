#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "tcp_sensor.h"
#include "tcp_sensor.skel.h"

static volatile sig_atomic_t running = 1;
static int output_fd = -1;
static struct sockaddr_un output_addr;

static void stop(int signo)
{
    (void)signo;
    running = 0;
}

static void append_options(char *buffer, size_t size, const struct zci_tcp_event *event)
{
    size_t offset = 0;
    offset += snprintf(buffer + offset, size - offset, "[");
    for (__u8 i = 0; i < event->option_count && offset < size; i++) {
        offset += snprintf(
            buffer + offset,
            size - offset,
            "%s%u",
            i == 0 ? "" : ",",
            event->options[i]
        );
    }
    if (offset < size)
        snprintf(buffer + offset, size - offset, "]");
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;
    if (data_sz < sizeof(struct zci_tcp_event))
        return 0;

    const struct zci_tcp_event *event = data;
    char ip[INET6_ADDRSTRLEN] = {0};
    if (event->ip_version == 4) {
        inet_ntop(AF_INET, event->remote_addr, ip, sizeof(ip));
    } else if (event->ip_version == 6) {
        inet_ntop(AF_INET6, event->remote_addr, ip, sizeof(ip));
    } else {
        return 0;
    }

    char options[192] = {0};
    append_options(options, sizeof(options), event);

    char mss[32];
    char scale[32];
    char ttl[32];
    char hop_limit[32];
    if (event->has_mss)
        snprintf(mss, sizeof(mss), "%u", event->mss);
    else
        snprintf(mss, sizeof(mss), "null");
    if (event->has_window_scale)
        snprintf(scale, sizeof(scale), "%u", event->window_scale);
    else
        snprintf(scale, sizeof(scale), "null");
    if (event->ip_version == 4) {
        snprintf(ttl, sizeof(ttl), "%u", event->ttl_or_hop_limit);
        snprintf(hop_limit, sizeof(hop_limit), "null");
    } else {
        snprintf(ttl, sizeof(ttl), "null");
        snprintf(hop_limit, sizeof(hop_limit), "%u", event->ttl_or_hop_limit);
    }

    char json[2048];
    int len = snprintf(
        json,
        sizeof(json),
        "{\"remote_ip\":\"%s\",\"remote_port\":%u,\"local_port\":%u,"
        "\"tcp\":{\"source\":\"ebpf-xdp-syn\",\"ip_version\":%u,"
        "\"ttl\":%s,\"hop_limit\":%s,\"window_size\":%u,\"mss\":%s,"
        "\"window_scale\":%s,\"sack_permitted\":%s,\"timestamps\":%s,"
        "\"ecn\":%s,\"options_order\":%s,\"syn_payload_len\":%u}}",
        ip,
        event->remote_port,
        event->local_port,
        event->ip_version,
        ttl,
        hop_limit,
        event->window_size,
        mss,
        scale,
        event->sack_permitted ? "true" : "false",
        event->timestamps ? "true" : "false",
        event->ecn ? "true" : "false",
        options,
        event->syn_payload_len
    );

    if (len <= 0 || (size_t)len >= sizeof(json))
        return 0;

    sendto(
        output_fd,
        json,
        strlen(json),
        MSG_DONTWAIT,
        (struct sockaddr *)&output_addr,
        sizeof(output_addr)
    );
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: %s <interface> [collector-socket]\n", argv[0]);
        return 2;
    }

    const char *interface = argv[1];
    const char *socket_path = argc == 3 ? argv[2] : "/run/zci/tcp-sensor.sock";
    unsigned int ifindex = if_nametoindex(interface);
    if (!ifindex) {
        fprintf(stderr, "unknown interface: %s\n", interface);
        return 2;
    }

    signal(SIGINT, stop);
    signal(SIGTERM, stop);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    struct tcp_sensor_bpf *skel = tcp_sensor_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open/load BPF skeleton\n");
        return 1;
    }

    struct bpf_link *link = bpf_program__attach_xdp(skel->progs.capture_syn, ifindex);
    if (!link) {
        fprintf(stderr, "failed to attach XDP program to %s\n", interface);
        tcp_sensor_bpf__destroy(skel);
        return 1;
    }

    output_fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (output_fd < 0) {
        perror("socket");
        bpf_link__destroy(link);
        tcp_sensor_bpf__destroy(skel);
        return 1;
    }
    memset(&output_addr, 0, sizeof(output_addr));
    output_addr.sun_family = AF_UNIX;
    snprintf(output_addr.sun_path, sizeof(output_addr.sun_path), "%s", socket_path);

    struct ring_buffer *ring = ring_buffer__new(
        bpf_map__fd(skel->maps.events),
        handle_event,
        NULL,
        NULL
    );
    if (!ring) {
        fprintf(stderr, "failed to create ring buffer\n");
        close(output_fd);
        bpf_link__destroy(link);
        tcp_sensor_bpf__destroy(skel);
        return 1;
    }

    fprintf(stderr, "ZCI TCP sensor attached to %s -> %s\n", interface, socket_path);
    while (running) {
        int rc = ring_buffer__poll(ring, 250);
        if (rc == -EINTR)
            continue;
        if (rc < 0) {
            fprintf(stderr, "ring_buffer__poll: %d\n", rc);
            break;
        }
    }

    ring_buffer__free(ring);
    close(output_fd);
    bpf_link__destroy(link);
    tcp_sensor_bpf__destroy(skel);
    return 0;
}
