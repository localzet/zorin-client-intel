#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "tcp_sensor.h"

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline void parse_tcp_options(
    void *tcp_start,
    void *data_end,
    __u32 tcp_header_len,
    struct zci_tcp_event *event)
{
    if (tcp_header_len <= 20)
        return;

    __u8 *cursor = (__u8 *)tcp_start + 20;
    __u8 *limit = (__u8 *)tcp_start + tcp_header_len;
    if ((void *)limit > data_end)
        return;

#pragma unroll
    for (int i = 0; i < ZCI_MAX_TCP_OPTIONS; i++) {
        if ((void *)(cursor + 1) > data_end || cursor >= limit)
            break;

        __u8 kind = *cursor;
        if (event->option_count < ZCI_MAX_TCP_OPTIONS)
            event->options[event->option_count++] = kind;

        if (kind == 0)
            break;
        if (kind == 1) {
            cursor += 1;
            continue;
        }

        if ((void *)(cursor + 2) > data_end || cursor + 2 > limit)
            break;
        __u8 len = *(cursor + 1);
        if (len < 2 || cursor + len > limit || (void *)(cursor + len) > data_end)
            break;

        if (kind == 2 && len == 4) {
            event->mss = ((__u16)*(cursor + 2) << 8) | *(__u8 *)(cursor + 3);
            event->has_mss = 1;
        } else if (kind == 3 && len == 3) {
            event->window_scale = *(cursor + 2);
            event->has_window_scale = 1;
        } else if (kind == 4 && len == 2) {
            event->sack_permitted = 1;
        } else if (kind == 8 && len == 10) {
            event->timestamps = 1;
        }

        cursor += len;
    }
}

static __always_inline int emit_ipv4(void *data, void *data_end, struct iphdr *ip)
{
    __u32 ip_header_len = (__u32)ip->ihl * 4;
    if (ip_header_len < sizeof(*ip))
        return XDP_PASS;
    if ((void *)ip + ip_header_len > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_header_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    __u8 *raw_tcp = (__u8 *)tcp;
    __u8 flags = raw_tcp[13];
    if (!(flags & 0x02) || (flags & 0x10))
        return XDP_PASS;

    __u32 tcp_header_len = ((__u32)(raw_tcp[12] >> 4)) * 4;
    if (tcp_header_len < sizeof(*tcp) || (void *)tcp + tcp_header_len > data_end)
        return XDP_PASS;

    struct zci_tcp_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return XDP_PASS;
    __builtin_memset(event, 0, sizeof(*event));

    event->ip_version = 4;
    __builtin_memcpy(event->remote_addr, &ip->saddr, 4);
    event->remote_port = bpf_ntohs(tcp->source);
    event->local_port = bpf_ntohs(tcp->dest);
    event->ttl_or_hop_limit = ip->ttl;
    event->window_size = bpf_ntohs(tcp->window);
    event->ecn = (flags & 0xc0) != 0;

    __u16 total_len = bpf_ntohs(ip->tot_len);
    __u32 headers = ip_header_len + tcp_header_len;
    if (total_len >= headers)
        event->syn_payload_len = total_len - headers;

    parse_tcp_options(tcp, data_end, tcp_header_len, event);
    bpf_ringbuf_submit(event, 0);
    return XDP_PASS;
}

static __always_inline int emit_ipv6(void *data, void *data_end, struct ipv6hdr *ip6)
{
    if ((void *)(ip6 + 1) > data_end)
        return XDP_PASS;

    // Базовый сенсор обрабатывает TCP непосредственно после IPv6 header.
    // Extension-header walker можно добавить отдельно, не меняя формат события.
    if (ip6->nexthdr != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)(ip6 + 1);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    __u8 *raw_tcp = (__u8 *)tcp;
    __u8 flags = raw_tcp[13];
    if (!(flags & 0x02) || (flags & 0x10))
        return XDP_PASS;

    __u32 tcp_header_len = ((__u32)(raw_tcp[12] >> 4)) * 4;
    if (tcp_header_len < sizeof(*tcp) || (void *)tcp + tcp_header_len > data_end)
        return XDP_PASS;

    struct zci_tcp_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return XDP_PASS;
    __builtin_memset(event, 0, sizeof(*event));

    event->ip_version = 6;
    __builtin_memcpy(event->remote_addr, &ip6->saddr, 16);
    event->remote_port = bpf_ntohs(tcp->source);
    event->local_port = bpf_ntohs(tcp->dest);
    event->ttl_or_hop_limit = ip6->hop_limit;
    event->window_size = bpf_ntohs(tcp->window);
    event->ecn = (flags & 0xc0) != 0;

    __u16 payload_len = bpf_ntohs(ip6->payload_len);
    if (payload_len >= tcp_header_len)
        event->syn_payload_len = payload_len - tcp_header_len;

    parse_tcp_options(tcp, data_end, tcp_header_len, event);
    bpf_ringbuf_submit(event, 0);
    return XDP_PASS;
}

SEC("xdp")
int capture_syn(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 protocol = bpf_ntohs(eth->h_proto);
    if (protocol == ETH_P_IP) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;
        return emit_ipv4(data, data_end, ip);
    }

    if (protocol == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        return emit_ipv6(data, data_end, ip6);
    }

    return XDP_PASS;
}
