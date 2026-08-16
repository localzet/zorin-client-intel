#ifndef ZCI_TCP_SENSOR_H
#define ZCI_TCP_SENSOR_H

#include <linux/types.h>

#define ZCI_MAX_TCP_OPTIONS 24

struct zci_tcp_event {
    __u8 ip_version;
    __u8 remote_addr[16];
    __u16 remote_port;
    __u16 local_port;
    __u8 ttl_or_hop_limit;
    __u16 window_size;
    __u16 mss;
    __u8 window_scale;
    __u8 has_mss;
    __u8 has_window_scale;
    __u8 sack_permitted;
    __u8 timestamps;
    __u8 ecn;
    __u8 option_count;
    __u8 options[ZCI_MAX_TCP_OPTIONS];
    __u16 syn_payload_len;
};

#endif
