use crate::IpObservation;
use std::net::IpAddr;

pub fn describe_ip(ip: IpAddr) -> IpObservation {
    match ip {
        IpAddr::V4(ip) => {
            let scope = if ip.is_loopback() {
                "loopback"
            } else if ip.is_private() {
                "private"
            } else if ip.is_link_local() {
                "link_local"
            } else if ip.is_multicast() {
                "multicast"
            } else if ip.is_unspecified() {
                "unspecified"
            } else if ip.is_documentation() {
                "documentation"
            } else {
                "public"
            };

            IpObservation {
                version: 4,
                scope: scope.to_string(),
                is_loopback: ip.is_loopback(),
                is_private_or_unique_local: ip.is_private(),
                is_link_local: ip.is_link_local(),
                is_multicast: ip.is_multicast(),
                is_unspecified: ip.is_unspecified(),
                is_documentation: ip.is_documentation(),
            }
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            let is_documentation = segments[0] == 0x2001 && segments[1] == 0x0db8;
            let scope = if ip.is_loopback() {
                "loopback"
            } else if ip.is_unique_local() {
                "unique_local"
            } else if ip.is_unicast_link_local() {
                "link_local"
            } else if ip.is_multicast() {
                "multicast"
            } else if ip.is_unspecified() {
                "unspecified"
            } else if is_documentation {
                "documentation"
            } else {
                "public"
            };

            IpObservation {
                version: 6,
                scope: scope.to_string(),
                is_loopback: ip.is_loopback(),
                is_private_or_unique_local: ip.is_unique_local(),
                is_link_local: ip.is_unicast_link_local(),
                is_multicast: ip.is_multicast(),
                is_unspecified: ip.is_unspecified(),
                is_documentation,
            }
        }
    }
}
