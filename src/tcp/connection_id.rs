use etherparse::{IpHeader, TcpHeader};
use std::fmt;
use std::fmt::{Display, Formatter};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::ip_utils::IpPair;

/// From the spec:
///
/// > To allow for many processes within a single Host to use TCP
/// > communication facilities simultaneously, the TCP provides a set of
/// > addresses or ports within each host. Concatenated with the network
/// > and host addresses from the internet communication layer, this forms
/// > a socket. A pair of sockets uniquely identifies each connection.
///
/// Written from the point of view of an incoming connection.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum ConnectionId {
    V4 {
        remote_addr: Ipv4Addr,
        remote_port: u16,
        local_addr: Ipv4Addr,
        local_port: u16,
    },
    V6 {
        remote_addr: Ipv6Addr,
        remote_port: u16,
        local_addr: Ipv6Addr,
        local_port: u16,
    },
}

impl ConnectionId {
    /// Create a new `ConnectionId` from incoming headers
    pub fn from_incoming(
        incoming_ip_header: &IpHeader,
        incoming_tcp_header: &TcpHeader,
    ) -> ConnectionId {
        let ips = IpPair::from(incoming_ip_header);

        match ips {
            IpPair::V4 { src, dst } => ConnectionId::V4 {
                remote_addr: src,
                remote_port: incoming_tcp_header.source_port,
                local_addr: dst,
                local_port: incoming_tcp_header.destination_port,
            },
            IpPair::V6 { src, dst } => ConnectionId::V6 {
                remote_addr: src,
                remote_port: incoming_tcp_header.source_port,
                local_addr: dst,
                local_port: incoming_tcp_header.destination_port,
            },
        }
    }

    /// Create a new `ConnectionId` from outgoing headers
    pub fn from_outgoing(
        outgoing_ip_header: &IpHeader,
        outgoing_tcp_header: &TcpHeader,
    ) -> ConnectionId {
        let ips = IpPair::from(outgoing_ip_header);

        match ips {
            IpPair::V4 { src, dst } => ConnectionId::V4 {
                remote_addr: dst,
                remote_port: outgoing_tcp_header.destination_port,
                local_addr: src,
                local_port: outgoing_tcp_header.source_port,
            },
            IpPair::V6 { src, dst } => ConnectionId::V6 {
                remote_addr: dst,
                remote_port: outgoing_tcp_header.destination_port,
                local_addr: src,
                local_port: outgoing_tcp_header.source_port,
            },
        }
    }

    pub fn local_port(&self) -> u16 {
        match self {
            ConnectionId::V4 { local_port, .. } => *local_port,
            ConnectionId::V6 { local_port, .. } => *local_port,
        }
    }

    pub fn remote_port(&self) -> u16 {
        match self {
            ConnectionId::V4 { remote_port, .. } => *remote_port,
            ConnectionId::V6 { remote_port, .. } => *remote_port,
        }
    }
}

impl Display for ConnectionId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ConnectionId::V4 {
                remote_addr,
                remote_port,
                local_addr,
                local_port,
            } => write!(
                f,
                "{}:{} <> [{}:{}]",
                remote_addr, remote_port, local_addr, local_port
            ),
            ConnectionId::V6 {
                remote_addr,
                remote_port,
                local_addr,
                local_port,
            } => write!(
                f,
                "{}:{} <> [{}:{}]",
                remote_addr, remote_port, local_addr, local_port
            ),
        }
    }
}
