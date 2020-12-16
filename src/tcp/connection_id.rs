use etherparse::{IpHeader, TcpHeader};
use std::fmt::{Display, Formatter};
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::{fmt, unimplemented};

use super::types::*;
use crate::ip_utils::IpPair;

/// Each connection is uniquely specified by a pair of sockets identifying its two sides.
///
/// From the spec:
///
/// > To allow for many processes within a single Host to use TCP
/// > communication facilities simultaneously, the TCP provides a set of
/// > addresses or ports within each host. Concatenated with the network
/// > and host addresses from the internet communication layer, this forms
/// > a socket. A pair of sockets uniquely identifies each connection.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum ConnectionId {
    V4 {
        remote_socket: SocketAddrV4,
        local_socket: SocketAddrV4,
    },
    #[allow(dead_code)]
    V6 {
        remote_socket: SocketAddrV6,
        local_socket: SocketAddrV6,
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
                remote_socket: SocketAddrV4::new(
                    src,
                    incoming_tcp_header.source_port,
                ),
                local_socket: SocketAddrV4::new(
                    dst,
                    incoming_tcp_header.destination_port,
                ),
            },
            IpPair::V6 { src: _, dst: _ } => unimplemented!("IPv6"),
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
                remote_socket: SocketAddrV4::new(
                    dst,
                    outgoing_tcp_header.destination_port,
                ),
                local_socket: SocketAddrV4::new(
                    src,
                    outgoing_tcp_header.source_port,
                ),
            },
            IpPair::V6 { src: _, dst: _ } => unimplemented!("IPv6"),
        }
    }

    pub fn local_socket(&self) -> SocketAddr {
        match self {
            ConnectionId::V4 { local_socket, .. } => {
                SocketAddr::V4(*local_socket)
            }

            ConnectionId::V6 {
                local_socket: _, ..
            } => {
                unimplemented!("IPv6")
            }
        }
    }

    pub fn local_port(&self) -> PortNum {
        match self {
            ConnectionId::V4 { local_socket, .. } => local_socket.port(),
            ConnectionId::V6 { local_socket, .. } => local_socket.port(),
        }
    }

    pub fn remote_port(&self) -> PortNum {
        match self {
            ConnectionId::V4 { remote_socket, .. } => remote_socket.port(),
            ConnectionId::V6 { remote_socket, .. } => remote_socket.port(),
        }
    }
}

impl Display for ConnectionId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ConnectionId::V4 {
                remote_socket,
                local_socket,
            } => write!(
                f,
                "{}:{} <> [{}:{}]",
                remote_socket.ip(),
                remote_socket.port(),
                local_socket.ip(),
                local_socket.port()
            ),
            ConnectionId::V6 {
                remote_socket,
                local_socket,
            } => write!(
                f,
                "{}:{} <> [{}:{}]",
                remote_socket.ip(),
                remote_socket.port(),
                local_socket.ip(),
                local_socket.port()
            ),
        }
    }
}
