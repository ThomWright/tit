use etherparse::{
    IpHeader, IpTrafficClass, Ipv4Header, PacketBuilder, TcpHeader,
};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::errors::{Result, TitError};
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

    fn local_port(&self) -> u16 {
        match self {
            ConnectionId::V4 { local_port, .. } => *local_port,
            ConnectionId::V6 { local_port, .. } => *local_port,
        }
    }

    fn remote_port(&self) -> u16 {
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

#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
enum TcpState {
    /// Represents waiting for a connection request from any remote
    /// TCP and port.
    Listen,
    /// Represents waiting for a matching connection request
    /// after having sent a connection request.
    SynSent,
    /// Represents waiting for a confirming connection
    /// request acknowledgment after having both received and sent a
    /// connection request.
    SynReceived,
    /// Represents an open connection, data received can be
    /// delivered to the user. The normal state for the data transfer phase
    /// of the connection.
    Established,
    /// Represents waiting for a connection termination request
    /// from the remote TCP, or an acknowledgment of the connection
    /// termination request previously sent.
    FinWait1,
    /// Represents waiting for a connection termination request
    /// from the remote TCP.
    FinWait2,
    /// Represents waiting for a connection termination request
    /// from the local user.
    CloseWait,
    /// Represents waiting for a connection termination request
    /// acknowledgment from the remote TCP.
    Closing,
    /// Represents waiting for an acknowledgment of the
    /// connection termination request previously sent to the remote TCP
    /// (which includes an acknowledgment of its connection termination
    /// request).
    LastAck,
    /// Represents waiting for enough time to pass to be sure
    /// the remote TCP received the acknowledgment of its connection
    /// termination request.
    TimeWait,
    /// Represents no connection state at all.
    ///
    /// CLOSED is fictional because it represents the state when there is
    /// no TCB, and therefore, no connection.
    Closed,
}

impl TcpState {
    /// Is this a non-synchronised state?
    fn is_non_sync(&self) -> bool {
        match self {
            TcpState::Listen | TcpState::SynSent | TcpState::SynReceived => {
                true
            }
            _ => false,
        }
    }
}

/// In the spec this is called a Transmission Control Block (TCB)
///
/// ## Send Sequence Space
///
/// ```txt
///      1         2          3          4
/// ----------|----------|----------|----------
///        SND.UNA    SND.NXT    SND.UNA
///                             +SND.WND
/// ```
///
/// 1. old sequence numbers which have been acknowledged
/// 2. sequence numbers of unacknowledged data
/// 3. sequence numbers allowed for new data transmission
/// 4. future sequence numbers which are not yet allowed
///
/// ## Receive Sequence Space
///
/// ```txt
///      1          2          3
/// ----------|----------|----------
///        RCV.NXT    RCV.NXT
///                  +RCV.WND
/// ```
///
/// 1. old sequence numbers which have been acknowledged
/// 2. sequence numbers allowed for new reception
/// 3. future sequence numbers which are not yet allowed
#[allow(dead_code)]
struct Connection {
    id: ConnectionId,

    state: TcpState,

    /// Send unacknowledged
    ///
    /// Oldest unacknowledged sequence number
    snd_una: u32,
    /// Send next
    ///
    /// Next sequence number to be sent
    snd_nxt: u32,
    /// Send window
    snd_wnd: u16,
    /// Send urgent pointer
    snd_up: bool,
    /// Segment sequence number used for last window update
    snd_wl1: u32,
    /// Segment acknowledgment number used for last window update
    snd_wl2: u32,
    /// Initial send sequence number
    iss: u32,

    /// Receive next
    ///
    /// Next sequence number expected on an incoming segments, and
    /// is the left or lower edge of the receive window
    rcv_nxt: u32,
    /// Receive window
    rcv_wnd: u16,
    /// Receive urgent pointer
    rcv_up: bool,
    /// Initial receive sequence number
    irs: u32,
}

impl Connection {
    fn new(
        id: ConnectionId,
        hdr: &TcpHeader,
        seq_gen: &SeqGen,
    ) -> Option<Connection> {
        if hdr.rst {
            return None;
        }
        if hdr.ack {
            // TODO: send RST
            // <SEQ=SEG.ACK><CTL=RST>
        }
        if !hdr.syn {
            return None;
        }
        let iss = seq_gen.gen_iss();
        Some(Connection {
            id,
            state: TcpState::SynReceived,
            snd_una: iss,
            snd_nxt: iss,
            snd_wnd: 1024,
            snd_up: false,
            snd_wl1: 0,
            snd_wl2: 0,
            iss,
            rcv_nxt: hdr.sequence_number + 1,
            rcv_wnd: hdr.window_size,
            rcv_up: false,
            irs: hdr.sequence_number,
        })
    }

    fn send_syn_ack(
        &mut self,
        mut res_buf: &mut [u8],
    ) -> Result<Option<usize>> {
        // we need our SYN to be ACK'ed
        self.snd_nxt = self.snd_nxt.wrapping_add(1);

        let res = PacketBuilder::ip(match self.id {
            ConnectionId::V4 {
                local_addr,
                remote_addr,
                ..
            } => IpHeader::Version4(Ipv4Header::new(
                0,
                64,
                IpTrafficClass::Tcp,
                local_addr.octets(),
                remote_addr.octets(),
            )),
            ConnectionId::V6 {
                local_addr: _,
                remote_addr: _,
                ..
            } => unimplemented!(
              "Ipv6Header is a pain to create - the etherparse API is lacking"
            ),
        })
        .tcp(
            self.id.local_port(),
            self.id.remote_port(),
            self.snd_nxt,
            self.snd_wnd,
        )
        .syn()
        .ack(self.rcv_nxt);

        let res_len = res.size(0);

        res.write(&mut res_buf, &[])?;

        return Ok(Some(res_len));
    }

    fn receive(
        &mut self,
        hdr: &TcpHeader,
        mut res_buf: &mut [u8],
    ) -> Result<Option<usize>> {
        if hdr.ack {
            return self.receive_ack(&hdr, &mut res_buf);
        }
        Ok(None)
    }

    fn receive_ack(
        &mut self,
        hdr: &TcpHeader,
        mut res_buf: &mut [u8],
    ) -> Result<Option<usize>> {
        if !self.acceptable_ack(hdr) {
            if self.state.is_non_sync() {
                // TODO: RST, close connection?
                // <SEQ=SEG.ACK><CTL=RST>
            } else {
                // TODO:
                // send an empty acknowledgment segment containing the current
                // send-sequence number and an acknowledgment indicating the
                // next sequence number expected to be received
            }
        }
        if self.state == TcpState::SynReceived {
            self.state = TcpState::Established;
        }
        self.snd_una = hdr.acknowledgment_number;

        Ok(None)
    }

    fn send_rst(&mut self, mut res_buf: &mut [u8]) -> Result<Option<usize>> {
        // TODO:
        Ok(None)
    }

    fn acceptable_ack(&self, hdr: &TcpHeader) -> bool {
        acceptable_ack(self.snd_una, hdr.acknowledgment_number, self.snd_nxt)
    }
}

/// Is SEG.ACK acceptable, given SND.UNA and SND.NXT?
///
/// This wraps around the u32 number space.
///
/// `SND.UNA < SEG.ACK =< SND.NXT`
///
/// ```txt
/// ----------|----------|----------
///        SND.UNA    SND.NXT
/// ```
fn acceptable_ack(snd_una: u32, ack_num: u32, snd_nxt: u32) -> bool {
    is_between_wrapped(snd_una, ack_num, snd_nxt.wrapping_add(1))
}

fn wrapping_lt(lhs: u32, rhs: u32) -> bool {
    lhs.wrapping_sub(rhs) > (1 << 31)
}

/// Stolen from: https://github.com/jonhoo/rust-tcp
/// Which references: https://tools.ietf.org/html/rfc1323
fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    wrapping_lt(start, x) && wrapping_lt(x, end)
}

type Connections = HashMap<ConnectionId, Connection>;

pub struct Tcp {
    connections: Connections,
    seq_gen: SeqGen,
}

impl Tcp {
    pub fn new() -> Tcp {
        Tcp {
            connections: HashMap::default(),
            seq_gen: SeqGen {},
        }
    }

    pub fn receive(
        &mut self,
        ip_header: &IpHeader,
        tcp_header: &TcpHeader,
        payload: &[u8],
        // TODO: we don't want to just send this, we need to remember it in case we need to retransmit it
        mut res_buf: &mut [u8],
    ) -> Result<Option<usize>> {
        Tcp::verify_checksum(ip_header, tcp_header, payload)?;

        let conn_id = ConnectionId::from_incoming(&ip_header, &tcp_header);

        match self.connections.entry(conn_id) {
            Entry::Occupied(mut c) => {
                c.get_mut().receive(&tcp_header, &mut res_buf)
            }
            Entry::Vacant(entry) => {
                match Connection::new(conn_id, &tcp_header, &self.seq_gen) {
                    Some(conn) => {
                        let conn = entry.insert(conn);
                        conn.send_syn_ack(&mut res_buf)
                    }
                    None => {
                        // TODO: RST?
                        Ok(None)
                    }
                }
            }
        }
    }

    // TODO: test this works as I expect!
    fn verify_checksum(
        ip_header: &IpHeader,
        tcp_header: &TcpHeader,
        payload: &[u8],
    ) -> Result<()> {
        match ip_header {
            IpHeader::Version4(hdr) => {
                if tcp_header.calc_checksum_ipv4(hdr, &payload)?
                    != tcp_header.checksum
                {
                    return Err(TitError::ChecksumDifference);
                }
            }
            IpHeader::Version6(hdr) => {
                if tcp_header.calc_checksum_ipv6(hdr, &payload)?
                    != tcp_header.checksum
                {
                    return Err(TitError::ChecksumDifference);
                }
            }
        };
        Ok(())
    }
}

struct SeqGen {
    // TODO: some random number generator?
}
impl SeqGen {
    fn gen_iss(&self) -> u32 {
        0 // FIXME: generate a secure initial sequence number
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::{
        IpHeader, IpTrafficClass, Ipv4Header, PacketHeaders, SerializedSize,
        TcpHeader, TCP_MINIMUM_HEADER_SIZE,
    };

    #[test]
    fn original_syn() {
        let mut tcp = Tcp::new();

        let payload = [];
        let (req_ip_hdr, mut req_tcp_hdr) = create_headers(&payload);

        req_tcp_hdr.syn = true;
        req_tcp_hdr.checksum = req_tcp_hdr
            .calc_checksum_ipv4(&req_ip_hdr, &payload)
            .unwrap();

        let mut res_buf = [0u8; 1500];
        let res_len = tcp
            .receive(
                &IpHeader::Version4(req_ip_hdr),
                &req_tcp_hdr,
                &payload,
                &mut res_buf,
            )
            .unwrap();

        assert_eq!(
            res_len,
            Some(Ipv4Header::SERIALIZED_SIZE + TCP_MINIMUM_HEADER_SIZE),
            "response length should be size of IP+TCP headers"
        );
        let res_headers =
            PacketHeaders::from_ip_slice(&res_buf[..res_len.unwrap()]).unwrap();

        assert_eq!(
            res_headers.payload.len(),
            0,
            "should respond with no payload"
        );
        // let res_ip_hdr = res_headers.ip.unwrap();
        // TODO: assert we're responding to/from the correct IP
        let res_tcp_hdr = res_headers.transport.unwrap().tcp().unwrap();
        assert_eq!(res_tcp_hdr.syn, true, "should respond with a SYN");
        assert_eq!(res_tcp_hdr.ack, true, "should respond with an ACK");
        assert_eq!(
            res_tcp_hdr.acknowledgment_number,
            req_tcp_hdr.sequence_number + 1,
            "response should acknowledge the correct sequence number"
        );
    }

    #[test]
    fn three_way() {
        let mut tcp = Tcp::new();

        // SYN ->
        let mut syn_res_buf = [0u8; 1500];
        let syn_res_len = send_syn(&mut tcp, &mut syn_res_buf);

        // SYN/ACK <-
        let syn_ack_hdr =
            PacketHeaders::from_ip_slice(&syn_res_buf[..syn_res_len.unwrap()])
                .unwrap()
                .transport
                .unwrap()
                .tcp()
                .unwrap();

        // ACK ->
        let mut ack_res_buf = [0u8; 1500];
        let ack_res_len = send_ack(&mut tcp, &syn_ack_hdr, &mut ack_res_buf);

        assert_eq!(ack_res_len, None, "should be no response to the ACK");

        // TODO: assert state of `tcp`
    }

    fn send_syn(tcp: &mut Tcp, mut res_buf: &mut [u8]) -> Option<usize> {
        let payload = [];
        let (req_ip_hdr, mut req_tcp_hdr) = create_headers(&payload);
        req_tcp_hdr.syn = true;
        req_tcp_hdr.checksum = req_tcp_hdr
            .calc_checksum_ipv4(&req_ip_hdr, &payload)
            .unwrap();

        tcp.receive(
            &IpHeader::Version4(req_ip_hdr),
            &req_tcp_hdr,
            &payload,
            &mut res_buf,
        )
        .unwrap()
    }

    fn send_ack(
        tcp: &mut Tcp,
        hdr_to_ack: &TcpHeader,
        mut res_buf: &mut [u8],
    ) -> Option<usize> {
        let payload = [];
        let (req_ip_hdr, mut req_tcp_hdr) = create_headers(&payload);
        req_tcp_hdr.ack = true;
        req_tcp_hdr.acknowledgment_number = hdr_to_ack.sequence_number + 1;
        req_tcp_hdr.checksum = req_tcp_hdr
            .calc_checksum_ipv4(&req_ip_hdr, &payload)
            .unwrap();

        tcp.receive(
            &IpHeader::Version4(req_ip_hdr),
            &req_tcp_hdr,
            &payload,
            &mut res_buf,
        )
        .unwrap()
    }

    fn create_headers(payload: &[u8]) -> (Ipv4Header, TcpHeader) {
        let tcp_hdr = TcpHeader::new(4321, 80, 0, 1024);

        let ip_hdr = Ipv4Header::new(
            tcp_hdr.header_len() + payload.len() as u16,
            64,
            IpTrafficClass::Tcp,
            [192, 168, 0, 1],
            [10, 0, 0, 10],
        );

        (ip_hdr, tcp_hdr)
    }

    #[test]
    fn acceptable_ack_nowrap_simple_true() {
        let snd_una = 10;
        let snd_next = 20;
        let ack_num = 15;
        assert_eq!(acceptable_ack(snd_una, ack_num, snd_next), true);
    }

    #[test]
    fn acceptable_ack_nowrap_simple_false() {
        let snd_una = 10;
        let snd_next = 20;
        let ack_num = 25;
        assert_eq!(acceptable_ack(snd_una, ack_num, snd_next), false);
    }

    #[test]
    fn acceptable_ack_nowrap_una_ack_eq() {
        let snd_una = 10;
        let snd_next = 20;
        let ack_num = 10;
        assert_eq!(acceptable_ack(snd_una, ack_num, snd_next), false);
    }

    #[test]
    fn acceptable_ack_nowrap_nxt_ack_eq() {
        let snd_una = 10;
        let snd_next = 20;
        let ack_num = 20;
        assert_eq!(acceptable_ack(snd_una, ack_num, snd_next), true);
    }

    #[test]
    fn acceptable_ack_wrap_ack_under() {
        let snd_una = std::u32::MAX - 5;
        let snd_next = 5;
        let ack_num = std::u32::MAX - 1;
        assert_eq!(acceptable_ack(snd_una, ack_num, snd_next), true);
    }

    #[test]
    fn acceptable_ack_wrap_ack_over() {
        let snd_una = std::u32::MAX - 5;
        let snd_next = 5;
        let ack_num = 1;
        assert_eq!(acceptable_ack(snd_una, ack_num, snd_next), true);
    }
}
