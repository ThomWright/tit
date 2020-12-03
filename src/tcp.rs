use etherparse::{IpHeader, IpTrafficClass, Ipv4Header, PacketBuilder, TcpHeader};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::errors::TitError;
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
  pub fn new(incoming_ip_header: &IpHeader, incoming_tcp_header: &TcpHeader) -> ConnectionId {
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
  Closed,
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
struct Connection {
  state: TcpState,

  /// Send unacknowledged
  snd_una: u32,
  /// Send next
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
  rcv_nxt: u32,
  /// Receive window
  rcv_wnd: u16,
  /// Receive urgent pointer
  rcv_up: bool,
  /// Initial receive sequence number
  irs: u32,
}

impl Default for Connection {
  fn default() -> Self {
    Connection {
      state: TcpState::Closed,
      snd_una: 0,
      snd_nxt: 0,
      snd_wnd: 0,
      snd_up: false,
      snd_wl1: 0,
      snd_wl2: 0,
      iss: 0,
      rcv_nxt: 0,
      rcv_wnd: 0,
      rcv_up: false,
      irs: 0,
    }
  }
}

impl Connection {
  fn new_incoming(hdr: &TcpHeader, iss: u32) -> Connection {
    Connection {
      state: TcpState::SynReceived,
      iss,
      snd_una: iss,
      snd_nxt: iss,
      irs: hdr.sequence_number,
      rcv_nxt: hdr.sequence_number + 1,
      rcv_wnd: hdr.window_size,
      ..Connection::default()
    }
  }
}

type Connections = HashMap<ConnectionId, Connection>;

pub struct Tcp {
  connections: Connections,
}

impl Tcp {
  pub fn new() -> Tcp {
    Tcp {
      connections: HashMap::default(),
    }
  }

  pub fn receive(
    &mut self,
    ip_header: &IpHeader,
    tcp_header: &TcpHeader,
    payload: &[u8],
    // TODO: we don't want to just send this, we need to remember it in case we need to retransmit it
    mut res_buf: &mut [u8],
  ) -> Result<Option<usize>, TitError> {
    // TODO: verify checksum

    let conn_id = ConnectionId::new(&ip_header, &tcp_header);

    if tcp_header.syn {
      match self.connections.entry(conn_id) {
        Entry::Occupied(_) => {}
        Entry::Vacant(entry) => {
          let conn = Connection::new_incoming(&tcp_header, Tcp::gen_iss());

          // TODO: just echo back for now, do something better later
          let res = PacketBuilder::ip(match conn_id {
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
            } => unimplemented!("Ipv6Header is a pain to create - the etherparse API is lacking"),
          })
          .tcp(
            conn_id.local_port(),
            conn_id.remote_port(),
            conn.snd_nxt,
            conn.snd_wnd,
          )
          .syn()
          .ack(conn.rcv_nxt);

          entry.insert(conn);

          let res_payload = payload;
          let res_len = res.size(res_payload.len());

          res.write(&mut res_buf, res_payload)?;

          return Ok(Some(res_len));
        }
      }
    }
    Ok(None)
  }

  fn gen_iss() -> u32 {
    0 // FIXME: generate a secure initial sequence number
  }
}
