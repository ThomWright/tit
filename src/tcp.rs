use etherparse::{IpHeader, IpTrafficClass, Ipv4Header, PacketBuilder, TcpHeader};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fmt;
use std::fmt::{Display, Formatter};

use crate::errors::TitError;
use crate::ip_utils::IpPair;
use crate::print;

/// From the spec:
///
/// > To allow for many processes within a single Host to use TCP
/// > communication facilities simultaneously, the TCP provides a set of
/// > addresses or ports within each host.  Concatenated with the network
/// > and host addresses from the internet communication layer, this forms
/// > a socket.  A pair of sockets uniquely identifies each connection.
///
/// Written from the point of view of an incoming connection.
///
/// TODO: remove `IpPair` and just make this an enum?
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct ConnectionId {
  ip_addrs: IpPair,
  src_port: u16,
  dst_port: u16,
}

impl ConnectionId {
  pub fn new(ip_header: &IpHeader, tcp_header: &TcpHeader) -> ConnectionId {
    let ips = IpPair::from(ip_header);

    ConnectionId {
      ip_addrs: ips,
      src_port: tcp_header.source_port,
      dst_port: tcp_header.destination_port,
    }
  }
}

impl Display for ConnectionId {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    match self.ip_addrs {
      IpPair::V4 { src, .. } => write!(f, "{}:{}", src, self.src_port)?,
      IpPair::V6 { src, .. } => write!(f, "{}:{}", src, self.src_port)?,
    };
    write!(f, " -> ")?;
    match self.ip_addrs {
      IpPair::V4 { dst, .. } => write!(f, "{}:{}", dst, self.dst_port)?,
      IpPair::V6 { dst, .. } => write!(f, "{}:{}", dst, self.dst_port)?,
    };
    Ok(())
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

struct ConnectionState {
  state: TcpState,
}

/// In the spec this is called a Transmission Control Block (TCB)
type Connections = HashMap<ConnectionId, ConnectionState>;

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

    // print::tcp_header(&tcp_header);
    // println!("{:#?}", tcp_header);
    // println!("{:#?}", tcp_header.options_iterator().collect::<Vec<_>>());

    if tcp_header.syn {
      match self.connections.entry(conn_id) {
        Entry::Occupied(_) => {}
        Entry::Vacant(entry) => {
          entry.insert(ConnectionState {
            state: TcpState::SynReceived,
          });

          // TODO: just echo back for now, do something better later
          let res = PacketBuilder::ip(match conn_id.ip_addrs {
            IpPair::V4 { src, dst } => IpHeader::Version4(Ipv4Header::new(
              0,
              64,
              IpTrafficClass::Tcp,
              dst.octets(),
              src.octets(),
            )),
            IpPair::V6 { .. } => unimplemented!(),
          })
          .tcp(
            conn_id.dst_port,
            conn_id.src_port,
            tcp_header.sequence_number + 1, // FIXME: lol
            tcp_header.window_size,         // TODO: uuhhh just use whatever the client uses
          )
          .syn()
          .ack(tcp_header.sequence_number);

          let res_payload = payload;
          let res_len = res.size(res_payload.len());

          res.write(&mut res_buf, res_payload)?;

          return Ok(Some(res_len));
        }
      }
    }
    Ok(None)
  }
}
