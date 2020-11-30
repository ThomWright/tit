use etherparse::TcpHeader;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct ConnectionId {
  src_addr: IpAddr,
  src_port: u16,
  dst_addr: IpAddr,
  dst_port: u16,
}

impl ConnectionId {
  pub fn new(src_addr: IpAddr, src_port: u16, dst_addr: IpAddr, dst_port: u16) -> ConnectionId {
    ConnectionId {
      src_addr,
      src_port,
      dst_addr,
      dst_port,
    }
  }
}

impl Display for ConnectionId {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "{}:{} -> {}:{}",
      self.src_addr, self.src_port, self.dst_addr, self.dst_port
    )
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
    connection_id: ConnectionId,
    header: &TcpHeader,
    payload: &[u8],
    response: &mut [u8],
  ) -> Option<usize> {
    if header.syn {
      match self.connections.entry(connection_id) {
        Entry::Occupied(_) => {}
        Entry::Vacant(entry) => {
          entry.insert(ConnectionState {
            state: TcpState::SynReceived,
          });
        }
      }
    }
    None
  }
}
