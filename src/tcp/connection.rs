use etherparse::{
    IpHeader, IpTrafficClass, Ipv4Header, PacketBuilder, TcpHeader,
};

use super::connection_id::ConnectionId;
use super::tcp::SeqGen;
use crate::errors::Result;

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
pub struct Connection {
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
    pub fn new(
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

    pub fn send_syn_ack(
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

    pub fn receive(
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

#[cfg(test)]
mod tests {
    use super::*;

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
