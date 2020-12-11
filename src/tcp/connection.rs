use etherparse::{
    IpHeader, IpTrafficClass, Ipv4Header, PacketBuilder, PacketBuilderStep,
    TcpHeader,
};
use std::fmt;

use super::socket_id::ConnectionId;
use super::tcp::SeqGen;
use super::types::*;
use crate::errors::Result;

#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
enum State {
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

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
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

    state: State,

    /// Send unacknowledged
    ///
    /// Oldest unacknowledged sequence number
    snd_una: LocalSeqNum,
    /// Send next
    ///
    /// Next sequence number to be sent
    snd_nxt: LocalSeqNum,
    /// Send window
    snd_wnd: WindowSize,
    /// Send urgent pointer
    snd_up: bool,
    /// Segment sequence number used for last window update
    snd_wl1: RemoteSeqNum,
    /// Segment acknowledgment number used for last window update
    snd_wl2: LocalSeqNum,
    /// Initial send sequence number
    iss: LocalSeqNum,

    /// Receive next
    ///
    /// Next sequence number expected on an incoming segments, and
    /// is the left or lower edge of the receive window
    rcv_nxt: RemoteSeqNum,
    /// Receive window
    rcv_wnd: WindowSize,
    /// Receive urgent pointer
    rcv_up: bool,
    /// Initial receive sequence number
    irs: RemoteSeqNum,
}

impl Connection {
    pub fn new(
        id: ConnectionId,
        hdr: &TcpHeader,
        seq_gen: &SeqGen,
    ) -> Connection {
        let iss = seq_gen.gen_iss();
        Connection {
            id,
            state: State::SynReceived,
            snd_una: iss,
            snd_nxt: iss.wrapping_add(1),
            snd_wnd: 1024,
            snd_up: false,
            snd_wl1: 0,
            snd_wl2: 0,
            iss,
            rcv_nxt: hdr.sequence_number.wrapping_add(1),
            rcv_wnd: hdr.window_size,
            rcv_up: false,
            irs: hdr.sequence_number,
        }
    }

    pub fn receive(
        &mut self,
        hdr: &TcpHeader,
        payload: &[u8],
        mut res_buf: &mut [u8],
    ) -> Result<Option<usize>> {
        // TODO: first check sequence number
        match self.state {
            State::SynReceived
            | State::Established
            | State::FinWait1
            | State::FinWait2
            | State::CloseWait
            | State::Closing
            | State::LastAck
            | State::TimeWait => {
                // TODO: If the RCV.WND is zero, no segments will be acceptable,
                // but special allowance should be made to accept valid ACKs, URGs and RSTs.

                // If an incoming segment is not acceptable, an acknowledgment
                // should be sent in reply (unless the RST bit is set, if so
                // drop the segment and return):
                //     <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
                if !self.acceptable_seq_num(&hdr, &payload) {
                    if hdr.rst {
                        return Ok(None);
                    } else {
                        return self.send_ack(&mut res_buf);
                        // After sending the acknowledgment, drop the unacceptable
                        // segment and return.
                    }
                }
            }
            _ => {}
        }
        // TODO: NEXT
        // TODO: second check the RST bit
        // third check security and precedence (nah)
        // TODO: fourth, check the SYN bit
        // fifth check the ACK field
        if hdr.ack {
            // Note that once in the ESTABLISHED state all segments must carry current acknowledgment information
            // TODO: in some (all?) cases we don't want to return here, we want to keep processing
            self.receive_ack(&hdr, &mut res_buf)
        } else {
            // if the ACK bit is off drop the segment and return
            Ok(None)
        }
        // TODO: sixth, check the URG bit
        // uhhh we've already dropped the segment... WUT
        // TODO: seventh, process the segment text
        // TODO: eighth, check the FIN bit
    }

    fn receive_ack(
        &mut self,
        hdr: &TcpHeader,
        mut res_buf: &mut [u8],
    ) -> Result<Option<usize>> {
        if self.state == State::SynReceived {
            if self.acceptable_ack(hdr) {
                // enter ESTABLISHED state and continue processing
                self.state = State::Established;
            // TODO:
            // SND.WND <- SEG.WND
            // SND.WL1 <- SEG.SEQ
            // SND.WL2 <- SEG.ACK
            } else {
                return self.send_rst(
                    hdr.acknowledgment_number,
                    &mut res_buf,
                    "unacceptable ACK",
                );
            }
        }

        match self.state {
            State::Established
            | State::FinWait1
            | State::FinWait2
            | State::CloseWait
            | State::Closing => {
                if self.acceptable_ack(hdr) {
                    self.snd_una = hdr.acknowledgment_number;
                    // TODO: remove acknowledged segments from the retransmission queue
                    // TODO: the send window should be updated
                }
            }
            _ => {}
        }

        if self.state == State::FinWait1 {
            // TODO: if our FIN is now acknowledged then enter FIN-WAIT-2 and continue processing in that state
        }
        if self.state == State::FinWait2 {
            // TODO: if the retransmission queue is empty, the user's CLOSE can be acknowledged ("ok") but do not delete the TCB
        }
        if self.state == State::Closing {
            // TODO: if the ACK acknowledges our FIN then enter the TIME-WAIT state, otherwise ignore the segment
        }

        match self.state {
            State::Established
            | State::FinWait1
            | State::FinWait2
            | State::CloseWait
            | State::Closing
            | State::LastAck
            | State::TimeWait => {
                if !self.acceptable_ack(hdr) {
                    // If the ACK is a duplicate (SEG.ACK < SND.UNA), it can be ignored.

                    // If the ACK acks something not yet sent (SEG.ACK > SND.NXT) then send an ACK,
                    // drop the segment, and return.
                    if wrapping_lt(self.snd_nxt, hdr.acknowledgment_number) {
                        // If the connection is in a synchronized state (ESTABLISHED,
                        // FIN-WAIT-1, FIN-WAIT-2, CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT),
                        // any unacceptable segment (out of window sequence number or
                        // unacceptible acknowledgment number) must elicit only an empty
                        // acknowledgment segment containing the current send-sequence number
                        // and an acknowledgment indicating the next sequence number expected
                        // to be received, and the connection remains in the same state.
                        return self.send_ack(&mut res_buf);
                    }
                }
            }
            _ => {}
        }

        Ok(None)
    }

    pub fn send_syn_ack(
        &mut self,
        mut res_buf: &mut [u8],
    ) -> Result<Option<usize>> {
        let res = self
            .create_packet_builder()
            .tcp(
                self.id.local_port(),
                self.id.remote_port(),
                self.iss,
                self.snd_wnd,
            )
            .syn()
            .ack(self.rcv_nxt);

        let res_len = res.size(0);

        res.write(&mut res_buf, &[])?;

        Ok(Some(res_len))
    }

    pub fn send_ack(
        &mut self,
        mut res_buf: &mut [u8],
    ) -> Result<Option<usize>> {
        let res = self
            .create_packet_builder()
            .tcp(
                self.id.local_port(),
                self.id.remote_port(),
                self.snd_nxt,
                self.snd_wnd,
            )
            .ack(self.rcv_nxt);

        let res_len = res.size(0);

        res.write(&mut res_buf, &[])?;

        Ok(Some(res_len))
    }

    fn send_rst(
        &self,
        seq_num: LocalSeqNum,
        mut res_buf: &mut [u8],
        reason: &str,
    ) -> Result<Option<usize>> {
        println!("Sending RST - State: {} - Reason: {}", self.state, reason);
        Connection::send_rst_packet(&self.id, seq_num, &mut res_buf)
    }

    fn create_packet_builder(&self) -> PacketBuilderStep<IpHeader> {
        Connection::create_packet_builder_for(&self.id)
    }

    fn create_packet_builder_for(
        conn_id: &ConnectionId,
    ) -> PacketBuilderStep<IpHeader> {
        PacketBuilder::ip(match conn_id {
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
    }

    pub fn send_rst_packet(
        conn_id: &ConnectionId,
        seq_num: LocalSeqNum,
        mut res_buf: &mut [u8],
    ) -> Result<Option<usize>> {
        let res = Connection::create_packet_builder_for(&conn_id)
            .tcp(conn_id.local_port(), conn_id.remote_port(), seq_num, 0)
            .rst();

        let res_len = res.size(0);

        res.write(&mut res_buf, &[])?;

        return Ok(Some(res_len));
    }

    pub fn send_rst_ack_packet(
        conn_id: &ConnectionId,
        seq_num: LocalSeqNum,
        ack_num: RemoteSeqNum,
        mut res_buf: &mut [u8],
    ) -> Result<Option<usize>> {
        let res = Connection::create_packet_builder_for(&conn_id)
            .tcp(conn_id.local_port(), conn_id.remote_port(), seq_num, 0)
            .ack(ack_num)
            .rst();

        let res_len = res.size(0);

        res.write(&mut res_buf, &[])?;

        return Ok(Some(res_len));
    }

    fn acceptable_ack(&self, hdr: &TcpHeader) -> bool {
        acceptable_ack(self.snd_una, hdr.acknowledgment_number, self.snd_nxt)
    }

    /// Segment Receive  Test
    /// Length  Window
    /// ------- -------  -------------------------------------------
    ///    0       0     SEG.SEQ = RCV.NXT
    ///    0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
    ///   >0       0     not acceptable
    ///   >0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
    ///               or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
    fn acceptable_seq_num(&self, hdr: &TcpHeader, payload: &[u8]) -> bool {
        let seg_seq = hdr.sequence_number;
        let seg_len = super::tcp::segment_length(&hdr, &payload);

        match (seg_len, self.rcv_wnd) {
            (0, 0) => seg_seq == self.rcv_nxt,
            (0, _) => is_between_wrapped(
                self.rcv_nxt.wrapping_sub(1),
                seg_seq,
                self.rcv_nxt.wrapping_add(self.rcv_wnd.into()),
            ),
            (_, 0) => false,
            (_, _) => {
                is_between_wrapped(
                    self.rcv_nxt.wrapping_sub(1),
                    seg_seq,
                    self.rcv_nxt.wrapping_add(self.rcv_wnd.into()),
                ) || is_between_wrapped(
                    self.rcv_nxt.wrapping_sub(1),
                    seg_seq.wrapping_add(seg_len - 1),
                    self.rcv_nxt.wrapping_add(self.rcv_wnd.into()),
                )
            }
        }
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
fn acceptable_ack(
    snd_una: LocalSeqNum,
    ack_num: LocalSeqNum,
    snd_nxt: LocalSeqNum,
) -> bool {
    is_between_wrapped(snd_una, ack_num, snd_nxt.wrapping_add(1))
}

fn wrapping_lt(lhs: u32, rhs: u32) -> bool {
    lhs.wrapping_sub(rhs) > (1 << 31)
}

/// Stolen from: https://github.com/jonhoo/rust-tcp
/// Which references: https://tools.ietf.org/html/rfc1323
///
/// The distance between `start` and `end` must be <= 1<<31.
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
