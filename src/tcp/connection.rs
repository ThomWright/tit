use arraydeque::ArrayDeque;
use crossbeam_channel::Sender;
use etherparse::{
    IpHeader, IpTrafficClass, Ipv4Header, PacketBuilder, PacketBuilderStep,
    TcpHeader,
};
use std::fmt;

use super::tcp::SeqGen;
use super::types::*;
use super::{connection_id::ConnectionId, TcpError};
use super::{errors::TcpResult, ReceiveResult};
use crate::{
    errors::Result,
    nic::{EthernetPacket, SendEthernetPacket},
    TitError,
};

const DATA_BUFFER_SIZE: usize = 2 << 15;

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

impl State {
    fn is_synchronized(&self) -> bool {
        match self {
            State::Established => true,
            State::FinWait1 => true,
            State::FinWait2 => true,
            State::CloseWait => true,
            State::Closing => true,
            State::LastAck => true,
            State::TimeWait => true,
            _ => false,
        }
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// An error which needs communicating to the user of the connection.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum UserVisibleError {
    ConnectionRefused,
    ConnectionReset,
}

/// How was this connection opened?
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
enum OpenType {
    Passive,
    Active,
}

/// A new state variable MAX.SND.WND is defined as the largest window
/// that the local sender has ever received from its peer.
///
/// Implementations can also chose to hard code the MAX.SND.WND value to
/// the maximum permissible window size, i.e., 65535 in the absence of
/// window scaling.  In the presence of the window scaling option, the
/// value becomes (MAX.SND.WND << Snd.Wind.Scale).
///
/// TODO: track this in state.
///
/// [RFC](https://tools.ietf.org/html/rfc5961#section-5)
const MAX_SND_WND: u32 = 65_535;

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
#[derive(Debug)]
pub struct Connection {
    id: ConnectionId,

    state: State,

    open_type: OpenType,
    error: Option<UserVisibleError>,

    /// Send unacknowledged
    ///
    /// Oldest unacknowledged sequence number
    snd_una: LocalSeqNum,
    /// Send next
    ///
    /// Next sequence number to be sent (drops back on retransmission?)
    snd_nxt: LocalSeqNum,
    /// Max sequence number sent
    snd_max: LocalSeqNum,
    /// The sequence number of the sent FIN (if sent)
    snd_fin: Option<LocalSeqNum>,
    /// Send window
    snd_wnd: WindowSize,
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
    rcv_up: RemoteSeqNum,
    /// Initial receive sequence number
    irs: RemoteSeqNum,

    // Buffers for data

    // TODO: consider using ringbuf? https://crates.io/crates/ringbuf
    inc_buf: ArrayDeque<[u8; DATA_BUFFER_SIZE]>,
    /// A queue of [`Sender`]s over which to send data to the user, along with
    /// the number of bytes which can be sent.
    ///
    /// Each item in the queue represents a RECEIVE command.
    recv_req_q: Vec<(Sender<ReceiveResult>, usize)>,
    // TODO: out_buf: ...,
}

impl Connection {
    pub fn passive_open(
        id: ConnectionId,
        hdr: &TcpHeader,
        seq_gen: &SeqGen,
    ) -> Connection {
        let iss = seq_gen.gen_iss();
        let snd_nxt = iss.wrapping_add(1);
        let rcv_nxt = hdr.sequence_number.wrapping_add(1);
        Connection {
            id,
            state: State::SynReceived,
            open_type: OpenType::Passive,
            error: None,
            snd_una: iss,
            snd_nxt,
            snd_max: iss,
            snd_fin: None,
            snd_wnd: 1024,
            snd_wl1: 0,
            snd_wl2: 0,
            iss,
            rcv_nxt,
            rcv_wnd: hdr.window_size,
            rcv_up: rcv_nxt,
            irs: hdr.sequence_number,

            inc_buf: ArrayDeque::new(),
            recv_req_q: vec![],
        }
    }

    pub fn handle_close(
        &mut self,
        snd_packet: &SendEthernetPacket,
    ) -> Result<()> {
        use State::*;
        match self.state {
            Listen => {
                // Any outstanding RECEIVEs are returned with "error: closing"
                // responses.  Delete TCB, enter CLOSED state, and return.

                // nah
            }
            SynSent => {
                // TODO:
                // Delete the TCB and return "error: closing" responses to any
                // queued SENDs, or RECEIVEs.
                self.state = Closed;
            }
            SynReceived => {
                // TODO:
                // If no SENDs have been issued and there is no pending data to
                // send, then form a FIN segment and send it, and enter FIN-WAIT-1
                // state; otherwise queue for processing after entering
                // ESTABLISHED state.

                self.send_fin(&snd_packet)?;
                self.state = State::FinWait1;
            }
            Established => {
                // TODO:
                // Queue this until all preceding SENDs have been segmentized,
                // then form a FIN segment and send it.  In any case, enter FIN-
                // WAIT-1 state.

                self.send_fin(&snd_packet)?;
                self.state = State::FinWait1;
            }
            FinWait1 | FinWait2 => {
                // Strictly speaking, this is an error and should receive a
                // "error: connection closing" response.  An "ok" response would
                // be acceptable, too, as long as a second FIN is not emitted (the
                // first FIN may be retransmitted though).
            }
            Closed => {}
            CloseWait => {
                // TODO:
                // Queue this request until all preceding SENDs have been
                // segmentized; then send a FIN segment, enter LAST-ACK state.

                self.send_fin(&snd_packet)?;
                self.state = State::LastAck;
            }
            Closing | LastAck | TimeWait => {
                // Respond with "error: connection closing".

                // nah
            }
        }

        Ok(())
    }

    pub fn handle_receive(
        &mut self,
        snd_data: Sender<TcpResult<Vec<u8>>>,
        buf_len: usize,
    ) -> Result<()> {
        use State::*;
        let result = match self.state {
            Closed => {
                // If the user does not have access to such a connection, return
                // "error: connection illegal for this process".
                // Otherwise return "error: connection does not exist".
                Err(TcpError::NoConnection)
            }
            Listen | SynSent | SynReceived => {
                // Queue for processing after entering ESTABLISHED state.  If
                // there is no room to queue this request, respond with "error:
                // insufficient resources".
                self.recv_req_q.push((snd_data.clone(), buf_len));

                Ok(())
            }

            Established | FinWait1 | FinWait2 => {
                // TODO:
                // If insufficient incoming segments are queued to satisfy the
                // request, queue the request.  If there is no queue space to
                // remember the RECEIVE, respond with "error: insufficient
                // resources".
                //
                // Reassemble queued incoming segments into receive buffer and
                // return to user.  Mark "push seen" (PUSH) if this is the case.
                //
                // If RCV.UP is in advance of the data currently being passed to
                // the user notify the user of the presence of urgent data.
                //
                // When the TCP endpoint takes responsibility for delivering data
                // to the user that fact must be communicated to the sender via an
                // acknowledgment.  The formation of such an acknowledgment is
                // described below in the discussion of processing an incoming
                // segment.
                self.recv_req_q.push((snd_data.clone(), buf_len));

                self.handle_pending_receives()?;

                Ok(())
            }

            CloseWait => {
                // TODO:
                // Since the remote side has already sent FIN, RECEIVEs must be
                // satisfied by text already on hand, but not yet delivered to the
                // user.  If no text is awaiting delivery, the RECEIVE will get a
                // "error: connection closing" response.  Otherwise, any remaining
                // text can be used to satisfy the RECEIVE.
                Ok(())
            }

            Closing | LastAck | TimeWait => {
                // Return "error: connection closing".
                Err(TcpError::ConnectionClosing)
            }
        };

        if let Err(e) = result {
            snd_data.send(Err(e)).map_err(|e| {
                TitError::SendIncomingDataChannelClosed(self.id, e)
            })?;
        }

        Ok(())
    }

    fn handle_pending_receives(&mut self) -> Result<()> {
        while !self.inc_buf.is_empty() && !self.recv_req_q.is_empty() {
            if let Some((snd_data, buf_len)) = self.recv_req_q.pop() {
                let len = buf_len.min(self.inc_buf.len());
                let data = self.inc_buf.drain(..len).collect();
                snd_data.send(Ok(data)).map_err(|e| {
                    TitError::SendIncomingDataChannelClosed(self.id, e)
                })?;
            }
        }
        Ok(())
    }

    pub fn handle_segment(
        &mut self,
        hdr: &TcpHeader,
        payload: &[u8],
        mut res_buf: &mut [u8],
    ) -> Result<Option<usize>> {
        if self.state == State::SynSent {
            // TODO:
            // first check the ACK bit
            // second check the RST bit
            // third check the security
            // fourth check the SYN bit
            // fifth, if neither of the SYN or RST bits is set then drop the segment and return.
        }

        let acceptable_seq = self.acceptable_seq_num(&hdr, &payload);

        // first check sequence number
        if self.state.is_synchronized() {
            // TODO: If the RCV.WND is zero, no segments will be acceptable,
            // but special allowance should be made to accept valid ACKs, URGs and RSTs.

            // If an incoming segment is not acceptable, an acknowledgment
            // should be sent in reply (unless the RST bit is set, if so
            // drop the segment and return):
            //     <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
            if !acceptable_seq {
                if hdr.rst {
                    return Ok(None);
                } else {
                    return self.send_ack(&mut res_buf);
                    // After sending the acknowledgment, drop the unacceptable
                    // segment and return.
                }
            }
        }

        // second check the RST bit
        if hdr.rst {
            return if !acceptable_seq {
                // FIXME: redundant check
                Ok(None)
            } else if hdr.sequence_number == self.rcv_nxt {
                match self.state {
                    State::SynReceived => {
                        // If this connection was initiated with a passive OPEN
                        // (i.e., came from the LISTEN state), then return this
                        // connection to LISTEN state and return. The user need
                        // not be informed.
                        //
                        // If this connection was initiated with an active OPEN
                        // (i.e., came from SYN-SENT state) then the connection
                        // was refused, signal the user "connection refused".
                        // Enter the CLOSED state and delete the TCB, and return.
                        //
                        // In either case, all segments on the retransmission
                        // queue should be removed.
                        match self.open_type {
                            OpenType::Passive => {
                                self.state = State::Listen;
                                Ok(None)
                            }
                            OpenType::Active => {
                                self.error =
                                    Some(UserVisibleError::ConnectionRefused);
                                self.state = State::Closed;
                                Ok(None)
                            }
                        }
                    }
                    State::Established
                    | State::FinWait1
                    | State::FinWait2
                    | State::CloseWait => {
                        // TODO:
                        // If the RST bit is set then, any outstanding RECEIVEs and
                        // SEND should receive "reset" responses.  All segment
                        // queues should be flushed.  Users should also receive an
                        // unsolicited general "connection reset" signal.  Enter the
                        // CLOSED state, delete the TCB, and return.
                        self.error = Some(UserVisibleError::ConnectionReset);
                        self.state = State::Closed;
                        Ok(None)
                    }
                    State::Closing | State::LastAck | State::TimeWait => {
                        // If the RST bit is set then, enter the CLOSED state,
                        // delete the TCB, and return.
                        self.state = State::Closed;
                        Ok(None)
                    }
                    _ => panic!("received RST in unexpected state"),
                }
            } else {
                self.send_ack(&mut res_buf)
            };
        }

        // third check security and precedence (nah)

        // fourth, check the SYN bit
        if hdr.syn {
            match self.state {
                State::SynReceived => {
                    // If the connection was initiated with a passive OPEN, then
                    // return this connection to the LISTEN state and return.
                    self.state = State::Listen;
                    return Ok(None);
                }
                State::Established
                | State::FinWait1
                | State::FinWait2
                | State::CloseWait
                | State::Closing
                | State::LastAck
                | State::TimeWait => {
                    // TODO: For the TIME-WAIT state, new connections can be accepted
                    // if the timestamp option is used and meets expectations

                    // RFC 5961: If the SYN bit is set, irrespective of the sequence number, TCP
                    // MUST send an ACK (also referred to as challenge ACK) to the remote
                    // peer
                    return self.send_ack(&mut res_buf);
                }
                _ => {}
            }
        }

        // fifth check the ACK field
        if !hdr.ack {
            // if the ACK bit is off drop the segment and return
            return Ok(None);
        }
        // Note that once in the ESTABLISHED state all segments must carry current acknowledgment information

        // TCP stacks that implement RFC 5961 MUST add an input check that
        // the ACK value is acceptable only if it is in the range of
        // ((SND.UNA - MAX.SND.WND) =< SEG.ACK =< SND.NXT).
        // All incoming segments whose ACK value doesn't satisfy the above
        // condition MUST be discarded and an ACK sent back.
        if !(self.acceptable_ack_rfc5961(hdr)) {
            return self.send_ack(&mut res_buf);
        }

        if self.state == State::SynReceived {
            if self.acceptable_ack(hdr) {
                // enter ESTABLISHED state and continue processing
                self.state = State::Established;

                self.snd_wnd = hdr.window_size;
                self.snd_wl1 = hdr.sequence_number;
                self.snd_wl2 = hdr.acknowledgment_number;
            } else {
                return self.send_rst(
                    hdr.acknowledgment_number,
                    &mut res_buf,
                    "unacceptable ACK",
                );
            }
        }

        if self.state.is_synchronized() {
            if !self.acceptable_ack(hdr) {
                // If the ACK acks something not yet sent (SEG.ACK > SND.NXT) then send an ACK,
                // drop the segment, and return.
                if wrapping_lt(self.snd_nxt, hdr.acknowledgment_number) {
                    eprintln!("Unacceptable ACK - not yet sent");
                    return self.send_ack(&mut res_buf);
                }
                // If the ACK is a duplicate (SEG.ACK < SND.UNA), it can be ignored.
            }
        };

        match self.state {
            State::Established
            | State::FinWait1
            | State::FinWait2
            | State::CloseWait
            | State::Closing => {
                if self.acceptable_ack(hdr) {
                    self.snd_una = hdr.acknowledgment_number;
                    // TODO: remove acknowledged segments from the retransmission queue
                    // TODO: Users should receive positive acknowledgments for buffers that have been SENT and fully acknowledged
                    // (i.e., SEND buffer should be returned with "ok" response)

                    // TODO: the send window should be updated
                    // If (SND.WL1 < SEG.SEQ or (SND.WL1
                    // = SEG.SEQ and SND.WL2 =< SEG.ACK)), set SND.WND <-
                    // SEG.WND, set SND.WL1 <- SEG.SEQ, and set SND.WL2 <-
                    // SEG.ACK.

                    // Note that SND.WND is an offset from SND.UNA, that
                    // SND.WL1 records the sequence number of the last
                    // segment used to update SND.WND, and that SND.WL2
                    // records the acknowledgment number of the last segment
                    // used to update SND.WND.  The check here prevents using
                    // old segments to update the window.

                    let fin_acked = self.fin_acked();

                    if self.state == State::FinWait1 && fin_acked {
                        // if our FIN is now acknowledged then enter FIN-WAIT-2 and continue processing in that state
                        self.state = State::FinWait2;
                    }
                    if self.state == State::FinWait2 {
                        // TODO: if the retransmission queue is empty, the user's CLOSE can be acknowledged ("ok") but do not delete the TCB
                    }
                    if self.state == State::Closing && fin_acked {
                        // if the ACK acknowledges our FIN then enter the TIME-WAIT state, otherwise ignore the segment
                        self.state = State::TimeWait;
                    }
                }
            }
            _ => {}
        }

        if self.state == State::LastAck {
            // The only thing that can arrive in this state is an
            // acknowledgment of our FIN.  If our FIN is now
            // acknowledged, delete the TCB, enter the CLOSED state,
            // and return.
            if self.acceptable_ack(hdr) {
                self.snd_una = hdr.acknowledgment_number;

                if self.fin_acked() {
                    self.state = State::Closed;
                    return Ok(None);
                }
            }
        }
        if self.state == State::TimeWait {
            // The only thing that can arrive in this state is a
            // retransmission of the remote FIN.  Acknowledge it, and
            // restart the 2 MSL timeout.
            let fin_ack_retx = self.snd_una == hdr.acknowledgment_number;

            if fin_ack_retx {
                // TODO: restart MSL timeout
                return self.send_ack(&mut res_buf);
            }
        }

        // sixth, check the URG bit
        if let State::Established | State::FinWait1 | State::FinWait2 =
            self.state
        {
            if hdr.urg {
                // If the URG bit is set, RCV.UP <- max(RCV.UP,SEG.UP).
                let urgent_pointer =
                    hdr.sequence_number + hdr.urgent_pointer as u32;
                self.rcv_up = self.rcv_up.max(urgent_pointer);
                // TODO: Signal the user that the remote side has urgent data if
                // the urgent pointer (RCV.UP) is in advance of the data
                // consumed.  If the user has already been signaled (or is
                // still in the "urgent mode") for this continuous sequence
                // of urgent data, do not signal the user again.
            }
        }

        let mut should_send_ack = false;
        let mut should_handle_receives = false;

        // TODO: seventh, process the segment text
        if let State::Established | State::FinWait1 | State::FinWait2 =
            self.state
        {
            // Once in the ESTABLISHED state, it is possible to deliver
            // segment text to user RECEIVE buffers.  Text from segments
            // can be moved into buffers until either the buffer is full
            // or the segment is empty.  If the segment empties and
            // carries a PUSH flag, then the user is informed, when the
            // buffer is returned, that a PUSH has been received.

            // When the TCP endpoint takes responsibility for delivering
            // the data to the user it must also acknowledge the receipt
            // of the data.

            // Once the TCP endpoint takes responsibility for the data
            // it advances RCV.NXT over the data accepted, and adjusts
            // RCV.WND as appropriate to the current buffer
            // availability.  The total of RCV.NXT and RCV.WND should
            // not be reduced.

            // A TCP implementation MAY send an ACK segment
            // acknowledging RCV.NXT when a valid segment arrives that
            // is in the window but not at the left window edge (MAY-
            // 13).

            // TODO: put data in receive buffer
            // TODO: window management

            if !payload.is_empty() {
                self.rcv_nxt = self.rcv_nxt.wrapping_add(payload.len() as u32);
                self.inc_buf.extend_back(payload.to_owned());
                should_handle_receives = true;

                // TODO: This acknowledgment should be piggybacked on a segment
                // being transmitted if possible without incurring undue
                // delay.
                should_send_ack = true;
            }
        }

        // eighth, check the FIN bit
        if hdr.fin {
            // TODO:
            // If the FIN bit is set, signal the user "connection closing"
            // and return any pending RECEIVEs with same message/
            // Note that FIN implies PUSH for any segment text not
            // yet delivered to the user.

            // Do not process the FIN if the state is CLOSED, LISTEN or
            // SYN-SENT since the SEG.SEQ cannot be validated; drop the
            // segment and return.
            if self.state == State::SynSent {
                return Ok(None);
            }

            // Advance RCV.NXT over the FIN.
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);

            match self.state {
                State::SynReceived | State::Established => {
                    self.state = State::CloseWait
                }
                State::FinWait1 => {
                    // If our FIN has been ACKed (perhaps in this segment),
                    // then enter TIME-WAIT, start the time-wait timer, turn
                    // off the other timers; otherwise enter the CLOSING
                    // state.
                    if self.fin_acked() {
                        self.state = State::TimeWait;
                    // TODO: start the time-wait timer, turn off the other timers
                    } else {
                        self.state = State::Closing;
                    }
                }
                State::FinWait2 => {
                    self.state = State::TimeWait;
                    // TODO: Start the time-wait timer, turn off the other timers.
                }
                State::TimeWait => {
                    // TODO: Restart the 2 MSL time-wait timeout.
                }
                _ => {}
            }

            // Send an acknowledgment for the FIN.
            return self.send_ack(&mut res_buf);
        }

        // TODO: need to work out when best to handling pending receives...
        if should_handle_receives {
            self.handle_pending_receives()?;
        }

        if should_send_ack {
            self.send_ack(&mut res_buf)
        } else {
            Ok(None)
        }
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

    pub fn send_fin(&mut self, snd_packet: &SendEthernetPacket) -> Result<()> {
        self.snd_fin = Some(self.snd_nxt);

        let packet = self
            .create_packet_builder()
            .tcp(
                self.id.local_port(),
                self.id.remote_port(),
                self.snd_nxt,
                self.snd_wnd,
            )
            .fin()
            .ack(self.rcv_nxt);

        self.snd_nxt = self.snd_nxt.wrapping_add(1);
        self.snd_max = self.snd_max.wrapping_add(1);

        let len = packet.size(0);

        let mut buf: Box<EthernetPacket> = Box::new([0; 1500]);

        // UGH
        packet.write(&mut &mut buf[..], &[])?;

        snd_packet
            .send((buf, len))
            .map_err(|e| TitError::NetworkPacketSendFailure(e))?;

        Ok(())
    }

    fn send_rst(
        &self,
        seq_num: LocalSeqNum,
        mut res_buf: &mut [u8],
        reason: &str,
    ) -> Result<Option<usize>> {
        Connection::send_rst_packet(
            &self.id,
            seq_num,
            &mut res_buf,
            &format!("{} - State: {}", reason, self.state),
        )
    }

    fn create_packet_builder(&self) -> PacketBuilderStep<IpHeader> {
        Connection::create_packet_builder_for(&self.id)
    }

    fn create_packet_builder_for(
        conn_id: &ConnectionId,
    ) -> PacketBuilderStep<IpHeader> {
        PacketBuilder::ip(match conn_id {
            ConnectionId::V4 {
                remote_socket,
                local_socket,
            } => IpHeader::Version4(Ipv4Header::new(
                0,
                64,
                IpTrafficClass::Tcp,
                local_socket.ip().octets(),
                remote_socket.ip().octets(),
            )),
            ConnectionId::V6 {
                remote_socket: _,
                local_socket: _,
            } => unimplemented!(
            "Ipv6Header is a pain to create - the etherparse API is lacking"
          ),
        })
    }

    pub fn send_rst_packet(
        conn_id: &ConnectionId,
        seq_num: LocalSeqNum,
        mut res_buf: &mut [u8],
        reason: &str,
    ) -> Result<Option<usize>> {
        eprintln!("Sending RST - Reason: {}", reason);

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
        reason: &str,
    ) -> Result<Option<usize>> {
        eprintln!("Sending RST/ACK - Reason: {}", reason);

        let res = Connection::create_packet_builder_for(&conn_id)
            .tcp(conn_id.local_port(), conn_id.remote_port(), seq_num, 0)
            .ack(ack_num)
            .rst();

        let res_len = res.size(0);

        res.write(&mut res_buf, &[])?;

        return Ok(Some(res_len));
    }

    /// TODO: more descriptive name
    /// `(SND.UNA - MAX.SND.WND) <= SEG.ACK <=SND.NXT`
    fn acceptable_ack_rfc5961(&self, hdr: &TcpHeader) -> bool {
        wrapping_lt(
            self.snd_una.wrapping_sub(MAX_SND_WND).wrapping_sub(1),
            hdr.acknowledgment_number,
        ) && wrapping_lt(
            hdr.acknowledgment_number,
            self.snd_nxt.wrapping_add(1),
        )
    }

    /// `SND.UNA < SEG.ACK =< SND.NXT`
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

    /// Has our FIN been ACKed?
    fn fin_acked(&self) -> bool {
        self.snd_fin
            .map_or(false, |fin_seq| self.snd_una == fin_seq.wrapping_add(1))
    }

    /// Should the connection state be deleted?
    pub fn should_delete(&self) -> bool {
        match self.state {
            State::Closed | State::Listen => true,
            _ => false,
        }
    }

    pub fn user_error(&self) -> Option<UserVisibleError> {
        self.error
    }
}

/// Is SEG.ACK acceptable, given SND.UNA and SND.NXT?
///
/// This wraps around the u32 number space.
///
/// A new acknowledgment (called an "acceptable ack"), is one for which the inequality below holds:
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
