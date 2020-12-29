use etherparse::{IpHeader, TcpHeader};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{mpsc, Arc, Mutex};

use super::connection::Connection;
use super::connection::UserVisibleError;
use super::connection_id::ConnectionId;
// use super::interfaces::{SharedStreams, TcpListener};
use super::types::*;
use crate::{
    errors::{Result, TcpChannelError, TitError},
    nic::{EthernetPacket, SendEthernetPacket},
};

#[derive(Debug)]
pub(crate) struct TcpPacket {
    ip_hdr: IpHeader,
    tcp_hdr: TcpHeader,
    payload: Box<[u8]>,
}
impl TcpPacket {
    pub fn new(
        ip_hdr: IpHeader,
        tcp_hdr: TcpHeader,
        payload: &[u8],
    ) -> TcpPacket {
        TcpPacket {
            ip_hdr,
            tcp_hdr,
            payload: Box::from(payload),
        }
    }
}

pub struct IncomingPackets(pub(crate) mpsc::Sender<TcpPacket>);

// pub(crate) enum TcpCommand {
//     Listen {
//         socket: SocketAddr,
//         ack: mpsc::Sender<Result<TcpListener>>,
//     },
//     // Send,
// }

pub struct TcpControl {
    /// On Linux it looks like if SO_REUSEPORT is set then we can get a stack of listening sockets on the same port.
    /// Let's not bother with that for now.
    listening_sockets: HashMap<
        PortNum,
        (
            SocketAddr,
            mpsc::Sender<(
                SocketAddr,
                (), // TODO: Arc<SharedStreams>
            )>,
        ),
    >,
}

impl TcpControl {
    // TODO: fn listen(&mut self, socket: SocketAddr) -> Result<TcpListener> {
    pub fn listen(&mut self, socket: SocketAddr) -> Result<()> {
        match self.listening_sockets.entry(socket.port()) {
            Entry::Occupied(_) => Err(TitError::EADDRINUSE),
            Entry::Vacant(entry) => {
                let (snd, rcv) = mpsc::channel();
                entry.insert((socket, snd));
                // TODO: Ok(TcpListener::new(rcv))
                Ok(())
            }
        }
    }
}

impl Default for TcpControl {
    fn default() -> Self {
        TcpControl {
            listening_sockets: HashMap::default(),
        }
    }
}

pub struct Tcp {
    control: Arc<Mutex<TcpControl>>,

    connections: HashMap<ConnectionId, Connection>,
    seq_gen: SeqGen,

    incoming_segments: mpsc::Receiver<TcpPacket>,
    // commands: mpsc::Receiver<TcpCommand>,
}

impl Tcp {
    pub fn new() -> (Tcp, IncomingPackets) {
        // let (cmd_snd, cmd_rcv) = mpsc::channel();
        let (inc_segment_snd, inc_segment_rcv) = mpsc::channel();
        (
            Tcp {
                control: Arc::default(),
                connections: HashMap::default(),
                seq_gen: SeqGen {},
                incoming_segments: inc_segment_rcv,
                // commands: cmd_rcv,
            },
            // cmd_snd,
            IncomingPackets(inc_segment_snd),
        )
    }

    pub fn start(
        mut self,
        send_packet: SendEthernetPacket,
    ) -> Arc<Mutex<TcpControl>> {
        // TODO: handle shutdown
        let control = self.control.clone();
        let _tcp_thread = std::thread::spawn(move || {
            let mut run = || -> Result<()> {
                let segment = self.incoming_segments.recv().map_err(|e| {
                    TitError::IncomingTcpChannelClosed(TcpChannelError::Recv(e))
                })?;

                let mut res_buf: EthernetPacket = [0u8; 1500];

                let len = self.receive(
                    &segment.ip_hdr,
                    &segment.tcp_hdr,
                    &segment.payload,
                    &mut res_buf,
                )?;

                if let Some(len) = len {
                    send_packet
                        .send((Box::new(res_buf), len))
                        .map_err(|e| TitError::NetworkPacketSendFailure(e))?;
                }

                Ok(())
            };

            loop {
                run().expect("error in TCP loop");
            }
        });
        control
    }

    // fn on_tick(&mut self) {
    //     // TODO: receive commands
    //     // TODO: handle timers
    //     while let Ok(cmd) = self.commands.try_recv() {
    //         match cmd {
    //             TcpCommand::Listen { socket, ack } => {
    //                 let result = self.listen(socket);
    //                 ack.send(result).expect("listen result channel not open");
    //             }
    //         }
    //     }
    // }

    // TODO: rename to on_packet?
    fn receive(
        &mut self,
        ip_hdr: &IpHeader,
        tcp_hdr: &TcpHeader,
        payload: &[u8],
        // From RFC1122:
        // In general, the processing of received segments MUST be
        // implemented to aggregate ACK segments whenever possible.
        // For example, if the TCP is processing a series of queued
        // segments, it MUST process them all before sending any ACK
        // segments.
        mut res_buf: &mut [u8],
    ) -> Result<Option<usize>> {
        Tcp::verify_checksum(ip_hdr, tcp_hdr, payload)?;

        let conn_id = ConnectionId::from_incoming(&ip_hdr, &tcp_hdr);

        match self.connections.entry(conn_id) {
            Entry::Occupied(mut entry) => {
                let conn = entry.get_mut();
                let res = conn.receive(&tcp_hdr, &payload, &mut res_buf);
                if let Some(error) = conn.user_error() {
                    // TODO: inform the user of any errors
                    match error {
                        UserVisibleError::ConnectionRefused => {
                            println!("connection refused")
                        }
                        UserVisibleError::ConnectionReset => {
                            println!("connection reset")
                        }
                    }
                }
                if conn.should_delete() {
                    entry.remove();
                    // TODO: flush any segment queues
                }
                res
            }
            Entry::Vacant(conn_entry) => {
                // Check we have a matching LISTEN-ing socket
                let conn_local = &conn_id.local_socket();

                // TODO: can we reduce lifetime of this lock?
                let control =
                    self.control.lock().expect("unable to get control lock");
                if let Some((_, snd)) = control
                    .listening_sockets
                    .get(&conn_local.port())
                    .filter(|(listening, _)| {
                        println!("{} - {}", listening, conn_local);
                        listening.ip().is_unspecified()
                            || listening.ip().eq(&conn_local.ip())
                    })
                {
                    // State: LISTEN

                    // first check for an RST
                    if tcp_hdr.rst {
                        Ok(None)

                    // second check for an ACK
                    } else if tcp_hdr.ack {
                        Connection::send_rst_packet(
                            &conn_id,
                            tcp_hdr.acknowledgment_number,
                            &mut res_buf,
                            "ACK received in LISTEN state",
                        )

                    // third check for a SYN
                    } else if tcp_hdr.syn {
                        // New connection
                        let conn = conn_entry.insert(Connection::passive_open(
                            conn_id,
                            &tcp_hdr,
                            &self.seq_gen,
                        ));
                        // snd.send((conn_id.remote_socket(), conn.streams()))
                        //     .expect("TcpListener closed?");
                        conn.send_syn_ack(&mut res_buf)

                    // fourth other text or control
                    } else {
                        // you are unlikely to get here, but if you do, drop the segment, and return
                        Ok(None)
                    }
                } else {
                    // if CLOSED (no matching socket in LISTEN state):
                    //   if RST: discard
                    //   else:
                    //     if ACK: <SEQ=SEG.ACK><CTL=RST>
                    //     else: <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
                    if tcp_hdr.rst {
                        Ok(None)
                    } else {
                        if tcp_hdr.ack {
                            // <SEQ=SEG.ACK><CTL=RST>
                            Connection::send_rst_packet(
                                &conn_id,
                                tcp_hdr.acknowledgment_number,
                                &mut res_buf,
                                "ACK received in CLOSED state",
                            )
                        } else {
                            // <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
                            // SEG.LEN = the number of octets occupied by the data in the segment(counting SYN and FIN)
                            Connection::send_rst_ack_packet(
                                &conn_id,
                                0,
                                tcp_hdr.sequence_number
                                    + segment_length(&tcp_hdr, &payload),
                                &mut res_buf,
                                "SYN received in CLOSED state",
                            )
                        }
                    }
                }
            }
        }
    }

    // TODO: test this works as I expect!
    fn verify_checksum(
        ip_hdr: &IpHeader,
        tcp_hdr: &TcpHeader,
        payload: &[u8],
    ) -> Result<()> {
        match ip_hdr {
            IpHeader::Version4(hdr) => {
                if tcp_hdr.calc_checksum_ipv4(hdr, &payload)?
                    != tcp_hdr.checksum
                {
                    return Err(TitError::ChecksumDifference);
                }
            }
            IpHeader::Version6(hdr) => {
                if tcp_hdr.calc_checksum_ipv6(hdr, &payload)?
                    != tcp_hdr.checksum
                {
                    return Err(TitError::ChecksumDifference);
                }
            }
        };
        Ok(())
    }
}

pub fn segment_length(tcp_hdr: &TcpHeader, payload: &[u8]) -> u32 {
    payload.len() as u32
        + if tcp_hdr.syn { 1 } else { 0 }
        + if tcp_hdr.fin { 1 } else { 0 }
}

pub struct SeqGen {
    // TODO: some random number generator?
}
impl SeqGen {
    pub fn gen_iss(&self) -> LocalSeqNum {
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
    use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};

    const SERVER_ADDR: [u8; 4] = [192, 168, 0, 1];
    const CLIENT_ADDR: [u8; 4] = [127, 0, 0, 1];
    const SERVER_PORT: PortNum = 4434;
    const CLIENT_PORT: PortNum = 4321;

    #[test]
    fn closed_socket_syn() {
        // No listening sockets
        let (mut tcp, _) = Tcp::new();

        let client_iss = 10;
        let mut res_buf = [0u8; 1500];
        let res_len =
            send_syn(&mut tcp, &mut res_buf, client_iss).expect("no response");

        let (_, res_tcp_hdr, payload_len) =
            extract_headers(&res_buf[..res_len]);

        // <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
        assert_eq!(payload_len, 0, "should respond with no payload");
        assert_eq!(res_tcp_hdr.rst, true, "should respond with a RST");
        assert_eq!(res_tcp_hdr.ack, true, "should respond with an ACK");
        assert_eq!(
            res_tcp_hdr.sequence_number, 0,
            "sequence number should be 0"
        );
        assert_eq!(
            res_tcp_hdr.acknowledgment_number,
            client_iss + 1,
            "acknowledgement number should be SEG.SEQ+SEG.LEN"
        );
    }

    #[test]
    fn passive_open_original_syn() {
        let mut tcp = new_listening_tcp();

        let client_iss = 0;

        let mut res_buf = [0u8; 1500];
        let res_len = send_syn(&mut tcp, &mut res_buf, client_iss);

        assert_eq!(
            res_len,
            Some(Ipv4Header::SERIALIZED_SIZE + TCP_MINIMUM_HEADER_SIZE),
            "response length should be size of IP+TCP headers"
        );

        let (res_ip_hdr, res_tcp_hdr, payload_len) =
            extract_headers(&res_buf[..res_len.unwrap()]);

        assert_eq!(payload_len, 0, "should respond with no payload");
        assert!(matches!(res_ip_hdr, IpHeader::Version4(..)));
        match res_ip_hdr {
            IpHeader::Version4(hdr) => {
                assert_eq!(hdr.destination, CLIENT_ADDR);
                assert_eq!(hdr.source, SERVER_ADDR);
            }
            _ => panic!("expected IPv4"),
        }
        assert_eq!(res_tcp_hdr.syn, true, "should respond with a SYN");
        assert_eq!(res_tcp_hdr.ack, true, "should respond with an ACK");
        assert_eq!(
            res_tcp_hdr.acknowledgment_number,
            client_iss + 1,
            "response should acknowledge the correct sequence number"
        );
        assert!(
            tcp.connections
                .get(&ConnectionId::V4 {
                    remote_socket: SocketAddrV4::new(
                        Ipv4Addr::from(CLIENT_ADDR),
                        CLIENT_PORT
                    ),
                    local_socket: SocketAddrV4::new(
                        Ipv4Addr::from(SERVER_ADDR),
                        SERVER_PORT
                    ),
                })
                .is_some(),
            "connection should exist"
        );
    }

    #[test]
    fn passive_open_three_way() {
        let mut tcp = new_listening_tcp();

        let client_iss = 0;

        // SYN ->
        let mut syn_res_buf = [0u8; 1500];
        let syn_res_len = send_syn(&mut tcp, &mut syn_res_buf, client_iss);

        // SYN/ACK <-
        let (_, syn_ack_hdr, _) =
            extract_headers(&syn_res_buf[..syn_res_len.unwrap()]);

        // ACK ->
        let mut ack_res_buf = [0u8; 1500];
        let ack_res_len = send_ack(
            &mut tcp,
            &syn_ack_hdr,
            &mut ack_res_buf,
            client_iss.wrapping_add(1),
        );

        assert_eq!(ack_res_len, None, "should be no response to the ACK");

        // TODO: assert state of `tcp` - connection should be ESTABLISHED
        // but that's private, so would need to test in connection.rs
    }

    #[test]
    #[ignore]
    fn unacceptable_ack_in_state_syn_received() {
        // TODO: should receive RST
    }

    #[test]
    #[ignore]
    fn unacceptable_ack_in_state_established() {
        // TODO: should receive ACK
    }

    #[test]
    #[ignore]
    fn duplicate_ack_in_state_established() {
        // TODO: should receive no response
    }

    #[test]
    #[ignore]
    fn unacceptable_seq_num() {
        // TODO: should receive an ACK in response
    }

    fn send_syn(
        tcp: &mut Tcp,
        mut res_buf: &mut [u8],
        seq_num: LocalSeqNum,
    ) -> Option<usize> {
        let payload = [];
        let (req_ip_hdr, mut req_tcp_hdr) = create_headers(&payload, seq_num);
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
        seq_num: LocalSeqNum,
    ) -> Option<usize> {
        let payload = [];
        let (req_ip_hdr, mut req_tcp_hdr) = create_headers(&payload, seq_num);
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

    fn create_headers(
        payload: &[u8],
        seq_num: LocalSeqNum,
    ) -> (Ipv4Header, TcpHeader) {
        let tcp_hdr = TcpHeader::new(CLIENT_PORT, SERVER_PORT, seq_num, 1024);

        let ip_hdr = Ipv4Header::new(
            tcp_hdr.header_len() + payload.len() as u16,
            64,
            IpTrafficClass::Tcp,
            CLIENT_ADDR,
            SERVER_ADDR,
        );

        (ip_hdr, tcp_hdr)
    }

    fn new_listening_tcp() -> Tcp {
        let (tcp, _) = Tcp::new();
        {
            let mut control =
                tcp.control.lock().expect("unable to get control lock");
            control
                .listen(SocketAddr::new(
                    IpAddr::from(Ipv4Addr::UNSPECIFIED),
                    SERVER_PORT,
                ))
                .unwrap();
        }
        tcp
    }

    fn extract_headers(buf: &[u8]) -> (IpHeader, TcpHeader, usize) {
        let headers = PacketHeaders::from_ip_slice(&buf)
            .expect("unable to parse headers");

        let ip_hdr = headers.ip.expect("unable to parse IP header");

        let tcp_hdr = headers
            .transport
            .expect("unable to parse TCP/UDP header")
            .tcp()
            .expect("unable to parse TCP header");

        (ip_hdr, tcp_hdr, headers.payload.len())
    }
}
