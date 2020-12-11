use etherparse::{IpHeader, TcpHeader};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::net::SocketAddr;

use super::connection::Connection;
use super::socket_id::{ConnectionId, ListeningSocketId};
use super::types::*;
use crate::errors::{Result, TitError};

pub struct Tcp {
    listening_sockets: HashMap<SocketAddr, ListeningSocketId>,
    connections: HashMap<ConnectionId, Connection>,
    seq_gen: SeqGen,
}

impl Tcp {
    pub fn new() -> Tcp {
        Tcp {
            listening_sockets: HashMap::default(),
            connections: HashMap::default(),
            seq_gen: SeqGen {},
        }
    }

    pub fn listen(&mut self, socket: ListeningSocketId) -> Result<()> {
        let ls = socket.local_socket();
        match self.listening_sockets.entry(ls) {
            Entry::Occupied(_) => Err(TitError::EADDRINUSE),
            Entry::Vacant(entry) => {
                entry.insert(socket);
                Ok(())
            }
        }
    }

    pub fn receive(
        &mut self,
        ip_hdr: &IpHeader,
        tcp_hdr: &TcpHeader,
        payload: &[u8],
        // TODO: this API isn't going to work, we will probably want to put outgoing segments on a queue
        // Also, from RFC1122:
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
            Entry::Occupied(mut c) => {
                c.get_mut().receive(&tcp_hdr, &payload, &mut res_buf)
            }
            Entry::Vacant(conn_entry) => {
                // Check we have a matching LISTEN-ing socket
                if self
                    .listening_sockets
                    .get(&conn_id.local_socket())
                    .filter(|s| s.matches(&conn_id))
                    .is_some()
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
                        )

                    // third check for a SYN
                    } else if tcp_hdr.syn {
                        let conn = conn_entry.insert(Connection::new(
                            conn_id,
                            &tcp_hdr,
                            &self.seq_gen,
                        ));
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
    use std::net::Ipv4Addr;

    const TEST_PORT: PortNum = 4434;

    #[test]
    fn closed_socket_syn() {
        // No listening sockets
        let mut tcp = Tcp::new();

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
    fn original_syn() {
        let mut tcp = new_listening_tcp();

        let client_iss = 0;

        let mut res_buf = [0u8; 1500];
        let res_len = send_syn(&mut tcp, &mut res_buf, client_iss);

        assert_eq!(
            res_len,
            Some(Ipv4Header::SERIALIZED_SIZE + TCP_MINIMUM_HEADER_SIZE),
            "response length should be size of IP+TCP headers"
        );

        let (_, res_tcp_hdr, payload_len) =
            extract_headers(&res_buf[..res_len.unwrap()]);

        assert_eq!(payload_len, 0, "should respond with no payload");
        // let res_ip_hdr = res_hdrs.ip.unwrap();
        // TODO: assert we're responding to/from the correct IP
        assert_eq!(res_tcp_hdr.syn, true, "should respond with a SYN");
        assert_eq!(res_tcp_hdr.ack, true, "should respond with an ACK");
        assert_eq!(
            res_tcp_hdr.acknowledgment_number,
            client_iss + 1,
            "response should acknowledge the correct sequence number"
        );
    }

    #[test]
    fn three_way() {
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
        let ack_res_len =
            send_ack(&mut tcp, &syn_ack_hdr, &mut ack_res_buf, client_iss.wrapping_add(1));

        assert_eq!(ack_res_len, None, "should be no response to the ACK");

        // TODO: assert state of `tcp`
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
    fn unaccpeptable_seq_num() {
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
        let tcp_hdr = TcpHeader::new(4321, TEST_PORT, seq_num, 1024);

        let ip_hdr = Ipv4Header::new(
            tcp_hdr.header_len() + payload.len() as u16,
            64,
            IpTrafficClass::Tcp,
            [192, 168, 0, 1],
            [127, 0, 0, 1],
        );

        (ip_hdr, tcp_hdr)
    }

    fn new_listening_tcp() -> Tcp {
        let mut tcp = Tcp::new();
        tcp.listen(ListeningSocketId::V4 {
            remote_addr: Ipv4Addr::UNSPECIFIED,
            remote_port: None,
            local_addr: Ipv4Addr::LOCALHOST,
            local_port: TEST_PORT,
        })
        .unwrap();
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
