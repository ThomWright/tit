use etherparse::{IpHeader, TcpHeader};
use std::collections::hash_map::Entry;
use std::collections::HashMap;

use super::connection::{Connection, ConnectionId};
use crate::errors::{Result, TitError};

pub struct Tcp {
    connections: HashMap<ConnectionId, Connection>,
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

pub struct SeqGen {
    // TODO: some random number generator?
}
impl SeqGen {
    pub fn gen_iss(&self) -> u32 {
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
}
