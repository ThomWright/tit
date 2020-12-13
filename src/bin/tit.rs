use std::net::Ipv4Addr;

use tit::print_tcp_key;
use tit::Interface;
use tit::ListeningSocketId;
use tit::Tcp;
use tit::TitError;

const IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 10);
const PORT: u16 = 4433;

fn main() -> Result<(), TitError> {
    // TODO: take CLI params to control active/passive open (similar to netcat)

    print_tcp_key();
    println!();

    let mut tcp_impl = Tcp::new();
    tcp_impl.listen(ListeningSocketId::V4 {
        remote_addr: Ipv4Addr::UNSPECIFIED,
        remote_port: None,
        local_addr: IP,
        local_port: PORT,
    })?;

    let interface = Interface::new(tcp_impl)?;
    interface.listen()?;

    Ok(())
}
