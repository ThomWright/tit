use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;

use tit::print_tcp_key;
use tit::Interface;
use tit::Tcp;
use tit::TitError;

const IP: Ipv4Addr = Ipv4Addr::UNSPECIFIED;
// const IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 10);
const PORT: u16 = 4433;

fn main() -> Result<(), TitError> {
    // TODO: take CLI params to control active/passive open (similar to netcat)

    print_tcp_key();
    println!();

    let mut tcp_impl = Tcp::new();
    tcp_impl.listen(SocketAddr::new(IpAddr::from(IP), PORT))?;

    let interface = Interface::new(tcp_impl)?;
    interface.listen()?;

    Ok(())
}
