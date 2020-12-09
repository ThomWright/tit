use std::net::Ipv4Addr;

use errors::TitError;
use tcp::ListeningSocketId;

mod errors;
mod interface;
mod ip_utils;
mod print;
mod tcp;

fn main() -> Result<(), TitError> {
    print::tcp_key();
    println!();

    let mut tcp_impl = tcp::Tcp::new();
    tcp_impl.listen(ListeningSocketId::V4 {
        remote_addr: Ipv4Addr::UNSPECIFIED,
        remote_port: None,
        local_addr: Ipv4Addr::LOCALHOST,
        local_port: 4434,
    })?;

    let interface = interface::Interface::new(tcp_impl)?;
    interface.listen()?;

    Ok(())
}
