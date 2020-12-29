use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;

use tit::print_tcp_key;
use tit::start_nic;
use tit::Tcp;
// use tit::TcpListener;
use tit::TitError;

const IP: Ipv4Addr = Ipv4Addr::UNSPECIFIED;
// const IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 10);
const PORT: u16 = 4433;

fn main() -> Result<(), TitError> {
    // TODO: take CLI params to control active/passive open (similar to netcat)

    print_tcp_key();
    println!();

    let (tcp_impl, incoming_tcp_packets) = Tcp::new();

    let outgoing_network_packets = start_nic(incoming_tcp_packets)?;

    let control = tcp_impl.start(outgoing_network_packets);
    {
        let listening_socket = SocketAddr::new(IpAddr::from(IP), PORT);
        control
            .lock()
            .expect("unable to get control lock")
            .listen(listening_socket)?;
    }

    // {
    //     let tcp_listener = TcpListener::bind(listening_socket, &tcp_cmds)?;
    //     let (mut stream, remote_socket) = tcp_listener.accept()?;
    //     println!("{}", remote_socket);

    //     let mut read_buf = [0; 512];
    //     let len = stream.read(&mut read_buf)?;

    //     println!("Data: {:#?}", &read_buf[..len]);
    // }

    std::thread::sleep(std::time::Duration::from_secs(1000));

    Ok(())
}
