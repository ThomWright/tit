use std::io;
use tun_tap;

fn main() -> io::Result<()> {
    let iface = tun_tap::Iface::new("tun_tit%d", tun_tap::Mode::Tun)?;

    println!("Interface name: {}", iface.name());

    std::thread::sleep(std::time::Duration::from_secs(2));

    Ok(())
}
