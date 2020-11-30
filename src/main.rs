use std::io;

mod interface;
mod ip_utils;
mod print;
mod tcp;

fn main() -> io::Result<()> {
    print::tcp_key();
    println!();

    let interface = interface::Interface::new()?;
    interface.listen();

    Ok(())
}
