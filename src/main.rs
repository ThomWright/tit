use errors::TitError;

mod errors;
mod interface;
mod ip_utils;
mod print;
mod tcp;

fn main() -> Result<(), TitError> {
    print::tcp_key();
    println!();

    let interface = interface::Interface::new()?;
    interface.listen()?;

    Ok(())
}
