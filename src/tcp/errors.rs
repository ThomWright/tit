#[derive(Debug)]
pub enum TcpError {
    EADDRINUSE,

    NoConnection,

    ConnectionClosing,
}

pub type TcpResult<T> = std::result::Result<T, TcpError>;
