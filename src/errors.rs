#[derive(Debug)]
pub enum TitError {
    Io(std::io::Error),
    PacketWrite(etherparse::WriteError),
    ChecksumDifference,
    ChecksumCalcFailure(etherparse::ValueError),

    EADDRINUSE,
}

impl From<std::io::Error> for TitError {
    fn from(e: std::io::Error) -> Self {
        TitError::Io(e)
    }
}

impl From<etherparse::WriteError> for TitError {
    fn from(e: etherparse::WriteError) -> Self {
        TitError::PacketWrite(e)
    }
}

impl From<etherparse::ValueError> for TitError {
    fn from(e: etherparse::ValueError) -> Self {
        TitError::ChecksumCalcFailure(e)
    }
}

pub type Result<T> = std::result::Result<T, TitError>;
