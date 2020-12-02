use etherparse::WriteError;

#[derive(Debug)]
pub enum TitError {
  Io(std::io::Error),
  PacketWrite(WriteError),
}

impl From<std::io::Error> for TitError {
  fn from(e: std::io::Error) -> Self {
    TitError::Io(e)
  }
}

impl From<WriteError> for TitError {
  fn from(e: WriteError) -> Self {
    TitError::PacketWrite(e)
  }
}
