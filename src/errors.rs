use crate::{nic::NetworkChannelContents, tcp};
use std::sync::mpsc;

#[derive(Debug)]
pub enum TitError {
    Io(std::io::Error),
    PacketWrite(etherparse::WriteError),
    ChecksumDifference,
    ChecksumCalcFailure(etherparse::ValueError),

    NetworkPacketSendFailure(mpsc::SendError<NetworkChannelContents>),

    IncomingTcpChannelClosed(TcpChannelError),
    OutgoingNetworkChannelClosed(mpsc::RecvError),

    ChanRcv(mpsc::RecvError),

    EADDRINUSE,
}

#[derive(Debug)]
pub struct TcpSendError(mpsc::SendError<tcp::TcpPacket>);
impl From<mpsc::SendError<tcp::TcpPacket>> for TcpSendError {
    fn from(e: mpsc::SendError<tcp::TcpPacket>) -> Self {
        TcpSendError(e)
    }
}

#[derive(Debug)]
pub enum TcpChannelError {
    Send(TcpSendError),
    Recv(mpsc::RecvError),
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
