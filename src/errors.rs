use crossbeam_channel;

use crate::{nic::NetworkChannelContents, tcp};
use tcp::TcpCommand;

#[derive(Debug)]
pub enum TitError {
    Io(std::io::Error),
    PacketWrite(etherparse::WriteError),
    ChecksumDifference,
    ChecksumCalcFailure(etherparse::ValueError),

    NetworkPacketSendFailure(
        crossbeam_channel::SendError<NetworkChannelContents>,
    ),

    IncomingTcpChannelClosed(TcpChannelError),
    OutgoingNetworkChannelClosed(crossbeam_channel::RecvError),

    TcpCommandSendFailure(crossbeam_channel::SendError<TcpCommand>),
    TcpCommandReceiveFailure(crossbeam_channel::RecvError),

    EADDRINUSE,
}

#[derive(Debug)]
pub struct TcpSendError(crossbeam_channel::SendError<tcp::TcpPacket>);
impl From<crossbeam_channel::SendError<tcp::TcpPacket>> for TcpSendError {
    fn from(e: crossbeam_channel::SendError<tcp::TcpPacket>) -> Self {
        TcpSendError(e)
    }
}

#[derive(Debug)]
pub enum TcpChannelError {
    Send(TcpSendError),
    Recv(crossbeam_channel::RecvError),
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
