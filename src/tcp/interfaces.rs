use crossbeam_channel;
use std::io;
use std::io::{Read, Write};
use std::net::SocketAddr;

use super::tcp::TcpCommand;
use crate::errors::{Result, TitError};

pub(crate) type NewConnection =
    (SocketAddr, crossbeam_channel::Receiver<Vec<u8>>);

pub struct TcpListener {
    /// Receiving pairs of remote [`SocketAddr`] and associated streams.
    new_connections: crossbeam_channel::Receiver<NewConnection>,
}

impl TcpListener {
    pub(crate) fn new(
        new_connections: crossbeam_channel::Receiver<NewConnection>,
    ) -> TcpListener {
        TcpListener { new_connections }
    }

    pub fn bind(
        addr: SocketAddr,
        tcp_cmd_chan: &crossbeam_channel::Sender<TcpCommand>,
    ) -> Result<TcpListener> {
        let (snd, rcv) = crossbeam_channel::unbounded();
        tcp_cmd_chan
            .send(TcpCommand::Listen {
                socket: addr,
                ack: snd,
            })
            .map_err(|e| TitError::TcpCommandSendFailure(e.into()))?;
        rcv.recv().expect("bind result channel closed")
    }

    pub fn accept(&self) -> Result<(TcpStream, SocketAddr)> {
        let (remote_socket, read) = self
            .new_connections
            .recv()
            .expect("pending connection channel not intact");
        Ok((TcpStream { read }, remote_socket))
    }
}
// TODO: impl Drop for TcpListener

pub struct TcpStream {
    read: crossbeam_channel::Receiver<Vec<u8>>,
    // TODO: sending stuff...
    // snd_chan: ??
}
// TODO: impl Drop for TcpStream

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        &self.read;
        // TODO:
        Ok(0)
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // TODO:
        Ok(0)
    }

    fn flush(&mut self) -> io::Result<()> {
        // TODO:
        Ok(())
    }
}
