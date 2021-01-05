use crossbeam_channel;
use std::io;
use std::io::{Read, Write};
use std::net::SocketAddr;

use super::TcpResult;
use super::{tcp::TcpCommand, ConnectionId};
use crate::errors::{Result, TitError};

pub(crate) type NewConnection = ConnectionId;

pub struct TcpListener {
    snd_tcp_cmd: crossbeam_channel::Sender<TcpCommand>,

    new_connections: crossbeam_channel::Receiver<NewConnection>,
}

impl TcpListener {
    pub fn bind(
        addr: SocketAddr,
        snd_tcp_cmd: &crossbeam_channel::Sender<TcpCommand>,
    ) -> Result<TcpListener> {
        let (snd_conn, rcv_conn) = crossbeam_channel::unbounded();
        let (snd_ack, rcv_ack) = crossbeam_channel::bounded(1);
        snd_tcp_cmd
            .send(TcpCommand::Listen {
                socket: addr,
                ack: snd_ack,
                snd_conn,
            })
            .map_err(|e| TitError::TcpCommandSendFailure(e.into()))?;

        rcv_ack
            .recv()
            .expect("bind result channel closed")
            .map_err(|e| TitError::BindFailure(e))?;

        Ok(TcpListener {
            snd_tcp_cmd: snd_tcp_cmd.clone(),
            new_connections: rcv_conn,
        })
    }

    pub fn accept(&self) -> Result<(TcpStream, SocketAddr)> {
        let connection_id = self
            .new_connections
            .recv()
            .expect("pending connection channel not intact");
        Ok((
            TcpStream::new(connection_id, self.snd_tcp_cmd.clone()),
            connection_id.remote_socket(),
        ))
    }
}
// TODO: impl Drop for TcpListener

pub type ReceiveResult = TcpResult<Vec<u8>>;

pub struct TcpStream {
    connection_id: ConnectionId,

    snd_tcp_cmd: crossbeam_channel::Sender<TcpCommand>,
    read_chan: (
        crossbeam_channel::Sender<ReceiveResult>,
        crossbeam_channel::Receiver<ReceiveResult>,
    ),
    // TODO: sending stuff...
    // snd_chan: ??
}
// TODO: impl Drop for TcpStream

impl TcpStream {
    fn new(
        connection_id: ConnectionId,
        snd_tcp_cmd: crossbeam_channel::Sender<TcpCommand>,
    ) -> TcpStream {
        TcpStream {
            snd_tcp_cmd,
            connection_id,
            read_chan: crossbeam_channel::bounded(1),
        }
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        // TODO: better error handling
        let _ = self.snd_tcp_cmd.send(TcpCommand::Close {
            conn_id: self.connection_id,
        });
    }
}

impl Read for TcpStream {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        self.snd_tcp_cmd
            .send(TcpCommand::Receive {
                conn_id: self.connection_id,
                buf_len: buf.len(),
                snd_data: self.read_chan.0.clone(),
            })
            // Is this a sensible error to return?
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))?;

        let data = self
            .read_chan
            .1
            .recv()
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))?;

        match data {
            Ok(data) => {
                assert!(data.len() < buf.len());

                buf.write(&data)?;

                Ok(data.len())
            }

            Err(_) => {
                // That's it I guess, no more streams for us
                Ok(0)
            }
        }
    }
}

impl Write for TcpStream {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        // TODO:
        Ok(0)
    }

    fn flush(&mut self) -> io::Result<()> {
        // TODO:
        Ok(())
    }
}
