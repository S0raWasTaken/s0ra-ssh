#![warn(clippy::pedantic, clippy::allow_attributes)]
use std::{
    env,
    fmt::Display,
    fs::File,
    io::{BufReader, Read, Write},
    sync::Arc,
};

struct ChildGuard(Box<dyn Child + Send + Sync>);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill().inspect_err(print_err);
    }
}

use portable_pty::{Child, CommandBuilder, PtySize, native_pty_system};
use rustls_pemfile::{certs, private_key};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, WriteHalf},
    net::TcpListener,
    select, spawn,
    sync::mpsc::{Receiver, Sender, channel},
    task::spawn_blocking,
};
use tokio_rustls::{TlsAcceptor, rustls::ServerConfig};

pub type BoxedError = Box<dyn std::error::Error + Send + Sync>;
pub type Res<T> = Result<T, BoxedError>;

/// Expects Result<T, E>
macro_rules! break_if {
    ($x:expr) => {
        if $x {
            break;
        }
    };
}

#[tokio::main]
async fn main() -> Res<()> {
    let listener = TcpListener::bind("127.0.0.1:2121").await?;
    println!("Listening on 2121");

    let acceptor = make_acceptor()?;

    loop {
        let (socket, address) = listener.accept().await?;
        println!("{address} Connected!");
        let acceptor = acceptor.clone();

        spawn(async move {
            let socket =
                acceptor.accept(socket).await.inspect_err(print_err)?;

            handle_client_connection(socket).await.inspect_err(print_err)
        });
    }
}

fn print_err<E: Display>(e: &E) {
    eprintln!("{e}");
}

fn make_acceptor() -> Res<TlsAcceptor> {
    let certs = certs(&mut BufReader::new(File::open("server.pem")?))
        .collect::<Result<Vec<_>, _>>()?;

    let key = private_key(&mut BufReader::new(File::open("key.pem")?))?
        .ok_or("Private key not found")?;

    Ok(TlsAcceptor::from(Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?,
    )))
}

async fn handle_client_connection<S>(socket: S) -> Res<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let pty = native_pty_system();
    let pair = pty.openpty(PtySize::default())?;

    let default_shell =
        env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());

    let mut cmd = CommandBuilder::new(default_shell);
    cmd.env("TERM", env::var("TERM").unwrap_or("xterm-256color".to_string()));

    let child = pair.slave.spawn_command(cmd)?;

    let _guard = ChildGuard(child);

    drop(pair.slave);
    let reader = pair.master.try_clone_reader()?;
    let writer = pair.master.take_writer()?;
    let (mut tcp_rx, tcp_tx) = tokio::io::split(socket);
    let (pty_tx, pty_rx) = channel::<Vec<u8>>(32);

    let mut pty_read = spawn_blocking(move || read_pty(reader, pty_tx));
    spawn(forward_to_tcp(pty_rx, tcp_tx));

    let (write_tx, write_rx) = channel::<Vec<u8>>(32);
    spawn_blocking(move || write_pty(writer, write_rx)); // one long-lived thread, like read_pty

    let mut buf = [0u8; 1024];
    loop {
        select! {
            _ = &mut pty_read => break,
            result = tcp_rx.read(&mut buf) => {
                let n = result?;
                break_if!(n == 0 || write_tx.send(buf[..n].to_vec()).await.is_err());
            }
        }
    }

    Ok(())
}

#[expect(clippy::needless_pass_by_value)]
fn read_pty(mut reader: Box<dyn Read + Send>, tx: Sender<Vec<u8>>) {
    let mut buf = [0u8; 1024];
    loop {
        match reader.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                break_if!(tx.blocking_send(buf[..n].to_vec()).is_err());
            }
        }
    }
}

fn write_pty(mut writer: Box<dyn Write + Send>, mut rx: Receiver<Vec<u8>>) {
    while let Some(data) = rx.blocking_recv() {
        if writer.write_all(&data).is_err() {
            break;
        }
    }
}

async fn forward_to_tcp<S: AsyncWrite>(
    mut rx: Receiver<Vec<u8>>,
    mut tcp_tx: WriteHalf<S>,
) {
    while let Some(data) = rx.recv().await {
        break_if!(tcp_tx.write_all(&data).await.is_err());
    }
}
