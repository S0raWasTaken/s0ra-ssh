#![warn(clippy::pedantic, clippy::allow_attributes)]

use std::{
    env,
    io::{Read, Write},
};

use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, tcp::OwnedWriteHalf},
    spawn,
    sync::mpsc::{Receiver, Sender, channel},
    task::spawn_blocking,
};

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

    loop {
        let (socket, address) = listener.accept().await?;
        println!("{address} Connected!");

        spawn(async move {
            handle_client_connection(socket).await.inspect_err(print_err)
        });
    }
}

async fn handle_client_connection(socket: TcpStream) -> Res<()> {
    let pty = native_pty_system();
    let pair = pty.openpty(PtySize::default())?;

    let default_shell = env::var("SHELL").unwrap_or("/bin/sh".to_string());

    let mut child =
        pair.slave.spawn_command(CommandBuilder::new(default_shell))?;

    drop(pair.slave);

    let reader = pair.master.try_clone_reader()?;
    let writer = pair.master.take_writer()?;
    let (mut tcp_rx, tcp_tx) = socket.into_split();
    let (pty_tx, pty_rx) = channel::<Vec<u8>>(32);

    spawn_blocking(move || read_pty(reader, pty_tx));
    spawn(forward_to_tcp(pty_rx, tcp_tx));

    let (write_tx, write_rx) = channel::<Vec<u8>>(32);
    spawn_blocking(move || write_pty(writer, write_rx)); // one long-lived thread, like read_pty

    let mut buf = [0u8; 1024];
    loop {
        let n = tcp_rx.read(&mut buf).await?;
        break_if!(n == 0 || write_tx.send(buf[..n].to_vec()).await.is_err());
    }

    child.kill()?;
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

async fn forward_to_tcp(mut rx: Receiver<Vec<u8>>, mut tcp_tx: OwnedWriteHalf) {
    while let Some(data) = rx.recv().await {
        break_if!(tcp_tx.write_all(&data).await.is_err());
    }
}
fn print_err(error: &BoxedError) {
    eprintln!("{error}");
}
