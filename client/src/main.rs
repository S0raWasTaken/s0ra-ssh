#![warn(clippy::pedantic, clippy::allow_attributes)]

use std::{
    error::Error,
    io::{Read, Write, stdin, stdout},
    process::exit,
};

use argh::{FromArgValue, FromArgs};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, tcp::OwnedWriteHalf},
    spawn,
    sync::mpsc::{Receiver, Sender, channel},
    task::spawn_blocking,
};

/// Expects Result<T, E>
macro_rules! break_if {
    ($x:expr) => {
        if $x {
            break;
        }
    };
}

struct UserAtHost {
    #[expect(dead_code)]
    user: String,
    host: String,
}

const INVALID_ARG: &str = "Invalid first argument, expected user@host";

impl FromArgValue for UserAtHost {
    // user@host expected
    fn from_arg_value(value: &str) -> Result<Self, String> {
        let mut split = value.split('@');

        let user = split.next().ok_or(INVALID_ARG)?.to_string();
        let host = split.next().ok_or(INVALID_ARG)?.to_string();
        Ok(Self { user, host })
    }
}

struct RawModeGuard;
impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
    }
}

/// meow
#[derive(FromArgs)]
struct Args {
    /// meow
    #[argh(positional)]
    user_at_host: UserAtHost,

    /// meow
    #[argh(option, default = "2121")]
    port: u16,
}

type BoxedError = Box<dyn Error + Send + Sync>;
type Res<T> = Result<T, BoxedError>;

#[tokio::main]
async fn main() -> Res<()> {
    let args: Args = argh::from_env();
    let host = args.user_at_host.host;
    let port = args.port;
    let socket = TcpStream::connect(format!("{host}:{port}")).await?;
    let (mut tcp_rx, tcp_tx) = socket.into_split();
    let (stdin_tx, stdin_rx) = channel::<Vec<u8>>(32);

    enable_raw_mode()?;
    let guard = RawModeGuard;

    spawn_blocking(move || read_stdin(stdin_tx));
    spawn(forward_to_server(stdin_rx, tcp_tx));

    let mut buf = [0u8; 1024];
    let mut stdout = stdout().lock();
    loop {
        let n = tcp_rx.read(&mut buf).await?;

        if n == 0 {
            drop(guard);
            exit(0);
        }

        stdout.write_all(&buf[..n])?;
        stdout.flush()?;
    }
}

#[expect(clippy::needless_pass_by_value)]
fn read_stdin(tx: Sender<Vec<u8>>) {
    let mut buf = [0u8; 1024];
    loop {
        match stdin().read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                break_if!(tx.blocking_send(buf[..n].to_vec()).is_err());
            }
        }
    }
}

async fn forward_to_server(
    mut rx: Receiver<Vec<u8>>,
    mut tcp_tx: OwnedWriteHalf,
) {
    while let Some(data) = rx.recv().await {
        break_if!(tcp_tx.write_all(&data).await.is_err());
    }
}
