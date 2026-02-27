#![warn(clippy::pedantic, clippy::allow_attributes)]

use std::{
    error::Error,
    io::{ErrorKind::UnexpectedEof, Read, Write, stdin, stdout},
    process::exit,
    sync::Arc,
};

use argh::{FromArgValue, FromArgs};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, WriteHalf},
    net::TcpStream,
    spawn,
    sync::mpsc::{Receiver, Sender, channel},
    task::spawn_blocking,
};
use tokio_rustls::{
    TlsConnector,
    client::TlsStream,
    rustls::{ClientConfig, pki_types::ServerName},
};

use crate::fingerprint::FingerprintCheck;

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

mod fingerprint;

#[tokio::main]
async fn main() -> Res<()> {
    let args: Args = argh::from_env();
    let host = args.user_at_host.host;
    let port = args.port;

    enable_raw_mode()?;
    let guard = RawModeGuard;

    let stream = connect_tls(&host, port).await?;
    let (mut tcp_rx, tcp_tx) = tokio::io::split(stream);
    let (stdin_tx, stdin_rx) = channel::<Vec<u8>>(32);

    spawn_blocking(move || read_stdin(stdin_tx));
    spawn(forward_to_server(stdin_rx, tcp_tx));

    let mut buf = [0u8; 1024];
    let mut stdout = stdout().lock();
    loop {
        match tcp_rx.read(&mut buf).await {
            Ok(n) if n > 0 => {
                stdout.write_all(&buf[..n])?;
                stdout.flush()?;
            }
            Err(e) if e.kind() != UnexpectedEof => return Err(e.into()),
            _ => {
                drop(guard);
                exit(0);
            }
        }
    }
}

async fn connect_tls(host: &str, port: u16) -> Res<TlsStream<TcpStream>> {
    let connector = TlsConnector::from(Arc::new(
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(FingerprintCheck))
            .with_no_client_auth(),
    ));

    let tcp = TcpStream::connect(format!("{host}:{port}")).await?;

    let domain = ServerName::try_from(host.to_string())?;

    Ok(connector.connect(domain, tcp).await?)
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

async fn forward_to_server<S: AsyncWrite>(
    mut rx: Receiver<Vec<u8>>,
    mut tcp_tx: WriteHalf<S>,
) {
    while let Some(data) = rx.recv().await {
        break_if!(tcp_tx.write_all(&data).await.is_err());
    }
}
