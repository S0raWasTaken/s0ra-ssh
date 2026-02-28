use std::{
    env,
    fmt::Display,
    fs::{self, File, create_dir_all},
    io::{BufReader, Read, Write},
    net::SocketAddr,
    path::PathBuf,
    process::exit,
    sync::Arc,
};

use dirs::config_dir;
use libssh0::{DropGuard, break_if};
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use rcgen::generate_simple_self_signed;
use rustls_pemfile::{certs, private_key};
use ssh_key::{AuthorizedKeys, PublicKey, SshSig};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, WriteHalf},
    net::{TcpListener, TcpStream},
    select, spawn,
    sync::mpsc::{Receiver, Sender, channel},
    task::spawn_blocking,
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    },
    server::TlsStream,
};

pub type BoxedError = Box<dyn std::error::Error + Send + Sync>;
pub type Res<T> = Result<T, BoxedError>;

#[tokio::main]
async fn main() -> Res<()> {
    let config_dir =
        config_dir().ok_or("Couldn't find the config directory")?;

    create_dir_all(&config_dir)?;

    let authorized_keys_path = config_dir.join("ssh0-daemon/authorized_keys");

    if !authorized_keys_path.exists() {
        eprintln!(
            "Please populate your authorized_keys file at {}",
            authorized_keys_path.display()
        );
        exit(1);
    }

    let authorized_keys = AuthorizedKeys::read_file(&authorized_keys_path)?
        .iter()
        .map(|e| e.public_key().clone())
        .collect::<Vec<_>>()
        .leak();

    if authorized_keys.is_empty() {
        return Err(format!(
            "authorized_keys file is empty, please add a public key at {}",
            authorized_keys_path.display()
        )
        .into());
    }

    dbg!(&authorized_keys);

    let listener = TcpListener::bind("127.0.0.1:2121").await?;
    println!("Listening on 2121");

    let acceptor = make_acceptor()?;

    loop {
        let (stream, address) = listener.accept().await?;
        println!("Sending challenge to {address}");

        spawn(authenticate_and_accept_connection(
            stream,
            address,
            authorized_keys,
            acceptor.clone(),
        ));
    }
}

async fn authenticate_and_accept_connection(
    stream: TcpStream,
    address: SocketAddr,
    authorized_keys: &[PublicKey],
    acceptor: TlsAcceptor,
) -> Res<()> {
    let mut socket = acceptor.accept(stream).await.inspect_err(print_err)?;

    authenticate(&mut socket, authorized_keys).await.inspect_err(|e| {
        eprintln!("Signature verification failed for {address}");
        eprintln!("{e}");
    })?;

    println!("Authorized!");

    handle_client_connection(socket).await.inspect_err(print_err)?;
    Ok(())
}

async fn authenticate(
    stream: &mut TlsStream<TcpStream>,
    authorized_keys: &[PublicKey],
) -> Res<()> {
    let challenge = rand::random::<[u8; 32]>();
    stream.write_all(&challenge).await?;

    let mut signature_length_reader = [0u8; 4];
    stream.read_exact(&mut signature_length_reader).await?;
    let signature_length = u32::from_be_bytes(signature_length_reader) as usize;

    let mut signature_bytes = vec![0u8; signature_length];
    stream.read_exact(&mut signature_bytes).await?;

    let signature = SshSig::from_pem(signature_bytes)?;

    if !authorized_keys
        .iter()
        .any(|entry| entry.verify("ssh0-auth", &challenge, &signature).is_ok())
    {
        stream.write_all(&[0]).await?;
        return Err("Unauthorized".into());
    }

    stream.write_all(&[1]).await?;

    Ok(())
}

fn print_err<E: Display>(e: &E) {
    eprintln!("{e}");
}

fn make_acceptor() -> Res<TlsAcceptor> {
    let (certs, key) = load_from_default_or_make_new()?;

    Ok(TlsAcceptor::from(Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?,
    )))
}

type CertKeyPair<'a> = (Vec<CertificateDer<'a>>, PrivateKeyDer<'a>);

fn load_from_default_or_make_new() -> Res<CertKeyPair<'static>> {
    let config_dir =
        config_dir().ok_or("Config dir not found")?.join("ssh0-daemon");

    create_dir_all(&config_dir)?;

    let cert_path = config_dir.join("cert.pem");
    let key_path = config_dir.join("key.pem");

    let (cert, key) = if cert_path.exists() && key_path.exists() {
        (
            certs(&mut new_reader(&cert_path)?)
                .collect::<Result<Vec<_>, _>>()?,
            private_key(&mut new_reader(&key_path)?)?
                .ok_or("Private key not found")?,
        )
    } else {
        let pair = generate_simple_self_signed([String::from("localhost")])?;
        let key_pem = pair.signing_key.serialize_pem();
        let cert_pem = pair.cert.pem();

        fs::write(cert_path, cert_pem)?;
        fs::write(key_path, key_pem)?;

        (
            vec![CertificateDer::from(pair.cert)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                pair.signing_key.serialize_der(),
            )),
        )
    };
    Ok((cert, key))
}

fn new_reader(file: &PathBuf) -> Res<BufReader<File>> {
    Ok(BufReader::new(File::open(file)?))
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

    let _guard = DropGuard::new(child, |child| {
        child.kill().inspect_err(print_err).ok();
    });

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
