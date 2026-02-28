use super::{Res, print_err};
use crate::{BoxedError, connection::handle_client_connection};
use libssh0::timeout;
use notify::{
    Event, EventKind, RecursiveMode::NonRecursive, Watcher, recommended_watcher,
};
use ssh_key::{PublicKey, SshSig};
use std::{
    net::SocketAddr,
    path::Path,
    sync::{Arc, RwLock},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

type AuthorizedKeys = Arc<RwLock<Vec<PublicKey>>>;

pub fn watch_authorized_keys(path: &'static Path) -> Res<AuthorizedKeys> {
    let keys = Arc::new(RwLock::new(load_authorized_keys(path)?));
    let keys_clone = Arc::clone(&keys);

    let mut watcher =
        recommended_watcher(move |event: notify::Result<Event>| {
            let Ok(event) = event else { return };

            if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_))
            {
                load_authorized_keys(path)
                    .inspect_err(print_err)
                    .inspect(|new_keys| {
                        (*keys_clone.write().unwrap()).clone_from(new_keys);
                    })
                    .ok();
            }
        })?;

    watcher.watch(path, NonRecursive)?;

    // Leaks the watcher, so it stays alive until the daemon exits.
    Box::leak(Box::new(watcher));

    Ok(keys)
}

pub fn load_authorized_keys(
    authorized_keys_path: &Path,
) -> Res<Vec<PublicKey>> {
    Ok(ssh_key::AuthorizedKeys::read_file(authorized_keys_path)?
        .iter()
        .map(|e| e.public_key().clone())
        .collect::<Vec<_>>())
}

pub async fn authenticate_and_accept_connection(
    stream: TcpStream,
    address: SocketAddr,
    authorized_keys: Vec<PublicKey>,
    acceptor: TlsAcceptor,
) -> Res<()> {
    let mut socket = timeout(acceptor.accept(stream)).await??;

    timeout(authenticate(&mut socket, &authorized_keys)).await?.inspect_err(
        |_| {
            eprintln!("Signature verification failed for {address}");
        },
    )?;

    println!("Authorized connection from {address}");

    let mut socket = handle_client_connection(socket).await?;

    socket.shutdown().await?;
    Ok(())
}

pub async fn authenticate(
    stream: &mut TlsStream<TcpStream>,
    authorized_keys: &[PublicKey],
) -> Res<()> {
    let challenge = rand::random::<[u8; 32]>();
    stream.write_all(&challenge).await?;

    let mut signature_length_reader = [0u8; 4];
    stream.read_exact(&mut signature_length_reader).await?;
    let signature_length = u32::from_be_bytes(signature_length_reader) as usize;

    if signature_length > 4096 {
        return kill_stream(stream, "Signature too large").await;
    }

    let mut signature_bytes = vec![0u8; signature_length];
    stream.read_exact(&mut signature_bytes).await?;

    let signature = match SshSig::from_pem(signature_bytes) {
        Ok(sig) => sig,
        Err(e) => return kill_stream(stream, e).await,
    };

    if !authorized_keys
        .iter()
        .any(|entry| entry.verify("ssh0-auth", &challenge, &signature).is_ok())
    {
        return kill_stream(stream, "Unauthorized").await;
    }

    stream.write_all(&[1]).await?;
    stream.flush().await?;

    Ok(())
}

async fn kill_stream(
    stream: &mut TlsStream<TcpStream>,
    error: impl Into<BoxedError>,
) -> Res<()> {
    stream.write_all(&[0]).await?;
    stream.flush().await?;
    stream.shutdown().await?;

    Err(error.into())
}
