use super::{Res, print_err};
use crate::connection::handle_client_connection;
use libssh0::timeout;
use ssh_key::{AuthorizedKeys, PublicKey, SshSig};
use std::{net::SocketAddr, path::Path};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

pub fn load_authorized_keys(
    authorized_keys_path: &Path,
) -> Res<Vec<PublicKey>> {
    Ok(AuthorizedKeys::read_file(authorized_keys_path)?
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
    let mut socket = acceptor.accept(stream).await.inspect_err(print_err)?;

    timeout(authenticate(&mut socket, &authorized_keys)).await?.inspect_err(
        |e| {
            eprintln!("Signature verification failed for {address}");
            eprintln!("{e}");
        },
    )?;

    println!("Authorized!");

    let mut socket =
        handle_client_connection(socket).await.inspect_err(print_err)?;

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
        stream.write_all(&[0]).await?;
        stream.shutdown().await?;
        return Err("Signature too large".into());
    }

    let mut signature_bytes = vec![0u8; signature_length];
    stream.read_exact(&mut signature_bytes).await?;

    let signature = SshSig::from_pem(signature_bytes)?;

    if !authorized_keys
        .iter()
        .any(|entry| entry.verify("ssh0-auth", &challenge, &signature).is_ok())
    {
        stream.write_all(&[0]).await?;
        stream.shutdown().await?;
        return Err("Unauthorized".into());
    }

    stream.write_all(&[1]).await?;

    Ok(())
}
