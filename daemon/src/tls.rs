use super::Res;
use dirs::config_dir;
use rcgen::generate_simple_self_signed;
use rustls_pemfile::{certs, private_key};
use std::{
    fs::{self, File, create_dir_all},
    io::BufReader,
    path::PathBuf,
    sync::Arc,
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    },
};

pub fn make_acceptor() -> Res<TlsAcceptor> {
    let (certs, key) = load_from_default_or_make_new()?;

    Ok(TlsAcceptor::from(Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?,
    )))
}

pub type CertKeyPair<'a> = (Vec<CertificateDer<'a>>, PrivateKeyDer<'a>);

pub fn load_from_default_or_make_new() -> Res<CertKeyPair<'static>> {
    let config_dir =
        config_dir().ok_or("Config dir not found")?.join("ssh0-daemon");

    create_dir_all(&config_dir)?;

    let cert_path = config_dir.join("cert.pem");
    let key_path = config_dir.join("key.pem");

    let (cert, key) = if cert_path.exists() && key_path.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&key_path)?.permissions().mode();
            if mode & 0o077 != 0 {
                return Err(format!(
                "Private key {} has too permissive permissions ({:o}), expected at most (600)",
                key_path.display(),
                mode & 0o777
            ).into());
            }
        }
        (
            certs(&mut new_reader(&cert_path)?)
                .collect::<Result<Vec<_>, _>>()?,
            private_key(&mut new_reader(&key_path)?)?
                .ok_or("Private key not found")?,
        )
    } else {
        let pair = generate_simple_self_signed([
            String::from("localhost"),
            String::from("127.0.0.1"),
            String::from("::1"),
        ])?;
        let key_pem = pair.signing_key.serialize_pem();
        let cert_pem = pair.cert.pem();

        fs::write(cert_path, cert_pem)?;

        #[cfg(unix)]
        {
            use std::fs::OpenOptions;
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;

            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&key_path)?;
            file.write_all(key_pem.as_bytes())?;
        }

        #[cfg(not(unix))]
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

pub fn new_reader(file: &PathBuf) -> Res<BufReader<File>> {
    Ok(BufReader::new(File::open(file)?))
}
