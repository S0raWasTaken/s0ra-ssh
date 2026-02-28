use daybreak::{FileDatabase, deser::Yaml};
use dirs::config_dir;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    error::Error,
    fs::create_dir_all,
    io::{Read, Write, stdin, stdout},
    sync::Arc,
};
use tokio_rustls::rustls::{
    self, DigitallySignedStruct, OtherError, SignatureScheme,
    client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    },
    crypto::{
        aws_lc_rs::default_provider, verify_tls12_signature,
        verify_tls13_signature,
    },
    pki_types::{CertificateDer, ServerName, UnixTime},
};

fn into_other<E>(e: E) -> OtherError
where
    E: Error + Send + Sync + 'static,
{
    OtherError(Arc::new(e))
}

type Host = String;
type Fingerprint = String;

const FINGERPRINT_MISMATCH: &str = "warning: fingerprint mismatch! the host's fingerprint has changed.\n  This could indicate an MITM attack.";
const RED: &str = "\x1b[0;31m";
const RESET: &str = "\x1b[0m";

#[derive(Debug)]
pub struct FingerprintCheck;

impl ServerCertVerifier for FingerprintCheck {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let fingerprint = hex::encode(Sha256::digest(end_entity.as_ref()));
        let server_name = server_name.to_str();

        let db = config_dir()
            .map(|config| {
                let path = config.join("ssh0/known_hosts");
                create_dir_all(path.parent().unwrap())
                    .map_err(into_other)?;
                FileDatabase::<HashMap<Host, Fingerprint>, Yaml>::load_from_path_or_default(
                    path,
                )
                .map_err(into_other)
            })
            .transpose()?;

        let mut fingerprint_mismatch = false;

        let is_known_host = db
            .as_ref()
            .map(|db| -> Result<Option<String>, daybreak::Error> {
                let mut db = db.get_data(false)?; // No need to double load
                Ok(db.remove(&server_name.to_string()))
            })
            .transpose()
            .map_err(into_other)?
            .flatten()
            .is_some_and(|known_fingerprint| {
                let matches = known_fingerprint == fingerprint;

                if !matches {
                    eprintln!(
                        "{FINGERPRINT_MISMATCH}\n  \
                            host:       {server_name}\n  \
                            expected:   {known_fingerprint}\n  \
                            found:      {RED}{fingerprint}{RESET}"
                    );
                }
                fingerprint_mismatch = !matches;
                matches
            });

        if !is_known_host && !fingerprint_mismatch {
            println!("The server's fingerprint is {fingerprint}");
        }

        let should_reject = if is_known_host {
            false
        } else if fingerprint_mismatch
            && !request_confirmation("Are you aware of the risk?")?
        {
            true
        } else {
            !request_confirmation("Trust new fingerprint?")?
        };

        if should_reject {
            eprintln!("Rejected!\n");
            return Err(rustls::Error::General(
                "certificate rejected by user".into(),
            ));
        }

        if !is_known_host {
            db.map(|db| -> Result<(), daybreak::Error> {
                #[expect(
                    clippy::excessive_nesting,
                    reason = "Not worth refactoring"
                )]
                {
                    let mut data = db.borrow_data_mut()?;
                    data.insert(server_name.to_string(), fingerprint);
                }

                db.save()?;
                println!(
                    "Accepted!\nSaved new host to {}\n",
                    // Should be safe, if db exists, it must mean that the config_dir must too.
                    config_dir().unwrap().join("ssh0/known_hosts").display()
                );
                Ok(())
            })
            .transpose()
            .map_err(into_other)?;
        }

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        default_provider().signature_verification_algorithms.supported_schemes()
    }
}

// fn write_accepted(fingerprint: &str)

fn request_confirmation(message: &str) -> Result<bool, rustls::Error> {
    print!("{message} [Y/N] ");
    stdout().flush().map_err(into_other)?;

    let mut buffer = [0u8; 1];
    stdin().read_exact(&mut buffer).map_err(into_other)?;
    println!();

    // case-insensitive 'Y' check
    Ok(buffer[0] & 0xDF == b'Y')
}
