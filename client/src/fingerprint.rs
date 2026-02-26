use std::{
    io::{Read, Write, stdin, stdout},
    process::exit,
    sync::Arc,
};

use crossterm::terminal::disable_raw_mode;
use sha2::{Digest, Sha256};
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

#[derive(Debug)]
pub struct FingerprintCheck;

impl ServerCertVerifier for FingerprintCheck {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let fingerprint = Sha256::digest(end_entity.as_ref());
        if !request_confirmation(&hex::encode(fingerprint))? {
            eprintln!("Rejected!\n");
            disable_raw_mode().ok();
            exit(1);
        }

        println!("Accepted!\n");

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

fn request_confirmation(fingerprint: &str) -> Result<bool, rustls::Error> {
    print!(
        "The server's fingerprint is {fingerprint}\n\
        Do you trust it? [Y/N] "
    );
    stdout().flush().map_err(|e| OtherError(Arc::new(e)))?;

    let mut buffer = [0u8; 1];
    stdin().read_exact(&mut buffer).map_err(|e| OtherError(Arc::new(e)))?;

    // case-insensitive 'Y' check
    Ok(buffer[0] & 0xDF == b'Y')
}
