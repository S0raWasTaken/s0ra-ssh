use crate::{
    args::Args,
    keypair_auth::{authenticate_and_accept_connection, load_authorized_keys},
    rate_limit::RateLimiter,
    tls::make_acceptor,
};
use std::{fmt::Display, fs::create_dir_all, sync::Arc, time::Duration};
use tokio::{io::AsyncWriteExt, net::TcpListener, spawn, time::sleep};

pub type BoxedError = Box<dyn std::error::Error + Send + Sync>;
pub type Res<T> = Result<T, BoxedError>;

mod args;
mod connection;
mod keypair_auth;
mod rate_limit;
mod tls;

#[tokio::main]
async fn main() -> Res<()> {
    let args: Args = argh::from_env();
    let Args { host, port, .. } = args;

    let config_dir = args
        .config_dir
        .or_else(dirs::config_dir)
        .map(|dir| dir.join("ssh0-daemon"))
        .ok_or("Couldn't find the config directory.")?;

    create_dir_all(&config_dir)?;

    let authorized_keys_path = config_dir.join("authorized_keys");

    let listener = TcpListener::bind(format!("{host}:{port}",)).await?;
    println!("Listening on {port}");

    let acceptor = make_acceptor(&config_dir)?;

    let rate_limiter = Arc::new(RateLimiter::new(5, Duration::from_mins(1)));
    let rl = Arc::clone(&rate_limiter);
    spawn(async move {
        loop {
            sleep(Duration::from_mins(5)).await;
            rl.cleanup();
        }
    });

    loop {
        let (mut stream, address) = listener.accept().await?;
        if !rate_limiter.is_allowed(address.ip()) {
            stream.shutdown().await.ok();
            continue;
        }

        println!("Sending challenge to {address}");

        let authorized_keys = load_authorized_keys(&authorized_keys_path)
            .unwrap_or_else(|e| {
                eprintln!("{e}");
                Vec::new()
            });
        spawn(authenticate_and_accept_connection(
            stream,
            address,
            authorized_keys,
            acceptor.clone(),
        ));
    }
}

fn print_err<E: Display>(e: &E) {
    eprintln!("{e}");
}
