use crate::{
    args::Args,
    keypair_auth::{authenticate_and_accept_connection, watch_authorized_keys},
    rate_limit::RateLimiter,
    tls::make_acceptor,
};
use libssh0::log;
use std::{fmt::Display, fs::create_dir_all, sync::Arc, time::Duration};
use tokio::{
    io::AsyncWriteExt, net::TcpListener, spawn, sync::Semaphore, time::sleep,
};

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
    let authorized_keys = watch_authorized_keys(&authorized_keys_path)?;

    let listener = TcpListener::bind((&*host, port)).await?;
    log!("Listening on {host}:{port}");

    let acceptor = make_acceptor(&config_dir)?;

    let rate_limiter = Arc::new(RateLimiter::new(3, Duration::from_mins(30)));
    let rl = Arc::clone(&rate_limiter);
    spawn(async move {
        loop {
            sleep(Duration::from_mins(5)).await;
            rl.cleanup();
        }
    });

    let semaphore = Arc::new(Semaphore::new(100));

    loop {
        let (mut stream, address) = listener.accept().await?;

        let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
            stream.shutdown().await.ok();
            continue;
        };

        if !rate_limiter.is_allowed(address.ip()) {
            stream.shutdown().await.ok();
            continue;
        }

        log!(e "Sending challenge to {address}");

        let authorized_keys = authorized_keys.read().unwrap().clone();
        let acceptor = acceptor.clone();
        let rate_limiter = Arc::clone(&rate_limiter);

        spawn(async move {
            let _permit = permit;
            authenticate_and_accept_connection(
                stream,
                address,
                authorized_keys,
                acceptor,
                rate_limiter,
            )
            .await
            .inspect_err(print_err)
        });
    }
}

fn print_err<E: Display>(e: &E) {
    log!(e "{e}");
}
