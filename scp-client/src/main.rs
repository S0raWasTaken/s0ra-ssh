#![feature(never_type)]
mod args;
mod io;
mod network;

use std::{collections::HashSet, path::PathBuf};

use indicatif::MultiProgress;
use libssh0::{BoxedError, Res, common::SessionType, timeout};
use libssh0_client::{authenticate, connect_tls, load_private_key};
use ssh_key::PrivateKey;
use tokio::{fs::metadata, net::TcpStream, task::JoinSet};
use tokio_rustls::client::TlsStream;

use crate::args::{Args, FileInfo, UnparsedGlob};

pub type Stream = TlsStream<TcpStream>;

struct Session {
    pub host: String,
    pub port: u16,
    pub source_path: PathBuf,
    pub source_name: String,
    pub destination: PathBuf,
    pub private_key: PrivateKey,
    pub kind: SessionType,
}

#[tokio::main]
async fn main() -> Res<()> {
    let Args {
        session_type,
        source_files,
        unparsed_globs,
        destination,
        key_path,
        port,
        task_limit,
    } = Args::from_argh()?;
    let mut print_banner = true;
    let private_key = load_private_key(key_path)?;

    let source_files = parse_globs(
        source_files,
        unparsed_globs,
        &private_key,
        session_type,
        &mut print_banner,
        port,
    )
    .await?;

    pre_flight_checks(session_type, &source_files, &destination).await?;

    let multi_progress_bar = MultiProgress::new();
    multi_progress_bar.set_move_cursor(true);

    let mut task_set = JoinSet::new();

    let mut sources = source_files.into_iter();

    for source in sources.by_ref().take(task_limit) {
        let destination_host = destination.host.clone();
        let destination = destination.path.clone();

        let session = Session {
            host: source.host.or(destination_host).unwrap(), // Shouldn't fail
            port,
            source_path: source.path.clone(),
            source_name: source.name.clone(),
            destination,
            private_key: private_key.clone(),
            kind: session_type,
        };

        task_set.spawn(file_transfer_session(
            session,
            multi_progress_bar.clone(),
            print_banner,
        ));
        print_banner = false;
    }

    while let Some(result) = task_set.join_next().await {
        result??;

        if let Some(source) = sources.next() {
            let destination_host = destination.host.clone();
            let destination = destination.path.clone();

            let session = Session {
                host: source.host.or(destination_host).unwrap(), // Shouldn't fail
                port,
                source_path: source.path.clone(),
                source_name: source.name.clone(),
                destination,
                private_key: private_key.clone(),
                kind: session_type,
            };

            task_set.spawn(file_transfer_session(
                session,
                multi_progress_bar.clone(),
                print_banner,
            ));
        }
    }

    Ok(())
}

async fn pre_flight_checks(
    session_type: SessionType,
    source_files: &[FileInfo],
    destination: &FileInfo,
) -> Res<()> {
    if !matches!(session_type, SessionType::Download) {
        return Ok(());
    }

    let destination_is_dir =
        metadata(&destination.path).await.is_ok_and(|m| m.is_dir());

    if source_files.len() > 1 && !destination_is_dir {
        return Err(
            "Destination must be an existing directory for multiple downloads"
                .into(),
        );
    }

    if !destination_is_dir || source_files.len() <= 1 {
        return Ok(());
    }

    let mut seen = HashSet::new();
    for source in source_files {
        let output = destination.path.join(&source.name);
        if !seen.insert(output) {
            return Err(
                "Two sources resolve to the same local output path".into()
            );
        }
    }

    Ok(())
}

async fn parse_globs(
    source_files: Vec<FileInfo>,
    unparsed_globs: Vec<UnparsedGlob>,
    private_key: &PrivateKey,
    session_type: SessionType,
    print_banner: &mut bool,
    port: u16,
) -> Res<Vec<FileInfo>> {
    if matches!(session_type, SessionType::Upload) || unparsed_globs.is_empty()
    {
        return Ok(source_files);
    }

    let mut parsed_globs = Vec::new();

    for UnparsedGlob { path, host } in unparsed_globs {
        let mut stream = connect_tls(&host, port).await?;
        timeout(authenticate(
            &mut stream,
            private_key,
            SessionType::Probe,
            *print_banner,
        ))
        .await??;
        *print_banner = false;

        let list = network::probe_parse_glob(stream, path, host).await?;
        parsed_globs.push(list);
    }

    Ok(vec![source_files, parsed_globs.into_iter().flatten().collect()]
        .into_iter()
        .flatten()
        .collect())
}

async fn file_transfer_session(
    session: Session,
    multi_progress_bar: MultiProgress,
    print_banner: bool,
) -> Res<()> {
    let mut stream = connect_tls(&session.host, session.port).await?;
    timeout(authenticate(
        &mut stream,
        &session.private_key,
        session.kind,
        print_banner,
    ))
    .await??;

    match session.kind {
        SessionType::Upload => {
            network::upload(
                stream,
                &session.source_path,
                session.destination.as_os_str(),
                &session.source_name,
                &multi_progress_bar,
            )
            .await?;
        }
        SessionType::Download => {
            network::download(
                stream,
                session.source_path.as_os_str(),
                &session.destination,
                &session.source_name,
                &multi_progress_bar,
            )
            .await?;
        }
        SessionType::Shell | SessionType::Probe => unreachable!(),
    }
    Ok::<(), BoxedError>(())
}
