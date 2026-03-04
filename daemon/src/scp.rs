use std::{
    io,
    path::{Path, PathBuf},
};

use libssh0::{
    common::{SCP_CONTINUE, SCP_ERROR, SCP_SUCCESS},
    read, read_exact,
};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
};

use crate::{Res, Stream};

const BUFFER_SIZE: usize = 8192;
const BUFFER_SIZE_U64: u64 = BUFFER_SIZE as u64;

// Server <- Client
pub async fn handle_upload(mut stream: Stream) -> Res<Stream> {
    let path = get_path(&mut stream).await?;
    let file_size = u64::from_be_bytes(read_exact!(stream, 8).await?);

    // No limit to file size :) have fun!
    if let Err(error) = receive_file(&mut stream, &path, file_size).await {
        write_error_and_kill(&mut stream, &error.to_string()).await?;
    }

    success(&mut stream).await?;
    Ok(stream)
}

// Server -> Client
pub async fn handle_download(mut stream: Stream) -> Res<Stream> {
    let path = get_path(&mut stream).await?;

    if let Err(error) = send_file(&mut stream, &path).await {
        write_error_and_kill(&mut stream, &error.to_string()).await?;
    }

    success(&mut stream).await?;
    Ok(stream)
}

async fn send_file(stream: &mut Stream, path: &Path) -> io::Result<()> {
    let mut file = File::open(path).await?;
    let file_size = file.metadata().await?.len();

    stream.write_all(&file_size.to_be_bytes()).await?;
    stream.flush().await?;

    let mut buffer = [0u8; BUFFER_SIZE];
    loop {
        let n = file.read(&mut buffer).await?;
        if n == 0 {
            break;
        }
        stream.write_all(&buffer[..n]).await?;
    }

    stream.flush().await?;
    Ok(())
}

async fn receive_file(
    stream: &mut Stream,
    output_path: &Path,
    file_size: u64,
) -> io::Result<()> {
    let mut file = File::create(output_path).await?;
    let mut remaining = file_size;
    let mut buffer = [0u8; BUFFER_SIZE];

    while remaining > 0 {
        let to_read = remaining.min(BUFFER_SIZE_U64) as usize;
        let n = stream.read(&mut buffer[..to_read]).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Connection was aborted prematurely",
            ));
        }
        file.write_all(&buffer[..n]).await?;
        remaining -= n as u64;
    }

    file.flush().await?;
    Ok(())
}

async fn get_path(mut stream: &mut Stream) -> Res<PathBuf> {
    let path_length = u32::from_be_bytes(read_exact!(stream, 4).await?);
    if path_length > 4096 {
        write_error_and_kill(stream, "Path too long (>4096 bytes)").await?;
    }

    step(stream).await?;

    let Ok(path_utf8) =
        String::from_utf8(read!(stream, path_length as usize).await?)
    else {
        write_error_and_kill(stream, "Path must be valid UTF-8").await?;
    };

    step(stream).await?;

    Ok(PathBuf::from(path_utf8))
}

#[inline]
async fn step(stream: &mut Stream) -> io::Result<()> {
    stream.write_all(&SCP_CONTINUE).await?;
    stream.flush().await
}

#[inline]
async fn success(stream: &mut Stream) -> io::Result<()> {
    stream.write_all(&SCP_SUCCESS).await?;
    stream.flush().await
}

// "we had an error" > "error length" > "error" > "flush" > "shutdown stream"
async fn write_error_and_kill(stream: &mut Stream, error: &str) -> Res<!> {
    stream.write_all(&SCP_ERROR).await?;
    stream.write_all(&u32::try_from(error.len())?.to_be_bytes()).await?;
    stream.write_all(error.as_bytes()).await?;

    stream.flush().await?;
    stream.shutdown().await?;
    Err(error.into())
}
