use argh::FromArgs;
use std::path::PathBuf;

/// Connect to a remote host via ssh0
#[derive(FromArgs)]
pub struct Args {
    /// the remote host to connect to
    #[argh(positional)]
    pub host: String,

    /// port to connect to (default: 2121)
    #[argh(option, default = "2121")]
    pub port: u16,

    /// private key path, tries to load from config folder by default
    #[argh(option, short = 'i')]
    pub key_path: Option<PathBuf>,
}
