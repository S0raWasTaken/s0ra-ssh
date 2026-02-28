use std::path::PathBuf;

use argh::FromArgs;

/// Daemon program for ssh0. It tries toprovide secure encrypted communications between
/// two untrusted hosts over an insecure network.
#[derive(FromArgs)]
pub struct Args {
    #[argh(positional, default = "String::from(\"0.0.0.0\")")]
    pub host: String,

    /// specifies the port which ssh0-daemon will bind itself to
    #[argh(option, default = "2121")]
    pub port: u16,

    /// specifies the config directory path to be used
    #[argh(option)]
    pub config_dir: Option<PathBuf>,
}
