use std::path::PathBuf;

use argh::{FromArgValue, FromArgs};
use dirs::config_dir;

fn default_config_path() -> PathBuf {
    let config_path = config_dir();
    if let Some(config_dir) = config_path {
        config_dir.join("ssh0")
    } else {
        eprintln!(
            "Couldn't find the default config dir for your OS. Try passing an --output value"
        );
        std::process::exit(1);
    }
}

#[derive(Default, Debug)]
enum KeypairType {
    Dsa,
    #[default]
    Ed25519,
    Rsa,
}

impl FromArgValue for KeypairType {
    fn from_arg_value(value: &str) -> Result<Self, String> {
        match &*value.to_lowercase() {
            "dsa" => Ok(KeypairType::Dsa),
            "ed" | "ed25519" => Ok(KeypairType::Ed25519),
            "rsa" => Ok(KeypairType::Rsa),
            _ => Err("Invalid key pair type".to_string()),
        }
    }
}

/// Generates a new authentication key for ssh0
#[derive(FromArgs, Debug)]
pub struct Args {
    /// key type
    #[argh(option, short = 't', default = "KeypairType::default()")]
    r#type: KeypairType,

    /// output path
    #[argh(option, short = 'o', default = "default_config_path()")]
    output: PathBuf,
}
