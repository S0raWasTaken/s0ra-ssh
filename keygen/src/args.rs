use std::path::PathBuf;

use argh::{FromArgValue, FromArgs};
use dirs::config_dir;
use ssh_key::Algorithm;

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

impl From<KeypairType> for Algorithm {
    fn from(val: KeypairType) -> Self {
        match val {
            KeypairType::Ed25519 => Self::Ed25519,
            KeypairType::Rsa512 => {
                Self::Rsa { hash: Some(ssh_key::HashAlg::Sha512) }
            }
            KeypairType::Rsa256 => {
                Self::Rsa { hash: Some(ssh_key::HashAlg::Sha256) }
            }
        }
    }
}

#[derive(Default, Debug)]
pub enum KeypairType {
    #[default]
    Ed25519,
    Rsa512,
    Rsa256,
}

impl FromArgValue for KeypairType {
    fn from_arg_value(value: &str) -> Result<Self, String> {
        match &*value.to_lowercase() {
            "ed" | "ed25519" => Ok(KeypairType::Ed25519),
            "rsa" | "rsa512" => Ok(KeypairType::Rsa512),
            "rsa256" => Ok(KeypairType::Rsa256),
            _ => Err("Invalid key pair type".to_string()),
        }
    }
}

/// Generates a new authentication key for ssh0.
#[derive(FromArgs, Debug)]
pub struct Args {
    /// accepted values: rsa, rsa256, rsa512, ed, ed25519
    #[argh(option, short = 't', default = "KeypairType::default()")]
    pub r#type: KeypairType,

    /// output path. Defaults to OS-specific config dir
    #[argh(option, short = 'o', default = "default_config_path()")]
    pub output: PathBuf,
}
