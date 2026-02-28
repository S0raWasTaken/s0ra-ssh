use std::{
    fs::create_dir_all,
    path::{Path, PathBuf},
};

use args::Args;
use dirs::config_dir;
use ssh_key::{Algorithm, LineEnding, PrivateKey, PublicKey, rand_core::OsRng};

mod args;

type Res<T> = Result<T, Box<dyn std::error::Error>>;
type KeyPair = (PublicKey, PrivateKey);

fn main() -> Res<()> {
    let args: Args = argh::from_env();
    println!("{args:#?}");

    let output_path = args.output.unwrap_or_else(default_config_path);

    let pair = make_key_pair(args.r#type.into())?;
    create_dir_all(&output_path)?;
    println!("Saving to {}...", output_path.display());
    save(pair, &output_path)
}

fn make_key_pair(algorithm: Algorithm) -> Res<KeyPair> {
    println!("Generating new {} key pair...", algorithm.as_str());
    let private_key = PrivateKey::random(&mut OsRng, algorithm)?;
    Ok((private_key.public_key().clone(), private_key))
}

fn save((public_key, private_key): KeyPair, output: &Path) -> Res<()> {
    let algorithm = match private_key.algorithm() {
        Algorithm::Dsa => "id_dsa",
        Algorithm::Ed25519 => "id_ed25519",
        Algorithm::Rsa { .. } => "id_rsa",
        _ => unreachable!(), // Ensured by Algorithm::from<KeyPairType>
    };

    let pub_path = output.join(format!("{algorithm}.pub"));
    let priv_path = output.join(algorithm);

    public_key.write_openssh_file(&pub_path)?;
    private_key.write_openssh_file(&priv_path, LineEnding::default())?;
    println!("Done!");
    Ok(())
}

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
