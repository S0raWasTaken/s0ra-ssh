use argh::{FromArgValue, FromArgs};

pub struct UserAtHost {
    #[expect(dead_code)]
    user: String,
    pub host: String,
}

const INVALID_ARG: &str = "Invalid first argument, expected user@host";

impl FromArgValue for UserAtHost {
    // user@host expected
    fn from_arg_value(value: &str) -> Result<Self, String> {
        let mut split = value.split('@');

        let user = split.next().ok_or(INVALID_ARG)?.to_string();
        let host = split.next().ok_or(INVALID_ARG)?.to_string();
        Ok(Self { user, host })
    }
}

/// meow
#[derive(FromArgs)]
pub struct Args {
    /// meow
    #[argh(positional)]
    pub user_at_host: UserAtHost,

    /// meow
    #[argh(option, default = "2121")]
    pub port: u16,
}
