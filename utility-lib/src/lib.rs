mod dropguard;
use std::time::Duration;

pub use dropguard::DropGuard;

/// # Errors
/// Fails when the future times out.
pub async fn timeout<F: IntoFuture>(
    f: F,
) -> Result<F::Output, tokio::time::error::Elapsed> {
    tokio::time::timeout(Duration::from_secs(10), f).await
}

#[macro_export]
macro_rules! break_if {
    ($x:expr) => {
        if $x {
            break;
        }
    };
}
