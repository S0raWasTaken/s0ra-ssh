use std::time::Duration;

mod dropguard;
pub use chrono;
pub use dropguard::DropGuard;

/// Wraps a future with a 10-second timeout.
///
/// # Errors
/// Returns [`tokio::time::error::Elapsed`] if the future does not complete within 10 seconds.
pub async fn timeout<F: IntoFuture>(
    f: F,
) -> Result<F::Output, tokio::time::error::Elapsed> {
    tokio::time::timeout(Duration::from_secs(10), f).await
}

/// Logs a timestamped message to stdout or stderr.
///
/// # Usage
/// ```
/// log!("Connected from {address}");       // stdout
/// log!(e "Auth failed for {address}");    // stderr
/// ```
#[macro_export]
macro_rules! log {
    (e $($arg:tt)*) => {
        eprintln!("[{}] {}", $crate::chrono::Local::now().format("%Y-%m-%d %H:%M:%S"), format_args!($($arg)*))
    };
    ($($arg:tt)*) => {
        println!("[{}] {}", $crate::chrono::Local::now().format("%Y-%m-%d %H:%M:%S"), format_args!($($arg)*))
    };
}

/// Breaks out of the current loop if the given expression is `true`.
///
/// # Example
/// ```
/// break_if!(n == 0 || tx.send(data).await.is_err());
/// ```
#[macro_export]
macro_rules! break_if {
    ($x:expr) => {
        if $x {
            break;
        }
    };
}
