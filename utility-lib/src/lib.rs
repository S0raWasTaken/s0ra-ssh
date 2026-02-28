mod dropguard;
pub use dropguard::DropGuard;

/// Expects Result<T, E>
#[macro_export]
macro_rules! break_if {
    ($x:expr) => {
        if $x {
            break;
        }
    };
}
