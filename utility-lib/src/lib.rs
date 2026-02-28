mod dropguard;
pub use dropguard::DropGuard;

#[macro_export]
macro_rules! break_if {
    ($x:expr) => {
        if $x {
            break;
        }
    };
}
