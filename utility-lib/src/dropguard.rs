use std::panic::{AssertUnwindSafe, catch_unwind};

/// A guard that runs a closure on drop, useful for cleanup logic.
///
/// The closure is protected with [`std::panic::catch_unwind`] so panics
/// inside it do not propagate — this is safe for the current use cases
/// (killing child processes, disabling raw mode) since they don't access
/// shared state that could be left inconsistent.
///
/// # Example
/// ```ignore
/// let _guard = DropGuard::new(child, |child| {
///     child.kill().ok();
/// });
/// ```
pub struct DropGuard<T, F: Fn(&mut T)> {
    object: T,
    run_on_drop: F,
}

impl<T, F: Fn(&mut T)> DropGuard<T, F> {
    pub fn new(object: T, run_on_drop: F) -> Self {
        Self { object, run_on_drop }
    }
}

impl<T, F: Fn(&mut T)> Drop for DropGuard<T, F> {
    fn drop(&mut self) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            (self.run_on_drop)(&mut self.object);
        }));
    }
}
