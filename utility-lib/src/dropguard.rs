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
        (self.run_on_drop)(&mut self.object);
    }
}
