use std::ops::{Deref, DerefMut};

#[derive(Debug)]
pub struct LazyMut<T: Default>(Option<T>);
impl<T: Default> Deref for LazyMut<T> {
	type Target = T;
	fn deref(&self) -> &Self::Target {
		unreachable!();
	}
}
impl<T: Default> DerefMut for LazyMut<T> {
	fn deref_mut(&mut self) -> &mut Self::Target {
		return self.0.get_or_insert_with(|| T::default());
	}
}
impl<T: Default> Default for LazyMut<T> {
	fn default() -> Self {
		return Self(None);
	}
}