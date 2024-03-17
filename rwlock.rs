use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering};

pub struct RwLock<T> {
    data: UnsafeCell<T>,
    lock: AtomicUsize,
}

pub struct RwLockReadGuard<'a, T> {
    lock: &'a AtomicUsize,
    data: NonNull<T>,
}

pub struct RwLockWriteGuard<'a, T> {
    lock: &'a RwLock<T>,
}

unsafe impl<T: Send> Send for RwLock<T> {}
unsafe impl<T: Send + Sync> Sync for RwLock<T> {}

unsafe impl<T: Sync> Send for RwLockReadGuard<'_, T> {}
unsafe impl<T: Sync> Sync for RwLockReadGuard<'_, T> {}

unsafe impl<T: Send + Sync> Send for RwLockWriteGuard<'_, T> {}
unsafe impl<T: Send + Sync> Sync for RwLockWriteGuard<'_, T> {}

impl<T> RwLock<T> {
    pub const fn new(t: T) -> Self {
        Self {
            lock: AtomicUsize::new(0),
            data: UnsafeCell::new(t),
        }
    }
}

impl<T> RwLock<T> {
    pub fn dump_lock_state(&self) {
        eprintln!("lock: {:b}", self.lock.load(Ordering::Relaxed));
        eprintln!("{:p}", self);
    }

    const WRITE_LOCK_MASK: usize = 1 << (usize::BITS - 1);

    pub fn try_read(&self) -> Option<RwLockReadGuard<T>> {
        let val = self.lock.fetch_add(1, Ordering::Acquire);
        if (val & Self::WRITE_LOCK_MASK) == 0 {
            // was not already locked as Write so we're good.
            Some(RwLockReadGuard {
                lock: &self.lock,
                data: unsafe { NonNull::new_unchecked(self.data.get()) },
            })
        } else {
            // failed to lock. reset
            let _ = self.lock.fetch_sub(1, Ordering::Release);
            None
        }
    }

    pub fn try_write(&self) -> Option<RwLockWriteGuard<T>> {
        let val = self.lock.fetch_or(Self::WRITE_LOCK_MASK, Ordering::AcqRel);
        if (val & Self::WRITE_LOCK_MASK) == 0 {
            Some(RwLockWriteGuard { lock: &self })
        } else {
            // no need to undo what we did.
            None
        }
    }

    pub fn read(&self) -> RwLockReadGuard<T> {
        loop {
            match self.try_read() {
                Some(g) => break g,
                None => core::hint::spin_loop(),
            }
        }
    }

    pub fn write(&self) -> RwLockWriteGuard<T> {
        loop {
            match self.try_write() {
                Some(g) => break g,
                None => core::hint::spin_loop(),
            }
        }
    }
}

impl<'a, T> Deref for RwLockReadGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { self.data.as_ref() }
    }
}

impl<'a, T> Deref for RwLockWriteGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T> DerefMut for RwLockWriteGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<'a, T> Drop for RwLockReadGuard<'a, T> {
    fn drop(&mut self) {
        self.lock.fetch_sub(1, Ordering::Release);
    }
}

impl<'a, T> Drop for RwLockWriteGuard<'a, T> {
    fn drop(&mut self) {
        let val = self
            .lock
            .lock
            .fetch_xor(RwLock::<T>::WRITE_LOCK_MASK, Ordering::Release);
    }
}
