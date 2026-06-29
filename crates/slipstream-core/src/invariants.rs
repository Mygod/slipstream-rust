#[cfg(target_has_atomic = "64")]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(not(target_has_atomic = "64"))]
use std::sync::Mutex;

pub struct InvariantReporter {
    interval_us: u64,
    #[cfg(target_has_atomic = "64")]
    last_log_at: AtomicU64,
    #[cfg(not(target_has_atomic = "64"))]
    last_log_at: Mutex<u64>,
}

impl InvariantReporter {
    pub const fn new(interval_us: u64) -> Self {
        Self {
            interval_us,
            #[cfg(target_has_atomic = "64")]
            last_log_at: AtomicU64::new(0),
            #[cfg(not(target_has_atomic = "64"))]
            last_log_at: Mutex::new(0),
        }
    }

    #[cfg(target_has_atomic = "64")]
    fn should_log(&self, now_us: u64) -> bool {
        loop {
            let last = self.last_log_at.load(Ordering::Relaxed);
            if now_us.saturating_sub(last) < self.interval_us {
                return false;
            }
            if self
                .last_log_at
                .compare_exchange(last, now_us, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
    }

    #[cfg(not(target_has_atomic = "64"))]
    fn should_log(&self, now_us: u64) -> bool {
        let mut last = self
            .last_log_at
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if now_us.saturating_sub(*last) < self.interval_us {
            return false;
        }
        *last = now_us;
        true
    }

    pub fn report<M, L>(&self, now_us: u64, make_message: M, log: L)
    where
        M: FnOnce() -> String,
        L: FnOnce(&str),
    {
        let should_log = self.should_log(now_us);
        let should_panic = cfg!(any(test, feature = "invariant-panic"));
        if should_log || should_panic {
            let message = make_message();
            if should_log {
                log(&message);
            }
            if should_panic {
                panic!("{}", message);
            }
        }
    }
}
