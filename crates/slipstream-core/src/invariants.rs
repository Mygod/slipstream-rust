use std::fmt::Display;
use std::sync::atomic::{AtomicU64, Ordering};

pub struct InvariantReporter {
    interval_us: u64,
    last_log_at: AtomicU64,
}

impl InvariantReporter {
    pub const fn new(interval_us: u64) -> Self {
        Self {
            interval_us,
            last_log_at: AtomicU64::new(0),
        }
    }

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

    pub fn report<F>(&self, now_us: u64, message: impl Display, log: F)
    where
        F: FnOnce(&str),
    {
        let message = message.to_string();
        if self.should_log(now_us) {
            log(&message);
        }
        #[cfg(any(test, feature = "invariant-panic"))]
        panic!("{}", message);
    }
}
