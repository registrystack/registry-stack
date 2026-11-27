// SPDX-License-Identifier: Apache-2.0

//! The one clock every expiry in the service reads, so tests can move time
//! without sleeping.

use std::time::Instant;

/// A source of monotonic time.
pub trait Clock: Send + Sync + 'static {
    fn now(&self) -> Instant;
}

/// The operating system's monotonic clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

#[cfg(test)]
pub(crate) use manual::ManualClock;

#[cfg(test)]
mod manual {
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use super::Clock;

    /// A clock that moves only when a test advances it.
    #[derive(Debug)]
    pub(crate) struct ManualClock {
        start: Instant,
        elapsed: Mutex<Duration>,
    }

    impl ManualClock {
        pub(crate) fn new() -> Self {
            Self {
                start: Instant::now(),
                elapsed: Mutex::new(Duration::ZERO),
            }
        }

        pub(crate) fn advance(&self, by: Duration) {
            *self.elapsed.lock().expect("clock lock") += by;
        }
    }

    impl Clock for ManualClock {
        fn now(&self) -> Instant {
            self.start + *self.elapsed.lock().expect("clock lock")
        }
    }

    #[test]
    fn a_manual_clock_moves_only_when_advanced() {
        let clock = ManualClock::new();
        let first = clock.now();
        assert_eq!(clock.now(), first);
        clock.advance(Duration::from_secs(5));
        assert_eq!(clock.now() - first, Duration::from_secs(5));
    }
}
