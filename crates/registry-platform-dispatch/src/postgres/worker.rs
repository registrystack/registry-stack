// SPDX-License-Identifier: Apache-2.0

//! A bounded-concurrency worker that drains due jobs and then polls.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::task::JoinSet;

use super::dispatcher::{DispatchOutcome, Dispatcher};
use super::store::{DispatchEvent, DispatchStore, DispatchTransport};

/// How one worker drains and polls.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkerConfig {
    /// The most sends one worker runs at once.
    pub concurrency: NonZeroUsize,
    /// How long the worker waits after a drain finds no due job.
    pub idle_poll: Duration,
}

/// Runs [`Dispatcher::dispatch_once`] on `concurrency` lanes until no job is
/// due, then waits `idle_poll` or for shutdown.
pub struct DispatchWorker<S: DispatchStore, T> {
    dispatcher: Dispatcher<S>,
    transport: Arc<T>,
    config: WorkerConfig,
}

impl<S, T> DispatchWorker<S, T>
where
    S: DispatchStore,
    T: DispatchTransport<Job = S::Job, Detail = S::Detail> + 'static,
{
    #[must_use]
    pub fn new(dispatcher: Dispatcher<S>, transport: Arc<T>, config: WorkerConfig) -> Self {
        Self {
            dispatcher,
            transport,
            config,
        }
    }

    /// Dispatch due jobs on every lane until each lane finds none, fails, or
    /// sees shutdown, and return how many jobs moved. A lane that fails
    /// reports [`DispatchEvent::IterationFailed`] and stops for this drain.
    pub async fn drain(&self, shutdown: &watch::Receiver<bool>) -> usize {
        let mut lanes = JoinSet::new();
        for _ in 0..self.config.concurrency.get() {
            let dispatcher = self.dispatcher.clone();
            let transport = Arc::clone(&self.transport);
            let shutdown = shutdown.clone();
            lanes.spawn(async move {
                let mut moved = 0_usize;
                while !*shutdown.borrow() {
                    match dispatcher.dispatch_once(transport.as_ref()).await {
                        Ok(DispatchOutcome::Idle) => break,
                        Ok(_) => moved += 1,
                        Err(_) => {
                            dispatcher
                                .store()
                                .operational_event(DispatchEvent::IterationFailed);
                            break;
                        }
                    }
                }
                moved
            });
        }
        let mut moved = 0;
        while let Some(lane) = lanes.join_next().await {
            match lane {
                Ok(count) => moved += count,
                Err(_) => self
                    .dispatcher
                    .store()
                    .operational_event(DispatchEvent::IterationFailed),
            }
        }
        moved
    }

    /// Drain, then poll, until `shutdown` turns true or its sender closes.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        loop {
            if *shutdown.borrow() {
                return;
            }
            self.drain(&shutdown).await;
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return;
                    }
                }
                () = tokio::time::sleep(self.config.idle_poll) => {}
            }
        }
    }
}
