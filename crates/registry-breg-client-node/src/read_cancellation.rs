//! Invocation-local cancellation for Node reads. Dropping the canonical client
//! future drops pending token acquisition, request send or bounded body read.
//! No detached task, transport pool mutation, pagination or retry is introduced.

use std::future::Future;

use napi::Result;
use napi_derive::napi;
use tokio::sync::watch;

use crate::binding_error;

/// Internal bridge for the public facade's per-invocation AbortSignal.
#[napi]
pub struct ReadCancellation {
    cancelled: watch::Sender<bool>,
}

#[napi]
impl ReadCancellation {
    #[napi(constructor)]
    pub fn new() -> Self {
        let (cancelled, _) = watch::channel(false);
        Self { cancelled }
    }

    #[napi]
    pub fn cancel(&self) {
        self.cancelled.send_replace(true);
    }
}

impl Default for ReadCancellation {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) async fn read<T>(
    cancellation: Option<&ReadCancellation>,
    operation: impl Future<Output = Result<T>>,
) -> Result<T> {
    let Some(cancellation) = cancellation else {
        return operation.await;
    };
    let mut cancelled = cancellation.cancelled.subscribe();
    if *cancelled.borrow() {
        return Err(binding_error(
            "cancelled",
            "Base Registry read was cancelled",
        ));
    }
    tokio::select! {
        biased;
        _ = cancelled.changed() => Err(binding_error("cancelled", "Base Registry read was cancelled")),
        result = operation => result,
    }
}
