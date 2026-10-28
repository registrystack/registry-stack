// SPDX-License-Identifier: Apache-2.0

//! Exact database admission shared by Record-timer operator reads and transitions.

use std::str::FromStr as _;
use std::time::Duration;

use deadpool_postgres::Client;

use crate::timer_operator::{
    TimerControlState, TimerEffectiveLimits, TimerOperatorError, DEFAULT_TIMER_LIST_LIMIT,
};

use super::{
    begin_registry_read_transaction_with_reason, begin_registry_transaction_with_reason, timer,
    ExpectedRegistryIdentity, GuardedTransaction, RegistryLockKey, RegistryTransactionError,
    RuntimePool,
};

pub(crate) const fn operator_read_statement_budget() -> Duration {
    Duration::from_secs(10)
}

#[derive(Clone)]
pub(crate) struct TimerOperatorStore {
    pub(super) pool: RuntimePool,
    pub(super) expected: ExpectedRegistryIdentity,
    pub(super) lock_key: RegistryLockKey,
    pub(super) lock_timeout: Duration,
    pub(super) statement_budget: Duration,
    pub(super) limits: TimerEffectiveLimits,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct TimerStoreAdmission {
    pub(super) protocol_version: u32,
    pub(super) control_state: TimerControlState,
    pub(super) control_epoch: i64,
    pub(super) instance_epoch: i64,
}

impl TimerOperatorStore {
    pub(crate) fn new(
        pool: RuntimePool,
        expected: ExpectedRegistryIdentity,
        lock_key: RegistryLockKey,
        lock_timeout: Duration,
        statement_budget: Duration,
        limits: TimerEffectiveLimits,
    ) -> Result<Self, TimerOperatorError> {
        expected
            .validate()
            .map_err(|_| TimerOperatorError::PackageRefused)?;
        if lock_timeout.is_zero()
            || lock_timeout > Duration::from_secs(30)
            || statement_budget.is_zero()
            || statement_budget > Duration::from_secs(30)
            || limits.claim_batch_maximum == 0
            || limits.stale_revision_batch_maximum == 0
            || limits.elapsed_window_batch_maximum == 0
            || limits.maximum_concurrent_attempts == 0
            || limits.operator_list_maximum < DEFAULT_TIMER_LIST_LIMIT
        {
            return Err(TimerOperatorError::OperationRefused);
        }
        Ok(Self {
            pool,
            expected,
            lock_key,
            lock_timeout,
            statement_budget,
            limits,
        })
    }

    pub(super) async fn client(&self) -> Result<Client, TimerOperatorError> {
        self.pool
            .get()
            .await
            .map_err(|_| TimerOperatorError::DatabaseUnavailable)
    }

    pub(super) async fn begin_read<'a>(
        &self,
        client: &'a mut Client,
    ) -> Result<(GuardedTransaction<'a>, TimerStoreAdmission), TimerOperatorError> {
        let guarded = begin_registry_read_transaction_with_reason(
            client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
        )
        .await
        .map_err(|error| match error {
            RegistryTransactionError::TimerProtocolUnsupported => {
                TimerOperatorError::ProtocolUnsupported
            }
            RegistryTransactionError::Lock(_) => TimerOperatorError::InProgress,
            RegistryTransactionError::Kernel(_) => TimerOperatorError::DatabaseUnavailable,
        })?;
        guarded
            .set_statement_budget(self.statement_budget)
            .await
            .map_err(|_| TimerOperatorError::DatabaseUnavailable)?;
        let protocol = timer::read_timer_protocol(guarded.transaction())
            .await
            .map_err(|_| TimerOperatorError::DatabaseUnavailable)?;
        if protocol.protocol_version != timer::SUPPORTED_TIMER_PROTOCOL_VERSION {
            return Err(TimerOperatorError::ProtocolUnsupported);
        }
        if protocol.bound_instance_epoch != protocol.registry_instance_epoch {
            return Err(TimerOperatorError::OperationRefused);
        }
        let control_state = TimerControlState::from_str(&protocol.control_state)?;
        Ok((
            guarded,
            TimerStoreAdmission {
                protocol_version: u32::try_from(protocol.protocol_version)
                    .map_err(|_| TimerOperatorError::ProtocolUnsupported)?,
                control_state,
                control_epoch: protocol.control_epoch,
                instance_epoch: protocol.registry_instance_epoch,
            },
        ))
    }

    pub(super) async fn begin_write<'a>(
        &self,
        client: &'a mut Client,
    ) -> Result<(GuardedTransaction<'a>, TimerStoreAdmission), TimerOperatorError> {
        let guarded = begin_registry_transaction_with_reason(
            client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
        )
        .await
        .map_err(|error| match error {
            RegistryTransactionError::TimerProtocolUnsupported => {
                TimerOperatorError::ProtocolUnsupported
            }
            RegistryTransactionError::Lock(_) => TimerOperatorError::InProgress,
            RegistryTransactionError::Kernel(_) => TimerOperatorError::DatabaseUnavailable,
        })?;
        guarded
            .set_statement_budget(self.statement_budget)
            .await
            .map_err(|_| TimerOperatorError::DatabaseUnavailable)?;
        let protocol = timer::read_timer_protocol(guarded.transaction())
            .await
            .map_err(|_| TimerOperatorError::DatabaseUnavailable)?;
        if protocol.protocol_version != timer::SUPPORTED_TIMER_PROTOCOL_VERSION {
            return Err(TimerOperatorError::ProtocolUnsupported);
        }
        if protocol.bound_instance_epoch != protocol.registry_instance_epoch {
            return Err(TimerOperatorError::OperationRefused);
        }
        let control_state = TimerControlState::from_str(&protocol.control_state)?;
        Ok((
            guarded,
            TimerStoreAdmission {
                protocol_version: u32::try_from(protocol.protocol_version)
                    .map_err(|_| TimerOperatorError::ProtocolUnsupported)?,
                control_state,
                control_epoch: protocol.control_epoch,
                instance_epoch: protocol.registry_instance_epoch,
            },
        ))
    }

    pub(super) const fn limits(&self) -> TimerEffectiveLimits {
        self.limits
    }
}
