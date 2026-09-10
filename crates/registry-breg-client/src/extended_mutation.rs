// SPDX-License-Identifier: Apache-2.0

//! Metadata-bound direct mutation methods beyond Create and PATCH.

use uuid::Uuid;

use crate::{
    BRegComplete, BRegEtag, BRegIdempotencyKey, BRegRecordFormat, BRegTombstoneBinding,
    BaseRegistryClient, BaseRegistryClientError, RegistryRecordSingleResponse,
};

impl BaseRegistryClient {
    /// Tombstone one record against the caller's original strong entity tag.
    ///
    /// The server returns the resulting Registry Record envelope. This method
    /// performs no condition refresh and never retries the mutation.
    pub async fn tombstone_record(
        &self,
        operation: &BRegTombstoneBinding,
        record_identifier: Uuid,
        etag: &BRegEtag,
        idempotency_key: &BRegIdempotencyKey,
        format: BRegRecordFormat,
    ) -> Result<BRegComplete<RegistryRecordSingleResponse>, BaseRegistryClientError> {
        if !operation.matches_source(&self.source_binding())
            || operation.source_binding() != self.source_binding()
        {
            return Err(BaseRegistryClientError::invalid_request(
                "the Base Registry Engine tombstone operation belongs to another client source",
            ));
        }
        self.execute_tombstone(
            &operation.path_for_record(record_identifier),
            operation.access_profile(),
            operation.registry_identifier(),
            operation.dataset_identifier(),
            operation.entity_identifier(),
            record_identifier,
            etag,
            idempotency_key,
            format,
        )
        .await
    }
}
