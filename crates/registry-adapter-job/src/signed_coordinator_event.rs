// SPDX-License-Identifier: Apache-2.0

//! The off-by-default signed Coordinator event destination. Event identity,
//! body metadata, and selected public receiver identity are frozen per item
//! sequence, so a lost admission answer can be recovered without redirecting
//! the same event id or changing its canonical body.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use registry_adapter_connectors::coordinator_event::{
    CoordinatorEvent, CoordinatorEventConnector, CoordinatorEventOutcome, CoordinatorEventReceiver,
};
use registry_adapter_core::JobIdentity;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::destination::{DeliverableItem, DeliveryIdentity, HandOffOutcome, JobDestination};

const REVISED_ITEM: &str = "adapter.job.revised-item";
const EVENT_UNSIGNABLE: &str = "adapter.event-unsignable";
const EVENT_UNCERTAIN: &str = "coordinator.event.outcome-uncertain";
const RECEIVER_IDENTITY_DOMAIN: &[u8] = b"registry-adapter/signed-coordinator-receiver/v1";

/// Public, credential-free configuration covered by the durable selected
/// receiver identity. Values are already validated by their owning authored
/// and runtime models; the digest only establishes exact equality on retry.
pub struct CoordinatorReceiverDigestContext<'a> {
    pub binding: &'a str,
    pub base_url: &'a str,
    pub tls_trust_profile: Option<&'a str>,
    pub workflow: &'a str,
    pub trigger: &'a str,
    pub source: &'a str,
    pub event_type: &'a str,
    pub data_schema: &'a str,
}

/// Derive the durable 32-byte selected receiver identity. Credential
/// references and material, resolved TLS bytes, private CIDR policy, timeout,
/// and delivery attempt settings are deliberately excluded.
#[must_use]
pub fn receiver_identity(context: &CoordinatorReceiverDigestContext<'_>) -> [u8; 32] {
    fn component(digest: &mut Sha256, value: &[u8]) {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }

    let mut digest = Sha256::new();
    component(&mut digest, RECEIVER_IDENTITY_DOMAIN);
    component(&mut digest, context.binding.as_bytes());
    component(&mut digest, context.base_url.as_bytes());
    match context.tls_trust_profile {
        Some(profile) => {
            digest.update([1]);
            component(&mut digest, profile.as_bytes());
        }
        None => digest.update([0]),
    }
    for value in [
        context.workflow,
        context.trigger,
        context.source,
        context.event_type,
        context.data_schema,
    ] {
        component(&mut digest, value.as_bytes());
    }
    digest.finalize().into()
}

/// One validated trigger contract and its durable public identity.
pub struct SignedCoordinatorEventReceiver {
    receiver: CoordinatorEventReceiver,
    identity: [u8; 32],
}

impl SignedCoordinatorEventReceiver {
    #[must_use]
    pub fn new(receiver: CoordinatorEventReceiver, identity: [u8; 32]) -> Self {
        Self { receiver, identity }
    }
}

/// A real job destination over the shared signed-event transport.
pub struct SignedCoordinatorEventDestination {
    connector: Arc<CoordinatorEventConnector>,
    primary: SignedCoordinatorEventReceiver,
    revised: Option<SignedCoordinatorEventReceiver>,
}

impl SignedCoordinatorEventDestination {
    /// Bind the primary trigger and an optional revised trigger under one
    /// shared destination authority, source, and signing key.
    #[must_use]
    pub fn new(
        connector: Arc<CoordinatorEventConnector>,
        primary: SignedCoordinatorEventReceiver,
        revised: Option<SignedCoordinatorEventReceiver>,
    ) -> Self {
        Self {
            connector,
            primary,
            revised,
        }
    }

    fn selected(&self, item: &DeliverableItem) -> Option<&SignedCoordinatorEventReceiver> {
        if item.admitted_before {
            self.revised.as_ref()
        } else {
            Some(&self.primary)
        }
    }
}

impl JobDestination for SignedCoordinatorEventDestination {
    fn delivery_identity(
        &self,
        job: &JobIdentity,
        item: &DeliverableItem,
    ) -> Option<DeliveryIdentity> {
        let selected = self.selected(item)?;
        Some(DeliveryIdentity {
            receiver: selected.identity,
            canonical_body: projected_event(job, item, &event_id(job, item)).and_then(|event| {
                self.connector
                    .canonical_body_digest(&selected.receiver, &event)
                    .map_err(|_| ())
            }),
        })
    }

    fn deliver<'a>(
        &'a self,
        job: &'a JobIdentity,
        item: &'a DeliverableItem,
    ) -> Pin<Box<dyn Future<Output = HandOffOutcome> + Send + 'a>> {
        Box::pin(async move {
            let Some(selected) = self.selected(item) else {
                if item.delivery_attempt > 1 {
                    return HandOffOutcome::StopPass {
                        code: crate::pass::COORDINATOR_RECEIVER_CHANGED.to_string(),
                    };
                }
                return HandOffOutcome::Held {
                    code: REVISED_ITEM.to_string(),
                    run_id: item.prior_run_id.clone(),
                };
            };
            let event_id = event_id(job, item);
            let event = match projected_event(job, item, &event_id) {
                Ok(event) => event,
                Err(()) => {
                    return HandOffOutcome::Refused {
                        code: EVENT_UNSIGNABLE.to_string(),
                    };
                }
            };
            match self
                .connector
                .admit(
                    &selected.receiver,
                    event,
                    item.sequence,
                    item.delivery_attempt,
                )
                .await
            {
                CoordinatorEventOutcome::Admitted { run_id } => HandOffOutcome::Acknowledged {
                    run_id: Some(run_id),
                },
                CoordinatorEventOutcome::Unsignable => HandOffOutcome::Refused {
                    code: EVENT_UNSIGNABLE.to_string(),
                },
                CoordinatorEventOutcome::Refused { code } => HandOffOutcome::Refused {
                    code: code.to_string(),
                },
                CoordinatorEventOutcome::Stop { code } => HandOffOutcome::StopPass {
                    code: code.to_string(),
                },
                CoordinatorEventOutcome::Uncertain => HandOffOutcome::StopPass {
                    code: EVENT_UNCERTAIN.to_string(),
                },
            }
        })
    }
}

fn projected_event(
    job: &JobIdentity,
    item: &DeliverableItem,
    event_id: &str,
) -> Result<CoordinatorEvent, ()> {
    let mut data = serde_json::json!({
        "job": {"id": job.id.as_str(), "version": job.version},
        "key": item.key,
        "sequence": item.sequence,
        "digest": item.digest,
        "item": item.projected,
    });
    if let Some(prior_run_id) = &item.prior_run_id {
        data.as_object_mut()
            .expect("the fixed event data is an object")
            .insert("priorRunId".to_string(), prior_run_id.clone().into());
    }
    CoordinatorEvent::projected(
        event_id,
        item.event_time,
        item.key.clone(),
        item.sequence,
        data,
    )
    .map_err(|_| ())
}

fn event_id(job: &JobIdentity, item: &DeliverableItem) -> String {
    let mut digest = Sha256::new();
    let sequence = item.sequence.to_string();
    for component in [
        job.id.as_str().as_bytes(),
        job.version.as_bytes(),
        item.key.as_bytes(),
        sequence.as_bytes(),
        item.digest.as_bytes(),
    ] {
        digest.update((component.len() as u64).to_be_bytes());
        digest.update(component);
    }
    let digest = digest.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    // Mark the deterministic, namespaced SHA-256 name as a UUIDv5-shaped
    // identifier while retaining the full governed input framing above.
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes).hyphenated().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item() -> DeliverableItem {
        DeliverableItem {
            key: "submissions/a".to_string(),
            sequence: 1,
            digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            prior_run_id: None,
            admitted_before: false,
            first_seen: std::time::SystemTime::UNIX_EPOCH,
            event_time: std::time::SystemTime::UNIX_EPOCH,
            delivery_attempt: 1,
            projected: serde_json::json!({"answers.age": "045"}),
        }
    }

    fn job() -> JobIdentity {
        JobIdentity {
            id: "case-daily".parse().expect("a local id"),
            version: "1".to_string(),
        }
    }

    #[test]
    fn event_identity_is_stable_and_changes_with_logical_delivery() {
        let job = job();
        let mut item = item();
        let first = event_id(&job, &item);
        assert_eq!(first, event_id(&job, &item));
        assert!(Uuid::parse_str(&first).is_ok());
        item.sequence += 1;
        assert_ne!(first, event_id(&job, &item));
    }

    #[test]
    fn projected_event_has_the_one_fixed_data_shape_and_frozen_event_time() {
        let job = job();
        let mut item = item();
        item.event_time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_767_225_600);
        item.prior_run_id = Some("3a8b49f8-89fd-49f7-a2ea-60af3d694ec8".to_string());
        let event = projected_event(&job, &item, "00000000-0000-4000-8000-000000000001")
            .expect("the fixed event maps");
        assert_eq!(std::time::SystemTime::from(event.time), item.event_time);
        assert_eq!(
            event.data,
            serde_json::json!({
                "job": {"id": "case-daily", "version": "1"},
                "key": "submissions/a",
                "sequence": 1,
                "digest": item.digest,
                "priorRunId": "3a8b49f8-89fd-49f7-a2ea-60af3d694ec8",
                "item": {"answers.age": "045"}
            })
        );
    }

    #[test]
    fn receiver_identity_covers_public_routing() {
        let base = CoordinatorReceiverDigestContext {
            binding: "coordinator-main",
            base_url: "https://coordinator.example/",
            tls_trust_profile: Some("institution-ca"),
            workflow: "case-ingestion",
            trigger: "submitted",
            source: "urn:registry-adapter:job:case-daily",
            event_type: "org.example.case-submitted.v1",
            data_schema: "urn:example:schema:case-submitted:v1",
        };
        let first = receiver_identity(&base);
        assert_eq!(first, receiver_identity(&base));
        let changed = CoordinatorReceiverDigestContext {
            trigger: "revised",
            ..base
        };
        assert_ne!(first, receiver_identity(&changed));
    }

    #[tokio::test]
    async fn an_absent_revised_receiver_holds_a_first_attempt_but_stops_a_pending_retry() {
        let policy = Arc::new(
            registry_platform_httputil::destination::EventDestinationPolicy::new(
                "coordinator-test",
                "http://127.0.0.1:9/",
                registry_platform_httputil::destination::DestinationProfile::LoopbackDevelopmentHttp,
                &[],
            )
            .expect("the inert destination policy freezes"),
        );
        let connector = Arc::new(
            CoordinatorEventConnector::new(
                policy,
                "urn:registry-adapter:job:case-daily",
                vec![0x55; 32],
                std::time::Duration::from_secs(1),
            )
            .expect("the inert connector freezes"),
        );
        let primary = SignedCoordinatorEventReceiver::new(
            CoordinatorEventReceiver::new(
                "case-ingestion",
                "submitted",
                "org.example.case-submitted.v1",
                "urn:example:schema:case-submitted:v1",
            )
            .expect("the primary receiver freezes"),
            [0x11; 32],
        );
        let destination = SignedCoordinatorEventDestination::new(connector, primary, None);
        let mut revised = item();
        revised.admitted_before = true;
        revised.sequence = 2;
        revised.prior_run_id = Some("3a8b49f8-89fd-49f7-a2ea-60af3d694ec8".to_string());

        assert_eq!(
            destination.deliver(&job(), &revised).await,
            HandOffOutcome::Held {
                code: REVISED_ITEM.to_string(),
                run_id: revised.prior_run_id.clone(),
            }
        );

        revised.delivery_attempt = 2;
        assert_eq!(
            destination.deliver(&job(), &revised).await,
            HandOffOutcome::StopPass {
                code: crate::pass::COORDINATOR_RECEIVER_CHANGED.to_string(),
            }
        );
    }
}
