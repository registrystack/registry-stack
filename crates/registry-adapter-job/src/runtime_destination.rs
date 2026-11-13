// SPDX-License-Identifier: Apache-2.0

//! Host-side activation of the one destination selected by an authored job.
//! Product clients and signing material stay here, outside the route engine.

use std::collections::BTreeMap;
#[cfg(any(feature = "direct-breg", feature = "signed-coordinator-event"))]
use std::sync::Arc;
#[cfg(any(feature = "direct-breg", feature = "signed-coordinator-event"))]
use std::time::Duration;

#[cfg(any(feature = "direct-breg", feature = "signed-coordinator-event"))]
use registry_adapter_core::AdapterEndpointBindings;
#[cfg(feature = "direct-breg")]
use registry_adapter_core::DirectBregMode;
#[cfg(feature = "signed-coordinator-event")]
use registry_adapter_core::EndpointBinding;
use registry_adapter_core::{AdapterJob, JobDestination};
use registry_adapter_engine::job::JobProgram;
use registry_adapter_engine::job_sources::JobRuntimeConfig;
use registry_platform_config::SecretResolver;
#[cfg(feature = "signed-coordinator-event")]
use registry_platform_yaml::ExternalId;
use registry_platform_yaml::{BoundedU64, LocalId, SecretReference, Url};
use serde::Deserialize;

use crate::destination::JobDestination as DestinationSeam;

/// Refuse an authored destination when its explicit release feature is not
/// present. No destination falls back to fixtures or another destination.
pub fn require_compiled_destination(destination: &JobDestination) -> Result<(), &'static str> {
    match destination {
        JobDestination::DirectBreg { .. } if !cfg!(feature = "direct-breg") => {
            Err("adapter.job.destination-direct-breg-not-compiled")
        }
        JobDestination::SignedCoordinatorEvent { .. }
            if !cfg!(feature = "signed-coordinator-event") =>
        {
            Err("adapter.job.destination-signed-coordinator-event-not-compiled")
        }
        _ => Ok(()),
    }
}

/// Runtime-only connection and credential bindings, keyed by the authored
/// destination's `binding` id. Authored workflow and BReg operation authority
/// never move into this environment document.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum RuntimeDestinationBinding {
    DirectBreg {
        base_url: Url,
        token_endpoint: Url,
        client_id: String,
        private_key_ref: SecretReference,
        /// The authorization server's issuer identifier, the sole client
        /// assertion audience RFC 10070 section 4 allows.
        client_assertion_audience: String,
        scopes: Vec<String>,
        resource: String,
        attempt_timeout_milliseconds: BoundedU64<1, 10_000>,
        #[serde(default)]
        data_tls_trust_profile: Option<LocalId>,
        #[serde(default)]
        token_tls_trust_profile: Option<LocalId>,
    },
    SignedCoordinatorEvent {
        base_url: Url,
        signing_key_ref: SecretReference,
        attempt_timeout_milliseconds: BoundedU64<1, 10_000>,
        #[serde(default)]
        tls_trust_profile: Option<LocalId>,
    },
}

/// Activate the one authored destination from its exact runtime binding.
/// Missing features, bindings, secrets, trust material, and kind mismatches
/// refuse startup. The fixture destination is never an operational fallback.
pub async fn activate_destination<'a>(
    program: &'a JobProgram,
    runtime: &JobRuntimeConfig,
    resolver: &SecretResolver,
) -> Result<Box<dyn DestinationSeam + 'a>, String> {
    require_compiled_destination(&program.job.destination).map_err(not_compiled_message)?;
    let bindings = load_runtime_bindings(runtime)?;
    match &program.job.destination {
        JobDestination::DirectBreg { binding, .. } => {
            let configured = bindings
                .get(binding)
                .ok_or_else(|| missing_binding(binding))?;
            #[cfg(feature = "direct-breg")]
            {
                activate_direct(program, configured, &runtime.core, resolver).await
            }
            #[cfg(not(feature = "direct-breg"))]
            {
                let _ = (configured, &runtime.core, resolver);
                unreachable!("the feature guard returned before activation")
            }
        }
        JobDestination::SignedCoordinatorEvent { binding, .. } => {
            let configured = bindings
                .get(binding)
                .ok_or_else(|| missing_binding(binding))?;
            #[cfg(feature = "signed-coordinator-event")]
            {
                activate_signed(program, configured, &runtime.core, resolver)
            }
            #[cfg(not(feature = "signed-coordinator-event"))]
            {
                let _ = (configured, &runtime.core, resolver);
                unreachable!("the feature guard returned before activation")
            }
        }
    }
}

/// Check destination feature and runtime binding shape without resolving a
/// secret or opening a network connection. `adapter-job check` uses this
/// before it reports success.
pub fn check_destination_runtime(
    job: &AdapterJob,
    runtime: &JobRuntimeConfig,
) -> Result<(), String> {
    require_compiled_destination(&job.destination).map_err(not_compiled_message)?;
    let bindings = load_runtime_bindings(runtime)?;
    let (binding, expected) = match &job.destination {
        JobDestination::DirectBreg { binding, .. } => (binding, "direct-breg"),
        JobDestination::SignedCoordinatorEvent { binding, .. } => {
            (binding, "signed-coordinator-event")
        }
    };
    let configured = bindings
        .get(binding)
        .ok_or_else(|| missing_binding(binding))?;
    let actual = match configured {
        RuntimeDestinationBinding::DirectBreg { .. } => "direct-breg",
        RuntimeDestinationBinding::SignedCoordinatorEvent { .. } => "signed-coordinator-event",
    };
    if actual != expected {
        return Err("the runtime destination kind does not match the job destination".to_string());
    }
    Ok(())
}

fn load_runtime_bindings(
    runtime: &JobRuntimeConfig,
) -> Result<BTreeMap<LocalId, RuntimeDestinationBinding>, String> {
    let bindings = runtime
        .destinations
        .as_ref()
        .ok_or_else(|| "the runtime config carries no destinations block".to_string())?;
    let bindings =
        serde_json::from_value::<BTreeMap<LocalId, RuntimeDestinationBinding>>(bindings.clone())
            .map_err(|error| {
                // A missing member is named, because its name is the fix.
                // Any other refusal stays value-free: serde's text for it
                // can echo the refused value.
                let text = error.to_string();
                if text.starts_with("missing field ") {
                    format!("the runtime destinations block was refused: {text}")
                } else {
                    "the runtime destinations block was refused".to_string()
                }
            })?;
    Ok(bindings)
}

fn missing_binding(binding: &LocalId) -> String {
    format!(
        "the job's destination binding `{binding}` is not in the runtime `destinations` block; add `destinations.{binding}` or change the job's `destination.binding`"
    )
}

/// The refusal text for a destination whose release feature is absent: the
/// code stays first for scripts, the sentence names the fix.
fn not_compiled_message(code: &str) -> String {
    let feature = if code.contains("signed-coordinator-event") {
        "signed-coordinator-event"
    } else {
        "direct-breg"
    };
    format!("{code}: this adapter-job build lacks the `{feature}` feature; use a build that includes it or change the job's destination type")
}

#[cfg(feature = "direct-breg")]
async fn activate_direct<'a>(
    program: &'a JobProgram,
    configured: &RuntimeDestinationBinding,
    core: &AdapterEndpointBindings,
    resolver: &SecretResolver,
) -> Result<Box<dyn DestinationSeam + 'a>, String> {
    use crate::direct_breg::{
        DirectBregDestination, DirectBregMappingRefused, DirectBregOperation,
    };
    use registry_adapter_connectors::breg::{BregConnector, BregConnectorConfig};
    use registry_platform_crypto::PrivateJwk;
    use registry_platform_httputil::client::{PrivateKeyJwt, PrivateKeyJwtConfig};
    use registry_platform_httputil::FetchUrlPolicy;

    let JobDestination::DirectBreg {
        binding,
        access_profile,
        action,
        mode,
        mapping,
        ..
    } = &program.job.destination
    else {
        unreachable!("the authored destination selects direct BReg")
    };
    let RuntimeDestinationBinding::DirectBreg {
        base_url,
        token_endpoint,
        client_id,
        private_key_ref,
        client_assertion_audience,
        scopes,
        resource,
        attempt_timeout_milliseconds,
        data_tls_trust_profile,
        token_tls_trust_profile,
    } = configured
    else {
        return Err("the runtime destination kind does not match the job destination".to_string());
    };
    let key = resolver
        .resolve(private_key_ref.as_str())
        .map_err(|_| "the direct BReg private key could not be resolved".to_string())?;
    let key = std::str::from_utf8(key.expose_secret())
        .ok()
        .and_then(|json| PrivateJwk::parse(json).ok())
        .ok_or_else(|| "the direct BReg private key was refused".to_string())?;
    let mut token_config = PrivateKeyJwtConfig::new(token_endpoint.to_url(), client_id, key)
        .with_audience(client_assertion_audience)
        .with_scopes(scopes.iter().cloned())
        .with_resource(resource)
        .with_attempt_timeout(Duration::from_millis(attempt_timeout_milliseconds.get()))
        .with_fetch_url_policy(if token_endpoint.is_https() {
            FetchUrlPolicy::strict()
        } else {
            FetchUrlPolicy::dev()
        });
    if let Some(profile) = token_tls_trust_profile {
        let roots = registry_adapter_engine::auth::capture_ca_bundle(core, profile.as_str())
            .map_err(|_| "the direct BReg token TLS material was refused".to_string())?;
        token_config = token_config.with_trusted_root_certificates(roots.as_bytes().to_vec());
    }
    let tokens = Arc::new(
        PrivateKeyJwt::new(token_config)
            .map_err(|_| "the direct BReg credential configuration was refused".to_string())?,
    );
    let mut connector_config =
        BregConnectorConfig::for_action(base_url.as_str(), tokens, access_profile, action)
            .with_attempt_timeout(Duration::from_millis(attempt_timeout_milliseconds.get()));
    if let Some(profile) = data_tls_trust_profile {
        let roots = registry_adapter_engine::auth::capture_ca_bundle(core, profile.as_str())
            .map_err(|_| "the direct BReg data TLS material was refused".to_string())?;
        connector_config =
            connector_config.with_trusted_root_certificates(roots.as_bytes().to_vec());
    }
    let connector = Arc::new(
        BregConnector::connect(connector_config)
            .await
            .map_err(|fault| direct_breg_bind_refusal(binding, &fault, action, access_profile))?,
    );
    let expected_mode = match mode {
        DirectBregMode::Immediate => "immediate",
        DirectBregMode::Proposal => "proposal",
    };
    if connector.action_mode_name() != expected_mode {
        return Err(
            "the direct BReg Action mode does not match the authored destination".to_string(),
        );
    }
    if connector.action_requires_target_conditions() {
        return Err(direct_breg_guarded_action_refusal(action));
    }
    if *mode == DirectBregMode::Proposal
        && !connector.catalog().iter().any(|descriptor| {
            descriptor.name == registry_adapter_connectors::breg::proposal::START.name
        })
    {
        return Err(direct_breg_proposal_get_refusal(action, access_profile));
    }
    let mapper = move |item: &crate::destination::DeliverableItem| {
        let exchange = serde_json::json!({
            "body": item.projected,
            "headers": {},
            "properties": {}
        });
        let mapped = program
            .map_destination(mapping, &exchange)
            .map_err(|_| DirectBregMappingRefused)?;
        match mode {
            DirectBregMode::Immediate => Ok(DirectBregOperation::ImmediateAction { input: mapped }),
            DirectBregMode::Proposal => {
                #[derive(Deserialize)]
                #[serde(rename_all = "camelCase", deny_unknown_fields)]
                struct ProposalMapping {
                    start_input: serde_json::Value,
                    submit_body: serde_json::Value,
                }
                let mapped = serde_json::from_value::<ProposalMapping>(mapped)
                    .map_err(|_| DirectBregMappingRefused)?;
                Ok(DirectBregOperation::Proposal {
                    start_input: mapped.start_input,
                    submit_body: mapped.submit_body,
                })
            }
        }
    };
    let receiver = crate::direct_breg::receiver_identity(
        &crate::direct_breg::DirectBregReceiverDigestContext {
            binding: binding.as_str(),
            base_url: base_url.as_str(),
            token_endpoint: token_endpoint.as_str(),
            client_id,
            data_tls_trust_profile: data_tls_trust_profile.as_ref().map(LocalId::as_str),
            access_profile,
            action,
            mode: expected_mode,
        },
    );
    Ok(Box::new(DirectBregDestination::new(
        connector, mapper, receiver,
    )))
}

/// One direct BReg bind failure as its closed code, the field to check,
/// and the fix. The Action and profile are authored selectors, not secrets.
#[cfg(feature = "direct-breg")]
fn direct_breg_bind_refusal(
    binding: &LocalId,
    fault: &registry_adapter_connectors::operation::ConnectorFault,
    action: &str,
    profile: &str,
) -> String {
    use registry_adapter_connectors::breg::TOKEN_UNAVAILABLE;
    use registry_adapter_connectors::operation::ConnectorFault;
    match fault {
        ConnectorFault::AuthorityAbsent => format!(
            "adapter.job.breg-action-not-granted: BReg does not disclose Action `{action}` to access profile `{profile}`; check the job's action and accessProfile, and grant the Action to that profile in BReg"
        ),
        ConnectorFault::Native { code: Some(code) } if code.starts_with("transport.") => {
            format!("adapter.job.breg-unreachable: BReg did not answer the metadata read; check `destinations.{binding}` baseUrl and dataTlsTrustProfile, and that BReg is running")
        }
        ConnectorFault::Native { code: Some(code) }
            if code == TOKEN_UNAVAILABLE || code == "authentication.refused" =>
        {
            format!("adapter.job.breg-credential-refused: no bearer credential BReg accepts was obtained; check `destinations.{binding}` tokenEndpoint, clientAssertionAudience, clientId, privateKeyRef, scopes and resource, and that BReg trusts the issuer")
        }
        _ => format!(
            "adapter.job.breg-metadata-refused: BReg's metadata could not be read under access profile `{profile}`; check that `destinations.{binding}` baseUrl names a BReg deployment of a compatible version"
        ),
    }
}

/// An Action that declares target-condition keys: its request depends on a
/// conditions read that its own application changes, so a lost response
/// cannot be recovered by sending the same request again.
#[cfg(feature = "direct-breg")]
fn direct_breg_guarded_action_refusal(action: &str) -> String {
    format!(
        "adapter.job.breg-action-guarded: Action `{action}` declares target-condition keys, so a lost response cannot be recovered on the direct path; use the signed-coordinator-event destination, which resolves the target, or an Action without target-condition keys"
    )
}

/// A Proposal-mode Action whose profile lacks the Proposal get grant: the
/// job cannot read a started draft back to submit it.
#[cfg(feature = "direct-breg")]
fn direct_breg_proposal_get_refusal(action: &str, profile: &str) -> String {
    format!(
        "adapter.job.breg-proposal-get-not-granted: BReg does not grant Proposal get for Action `{action}` to access profile `{profile}`; grant Proposal get and submit to that profile in BReg"
    )
}

#[cfg(feature = "signed-coordinator-event")]
fn activate_signed<'a>(
    program: &'a JobProgram,
    configured: &RuntimeDestinationBinding,
    core: &AdapterEndpointBindings,
    resolver: &SecretResolver,
) -> Result<Box<dyn DestinationSeam + 'a>, String> {
    use registry_adapter_connectors::coordinator_event::{
        CoordinatorEventConnector, CoordinatorEventReceiver,
    };
    use registry_platform_httputil::destination::{DestinationProfile, EventDestinationPolicy};

    let JobDestination::SignedCoordinatorEvent {
        binding,
        workflow,
        trigger,
        source,
        event_type,
        data_schema,
        revised_receiver,
    } = &program.job.destination
    else {
        unreachable!("the authored destination selects signed events")
    };
    let RuntimeDestinationBinding::SignedCoordinatorEvent {
        base_url,
        signing_key_ref,
        attempt_timeout_milliseconds,
        tls_trust_profile,
    } = configured
    else {
        return Err("the runtime destination kind does not match the job destination".to_string());
    };
    let profile = if base_url.is_https() {
        DestinationProfile::ProductionHttps
    } else {
        DestinationProfile::LoopbackDevelopmentHttp
    };
    let private_cidrs = core
        .allowed_private_cidrs
        .iter()
        .map(registry_adapter_core::Cidr::network)
        .collect::<Vec<_>>();
    let mut policy =
        EventDestinationPolicy::new(binding.as_str(), base_url.as_str(), profile, &private_cidrs)
            .map_err(|_| "the signed-event destination policy was refused".to_string())?;
    if tls_trust_profile.is_some() {
        let endpoint = tls_endpoint(binding, base_url, tls_trust_profile.clone())?;
        let materials =
            registry_adapter_engine::auth::EndpointTls::resolve(&endpoint, core, resolver)
                .map_err(|_| "the signed-event destination TLS material was refused".to_string())?
                .into_materials();
        let material = materials.data.ok_or_else(|| {
            "the signed-event destination TLS profile produced no material".to_string()
        })?;
        policy = policy.require_configured_tls();
        policy
            .install_configured_tls(material)
            .map_err(|_| "the signed-event destination TLS material was refused".to_string())?;
    }
    let key = resolver
        .resolve(signing_key_ref.as_str())
        .map_err(|_| "the signed-event key could not be resolved".to_string())?;
    let connector = Arc::new(
        CoordinatorEventConnector::new(
            Arc::new(policy),
            source,
            key.expose_secret().to_vec(),
            Duration::from_millis(attempt_timeout_milliseconds.get()),
        )
        .map_err(|_| "the signed-event destination configuration was refused".to_string())?,
    );
    let selected = |selected_trigger: &str,
                    selected_type: &str,
                    selected_schema: &str|
     -> Result<
        crate::signed_coordinator_event::SignedCoordinatorEventReceiver,
        String,
    > {
        let receiver = CoordinatorEventReceiver::new(
            workflow.as_str(),
            selected_trigger,
            selected_type,
            selected_schema,
        )
        .map_err(|_| "the signed-event receiver configuration was refused".to_string())?;
        let identity = crate::signed_coordinator_event::receiver_identity(
            &crate::signed_coordinator_event::CoordinatorReceiverDigestContext {
                binding: binding.as_str(),
                base_url: base_url.as_str(),
                tls_trust_profile: tls_trust_profile.as_ref().map(LocalId::as_str),
                workflow: workflow.as_str(),
                trigger: selected_trigger,
                source,
                event_type: selected_type,
                data_schema: selected_schema,
            },
        );
        Ok(
            crate::signed_coordinator_event::SignedCoordinatorEventReceiver::new(
                receiver, identity,
            ),
        )
    };
    let primary = selected(trigger.as_str(), event_type, data_schema)?;
    let revised = revised_receiver
        .as_ref()
        .map(|receiver| {
            selected(
                receiver.trigger.as_str(),
                &receiver.event_type,
                &receiver.data_schema,
            )
        })
        .transpose()?;
    Ok(Box::new(
        crate::signed_coordinator_event::SignedCoordinatorEventDestination::new(
            connector, primary, revised,
        ),
    ))
}

#[cfg(feature = "signed-coordinator-event")]
fn tls_endpoint(
    binding: &LocalId,
    base_url: &Url,
    tls_trust_profile: Option<LocalId>,
) -> Result<EndpointBinding, String> {
    Ok(EndpointBinding {
        endpoint: ExternalId::new(binding.as_str())
            .map_err(|_| "the destination id was refused")?,
        base_url: base_url.clone(),
        credential: None,
        anonymous_https: None,
        attempt_timeout_milliseconds: None,
        maximum_response_bytes: None,
        maximum_concurrency: BoundedU64::new(8).expect("8 is inside the bound"),
        tls_trust_profile,
        mtls_identity: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each bind failure names its own closed code, the authored or
    /// runtime field to check, and the fix.
    #[cfg(feature = "direct-breg")]
    #[test]
    fn a_direct_breg_bind_failure_names_its_cause_and_fix() {
        use registry_adapter_connectors::breg::TOKEN_UNAVAILABLE;
        use registry_adapter_connectors::operation::ConnectorFault;
        let native = |code: &str| ConnectorFault::Native {
            code: Some(code.to_owned()),
        };
        let cases = [
            (
                ConnectorFault::AuthorityAbsent,
                "adapter.job.breg-action-not-granted: BReg does not disclose Action `register-household` to access profile `writer`",
            ),
            (native("transport.connect"), "adapter.job.breg-unreachable: "),
            (native("transport.timeout"), "adapter.job.breg-unreachable: "),
            (
                native(TOKEN_UNAVAILABLE),
                "adapter.job.breg-credential-refused: ",
            ),
            (
                native("authentication.refused"),
                "adapter.job.breg-credential-refused: ",
            ),
            (
                ConnectorFault::Native { code: None },
                "adapter.job.breg-metadata-refused: ",
            ),
            (
                ConnectorFault::InvalidInput,
                "adapter.job.breg-metadata-refused: ",
            ),
        ];
        for (fault, start) in cases {
            let binding = LocalId::new("household-registry").expect("a local id");
            let message =
                direct_breg_bind_refusal(&binding, &fault, "register-household", "writer");
            assert!(message.starts_with(start), "{fault:?}: {message}");
        }
        let guarded = direct_breg_guarded_action_refusal("update-household");
        assert!(
            guarded.starts_with(
                "adapter.job.breg-action-guarded: Action `update-household` declares target-condition keys"
            ),
            "{guarded}"
        );
        assert!(guarded.contains("signed-coordinator-event"), "{guarded}");
        assert!(
            direct_breg_proposal_get_refusal("register-household", "writer").starts_with(
                "adapter.job.breg-proposal-get-not-granted: BReg does not grant Proposal get for Action `register-household` to access profile `writer`"
            )
        );
    }
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;

    #[cfg(any(
        not(feature = "direct-breg"),
        not(feature = "signed-coordinator-event")
    ))]
    fn destination(value: serde_json::Value) -> JobDestination {
        serde_json::from_value(value).expect("a destination")
    }

    #[cfg(any(
        not(feature = "direct-breg"),
        not(feature = "signed-coordinator-event")
    ))]
    #[test]
    fn an_uncompiled_destination_refuses_without_fallback() {
        #[cfg(not(feature = "direct-breg"))]
        assert_eq!(
            require_compiled_destination(&destination(serde_json::json!({
                "type": "direct-breg",
                "binding": "breg-main",
                "accessProfile": "writer",
                "action": "register-household",
                "mode": "proposal",
                "mapping": {"file": "map.rhai", "entrypoint": "map_item", "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"},
                "receiptRetentionDays": 7
            }))),
            Err("adapter.job.destination-direct-breg-not-compiled")
        );
        #[cfg(not(feature = "signed-coordinator-event"))]
        assert_eq!(
            require_compiled_destination(&destination(serde_json::json!({
                "type": "signed-coordinator-event",
                "binding": "coordinator-main",
                "workflow": "case-ingestion",
                "trigger": "submitted",
                "source": "urn:registry-adapter:job:case-daily",
                "eventType": "org.example.case-submitted.v1",
                "dataSchema": "urn:example:schema:case-submitted:v1"
            }))),
            Err("adapter.job.destination-signed-coordinator-event-not-compiled")
        );
    }

    #[test]
    fn a_missing_binding_names_the_binding_and_both_fixes() {
        let binding = LocalId::new("household-registry").expect("a local id");
        let message = missing_binding(&binding);
        assert!(message.contains("`household-registry`"), "{message}");
        assert!(
            message.contains("`destinations.household-registry`"),
            "{message}"
        );
        assert!(message.contains("destination.binding"), "{message}");
    }

    #[test]
    fn the_not_compiled_refusal_keeps_the_code_and_names_the_feature() {
        let message = not_compiled_message("adapter.job.destination-direct-breg-not-compiled");
        assert!(
            message.starts_with("adapter.job.destination-direct-breg-not-compiled: "),
            "{message}"
        );
        assert!(message.contains("`direct-breg` feature"), "{message}");
        let message =
            not_compiled_message("adapter.job.destination-signed-coordinator-event-not-compiled");
        assert!(
            message.contains("`signed-coordinator-event` feature"),
            "{message}"
        );
    }

    #[cfg(feature = "direct-breg")]
    #[test]
    fn a_failed_bind_names_the_binding_a_closed_cause_and_the_next_step() {
        use registry_adapter_connectors::operation::ConnectorFault;
        let binding = LocalId::new("household-registry").expect("a local id");
        let connect = direct_breg_bind_refusal(
            &binding,
            &ConnectorFault::Native {
                code: Some("transport.connect".to_string()),
            },
            "register-household",
            "writer",
        );
        assert!(
            connect.starts_with("adapter.job.breg-unreachable: "),
            "{connect}"
        );
        assert!(
            connect.contains("`destinations.household-registry`"),
            "{connect}"
        );
        assert!(!connect.contains("bind metadata"), "{connect}");
        let token = direct_breg_bind_refusal(
            &binding,
            &ConnectorFault::Native {
                code: Some("authentication.refused".to_string()),
            },
            "register-household",
            "writer",
        );
        assert!(
            token.contains("`destinations.household-registry` tokenEndpoint"),
            "{token}"
        );
    }

    #[test]
    fn runtime_destination_bindings_are_explicit_and_closed() {
        let signed = serde_json::json!({
            "coordinator-main": {
                "type": "signed-coordinator-event",
                "baseUrl": "https://coordinator.example/",
                "signingKeyRef": "secret:env/COORDINATOR_EVENT_KEY",
                "attemptTimeoutMilliseconds": 3000,
                "tlsTrustProfile": "institution-ca"
            }
        });
        let parsed = serde_json::from_value::<BTreeMap<LocalId, RuntimeDestinationBinding>>(signed);
        assert!(parsed.is_ok(), "a complete signed binding parses");

        let missing_timeout = serde_json::json!({
            "coordinator-main": {
                "type": "signed-coordinator-event",
                "baseUrl": "https://coordinator.example/",
                "signingKeyRef": "secret:env/COORDINATOR_EVENT_KEY"
            }
        });
        assert!(
            serde_json::from_value::<BTreeMap<LocalId, RuntimeDestinationBinding>>(missing_timeout)
                .is_err(),
            "timeout never receives a silent default"
        );

        let unknown = serde_json::json!({
            "coordinator-main": {
                "type": "signed-coordinator-event",
                "baseUrl": "https://coordinator.example/",
                "signingKeyRef": "secret:env/COORDINATOR_EVENT_KEY",
                "attemptTimeoutMilliseconds": 3000,
                "fallbackUrl": "https://other.example/"
            }
        });
        assert!(
            serde_json::from_value::<BTreeMap<LocalId, RuntimeDestinationBinding>>(unknown)
                .is_err(),
            "unknown and fallback fields are refused"
        );
    }

    /// A direct BReg binding states its client assertion audience, the
    /// authorization server's issuer identifier RFC 10070 section 4 makes
    /// its sole value, and the refusal of one that does not names the member.
    #[test]
    fn a_direct_breg_binding_states_its_assertion_audience() {
        let directory = tempfile::tempdir().expect("a runtime directory");
        let runtime_path = directory.path().join("runtime.json");
        std::fs::write(
            &runtime_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "apiVersion": registry_adapter_core::ADAPTER_JOB_RUNTIME_API_VERSION,
                "kind": registry_adapter_core::ADAPTER_JOB_RUNTIME_KIND,
                "id": "audience-test",
                "endpoints": [],
                "destinations": {
                    "breg-main": {
                        "type": "direct-breg",
                        "baseUrl": "https://breg.example/",
                        "tokenEndpoint": "https://identity.example/token",
                        "clientId": "adapter-job",
                        "privateKeyRef": "secret:env/BREG_CLIENT_KEY",
                        "scopes": ["registry.write"],
                        "resource": "https://breg.example/",
                        "attemptTimeoutMilliseconds": 3000
                    }
                }
            }))
            .expect("serialize the runtime"),
        )
        .expect("write the runtime");
        let runtime = registry_adapter_engine::job_sources::JobRuntimeConfig::load(&runtime_path)
            .expect("the runtime document loads");
        let message = load_runtime_bindings(&runtime)
            .expect_err("a direct BReg binding without an assertion audience is refused");
        assert!(message.contains("clientAssertionAudience"), "{message}");
    }

    #[test]
    fn parsed_runtime_keeps_destination_reference_and_resolver_from_one_snapshot() {
        let directory = tempfile::tempdir().expect("a runtime directory");
        let old_root = directory.path().join("old-secrets");
        let new_root = directory.path().join("new-secrets");
        std::fs::create_dir(&old_root).expect("create the old secret root");
        std::fs::create_dir(&new_root).expect("create the new secret root");
        for (root, name, value) in [
            (&old_root, "old-key", b"old-snapshot-secret".as_slice()),
            (&new_root, "new-key", b"new-snapshot-secret".as_slice()),
        ] {
            let path = root.join(name);
            std::fs::write(&path, value).expect("write a synthetic destination secret");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("confine the synthetic destination secret");
        }
        let document = |root: &Path, base_url: &str, key: &str| {
            serde_json::json!({
                "apiVersion": registry_adapter_core::ADAPTER_JOB_RUNTIME_API_VERSION,
                "kind": registry_adapter_core::ADAPTER_JOB_RUNTIME_KIND,
                "id": "snapshot-test",
                "secretProviders": {"file": {"root": root}},
                "endpoints": [],
                "destinations": {
                    "coordinator-main": {
                        "type": "signed-coordinator-event",
                        "baseUrl": base_url,
                        "signingKeyRef": format!("secret:file/{key}"),
                        "attemptTimeoutMilliseconds": 1000
                    }
                }
            })
        };
        let runtime_path = directory.path().join("runtime.json");
        std::fs::write(
            &runtime_path,
            serde_json::to_vec_pretty(&document(&old_root, "http://127.0.0.1:41001", "old-key"))
                .unwrap(),
        )
        .expect("write snapshot A");
        let runtime = registry_adapter_engine::job_sources::JobRuntimeConfig::load(&runtime_path)
            .expect("load snapshot A once");
        let resolver = runtime
            .secret_resolver()
            .expect("derive snapshot A resolver");

        let replacement = directory.path().join("replacement.json");
        std::fs::write(
            &replacement,
            serde_json::to_vec_pretty(&document(&new_root, "http://127.0.0.1:41002", "new-key"))
                .unwrap(),
        )
        .expect("write snapshot B");
        std::fs::rename(&replacement, &runtime_path).expect("atomically replace the runtime file");

        let bindings = load_runtime_bindings(&runtime).expect("read only the parsed snapshot");
        let configured = bindings
            .get(&LocalId::new("coordinator-main").expect("a local id"))
            .expect("the snapshot destination binding");
        let RuntimeDestinationBinding::SignedCoordinatorEvent {
            base_url,
            signing_key_ref,
            ..
        } = configured
        else {
            panic!("the snapshot selects signed coordinator events")
        };
        assert_eq!(base_url.as_str(), "http://127.0.0.1:41001");
        assert_eq!(signing_key_ref.as_str(), "secret:file/old-key");
        let secret = resolver
            .resolve(signing_key_ref.as_str())
            .expect("snapshot A resolves its own key");
        assert_eq!(secret.expose_secret(), b"old-snapshot-secret");
    }
}
