// SPDX-License-Identifier: Apache-2.0
//! Offline payment configuration checks; neither command resolves credentials.
use crate::payment_fixtures::{self, FixtureError};
use clap::{Args, Subcommand};
use registry_adapter::payments::config::{PaymentsConfig, API_VERSION, KIND};
use registry_adapter::payments::pack::{
    ConnectorKind, PaymentCapability, PaymentProviderAuth, PaymentProviderPack, ProviderPackPin,
};
use registry_platform_config::{RuntimeConfigLoader, RuntimeEnvelope, DEFAULT_STAND_IN};
use registry_platform_yaml::{Diagnostic, Report};
use serde_json::{json, Value};
use std::{collections::BTreeMap, path::PathBuf};

const MAX_PAYMENT_PROVIDER_PACKS: usize = 32;

#[derive(Debug, Args)]
pub struct PaymentsArgs {
    #[command(subcommand)]
    pub command: PaymentsCommand,
}
#[derive(Debug, Subcommand)]
pub enum PaymentsCommand {
    /// Validate one reviewed payment provider pack without a deployment.
    CheckPack {
        /// Provider pack file to validate.
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },
    /// Validate one AdapterPayments file without fetching credentials or services.
    Check {
        /// AdapterPayments configuration file to validate.
        #[arg(value_name = "FILE")]
        file: PathBuf,
        /// Exact provider pack pinned by a payment connection. Repeat for every active pin.
        #[arg(long, value_name = "FILE")]
        provider_pack: Vec<PathBuf>,
        /// Offline provider request and response fixtures to check.
        #[arg(long, value_name = "FILE")]
        fixtures: Vec<PathBuf>,
        /// Refuse warnings as well as errors.
        #[arg(long)]
        deny_warnings: bool,
    },
    /// Export fixed payment routes, authority and schemas for configured connections.
    Contract {
        /// AdapterPayments configuration file whose contract is exported.
        #[arg(value_name = "FILE")]
        file: PathBuf,
        /// Exact provider pack pinned by a payment connection. Repeat for every active pin.
        #[arg(long, value_name = "FILE")]
        provider_pack: Vec<PathBuf>,
    },
    /// Replay provider mappings without connecting to Mifos or BReg.
    Fixtures {
        #[command(subcommand)]
        command: PaymentsFixturesCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum PaymentsFixturesCommand {
    /// Compare the pinned provider request and response mappings with fixtures.
    Replay {
        /// Payment connection configuration used for replay.
        #[arg(value_name = "FILE")]
        file: PathBuf,
        /// Provider pack pinned by the payment connection.
        #[arg(long, value_name = "FILE")]
        provider_pack: PathBuf,
        /// Payment fixture file. Repeat to replay multiple files.
        #[arg(long, value_name = "FILE", required = true)]
        fixtures: Vec<PathBuf>,
    },
}
pub fn command_name(command: &PaymentsCommand) -> &'static str {
    match command {
        PaymentsCommand::CheckPack { .. } => "payments check-pack",
        PaymentsCommand::Check { .. } => "payments check",
        PaymentsCommand::Contract { .. } => "payments contract",
        PaymentsCommand::Fixtures { .. } => "payments fixtures replay",
    }
}
pub struct PaymentCheck {
    pub value: Value,
    pub checked: Report,
    pub unavailable: bool,
    pub deny_warnings: bool,
}

struct LoadedProviderPack {
    path: PathBuf,
    pack: PaymentProviderPack,
    bytes: Vec<u8>,
}

struct ProviderPackRegistry {
    by_digest: BTreeMap<String, LoadedProviderPack>,
}

enum ProviderPackLoadError {
    Diagnostics(Vec<Diagnostic>),
    Problem {
        code: &'static str,
        message: &'static str,
        action: &'static str,
    },
}

#[derive(Clone, Copy)]
enum ProviderPackSelectionError {
    Missing,
    Mismatch,
}

impl ProviderPackRegistry {
    fn load(paths: &[PathBuf]) -> Result<Self, ProviderPackLoadError> {
        if paths.len() > MAX_PAYMENT_PROVIDER_PACKS {
            return Err(ProviderPackLoadError::Problem {
                code: "adapter.payment.provider-pack-limit",
                message: "Too many payment provider packs were supplied.",
                action: "Supply no more than 32 exact provider pack files.",
            });
        }
        let mut by_digest = BTreeMap::new();
        for path in paths {
            let absolute =
                std::fs::canonicalize(path).map_err(|_| ProviderPackLoadError::Problem {
                    code: "adapter.payment.provider-pack-unavailable",
                    message: "A payment provider pack could not be read.",
                    action: "Correct the provider pack path and retry.",
                })?;
            let bytes = std::fs::read(&absolute).map_err(|_| ProviderPackLoadError::Problem {
                code: "adapter.payment.provider-pack-unavailable",
                message: "A payment provider pack could not be read.",
                action: "Correct the provider pack path and retry.",
            })?;
            let pack = PaymentProviderPack::from_yaml(&bytes)
                .map_err(|report| ProviderPackLoadError::Diagnostics(report.into_diagnostics()))?;
            if pack.validate().is_err() {
                return Err(ProviderPackLoadError::Problem {
                    code: "adapter.payment.provider-pack-refused",
                    message: "A payment provider pack was refused.",
                    action: "Correct the provider pack and retry.",
                });
            }
            let digest = registry_platform_config::sha256_uri(&bytes);
            if by_digest.contains_key(&digest) {
                return Err(ProviderPackLoadError::Problem {
                    code: "adapter.payment.provider-pack-duplicate",
                    message: "A payment provider pack was supplied more than once.",
                    action: "Supply each exact provider pack file once.",
                });
            }
            if pack.connector == ConnectorKind::AdapterPaymentHttpV1
                && payment_fixtures::compile_mapped_pack(&absolute, &pack, &bytes).is_err()
            {
                return Err(ProviderPackLoadError::Problem {
                    code: "adapter.payment.provider-pack-script-refused",
                    message: "The payment provider scripts were refused.",
                    action: "Check the complete script inventory, digests and entrypoints.",
                });
            }
            by_digest.insert(
                digest,
                LoadedProviderPack {
                    path: absolute,
                    pack,
                    bytes,
                },
            );
        }
        Ok(Self { by_digest })
    }

    fn for_pin(
        &self,
        pin: &ProviderPackPin,
    ) -> Result<&LoadedProviderPack, ProviderPackSelectionError> {
        if let Some(loaded) = self.by_digest.get(&pin.digest) {
            return loaded
                .pack
                .check_pin(pin, &loaded.bytes)
                .map(|()| loaded)
                .map_err(|_| ProviderPackSelectionError::Mismatch);
        }
        if self
            .by_digest
            .values()
            .any(|loaded| loaded.pack.id == pin.id && loaded.pack.version == pin.version)
        {
            Err(ProviderPackSelectionError::Mismatch)
        } else {
            Err(ProviderPackSelectionError::Missing)
        }
    }

    fn only(&self) -> Option<&LoadedProviderPack> {
        if self.by_digest.len() == 1 {
            self.by_digest.values().next()
        } else {
            None
        }
    }
}

pub fn run(command: &PaymentsCommand) -> PaymentCheck {
    if let PaymentsCommand::CheckPack { file } = command {
        return check_pack(file);
    }
    let (file, provider_packs, fixtures, deny_warnings) = match command {
        PaymentsCommand::Check {
            file,
            provider_pack,
            fixtures,
            deny_warnings,
        } => (
            file,
            provider_pack.as_slice(),
            fixtures.as_slice(),
            *deny_warnings,
        ),
        PaymentsCommand::Contract {
            file,
            provider_pack,
        } => (file, provider_pack.as_slice(), &[][..], false),
        PaymentsCommand::Fixtures {
            command:
                PaymentsFixturesCommand::Replay {
                    file,
                    provider_pack,
                    fixtures,
                },
        } => (
            file,
            std::slice::from_ref(provider_pack),
            fixtures.as_slice(),
            false,
        ),
        PaymentsCommand::CheckPack { .. } => unreachable!("handled above"),
    };
    let absolute = match std::fs::canonicalize(file) {
        Ok(path) => path,
        Err(_) => {
            return PaymentCheck {
                value: json!({}),
                checked: Report::new(vec![Diagnostic::error(
                    "adapterctl.io-failure",
                    "",
                    "The payment configuration could not be read.",
                    "Correct the file path or permissions, then retry.",
                )]),
                unavailable: true,
                deny_warnings,
            }
        }
    };
    let check = RuntimeConfigLoader::new(RuntimeEnvelope {
        api_version: API_VERSION,
        kind: KIND,
    })
    .check_offline::<PaymentsConfig>(&absolute, true, |_| DEFAULT_STAND_IN);
    let mut additional = Vec::new();
    let mut value = json!({});
    if let Some(loaded) = &check.loaded {
        if loaded.config.validate().is_err() {
            additional.push(check.error_at(KIND, "adapter.payment.configuration", "/connections",
                "The payment connections were refused.",
                "Check connection scopes, unique caller identities, currency and synthetic provider bindings; then retry."));
        } else {
            match ProviderPackRegistry::load(provider_packs) {
                Ok(registry) => check_provider_pack_bindings(
                    &check,
                    &loaded.config,
                    &registry,
                    fixtures,
                    &mut additional,
                ),
                Err(ProviderPackLoadError::Diagnostics(diagnostics)) => {
                    additional.extend(diagnostics);
                }
                Err(ProviderPackLoadError::Problem {
                    code,
                    message,
                    action,
                }) => additional.push(check.error_at(KIND, code, "/connections", message, action)),
            }
            value["connectionCount"] =
                json!(loaded.config.connections.len() + loaded.config.disbursements.len());
            value["fixturesChecked"] = json!(fixtures.len());
            if matches!(command, PaymentsCommand::Contract { .. }) {
                value["contract"] = registry_adapter::payments::http::contract(&loaded.config);
            }
        }
    }
    PaymentCheck {
        value,
        checked: check.report_with(KIND, additional),
        unavailable: check.unavailable,
        deny_warnings,
    }
}

fn check_provider_pack_bindings(
    check: &registry_platform_config::RuntimeFileCheck<PaymentsConfig>,
    config: &PaymentsConfig,
    registry: &ProviderPackRegistry,
    fixtures: &[PathBuf],
    additional: &mut Vec<Diagnostic>,
) {
    check_payment_fixtures(check, registry, fixtures, additional);
    for (index, connection) in config.connections.iter().enumerate() {
        let path = format!("/connections/{index}/binding/providerPack");
        let Some(pin) = connection.binding.provider_pack.as_ref() else {
            if connection.binding.simulation {
                continue;
            }
            additional.push(check.error_at(
                KIND,
                "adapter.payment.provider-pack-required",
                &path,
                "A pinned payment provider pack was not supplied.",
                "Pass --provider-pack with the exact pinned pack file.",
            ));
            continue;
        };
        let selected = match registry.for_pin(pin) {
            Ok(selected) => selected,
            Err(error) => {
                let (code, message, action) = match error {
                    ProviderPackSelectionError::Missing => (
                        "adapter.payment.provider-pack-required",
                        "The pinned payment provider pack was not supplied.",
                        "Pass --provider-pack with the exact pinned pack file.",
                    ),
                    ProviderPackSelectionError::Mismatch => (
                        "adapter.payment.provider-pack-pin",
                        "The payment provider pack pin was refused.",
                        "Pin the exact reviewed provider pack bytes for this connection.",
                    ),
                };
                additional.push(check.error_at(KIND, code, &path, message, action));
                continue;
            }
        };
        if selected.pack.connector != connection.binding.connector_kind()
            || !selected
                .pack
                .capabilities
                .contains(&PaymentCapability::Collection)
        {
            additional.push(check.error_at(
                KIND,
                "adapter.payment.provider-pack-pin",
                &path,
                "The payment provider pack connector or capability was refused.",
                "Pin an exact provider pack with the connection's collection capability.",
            ));
            continue;
        }
        if matches!(
            &connection.binding.provider,
            registry_adapter::payments::config::CollectionProvider::Http { .. }
        ) && selected
            .pack
            .mapping
            .as_ref()
            .and_then(|mapping| mapping.collection.as_ref())
            .is_none_or(|operation| operation.auth != PaymentProviderAuth::Bearer)
        {
            additional.push(check.error_at(
                KIND,
                "adapter.payment.provider-pack-auth",
                &format!("/connections/{index}/binding/provider"),
                "The collection authentication profile was refused.",
                "Use a bearer collection pack supported by the HTTP host.",
            ));
        }
    }
    for (index, connection) in config.disbursements.iter().enumerate() {
        let path = format!("/disbursements/{index}/binding/providerPack");
        let selected = match registry.for_pin(&connection.binding.provider_pack) {
            Ok(selected) => selected,
            Err(error) => {
                let (code, message, action) = match error {
                    ProviderPackSelectionError::Missing => (
                        "adapter.payment.provider-pack-required",
                        "The pinned G2P provider pack was not supplied.",
                        "Pass --provider-pack with the exact pinned pack file.",
                    ),
                    ProviderPackSelectionError::Mismatch => (
                        "adapter.payment.provider-pack-pin",
                        "The G2P provider pack pin was refused.",
                        "Pin the exact reviewed provider pack bytes for this connection.",
                    ),
                };
                additional.push(check.error_at(KIND, code, &path, message, action));
                continue;
            }
        };
        if selected.pack.connector != ConnectorKind::AdapterPaymentHttpV1
            || !selected
                .pack
                .capabilities
                .contains(&PaymentCapability::Disbursement)
        {
            additional.push(check.error_at(
                KIND,
                "adapter.payment.provider-pack-pin",
                &path,
                "The G2P provider pack connector or capability was refused.",
                "Pin the exact mapped provider pack with disbursement capability.",
            ));
            continue;
        }
        let expected_auth = connection.binding.provider.auth_profile();
        let mapped_auth_matches = selected
            .pack
            .mapping
            .as_ref()
            .and_then(|mapping| mapping.disbursement.as_ref())
            .is_some_and(|operation| operation.auth == expected_auth);
        if !mapped_auth_matches {
            additional.push(check.error_at(
                KIND,
                "adapter.payment.provider-pack-auth",
                &format!("/disbursements/{index}/binding/provider"),
                "The disbursement authentication profile differs from the pinned pack.",
                "Select the host authentication profile required by the reviewed pack.",
            ));
        }
    }
}

fn check_payment_fixtures(
    check: &registry_platform_config::RuntimeFileCheck<PaymentsConfig>,
    registry: &ProviderPackRegistry,
    fixtures: &[PathBuf],
    additional: &mut Vec<Diagnostic>,
) {
    if fixtures.is_empty() {
        return;
    }
    let Some(selected) = registry.only() else {
        let (code, message, action) = if registry.by_digest.is_empty() {
            (
                "adapter.payment.fixture-pack-required",
                "Payment provider fixtures require a provider pack.",
                "Pass --provider-pack with the exact pinned pack file.",
            )
        } else {
            (
                "adapter.payment.fixture-pack-ambiguous",
                "Payment provider fixtures cannot select among multiple provider packs.",
                "Check fixtures with one --provider-pack invocation at a time.",
            )
        };
        additional.push(check.error_at(KIND, code, "/fixtures", message, action));
        return;
    };
    for fixture in fixtures {
        let replay = if selected.pack.connector == ConnectorKind::AdapterPaymentHttpV1 {
            payment_fixtures::replay_mapped(
                fixture,
                &selected.path,
                &selected.pack,
                &selected.bytes,
            )
        } else {
            payment_fixtures::replay(fixture, selected.pack.connector)
        };
        if let Err(error) = replay {
            let (code, message, action) = match error {
                FixtureError::Unavailable => (
                    "adapter.payment.fixture-unavailable",
                    "A payment provider fixture could not be read.",
                    "Correct the fixture path and retry.",
                ),
                FixtureError::Refused => (
                    "adapter.payment.fixture-refused",
                    "A payment provider fixture did not match the pinned connector mapping.",
                    "Correct the fixture or provider pack and retry.",
                ),
            };
            additional.push(check.error_at(KIND, code, "/fixtures", message, action));
        }
    }
}

fn check_pack(file: &PathBuf) -> PaymentCheck {
    let bytes = match std::fs::read(file) {
        Ok(bytes) => bytes,
        Err(_) => {
            return PaymentCheck {
                value: json!({}),
                checked: Report::new(vec![Diagnostic::error(
                    "adapterctl.io-failure",
                    "",
                    "The payment provider pack could not be read.",
                    "Correct the file path or permissions, then retry.",
                )]),
                unavailable: true,
                deny_warnings: false,
            }
        }
    };
    let (value, checked) = match PaymentProviderPack::from_yaml(&bytes) {
        Ok(pack)
            if pack.validate().is_ok()
                && (pack.connector != ConnectorKind::AdapterPaymentHttpV1
                    || payment_fixtures::compile_mapped_pack(file, &pack, &bytes).is_ok()) =>
        {
            (
                json!({"packId": pack.id, "version": pack.version, "capabilities": pack.capabilities,
                "digest": registry_platform_config::sha256_uri(&bytes)}),
                Report::new(vec![]),
            )
        }
        Ok(_) => (
            json!({}),
            Report::new(vec![Diagnostic::error(
                "adapter.payment.provider-pack-refused",
                "",
                "The payment provider pack was refused.",
                "Check its id, version, connector and capabilities.",
            )]),
        ),
        Err(report) => (json!({}), report),
    };
    PaymentCheck {
        value,
        checked,
        unavailable: false,
        deny_warnings: false,
    }
}
