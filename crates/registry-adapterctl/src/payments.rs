// SPDX-License-Identifier: Apache-2.0
//! Offline payment configuration checks; neither command resolves credentials.
use crate::payment_fixtures::{self, FixtureError};
use clap::{Args, Subcommand};
use registry_adapter::payments::config::{PaymentsConfig, API_VERSION, KIND};
use registry_adapter::payments::pack::{
    ConnectorKind, PaymentCapability, PaymentProviderAuth, PaymentProviderPack,
};
use registry_platform_config::{RuntimeConfigLoader, RuntimeEnvelope, DEFAULT_STAND_IN};
use registry_platform_yaml::{Diagnostic, Report};
use serde_json::{json, Value};
use std::path::PathBuf;

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
        /// Exact provider pack pinned by the payment connections.
        #[arg(long, value_name = "FILE")]
        provider_pack: Option<PathBuf>,
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
        /// Exact provider pack pinned by the payment connections.
        #[arg(long, value_name = "FILE")]
        provider_pack: Option<PathBuf>,
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

pub fn run(command: &PaymentsCommand) -> PaymentCheck {
    if let PaymentsCommand::CheckPack { file } = command {
        return check_pack(file);
    }
    let (file, provider_pack, fixtures, deny_warnings) = match command {
        PaymentsCommand::Check {
            file,
            provider_pack,
            fixtures,
            deny_warnings,
        } => (
            file,
            provider_pack.as_deref(),
            fixtures.as_slice(),
            *deny_warnings,
        ),
        PaymentsCommand::Contract {
            file,
            provider_pack,
        } => (file, provider_pack.as_deref(), &[][..], false),
        PaymentsCommand::Fixtures {
            command:
                PaymentsFixturesCommand::Replay {
                    file,
                    provider_pack,
                    fixtures,
                },
        } => (
            file,
            Some(provider_pack.as_path()),
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
            match provider_pack {
                Some(path) => match std::fs::read(path) {
                    Ok(bytes) => match PaymentProviderPack::from_yaml(&bytes) {
                        Ok(pack) => {
                            if pack.validate().is_err() {
                                additional.push(check.error_at(
                                    KIND,
                                    "adapter.payment.provider-pack-refused",
                                    "/connections",
                                    "The payment provider pack was refused.",
                                    "Correct the provider pack and retry.",
                                ));
                            }
                            if pack.connector == ConnectorKind::AdapterPaymentHttpV1
                                && payment_fixtures::compile_mapped_pack(path, &pack, &bytes)
                                    .is_err()
                            {
                                additional.push(check.error_at(
                                    KIND,
                                    "adapter.payment.provider-pack-script-refused",
                                    "/connections",
                                    "The payment provider scripts were refused.",
                                    "Check the complete script inventory, digests and entrypoints.",
                                ));
                            }
                            for connection in &loaded.config.connections {
                                if pack.connector != connection.binding.connector_kind()
                                    || !pack.capabilities.contains(&PaymentCapability::Collection)
                                    || connection
                                        .binding
                                        .provider_pack
                                        .as_ref()
                                        .is_none_or(|pin| pack.check_pin(pin, &bytes).is_err())
                                {
                                    additional.push(check.error_at(KIND, "adapter.payment.provider-pack-pin", "/connections",
                                        "The payment provider pack pin was refused.",
                                        "Pin the exact reviewed provider pack bytes for every connection."));
                                }
                                if pack.connector == ConnectorKind::AdapterPaymentHttpV1
                                    && pack
                                        .mapping
                                        .as_ref()
                                        .and_then(|mapping| mapping.collection.as_ref())
                                        .is_none_or(|operation| {
                                            operation.auth != PaymentProviderAuth::Bearer
                                        })
                                {
                                    additional.push(check.error_at(
                                        KIND,
                                        "adapter.payment.provider-pack-auth",
                                        "/connections",
                                        "The collection authentication profile was refused.",
                                        "Use a bearer collection pack supported by the HTTP host.",
                                    ));
                                }
                            }
                            for connection in &loaded.config.disbursements {
                                if pack.connector != ConnectorKind::AdapterPaymentHttpV1
                                    || !pack.capabilities.contains(&PaymentCapability::Disbursement)
                                    || pack
                                        .check_pin(&connection.binding.provider_pack, &bytes)
                                        .is_err()
                                {
                                    additional.push(check.error_at(KIND, "adapter.payment.provider-pack-pin", "/disbursements",
                                        "The G2P provider pack pin, connector, or capability was refused.",
                                        "Pin the exact mapped provider pack with disbursement capability."));
                                }
                                if pack.connector == ConnectorKind::AdapterPaymentHttpV1
                                    && pack
                                        .mapping
                                        .as_ref()
                                        .and_then(|mapping| mapping.disbursement.as_ref())
                                        .is_none_or(|operation| {
                                            operation.auth
                                                != connection.binding.provider.auth_profile()
                                        })
                                {
                                    additional.push(check.error_at(
                                        KIND,
                                        "adapter.payment.provider-pack-auth",
                                        "/disbursements",
                                        "The disbursement authentication profile differs from the pinned pack.",
                                        "Select the host authentication profile required by the reviewed pack.",
                                    ));
                                }
                            }
                            for fixture in fixtures {
                                let replay = if pack.connector
                                    == ConnectorKind::AdapterPaymentHttpV1
                                {
                                    payment_fixtures::replay_mapped(fixture, path, &pack, &bytes)
                                } else {
                                    payment_fixtures::replay(fixture, pack.connector)
                                };
                                if let Err(error) = replay {
                                    let (code, message, action) = match error {
                                        FixtureError::Unavailable => ("adapter.payment.fixture-unavailable", "A payment provider fixture could not be read.", "Correct the fixture path and retry."),
                                        FixtureError::Refused => ("adapter.payment.fixture-refused", "A payment provider fixture did not match the pinned connector mapping.", "Correct the fixture or provider pack and retry."),
                                    };
                                    additional.push(check.error_at(
                                        KIND,
                                        code,
                                        "/fixtures",
                                        message,
                                        action,
                                    ));
                                }
                            }
                        }
                        Err(report) => additional.extend(report.into_diagnostics()),
                    },
                    Err(_) => additional.push(check.error_at(
                        KIND,
                        "adapter.payment.provider-pack-unavailable",
                        "/connections",
                        "The payment provider pack could not be read.",
                        "Correct the provider pack path and retry.",
                    )),
                },
                None if loaded.config.connections.iter().any(|connection| {
                    connection.binding.provider_pack.is_some() || !connection.binding.simulation
                }) || !loaded.config.disbursements.is_empty() =>
                {
                    additional.push(check.error_at(
                        KIND,
                        "adapter.payment.provider-pack-required",
                        "/connections",
                        "A pinned payment provider pack was not supplied.",
                        "Pass --provider-pack with the exact pinned pack file.",
                    ));
                }
                None => {}
            }
            if !fixtures.is_empty() && provider_pack.is_none() {
                additional.push(check.error_at(
                    KIND,
                    "adapter.payment.fixture-pack-required",
                    "/fixtures",
                    "Payment provider fixtures require a provider pack.",
                    "Pass --provider-pack with the exact pinned pack file.",
                ));
            }
            value["connectionCount"] = json!(loaded.config.connections.len());
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
