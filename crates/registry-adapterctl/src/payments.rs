// SPDX-License-Identifier: Apache-2.0
//! Offline payment configuration checks; neither command resolves credentials.
use clap::{Args, Subcommand};
use registry_adapter::payments::config::{PaymentsConfig, API_VERSION, KIND};
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
    /// Validate one AdapterPayments file without fetching credentials or services.
    Check {
        /// AdapterPayments configuration file to validate.
        #[arg(value_name = "FILE")]
        file: PathBuf,
        /// Refuse warnings as well as errors.
        #[arg(long)]
        deny_warnings: bool,
    },
    /// Export fixed payment routes, authority and schemas for configured connections.
    Contract {
        /// AdapterPayments configuration file whose contract is exported.
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },
}
pub fn command_name(command: &PaymentsCommand) -> &'static str {
    match command {
        PaymentsCommand::Check { .. } => "payments check",
        PaymentsCommand::Contract { .. } => "payments contract",
    }
}
pub struct PaymentCheck {
    pub value: Value,
    pub checked: Report,
    pub unavailable: bool,
    pub deny_warnings: bool,
}

pub fn run(command: &PaymentsCommand) -> PaymentCheck {
    let (file, deny_warnings) = match command {
        PaymentsCommand::Check {
            file,
            deny_warnings,
        } => (file, *deny_warnings),
        PaymentsCommand::Contract { file } => (file, false),
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
            value["connectionCount"] = json!(loaded.config.connections.len());
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
