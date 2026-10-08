// SPDX-License-Identifier: Apache-2.0
//! The refusal of substitution expressions in the files BReg reads as
//! written.

use registry_platform_config::contains_environment_expression;
use registry_platform_yaml::{Refusal, ScalarHook, ScalarSite};

/// Refuses every `${...}` substitution expression in a file BReg reads as
/// written: an authored file, or an operator tool file that has no
/// substitution (CFG-SEC-2). Substitution applies to `runtime.yaml` only.
/// Text that is not an expression, such as a lone `${`, is accepted.
pub struct LiteralText {
    /// What to write instead, the refusal's suggested action.
    pub remedy: &'static str,
}

/// The remedy for a file whose values are written as they are meant.
pub const WRITE_THE_VALUE: &str = "Write the value in the file directly.";

/// The remedy for an operator tool file that names secrets.
pub const WRITE_THE_VALUE_OR_A_SECRET_REFERENCE: &str = "Write the value in the file directly, and name a secret with a secret reference (`secret:file/<name>` or `secret:env/<NAME>`).";

impl LiteralText {
    fn check(&self, text: &str) -> Result<(), Refusal> {
        if contains_environment_expression(text) {
            return Err(Refusal {
                code: "config.substitution-not-allowed".to_owned(),
                message: "a `${...}` expression is written in a file BReg reads as written; \
                          substitution applies to runtime.yaml only"
                    .to_owned(),
                suggested_action: self.remedy.to_owned(),
            });
        }
        Ok(())
    }
}

impl ScalarHook for LiteralText {
    fn key(&mut self, site: &ScalarSite<'_>) -> Result<(), Refusal> {
        self.check(site.text)
    }

    fn value(&mut self, site: &ScalarSite<'_>) -> Result<Option<String>, Refusal> {
        self.check(site.text).map(|()| None)
    }
}

#[cfg(test)]
mod tests {
    use registry_platform_yaml::{ApiVersion, EnvelopeRule, Expect, FormatSpec, Reader};

    use super::*;

    const FORMAT: FormatSpec<'static> = FormatSpec {
        kind: "BRegExample",
        envelope: EnvelopeRule::ApiVersionKind {
            api_versions: &[ApiVersion::current(
                "id.registrystack.org/formats/breg/example/v1",
            )],
            retired_api_versions: &[],
        },
        removed_keys: &[],
    };

    fn read(text: &str) -> Vec<(String, String, String)> {
        match Reader::new("example.yaml")
            .with_hook(&mut LiteralText {
                remedy: WRITE_THE_VALUE,
            })
            .read(text.as_bytes(), &Expect::one(&FORMAT))
        {
            Ok(_) => Vec::new(),
            Err(report) => report
                .diagnostics()
                .iter()
                .map(|diagnostic| {
                    (
                        diagnostic.code.clone(),
                        diagnostic.path.clone(),
                        diagnostic.suggested_action.clone(),
                    )
                })
                .collect(),
        }
    }

    const HEADER: &str =
        "apiVersion: id.registrystack.org/formats/breg/example/v1\nkind: BRegExample\n";

    #[test]
    fn cfg_sec_2_an_expression_is_refused_in_a_value_and_a_key_without_its_name() {
        for (body, path) in [
            ("note: \"${EXAMPLE_VARIABLE}\"\n", "/note"),
            ("note: \"prefix-${EXAMPLE_VARIABLE:-fallback}\"\n", "/note"),
            ("\"${EXAMPLE_VARIABLE}\": text\n", "/${EXAMPLE_VARIABLE}"),
        ] {
            let diagnostics = read(&format!("{HEADER}{body}"));
            assert_eq!(
                diagnostics,
                [(
                    "config.substitution-not-allowed".to_owned(),
                    path.to_owned(),
                    WRITE_THE_VALUE.to_owned(),
                )],
                "{body}"
            );
        }
    }

    #[test]
    fn cfg_sec_2_text_that_is_not_an_expression_is_accepted() {
        for body in [
            "note: \"costs ${\"\n",
            "note: \"${ not a name}\"\n",
            "note: plain\n",
        ] {
            assert!(read(&format!("{HEADER}{body}")).is_empty(), "{body}");
        }
    }
}
