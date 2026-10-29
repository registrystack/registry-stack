// SPDX-License-Identifier: Apache-2.0
//! Native PostgreSQL pattern checks for Action inputs.
//!
//! An input pattern is a PostgreSQL ARE expression, the dialect a Record field
//! pattern uses, so PostgreSQL evaluates it here too; no second regex engine
//! participates. The check follows the synchronous type and length validation
//! and runs on the same connection as the mutation.

use serde_json::{Map, Value};
use tokio_postgres::{error::SqlState, GenericClient};

use crate::model::CompiledAction;
use crate::mutation::MutationError;
use crate::problem_location::RequestLocation;

/// Refuses the first submitted string that does not match its input's pattern,
/// naming the input in the refusal. An absent or null value is not tested;
/// `required` decides those. A PostgreSQL failure refuses with `Unavailable`
/// and logs only the authored action and input identifiers: neither the
/// expression nor the submitted value leaves this function.
pub(crate) async fn check_input_patterns(
    client: &(impl GenericClient + Sync),
    action: &CompiledAction,
    input: &Map<String, Value>,
) -> Result<(), MutationError> {
    for declared in &action.inputs {
        let (Some(pattern), Some(Value::String(value))) =
            (declared.pattern.as_deref(), input.get(&declared.id))
        else {
            continue;
        };
        let matches: bool = client
            .query_one("SELECT $1::text ~ $2::text", &[value, &pattern])
            .await
            .and_then(|row| row.try_get(0))
            .map_err(|error| {
                let syntax = error.code() == Some(&SqlState::INVALID_REGULAR_EXPRESSION);
                tracing::error!(
                    action = %action.id,
                    input = %declared.id,
                    syntax,
                    "an action input pattern could not be evaluated"
                );
                MutationError::Unavailable
            })?;
        if !matches {
            return Err(MutationError::InvalidRequestAt(
                RequestLocation::action_input(&declared.api_name),
            ));
        }
    }
    Ok(())
}
