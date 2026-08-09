#![no_main]

use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use registry_platform_sqlite::{
    check_statement_offline, ColumnContract, ColumnType, ParameterContract, StatementContract,
    StatementLimits,
};

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    let sql: String = input.chars().take(16_384).collect();
    let contract = StatementContract {
        sql,
        columns: vec![ColumnContract {
            name: "result".to_owned(),
            value_type: ColumnType::String,
        }],
        parameters: vec![ParameterContract {
            name: "value".to_owned(),
            required: false,
        }],
        limits: StatementLimits {
            maximum_rows: 1,
            maximum_cell_bytes: 1_024,
            maximum_response_bytes: 1_024,
            maximum_statement_steps: 10_000,
            timeout: Duration::from_millis(100),
            concurrency: 1,
        },
        schema: None,
    };
    let _ = check_statement_offline(&contract);
});
