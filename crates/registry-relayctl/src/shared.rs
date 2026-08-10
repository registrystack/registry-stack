// SPDX-License-Identifier: Apache-2.0
//! The only dependency seam from adopter presentation into Relay semantics.

use registry_relay_v2::tooling::{
    self, CheckOptions, DiffOptions, GenerateOptions, InitOptions, InspectOptions, PackageOptions,
    TestOptions, ToolingError, ToolingReport,
};

use crate::Command;

pub(crate) fn execute(command: Command) -> Result<ToolingReport, ToolingError> {
    match command {
        Command::Init(args) => tooling::init_project(&InitOptions {
            project_root: args.project,
        }),
        Command::Inspect(args) => tooling::inspect_schema(&InspectOptions {
            database_path: args.database,
            starter_output: args.starters,
            statistical_view: args.statistical_view,
            time_column: args.time_column,
            measure_column: args.measure_column,
            attribute_columns: args.attribute_column,
        }),
        Command::Check(args) => tooling::check_project(&CheckOptions {
            project_root: args.project,
            production: args.production,
        }),
        Command::Generate(args) => tooling::generate_project(&GenerateOptions {
            project_root: args.project,
            output_dir: args.output,
        }),
        Command::Test(args) => tooling::test_project(&TestOptions {
            project_root: args.project,
            fixture_id: args.fixture,
        }),
        Command::Diff(args) => tooling::diff_projects(&DiffOptions {
            previous_root: args.previous,
            current_root: args.current,
        }),
        Command::Package(args) => tooling::package_project(&PackageOptions {
            project_root: args.project,
            output_dir: args.output,
        }),
    }
}
