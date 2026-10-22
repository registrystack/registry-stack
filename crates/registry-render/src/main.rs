use clap::Parser as _;

fn retired_option(args: &[std::ffi::OsString]) -> Option<&'static str> {
    let command = args.get(1)?.to_str()?;
    let has_option = |name: &str| {
        args.iter()
            .skip(2)
            .take_while(|arg| arg.as_os_str() != "--")
            .any(|argument| {
                argument.as_os_str() == name
                    || argument
                        .to_str()
                        .and_then(|argument| argument.strip_prefix(name))
                        .is_some_and(|suffix| suffix.starts_with('='))
            })
    };
    match command {
        "compile" if has_option("--json") => {
            Some("`--json` is no longer accepted; use `--format json` instead")
        }
        "validate" if has_option("--json") => {
            Some("`--json` is no longer accepted; use `--format json` instead")
        }
        "compile" if has_option("--out") => {
            Some("`--out` is no longer accepted; use `--output` instead")
        }
        _ => None,
    }
}

fn requests_json(args: &[std::ffi::OsString]) -> bool {
    let mut args = args
        .iter()
        .skip(1)
        .take_while(|arg| arg.as_os_str() != "--");
    while let Some(argument) = args.next() {
        if argument.as_os_str() == "--format" {
            return args.next().and_then(|value| value.to_str()) == Some("json");
        }
        if argument
            .to_str()
            .and_then(|value| value.strip_prefix("--format="))
            == Some("json")
        {
            return true;
        }
    }
    false
}

fn main() {
    let args = std::env::args_os().collect::<Vec<_>>();
    if let Some(message) = retired_option(&args) {
        let problem = registry_render::RenderProblem::new(
            registry_render::ProblemKind::InvalidArgument,
            message,
        );
        let code = registry_render::cli::report_problem(problem, requests_json(&args));
        registry_render::cli::flush();
        std::process::exit(code);
    }
    let format_supplied = args
        .iter()
        .skip(1)
        .take_while(|arg| arg.as_os_str() != "--")
        .any(|arg| {
            arg.as_os_str() == "--format"
                || arg
                    .to_str()
                    .is_some_and(|value| value.starts_with("--format="))
        });
    let cli = registry_render::cli::Cli::parse_from(args);
    let code = registry_render::cli::run(cli, format_supplied);
    registry_render::cli::flush();
    std::process::exit(code);
}
