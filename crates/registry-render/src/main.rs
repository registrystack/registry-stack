use clap::Parser as _;

fn main() {
    let cli = registry_render::cli::Cli::parse();
    let code = registry_render::cli::run(cli);
    registry_render::cli::flush();
    std::process::exit(code);
}
