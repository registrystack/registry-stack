#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let matches = registry_casework::command().get_matches();
    if let Err(error) = registry_casework::run(&matches).await {
        eprintln!("casework: {error}");
        std::process::exit(1);
    }
}
