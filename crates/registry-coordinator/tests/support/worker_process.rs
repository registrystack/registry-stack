// SPDX-License-Identifier: Apache-2.0
//! Explicit postgres-test-only process harness. Never part of an installed pilot.
//! Production ingress and activation are exercised by deployment/native journeys.
use clap::{Parser, Subcommand};
use registry_coordinator::{
    adapters::HttpAdapters, definition::Definition, runtime::RuntimeConfig, store::Store,
    worker::Worker,
};
use serde_json::json;
use std::{path::PathBuf, sync::Arc};
use uuid::Uuid;
#[derive(Parser)]
struct Cli {
    #[arg(long, global = true, default_value = "json")]
    format: String,
    #[arg(long)]
    runtime_config: PathBuf,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    InitDb,
    Start {
        #[arg(long)]
        project: PathBuf,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        producer: String,
        #[arg(long)]
        key_file: PathBuf,
    },
    Status {
        #[arg(long)]
        run: Uuid,
    },
    RetrySame {
        #[arg(long)]
        run: Uuid,
    },
    Worker,
}
#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let runtime = RuntimeConfig::load(&cli.runtime_config).expect("synthetic runtime");
    let store = Arc::new(
        Store::connect(&runtime.database_url().unwrap(), &runtime.namespace)
            .await
            .expect("test store"),
    );
    let value = match cli.command {
        Command::InitDb => {
            store.migrate().await.unwrap();
            json!({"initialized":true})
        }
        Command::Start {
            project,
            input,
            producer,
            key_file,
        } => {
            let definition = Definition::load(&project).unwrap();
            let input = serde_json::from_slice(&std::fs::read(input).unwrap()).unwrap();
            let key = std::fs::read_to_string(key_file).unwrap();
            let id = store
                .admit(
                    &definition,
                    input,
                    &producer,
                    &key,
                    &runtime.binding_digest_for(&definition.workflow).unwrap(),
                )
                .await
                .unwrap();
            json!({"runId":id})
        }
        Command::Status { run } => serde_json::to_value(store.status(run).await.unwrap()).unwrap(),
        Command::RetrySame { run } => {
            store
                .retry_same(run, &runtime.binding_digest().unwrap())
                .await
                .unwrap();
            json!({"scheduled":true})
        }
        Command::Worker => {
            let worker = Worker::new(store, Arc::new(HttpAdapters::new(&runtime).unwrap()));
            loop {
                worker.tick().await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        }
    };
    println!("{value}");
}
