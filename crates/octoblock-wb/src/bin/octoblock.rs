use std::env;
use std::process::ExitCode;
use std::sync::Arc;

use octoblock_fs::page::CasePolicy;
use octoblock_wb::cli::{CliCommand, execute_cli};
use octoblock_wb::lease::LeasePolicy;
use octoblock_wb::policy::PolicyEngine;
use octoblock_wb::{EngineConfig, WriteBackEngine};
use octopage_git::InMemory;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let raw_args: Vec<String> = env::args().skip(1).collect();
    if raw_args.is_empty() || raw_args[0] == "--help" || raw_args[0] == "-h" {
        println!(
            "octoblock — Git-backed write-back file system control plane\n\
             Usage: octoblock <status|sync|compact|branch|snapshot|merge|lease|conflicts|fsck> [args...]"
        );
        return ExitCode::SUCCESS;
    }

    let str_args: Vec<&str> = raw_args.iter().map(String::as_str).collect();
    let cmd = match CliCommand::parse_args(&str_args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };

    let state_dir = env::temp_dir().join("octoblock-cli-state");
    let remote = Arc::new(InMemory::new());
    let cfg = EngineConfig {
        lease_policy: LeasePolicy::Off,
        ..EngineConfig::default()
    };

    let mut engine = match WriteBackEngine::mkfs(
        remote,
        &state_dir,
        cfg,
        4096,
        CasePolicy::Sensitive,
        PolicyEngine::tier0_default(),
    )
    .await
    {
        Ok(eng) => eng,
        Err(e) => {
            eprintln!("failed to initialize engine: {e}");
            return ExitCode::from(1);
        }
    };

    match execute_cli(&mut engine, cmd).await {
        Ok(out) => {
            println!("{out}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("command error: {e}");
            ExitCode::from(1)
        }
    }
}