//! Guest-side System workspace operations without an interpreter dependency.

use anyhow::Result;
use clap::{Parser, Subcommand};
use openshell_kata::workspace::{self, RemoveOptions, Workspace};
use std::{path::PathBuf, process::ExitCode};

#[derive(Debug, Parser)]
#[command(version)]
struct Cli {
    /// Trusted workspace root override for isolated integration fixtures.
    #[arg(long, default_value = "/sandbox")]
    root: PathBuf,
    #[command(subcommand)]
    command: Operation,
}

#[derive(Debug, Subcommand)]
enum Operation {
    Protocol,
    Capability {
        id: String,
    },
    Capabilities,
    Quiesce,
    QuiesceExport,
    Hold {
        id: String,
    },
    Export,
    Import,
    Thaw,
    CapabilityAck {
        id: String,
    },
    #[command(disable_help_flag = true)]
    Docker {
        #[arg(num_args = 0.., trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    #[command(disable_help_flag = true)]
    DockerCompose {
        #[arg(num_args = 0.., trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    Run {
        id: String,
        command_json: String,
    },
    Kill {
        id: String,
    },
    Read {
        path: String,
    },
    Write {
        path: String,
    },
    Remove {
        path: String,
        #[arg(action = clap::ArgAction::Set)]
        recursive: bool,
        #[arg(action = clap::ArgAction::Set)]
        force: bool,
    },
    #[command(name = "__run-child", hide = true)]
    RunChild {
        id: String,
        command_json: String,
    },
}

// Two workers, not one for each CPU. This helper waits on one command and on files; a
// sandbox with a CPU quota reports its host's CPUs, and each worker thread takes one of
// the sandbox's process slots. Foundry, 11 November 2026: on a host with 192 CPUs the two
// controllers of one thread sandbox held 386 threads of its 2,048 slots while idle.
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> ExitCode {
    match execute(Cli::parse()).await {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err(error) => {
            eprintln!("kata-workspace: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn execute(cli: Cli) -> Result<i32> {
    if matches!(cli.command, Operation::Protocol) {
        println!("openshell-kata-workspace/1");
        return Ok(0);
    }
    let root = if matches!(
        cli.command,
        Operation::Docker { .. } | Operation::DockerCompose { .. }
    ) {
        std::env::var_os("OPENSHELL_WORKSPACE_ROOT")
            .map(PathBuf::from)
            .unwrap_or(cli.root)
    } else {
        cli.root
    };
    let workspace = Workspace::open(root)?;
    match cli.command {
        Operation::Protocol => unreachable!("protocol was handled before opening a workspace"),
        Operation::Capability { id } => {
            println!(
                "{}",
                serde_json::to_string(&workspace::capability(&workspace, &id)?)?
            );
            Ok(0)
        }
        Operation::QuiesceExport => {
            workspace::quiesce(&workspace).await?;
            workspace::export(&workspace, std::io::stdout().lock())?;
            Ok(0)
        }
        Operation::Export => {
            workspace::export(&workspace, std::io::stdout().lock())?;
            Ok(0)
        }
        Operation::Import => {
            workspace::import(&workspace, std::io::stdin().lock())?;
            Ok(0)
        }
        Operation::Hold { id } => {
            workspace::hold(&workspace, &id).await?;
            Ok(0)
        }
        Operation::Quiesce => {
            workspace::quiesce(&workspace).await?;
            Ok(0)
        }
        Operation::Thaw => {
            workspace::thaw(&workspace)?;
            Ok(0)
        }
        Operation::Capabilities => {
            println!(
                "{}",
                serde_json::to_string(&workspace::pending(&workspace)?)?
            );
            Ok(0)
        }
        Operation::CapabilityAck { id } => {
            workspace::acknowledge(&workspace, &id)?;
            Ok(0)
        }
        Operation::Docker { args } => workspace::request_docker(&workspace, &args, false),
        Operation::DockerCompose { args } => workspace::request_docker(&workspace, &args, true),
        Operation::Run { id, command_json } => workspace::run(&workspace, &id, &command_json).await,
        Operation::RunChild { id, command_json } => {
            workspace::run_child(&workspace, &id, &command_json).await
        }
        Operation::Kill { id } => {
            workspace::kill(&workspace, &id)?;
            Ok(0)
        }
        Operation::Read { path } => Ok(if workspace.read(&path, std::io::stdout().lock())? {
            0
        } else {
            66
        }),
        Operation::Write { path } => {
            workspace.write(&path, std::io::stdin().lock())?;
            Ok(0)
        }
        Operation::Remove {
            path,
            recursive,
            force,
        } => {
            workspace.remove(&path, RemoveOptions { recursive, force })?;
            Ok(0)
        }
    }
}
