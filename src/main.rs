//! The hullcheck command-line interface.
//!
//! Usage:
//!   hullcheck [PATH]        scan PATH (default: current directory)
//!   hullcheck --json        emit machine-readable JSON instead of the report
//!   hullcheck --exit-zero   always exit 0, even with Fix Now findings
//!   hullcheck --help | --version
//!
//! Exit code: 1 when any Fix Now finding is present (so CI can gate on it),
//! 0 otherwise. `--exit-zero` forces 0.

use std::path::Path;
use std::process::ExitCode;

use hullcheck::finding::Lane;
use hullcheck::report;
use hullcheck::review;

const HELP: &str = "\
hullcheck — read-only security review for the SaaS you built with an AI agent

USAGE:
    hullcheck [PATH] [OPTIONS]

ARGS:
    PATH                 repository to scan (default: current directory)

OPTIONS:
    --json               emit JSON instead of the human report
    --exit-zero          always exit 0, even when there are Fix Now findings
    -h, --help           print this help
    -V, --version        print version

hullcheck reads files only. It makes no network calls, writes nothing, and
never claims your app is secure. Full kit: https://www.rettecnologia.org/promptbook";

struct Args {
    path: String,
    json: bool,
    exit_zero: bool,
}

enum Parsed {
    Run(Args),
    Help,
    Version,
    Error(String),
}

fn parse(argv: &[String]) -> Parsed {
    let mut path: Option<String> = None;
    let mut json = false;
    let mut exit_zero = false;
    for arg in argv {
        match arg.as_str() {
            "-h" | "--help" => return Parsed::Help,
            "-V" | "--version" => return Parsed::Version,
            "--json" => json = true,
            "--exit-zero" => exit_zero = true,
            s if s.starts_with('-') => {
                return Parsed::Error(format!("unknown option: {s}"));
            }
            s => {
                if path.is_some() {
                    return Parsed::Error("more than one PATH given".to_string());
                }
                path = Some(s.to_string());
            }
        }
    }
    Parsed::Run(Args {
        path: path.unwrap_or_else(|| ".".to_string()),
        json,
        exit_zero,
    })
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match parse(&argv) {
        Parsed::Help => {
            println!("{HELP}");
            ExitCode::SUCCESS
        }
        Parsed::Version => {
            println!("hullcheck {}", report::VERSION);
            ExitCode::SUCCESS
        }
        Parsed::Error(msg) => {
            eprintln!("hullcheck: {msg}\n\n{HELP}");
            ExitCode::from(2)
        }
        Parsed::Run(args) => run(&args),
    }
}

fn run(args: &Args) -> ExitCode {
    let root = Path::new(&args.path);
    if !root.is_dir() {
        eprintln!("hullcheck: not a directory: {}", args.path);
        return ExitCode::from(2);
    }

    let (findings, scanned) = review(root);
    let fix_now = findings.iter().any(|f| f.lane == Lane::FixNow);

    if args.json {
        print!("{}", report::render_json(&findings, scanned));
    } else {
        let shown = root.display().to_string();
        print!("{}", report::render_text(&findings, scanned, &shown));
    }

    if fix_now && !args.exit_zero {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
