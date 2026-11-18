use anyhow::Result;
use axon::isa::{
    op_commit, op_filter, op_load, op_match, op_purge, op_scan, op_sub, op_xexec, FilterOpts,
    ScanOpts,
};
use axon::reg::{RegRef, RegisterRecord};
use axon::shm::ShmStore;
use axon::vm::execute_program;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "ax",
    version,
    about = "Axon: Deterministic Agent Execution Motor Pathway & Shared-Memory SSA Register VM"
)]
struct Cli {
    /// Custom shared-memory directory (defaults to $AXON_SHM_DIR or /dev/shm/axon-<uid>)
    #[arg(long, global = true)]
    shm_dir: Option<PathBuf>,

    /// Emit deterministic JSON output instead of human/compact SSA telemetry
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Scan filesystem deterministically into a new PathSet SSA register (replaces `find`)
    Scan {
        /// Root directory or file to scan
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Filter paths by glob pattern (e.g. "*.rs" or "src/**/*.rs")
        #[arg(short, long)]
        glob: Option<String>,

        /// Maximum directory traversal depth
        #[arg(short = 'd', long)]
        max_depth: Option<usize>,

        /// Include hidden files and directories
        #[arg(long)]
        hidden: bool,

        /// Include directory entries in the resulting PathSet
        #[arg(long)]
        dirs: bool,
    },

    /// Filter an existing PathSet or MatchSet register into a new SSA register
    Filter {
        /// Source register (e.g. r0, @r0, @last)
        reg: String,

        /// Filter by glob pattern
        #[arg(short, long)]
        glob: Option<String>,

        /// Filter by regular expression
        #[arg(short = 'e', long)]
        regex: Option<String>,

        /// Minimum file size in bytes (for PathSet)
        #[arg(long)]
        min_size: Option<u64>,

        /// Maximum file size in bytes (for PathSet)
        #[arg(long)]
        max_size: Option<u64>,
    },

    /// Search pattern across a register or path into a new MatchSet SSA register (replaces `grep`)
    Match {
        /// Source register (e.g. r0, @r0, @last) or filesystem path
        target: String,

        /// Regular expression (or literal string with --fixed)
        pattern: String,

        /// Treat pattern as a literal fixed string instead of regex
        #[arg(short = 'F', long)]
        fixed: bool,
    },

    /// Load file contents or line slices into a new TextBuf SSA register (replaces `cat`/`head`/`tail`)
    Load {
        /// Source register (e.g. r0, @r0, @last, r0[0]) or file path
        target: String,

        /// 1-based start line (inclusive)
        #[arg(short = 's', long)]
        start_line: Option<usize>,

        /// 1-based end line (inclusive)
        #[arg(short = 'e', long)]
        end_line: Option<usize>,
    },

    /// Stage regex/fixed substitutions in SSA memory into a DiffSet register without touching disk (replaces `sed`)
    Sub {
        /// Source register (e.g. r0, @r0, @last) or file path
        target: String,

        /// Search pattern (regex or fixed string with --fixed)
        pattern: String,

        /// Replacement text
        replacement: String,

        /// Treat pattern and replacement as literal fixed strings
        #[arg(short = 'F', long)]
        fixed: bool,
    },

    /// Atomically apply a staged DiffSet register to disk
    Commit {
        /// DiffSet register to commit (e.g. r2, @r2, @last)
        diff_reg: String,
    },

    /// Delete files in a PathSet register (dry-run unless --force is passed; replaces `rm`)
    Purge {
        /// PathSet register to purge (e.g. r0, @r0, @last)
        reg: String,

        /// Actually unlink files from disk (without --force, performs a dry-run audit)
        #[arg(short, long)]
        force: bool,
    },

    /// Execute a command template across items in a register (replaces `xargs`)
    Xexec {
        /// Source register supplying paths (e.g. r0, @r0, @last)
        reg: String,

        /// Command and arguments (use `{}` as placeholder for each item path)
        #[arg(required = true, num_args = 1.., trailing_var_arg = true)]
        cmd: Vec<String>,
    },

    /// Execute a multi-instruction Axon Register VM program (inline string or script file)
    Run {
        /// Inline Axon program (e.g. "r0 = SCAN . '*.rs'; r1 = MATCH r0 'fn '") or path to .ax file
        program: String,
    },

    /// List all allocated SSA registers in shared memory
    Regs,

    /// Inspect the detailed contents of an SSA register (supports indexing like `r0[0]` or `@last`)
    Inspect {
        /// Register reference (e.g. r0, @r0, @last, r0[2])
        #[arg(default_value = "@last")]
        reg: String,

        /// Maximum number of items to display
        #[arg(short, long)]
        limit: Option<usize>,
    },

    /// Clear all SSA registers in the active shared-memory namespace
    Reset,
}

fn print_record(rec: &RegisterRecord, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(rec)?);
    } else {
        print!("{}", rec.format_inspect(Some(20)));
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let store = ShmStore::open(cli.shm_dir)?;

    match cli.command {
        Commands::Scan {
            path,
            glob,
            max_depth,
            hidden,
            dirs,
        } => {
            let rec = op_scan(
                &store,
                None,
                &ScanOpts {
                    root: path,
                    glob,
                    max_depth,
                    hidden,
                    include_dirs: dirs,
                },
            )?;
            print_record(&rec, cli.json)?;
        }
        Commands::Filter {
            reg,
            glob,
            regex,
            min_size,
            max_size,
        } => {
            let rec = op_filter(
                &store,
                None,
                &reg,
                &FilterOpts {
                    glob,
                    regex,
                    min_size,
                    max_size,
                },
            )?;
            print_record(&rec, cli.json)?;
        }
        Commands::Match {
            target,
            pattern,
            fixed,
        } => {
            let rec = op_match(&store, None, &target, &pattern, fixed)?;
            print_record(&rec, cli.json)?;
        }
        Commands::Load {
            target,
            start_line,
            end_line,
        } => {
            let rec = op_load(&store, None, &target, start_line, end_line)?;
            print_record(&rec, cli.json)?;
        }
        Commands::Sub {
            target,
            pattern,
            replacement,
            fixed,
        } => {
            let rec = op_sub(&store, None, &target, &pattern, &replacement, fixed)?;
            print_record(&rec, cli.json)?;
        }
        Commands::Commit { diff_reg } => {
            let rec = op_commit(&store, None, &diff_reg)?;
            print_record(&rec, cli.json)?;
        }
        Commands::Purge { reg, force } => {
            let rec = op_purge(&store, None, &reg, force)?;
            print_record(&rec, cli.json)?;
        }
        Commands::Xexec { reg, cmd } => {
            let rec = op_xexec(&store, None, &reg, &cmd)?;
            print_record(&rec, cli.json)?;
        }
        Commands::Run { program } => {
            let steps = execute_program(&store, &program)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&steps)?);
            } else {
                for step in steps {
                    if let Some(rec) = step.register {
                        println!("{}", rec.summary_line());
                    }
                    if let Some(txt) = step.text_output {
                        if !txt.ends_with('\n') {
                            println!("{txt}");
                        } else {
                            print!("{txt}");
                        }
                    }
                }
            }
        }
        Commands::Regs => {
            let list = store.list()?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&list)?);
            } else if list.is_empty() {
                println!(
                    "No SSA registers allocated in {}",
                    store.root().display()
                );
            } else {
                for entry in list {
                    println!(
                        "{} = {}({} items) [op: {}, origin: {}]",
                        entry.name, entry.reg_type, entry.items, entry.opcode, entry.origin
                    );
                }
            }
        }
        Commands::Inspect { reg, limit } => {
            let reg_ref = RegRef::parse(&reg)?;
            let rec = store.resolve(&reg_ref)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&rec)?);
            } else {
                print!("{}", rec.format_inspect(limit));
            }
        }
        Commands::Reset => {
            let removed = store.reset()?;
            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "status": "reset",
                        "cleared_registers": removed,
                        "shm_dir": store.root()
                    })
                );
            } else {
                println!(
                    "Cleared {removed} SSA register(s) from {}",
                    store.root().display()
                );
            }
        }
    }

    Ok(())
}
