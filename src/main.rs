use anyhow::Result;
use axon::isa::{
    op_commit, op_dirty, op_edit, op_filter, op_load_with_context, op_match, op_outline, op_patch,
    op_purge, op_scan, op_set_algebra, op_slice, op_sub, op_undo, op_verify, op_write, op_xexec,
    schema_spec, trace_lineage, FilterOpts, ScanOpts, SetOp,
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

    /// Allocate a PathSet of modified or untracked files in the Git working tree
    Dirty {
        /// Repository directory to query
        #[arg(default_value = ".")]
        path: PathBuf,
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

    /// Paginate a register by slicing items in range [start..end) into a new SSA register
    Slice {
        /// Source register (e.g. r0, @r0, @last)
        reg: String,
        /// 0-based start index (inclusive)
        start: usize,
        /// 0-based end index (exclusive)
        end: usize,
    },

    /// Compute set union (or compose two DiffSet registers) into a new SSA register
    Union {
        /// First register (e.g. r0)
        reg_a: String,
        /// Second register (e.g. r1)
        reg_b: String,
    },

    /// Compute set intersection of two SSA registers into a new register
    Intersect {
        /// First register (e.g. r0)
        reg_a: String,
        /// Second register (e.g. r1)
        reg_b: String,
    },

    /// Compute set difference (reg_a \ reg_b) into a new SSA register
    Diff {
        /// First register (e.g. r0)
        reg_a: String,
        /// Second register to subtract (e.g. r1)
        reg_b: String,
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

    /// Extract structural symbol declarations (fn, struct, enum, trait, impl, class, def) into a MatchSet
    Outline {
        /// Source register (e.g. r0, @last) or filesystem path
        #[arg(default_value = "@last")]
        target: String,
    },

    /// Load file contents, line ranges, or ±N context windows around a MatchSet into a TextBuf register
    Load {
        /// Source register (e.g. r0, @r0, @last, r0[0]) or file path
        target: String,

        /// 1-based start line (inclusive)
        #[arg(short = 's', long)]
        start_line: Option<usize>,

        /// 1-based end line (inclusive)
        #[arg(short = 'e', long)]
        end_line: Option<usize>,

        /// Context lines (±N) to load around each match in a MatchSet (merges overlapping windows)
        #[arg(short = 'C', long)]
        context: Option<usize>,
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

    /// Stage surgical exact-anchor replacement in SSA memory (requires unique occurrence of old_block)
    Edit {
        /// Source register (e.g. r0[0]) or file path
        target: String,

        /// Exact unique text block to locate
        old_block: String,

        /// New text block to replace it with
        new_block: String,
    },

    /// Stage surgical line-range replacement in SSA memory into a DiffSet register without touching disk
    Patch {
        /// Source register (e.g. r0[0]) or file path
        target: String,

        /// 1-based start line to replace (inclusive)
        #[arg(short = 's', long)]
        start_line: usize,

        /// 1-based end line to replace (inclusive; defaults to start_line)
        #[arg(short = 'e', long)]
        end_line: Option<usize>,

        /// Replacement text for the line range
        #[arg(short = 'w', long)]
        with: String,
    },

    /// Stage creation (or full replacement) of a file into a DiffSet register in SSA memory
    Write {
        /// Target file path to create or overwrite when committed
        path: String,

        /// Full text content for the file
        content: String,
    },

    /// Verify CAS hashes and atomically apply a staged DiffSet register to disk
    Commit {
        /// DiffSet register to commit (e.g. r2, @r2, @last)
        diff_reg: String,
    },

    /// Transactionally apply a DiffSet, run a test/check command, and auto-UNDO if the command exits non-zero
    Verify {
        /// DiffSet register to commit and verify (e.g. r2, @last)
        diff_reg: String,

        /// Verification command and arguments (e.g. cargo check)
        #[arg(required = true, num_args = 1.., trailing_var_arg = true)]
        cmd: Vec<String>,
    },

    /// Atomically roll back a COMMIT (or DiffSet) register to its pre-commit state from /dev/shm
    Undo {
        /// COMMIT or DiffSet register to roll back (defaults to @last)
        #[arg(default_value = "@last")]
        reg: String,

        /// Force rollback even if the file on disk was modified after COMMIT
        #[arg(short, long)]
        force: bool,
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

    /// Reconstruct the chronological SSA lineage graph of registers in /dev/shm
    Trace,

    /// Emit the compact EBNF ISA specification and system-prompt reference for agents / Tiny LMs
    Schema,

    /// Display shared-memory usage and register statistics in /dev/shm
    Stats,

    /// Garbage-collect old SSA registers in /dev/shm while keeping the N most recent registers
    Gc {
        /// Number of most recent SSA registers to retain
        #[arg(short, long, default_value_t = 10)]
        keep: usize,
    },

    /// Inspect the detailed contents of an SSA register (supports indexing like `r0[0]` or `@last`)
    Inspect {
        /// Register reference (e.g. r0, @r0, @last, r0[2])
        #[arg(default_value = "@last")]
        reg: String,

        /// Maximum number of items to display
        #[arg(short, long)]
        limit: Option<usize>,

        /// Maximum character budget for the inspection output (truncates deterministically)
        #[arg(short = 'm', long)]
        max_chars: Option<usize>,
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
        Commands::Dirty { path } => {
            let rec = op_dirty(&store, None, &path)?;
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
        Commands::Slice { reg, start, end } => {
            let rec = op_slice(&store, None, &reg, start, end)?;
            print_record(&rec, cli.json)?;
        }
        Commands::Union { reg_a, reg_b } => {
            let rec = op_set_algebra(&store, None, SetOp::Union, &reg_a, &reg_b)?;
            print_record(&rec, cli.json)?;
        }
        Commands::Intersect { reg_a, reg_b } => {
            let rec = op_set_algebra(&store, None, SetOp::Intersect, &reg_a, &reg_b)?;
            print_record(&rec, cli.json)?;
        }
        Commands::Diff { reg_a, reg_b } => {
            let rec = op_set_algebra(&store, None, SetOp::Diff, &reg_a, &reg_b)?;
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
        Commands::Outline { target } => {
            let rec = op_outline(&store, None, &target)?;
            print_record(&rec, cli.json)?;
        }
        Commands::Load {
            target,
            start_line,
            end_line,
            context,
        } => {
            let rec =
                op_load_with_context(&store, None, &target, start_line, end_line, context)?;
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
        Commands::Edit {
            target,
            old_block,
            new_block,
        } => {
            let rec = op_edit(&store, None, &target, &old_block, &new_block)?;
            print_record(&rec, cli.json)?;
        }
        Commands::Patch {
            target,
            start_line,
            end_line,
            with,
        } => {
            let rec = op_patch(
                &store,
                None,
                &target,
                start_line,
                end_line.unwrap_or(start_line),
                &with,
            )?;
            print_record(&rec, cli.json)?;
        }
        Commands::Write { path, content } => {
            let rec = op_write(&store, None, &path, &content)?;
            print_record(&rec, cli.json)?;
        }
        Commands::Commit { diff_reg } => {
            let rec = op_commit(&store, None, &diff_reg)?;
            print_record(&rec, cli.json)?;
        }
        Commands::Verify { diff_reg, cmd } => {
            let rec = op_verify(&store, None, &diff_reg, &cmd)?;
            print_record(&rec, cli.json)?;
        }
        Commands::Undo { reg, force } => {
            let rec = op_undo(&store, None, &reg, force)?;
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
                        if let Some(v_reg) = step.virtual_reg {
                            println!(
                                "{} (local {}) = {}({} items) [op: {}, origin: {}]",
                                rec.name,
                                v_reg,
                                rec.value.type_name(),
                                rec.value.len(),
                                rec.opcode,
                                rec.origin
                            );
                        } else {
                            println!("{}", rec.summary_line());
                        }
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
                println!("No SSA registers allocated in {}", store.root().display());
            } else {
                for entry in list {
                    println!(
                        "{} = {}({} items) [op: {}, origin: {}]",
                        entry.name, entry.reg_type, entry.items, entry.opcode, entry.origin
                    );
                }
            }
        }
        Commands::Trace => {
            let txt = trace_lineage(&store)?;
            if cli.json {
                println!("{}", serde_json::json!({ "trace": txt }));
            } else {
                print!("{txt}");
            }
        }
        Commands::Schema => {
            let spec = schema_spec();
            if cli.json {
                println!("{}", serde_json::json!({ "schema": spec }));
            } else {
                println!("{spec}");
            }
        }
        Commands::Stats => {
            let st = store.stats()?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&st)?);
            } else {
                println!("SHM Directory   : {}", st.shm_dir);
                println!("Active Registers: {}", st.total_registers);
                println!("Total SHM Bytes : {} B", st.total_bytes);
                println!("Next Physical ID: r{}", st.next_id);
                for (ty, count) in &st.by_type {
                    println!("  - {:<12}: {}", ty, count);
                }
            }
        }
        Commands::Gc { keep } => {
            let rep = store.gc(keep)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&rep)?);
            } else {
                println!(
                    "GC removed {} register(s) ({} B freed), retained {} register(s) (next_id: r{})",
                    rep.removed_registers, rep.freed_bytes, rep.retained_registers, rep.next_id
                );
            }
        }
        Commands::Inspect {
            reg,
            limit,
            max_chars,
        } => {
            let reg_ref = RegRef::parse(&reg)?;
            let rec = store.resolve(&reg_ref)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&rec)?);
            } else {
                print!("{}", rec.format_inspect_with_budget(limit, max_chars));
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
