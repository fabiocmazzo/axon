use crate::isa::{
    op_commit, op_filter, op_load_with_context, op_match, op_outline, op_patch, op_purge, op_scan,
    op_set_algebra, op_sub, op_undo, op_xexec, FilterOpts, ScanOpts, SetOp,
};
use crate::reg::{RegRef, RegisterRecord};
use crate::shm::ShmStore;
use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize)]
pub struct VmStepOutput {
    pub instruction: String,
    pub register: Option<RegisterRecord>,
    pub text_output: Option<String>,
}

/// Split a script into statements separated by newlines or unquoted semicolons.
fn split_statements(script: &str) -> Vec<String> {
    let mut stmts = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    for ch in script.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' && (in_single || in_double) {
            current.push(ch);
            escaped = true;
            continue;
        }
        if ch == '\'' && !in_double {
            in_single = !in_single;
            current.push(ch);
            continue;
        }
        if ch == '"' && !in_single {
            in_double = !in_double;
            current.push(ch);
            continue;
        }
        if (ch == '\n' || ch == ';') && !in_single && !in_double {
            let trimmed = current.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') && !trimmed.starts_with("//") {
                stmts.push(trimmed.to_string());
            }
            current.clear();
        } else {
            current.push(ch);
        }
    }

    let trimmed = current.trim();
    if !trimmed.is_empty() && !trimmed.starts_with('#') && !trimmed.starts_with("//") {
        stmts.push(trimmed.to_string());
    }
    stmts
}

/// Tokenize a single VM instruction respecting single/double quotes and escape sequences.
pub fn tokenize_instruction(stmt: &str) -> Result<Vec<String>> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut token_started = false;
    let mut chars = stmt.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\\' && (in_single || in_double) {
            if let Some(&next_ch) = chars.peek() {
                match next_ch {
                    '"' | '\'' | '\\' => {
                        current.push(chars.next().unwrap());
                        continue;
                    }
                    'n' => {
                        let _ = chars.next();
                        current.push('\n');
                        continue;
                    }
                    't' => {
                        let _ = chars.next();
                        current.push('\t');
                        continue;
                    }
                    _ => {}
                }
            }
            current.push(ch);
            continue;
        }
        if ch == '\'' && !in_double {
            in_single = !in_single;
            token_started = true;
            continue;
        }
        if ch == '"' && !in_single {
            in_double = !in_double;
            token_started = true;
            continue;
        }
        if !in_single && !in_double {
            if ch == '#' {
                break;
            }
            if ch.is_whitespace() {
                if token_started || !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                    token_started = false;
                }
                continue;
            }
        }
        current.push(ch);
        token_started = true;
    }

    if in_single || in_double {
        bail!("Unterminated string literal in instruction: {stmt}");
    }
    if token_started || !current.is_empty() {
        tokens.push(current);
    }
    Ok(tokens)
}

fn parse_dest_binding(tokens: &[String]) -> Result<(Option<u32>, &[String])> {
    if tokens.len() >= 3 && tokens[1] == "=" {
        let lhs = &tokens[0];
        let parsed = RegRef::parse(lhs)
            .with_context(|| format!("Invalid destination SSA register '{lhs}'"))?;
        match parsed {
            RegRef::Id { id, index: None } => Ok((Some(id), &tokens[2..])),
            _ => bail!("Destination SSA binding must be a direct register ID like 'r0 =', got '{lhs}'"),
        }
    } else {
        Ok((None, tokens))
    }
}

/// Execute an Axon VM program (either inline code or a file path if `script_or_path` points to a file).
pub fn execute_program(store: &ShmStore, script_or_path: &str) -> Result<Vec<VmStepOutput>> {
    let source = if std::path::Path::new(script_or_path).is_file() {
        std::fs::read_to_string(script_or_path)
            .with_context(|| format!("Failed to read Axon script file '{script_or_path}'"))?
    } else {
        script_or_path.to_string()
    };

    let stmts = split_statements(&source);
    let mut outputs = Vec::with_capacity(stmts.len());

    for stmt in stmts {
        let tokens = tokenize_instruction(&stmt)?;
        if tokens.is_empty() {
            continue;
        }
        let (explicit_id, body) = parse_dest_binding(&tokens)?;
        if body.is_empty() {
            bail!("Empty opcode in statement: {stmt}");
        }

        let op = body[0].to_ascii_uppercase();
        let args = &body[1..];

        let step = match op.as_str() {
            "SCAN" => {
                let mut opts = ScanOpts {
                    root: PathBuf::from("."),
                    ..Default::default()
                };
                let mut pos_idx = 0;
                let mut i = 0;
                while i < args.len() {
                    match args[i].as_str() {
                        "--glob" | "-g" => {
                            i += 1;
                            opts.glob = Some(
                                args.get(i)
                                    .ok_or_else(|| anyhow!("SCAN --glob requires a pattern"))?
                                    .clone(),
                            );
                        }
                        "--max-depth" | "-d" => {
                            i += 1;
                            let val: usize = args
                                .get(i)
                                .ok_or_else(|| anyhow!("SCAN --max-depth requires a number"))?
                                .parse()?;
                            opts.max_depth = Some(val);
                        }
                        "--hidden" => opts.hidden = true,
                        "--dirs" => opts.include_dirs = true,
                        positional => {
                            if pos_idx == 0 {
                                opts.root = PathBuf::from(positional);
                            } else if pos_idx == 1 && opts.glob.is_none() {
                                opts.glob = Some(positional.to_string());
                            } else {
                                bail!("Unexpected argument '{positional}' in SCAN");
                            }
                            pos_idx += 1;
                        }
                    }
                    i += 1;
                }
                let rec = op_scan(store, explicit_id, &opts)?;
                VmStepOutput {
                    instruction: stmt,
                    register: Some(rec),
                    text_output: None,
                }
            }
            "FILTER" => {
                if args.is_empty() {
                    bail!("FILTER requires a source register");
                }
                let src_reg = &args[0];
                let mut opts = FilterOpts::default();
                let mut i = 1;
                while i < args.len() {
                    match args[i].as_str() {
                        "--glob" | "-g" => {
                            i += 1;
                            opts.glob = Some(
                                args.get(i)
                                    .ok_or_else(|| anyhow!("FILTER --glob requires a pattern"))?
                                    .clone(),
                            );
                        }
                        "--regex" | "-e" => {
                            i += 1;
                            opts.regex = Some(
                                args.get(i)
                                    .ok_or_else(|| anyhow!("FILTER --regex requires a pattern"))?
                                    .clone(),
                            );
                        }
                        "--min-size" => {
                            i += 1;
                            opts.min_size = Some(
                                args.get(i)
                                    .ok_or_else(|| anyhow!("FILTER --min-size requires bytes"))?
                                    .parse()?,
                            );
                        }
                        "--max-size" => {
                            i += 1;
                            opts.max_size = Some(
                                args.get(i)
                                    .ok_or_else(|| anyhow!("FILTER --max-size requires bytes"))?
                                    .parse()?,
                            );
                        }
                        positional if opts.glob.is_none() && opts.regex.is_none() => {
                            opts.glob = Some(positional.to_string());
                        }
                        other => bail!("Unexpected argument '{other}' in FILTER"),
                    }
                    i += 1;
                }
                let rec = op_filter(store, explicit_id, src_reg, &opts)?;
                VmStepOutput {
                    instruction: stmt,
                    register: Some(rec),
                    text_output: None,
                }
            }
            "UNION" | "INTERSECT" | "DIFF" => {
                if args.len() != 2 {
                    bail!("{op} requires <reg_a> <reg_b>");
                }
                let set_op = match op.as_str() {
                    "UNION" => SetOp::Union,
                    "INTERSECT" => SetOp::Intersect,
                    _ => SetOp::Diff,
                };
                let rec = op_set_algebra(store, explicit_id, set_op, &args[0], &args[1])?;
                VmStepOutput {
                    instruction: stmt,
                    register: Some(rec),
                    text_output: None,
                }
            }
            "MATCH" | "GREP" => {
                if args.len() < 2 {
                    bail!("MATCH requires <reg_or_path> <pattern> [--fixed]");
                }
                let target = &args[0];
                let pattern = &args[1];
                let fixed = args[2..].iter().any(|a| a == "--fixed" || a == "-F");
                let rec = op_match(store, explicit_id, target, pattern, fixed)?;
                VmStepOutput {
                    instruction: stmt,
                    register: Some(rec),
                    text_output: None,
                }
            }
            "OUTLINE" | "SYMBOLS" => {
                let target = args.first().map(|s| s.as_str()).unwrap_or("@last");
                let rec = op_outline(store, explicit_id, target)?;
                VmStepOutput {
                    instruction: stmt,
                    register: Some(rec),
                    text_output: None,
                }
            }
            "LOAD" | "READ" | "CAT" => {
                if args.is_empty() {
                    bail!("LOAD requires <reg_or_path>");
                }
                let target = &args[0];
                let mut start_line = None;
                let mut end_line = None;
                let mut context = None;
                let mut i = 1;
                while i < args.len() {
                    match args[i].as_str() {
                        "--start-line" | "-s" => {
                            i += 1;
                            start_line = Some(
                                args.get(i)
                                    .ok_or_else(|| anyhow!("LOAD --start-line requires a number"))?
                                    .parse()?,
                            );
                        }
                        "--end-line" | "-e" => {
                            i += 1;
                            end_line = Some(
                                args.get(i)
                                    .ok_or_else(|| anyhow!("LOAD --end-line requires a number"))?
                                    .parse()?,
                            );
                        }
                        "--context" | "-C" => {
                            i += 1;
                            context = Some(
                                args.get(i)
                                    .ok_or_else(|| anyhow!("LOAD --context requires a number"))?
                                    .parse()?,
                            );
                        }
                        other => bail!("Unexpected argument '{other}' in LOAD"),
                    }
                    i += 1;
                }
                let rec =
                    op_load_with_context(store, explicit_id, target, start_line, end_line, context)?;
                VmStepOutput {
                    instruction: stmt,
                    register: Some(rec),
                    text_output: None,
                }
            }
            "SUB" | "REPLACE" => {
                if args.len() < 3 {
                    bail!("SUB requires <reg_or_path> <pattern> <replacement> [--fixed]");
                }
                let target = &args[0];
                let pattern = &args[1];
                let replacement = &args[2];
                let fixed = args[3..].iter().any(|a| a == "--fixed" || a == "-F");
                let rec = op_sub(store, explicit_id, target, pattern, replacement, fixed)?;
                VmStepOutput {
                    instruction: stmt,
                    register: Some(rec),
                    text_output: None,
                }
            }
            "PATCH" => {
                if args.is_empty() {
                    bail!("PATCH requires <reg_or_path> --start-line <A> --end-line <B> --with <TEXT> (or <reg> <A> <B> <TEXT>)");
                }
                let target = &args[0];
                let mut start_line: Option<usize> = None;
                let mut end_line: Option<usize> = None;
                let mut replacement: Option<String> = None;

                if args.len() == 4 && !args[1].starts_with('-') {
                    start_line = Some(args[1].parse()?);
                    end_line = Some(args[2].parse()?);
                    replacement = Some(args[3].clone());
                } else {
                    let mut i = 1;
                    while i < args.len() {
                        match args[i].as_str() {
                            "--start-line" | "-s" => {
                                i += 1;
                                start_line = Some(
                                    args.get(i)
                                        .ok_or_else(|| anyhow!("PATCH --start-line requires line number"))?
                                        .parse()?,
                                );
                            }
                            "--end-line" | "-e" => {
                                i += 1;
                                end_line = Some(
                                    args.get(i)
                                        .ok_or_else(|| anyhow!("PATCH --end-line requires line number"))?
                                        .parse()?,
                                );
                            }
                            "--with" | "-w" => {
                                i += 1;
                                replacement = Some(
                                    args.get(i)
                                        .ok_or_else(|| anyhow!("PATCH --with requires replacement text"))?
                                        .clone(),
                                );
                            }
                            other => bail!("Unexpected argument '{other}' in PATCH"),
                        }
                        i += 1;
                    }
                }

                let s = start_line.ok_or_else(|| anyhow!("PATCH missing --start-line"))?;
                let e = end_line.unwrap_or(s);
                let rep = replacement.ok_or_else(|| anyhow!("PATCH missing --with replacement"))?;
                let rec = op_patch(store, explicit_id, target, s, e, &rep)?;
                VmStepOutput {
                    instruction: stmt,
                    register: Some(rec),
                    text_output: None,
                }
            }
            "COMMIT" | "APPLY" => {
                if args.is_empty() {
                    bail!("COMMIT requires <diff_reg>");
                }
                let rec = op_commit(store, explicit_id, &args[0])?;
                VmStepOutput {
                    instruction: stmt,
                    register: Some(rec),
                    text_output: None,
                }
            }
            "UNDO" | "ROLLBACK" => {
                let target = args.first().map(|s| s.as_str()).unwrap_or("@last");
                let force = args.iter().skip(1).any(|a| a == "--force" || a == "-f");
                let rec = op_undo(store, explicit_id, target, force)?;
                VmStepOutput {
                    instruction: stmt,
                    register: Some(rec),
                    text_output: None,
                }
            }
            "PURGE" | "RM" => {
                if args.is_empty() {
                    bail!("PURGE requires <pathset_reg> [--force]");
                }
                let force = args[1..].iter().any(|a| a == "--force" || a == "-f");
                let rec = op_purge(store, explicit_id, &args[0], force)?;
                VmStepOutput {
                    instruction: stmt,
                    register: Some(rec),
                    text_output: None,
                }
            }
            "XEXEC" | "XARGS" => {
                if args.len() < 2 {
                    bail!("XEXEC requires <reg> <cmd> [args...]");
                }
                let rec = op_xexec(store, explicit_id, &args[0], &args[1..])?;
                VmStepOutput {
                    instruction: stmt,
                    register: Some(rec),
                    text_output: None,
                }
            }
            "INSPECT" | "PRINT" => {
                let target = args.first().map(|s| s.as_str()).unwrap_or("@last");
                let reg_ref = RegRef::parse(target)?;
                let rec = store.resolve(&reg_ref)?;
                let formatted = rec.format_inspect(None);
                VmStepOutput {
                    instruction: stmt,
                    register: None,
                    text_output: Some(formatted),
                }
            }
            "REGS" => {
                let entries = store.list()?;
                let mut lines = Vec::with_capacity(entries.len());
                for e in entries {
                    lines.push(format!(
                        "{} = {}({} items) [op: {}, origin: {}]",
                        e.name, e.reg_type, e.items, e.opcode, e.origin
                    ));
                }
                VmStepOutput {
                    instruction: stmt,
                    register: None,
                    text_output: Some(lines.join("\n")),
                }
            }
            "RESET" => {
                let count = store.reset()?;
                VmStepOutput {
                    instruction: stmt,
                    register: None,
                    text_output: Some(format!("Reset {count} SSA register(s)")),
                }
            }
            unknown => bail!("Unknown Axon VM opcode '{unknown}' in statement: {stmt}"),
        };

        outputs.push(step);
    }

    Ok(outputs)
}
