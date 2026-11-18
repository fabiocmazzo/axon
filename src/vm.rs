use crate::isa::{
    op_commit, op_filter, op_load_with_context, op_match, op_outline, op_patch, op_purge, op_scan,
    op_set_algebra, op_sub, op_undo, op_xexec, FilterOpts, ScanOpts, SetOp,
};
use crate::reg::{RegRef, RegisterRecord};
use crate::shm::ShmStore;
use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize)]
pub struct VmStepOutput {
    pub instruction: String,
    pub virtual_reg: Option<String>,
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

/// Remap a virtual register operand (e.g. `r0`, `@r0`, `r0[1]`) to its physical `/dev/shm` SSA register
/// if `r0` was bound and renamed earlier in the current VM execution.
fn remap_operand(operand: &str, local_bindings: &BTreeMap<u32, u32>) -> String {
    if !RegRef::looks_like_reg(operand) {
        return operand.to_string();
    }
    if let Ok(RegRef::Id { id, index }) = RegRef::parse(operand) {
        if let Some(&phys_id) = local_bindings.get(&id) {
            return match index {
                Some(idx) => format!("@r{phys_id}[{idx}]"),
                None => format!("@r{phys_id}"),
            };
        }
    }
    operand.to_string()
}

/// Resolve the physical allocation target for a virtual destination register ID:
/// - Rejects duplicate assignment to the same virtual register within a single VM program (`SSA_VIOLATION`).
/// - If the requested ID is free in `/dev/shm`, binds directly to `Some(v_id)`.
/// - If already occupied in `/dev/shm` from a prior run, returns `None` so the store allocates the next
///   monotonic physical SSA register and maps `v_id -> phys_id` in `local_bindings`.
fn resolve_physical_target(
    store: &ShmStore,
    virtual_id: Option<u32>,
    local_bindings: &BTreeMap<u32, u32>,
) -> Result<Option<u32>> {
    if let Some(v_id) = virtual_id {
        if let Some(&existing_phys) = local_bindings.get(&v_id) {
            bail!(
                "SSA_VIOLATION: register r{v_id} is assigned multiple times in the same program (already bound to r{existing_phys})"
            );
        }
        if store.is_allocated(v_id)? {
            return Ok(None);
        }
        return Ok(Some(v_id));
    }
    Ok(None)
}

fn record_step(
    stmt: String,
    virtual_id: Option<u32>,
    rec: RegisterRecord,
    local_bindings: &mut BTreeMap<u32, u32>,
) -> VmStepOutput {
    let virtual_reg = if let Some(v_id) = virtual_id {
        local_bindings.insert(v_id, rec.id);
        if v_id != rec.id {
            Some(format!("r{v_id}"))
        } else {
            None
        }
    } else {
        None
    };
    VmStepOutput {
        instruction: stmt,
        virtual_reg,
        register: Some(rec),
        text_output: None,
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
    let mut local_bindings: BTreeMap<u32, u32> = BTreeMap::new();

    for stmt in stmts {
        let tokens = tokenize_instruction(&stmt)?;
        if tokens.is_empty() {
            continue;
        }
        let (virtual_id, body) = parse_dest_binding(&tokens)?;
        if body.is_empty() {
            bail!("Empty opcode in statement: {stmt}");
        }

        let op = body[0].to_ascii_uppercase();
        let args = &body[1..];
        let phys_target = resolve_physical_target(store, virtual_id, &local_bindings)?;

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
                let rec = op_scan(store, phys_target, &opts)?;
                record_step(stmt, virtual_id, rec, &mut local_bindings)
            }
            "FILTER" => {
                if args.is_empty() {
                    bail!("FILTER requires a source register");
                }
                let src_reg = remap_operand(&args[0], &local_bindings);
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
                let rec = op_filter(store, phys_target, &src_reg, &opts)?;
                record_step(stmt, virtual_id, rec, &mut local_bindings)
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
                let reg_a = remap_operand(&args[0], &local_bindings);
                let reg_b = remap_operand(&args[1], &local_bindings);
                let rec = op_set_algebra(store, phys_target, set_op, &reg_a, &reg_b)?;
                record_step(stmt, virtual_id, rec, &mut local_bindings)
            }
            "MATCH" | "GREP" => {
                if args.len() < 2 {
                    bail!("MATCH requires <reg_or_path> <pattern> [--fixed]");
                }
                let target = remap_operand(&args[0], &local_bindings);
                let pattern = &args[1];
                let fixed = args[2..].iter().any(|a| a == "--fixed" || a == "-F");
                let rec = op_match(store, phys_target, &target, pattern, fixed)?;
                record_step(stmt, virtual_id, rec, &mut local_bindings)
            }
            "OUTLINE" | "SYMBOLS" => {
                let raw_target = args.first().map(|s| s.as_str()).unwrap_or("@last");
                let target = remap_operand(raw_target, &local_bindings);
                let rec = op_outline(store, phys_target, &target)?;
                record_step(stmt, virtual_id, rec, &mut local_bindings)
            }
            "LOAD" | "READ" | "CAT" => {
                if args.is_empty() {
                    bail!("LOAD requires <reg_or_path>");
                }
                let target = remap_operand(&args[0], &local_bindings);
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
                let rec = op_load_with_context(
                    store,
                    phys_target,
                    &target,
                    start_line,
                    end_line,
                    context,
                )?;
                record_step(stmt, virtual_id, rec, &mut local_bindings)
            }
            "SUB" | "REPLACE" => {
                if args.len() < 3 {
                    bail!("SUB requires <reg_or_path> <pattern> <replacement> [--fixed]");
                }
                let target = remap_operand(&args[0], &local_bindings);
                let pattern = &args[1];
                let replacement = &args[2];
                let fixed = args[3..].iter().any(|a| a == "--fixed" || a == "-F");
                let rec = op_sub(store, phys_target, &target, pattern, replacement, fixed)?;
                record_step(stmt, virtual_id, rec, &mut local_bindings)
            }
            "PATCH" => {
                if args.is_empty() {
                    bail!("PATCH requires <reg_or_path> --start-line <A> --end-line <B> --with <TEXT> (or <reg> <A> <B> <TEXT>)");
                }
                let target = remap_operand(&args[0], &local_bindings);
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
                                        .ok_or_else(|| {
                                            anyhow!("PATCH --start-line requires line number")
                                        })?
                                        .parse()?,
                                );
                            }
                            "--end-line" | "-e" => {
                                i += 1;
                                end_line = Some(
                                    args.get(i)
                                        .ok_or_else(|| {
                                            anyhow!("PATCH --end-line requires line number")
                                        })?
                                        .parse()?,
                                );
                            }
                            "--with" | "-w" => {
                                i += 1;
                                replacement = Some(
                                    args.get(i)
                                        .ok_or_else(|| {
                                            anyhow!("PATCH --with requires replacement text")
                                        })?
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
                let rec = op_patch(store, phys_target, &target, s, e, &rep)?;
                record_step(stmt, virtual_id, rec, &mut local_bindings)
            }
            "COMMIT" | "APPLY" => {
                if args.is_empty() {
                    bail!("COMMIT requires <diff_reg>");
                }
                let diff_reg = remap_operand(&args[0], &local_bindings);
                let rec = op_commit(store, phys_target, &diff_reg)?;
                record_step(stmt, virtual_id, rec, &mut local_bindings)
            }
            "UNDO" | "ROLLBACK" => {
                let raw_target = args.first().map(|s| s.as_str()).unwrap_or("@last");
                let target = remap_operand(raw_target, &local_bindings);
                let force = args.iter().skip(1).any(|a| a == "--force" || a == "-f");
                let rec = op_undo(store, phys_target, &target, force)?;
                record_step(stmt, virtual_id, rec, &mut local_bindings)
            }
            "PURGE" | "RM" => {
                if args.is_empty() {
                    bail!("PURGE requires <pathset_reg> [--force]");
                }
                let target = remap_operand(&args[0], &local_bindings);
                let force = args[1..].iter().any(|a| a == "--force" || a == "-f");
                let rec = op_purge(store, phys_target, &target, force)?;
                record_step(stmt, virtual_id, rec, &mut local_bindings)
            }
            "XEXEC" | "XARGS" => {
                if args.len() < 2 {
                    bail!("XEXEC requires <reg> <cmd> [args...]");
                }
                let target = remap_operand(&args[0], &local_bindings);
                let rec = op_xexec(store, phys_target, &target, &args[1..])?;
                record_step(stmt, virtual_id, rec, &mut local_bindings)
            }
            "INSPECT" | "PRINT" => {
                let raw_target = args.first().map(|s| s.as_str()).unwrap_or("@last");
                let target = remap_operand(raw_target, &local_bindings);
                let reg_ref = RegRef::parse(&target)?;
                let rec = store.resolve(&reg_ref)?;
                let formatted = rec.format_inspect(None);
                VmStepOutput {
                    instruction: stmt,
                    virtual_reg: None,
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
                    virtual_reg: None,
                    register: None,
                    text_output: Some(lines.join("\n")),
                }
            }
            "RESET" => {
                let count = store.reset()?;
                local_bindings.clear();
                VmStepOutput {
                    instruction: stmt,
                    virtual_reg: None,
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
