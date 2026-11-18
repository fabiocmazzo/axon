use crate::reg::{
    CmdReceipt, FilePatch, FileSlice, PathEntry, RegRef, RegValue, RegisterRecord, SpanMatch,
};
use crate::shm::ShmStore;
use anyhow::{anyhow, bail, Context, Result};
use globset::{Glob, GlobMatcher};
use ignore::WalkBuilder;
use regex::Regex;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Default)]
pub struct ScanOpts {
    pub root: PathBuf,
    pub glob: Option<String>,
    pub max_depth: Option<usize>,
    pub hidden: bool,
    pub include_dirs: bool,
}

#[derive(Debug, Clone, Default)]
pub struct FilterOpts {
    pub glob: Option<String>,
    pub regex: Option<String>,
    pub min_size: Option<u64>,
    pub max_size: Option<u64>,
}

fn build_glob(pattern: &Option<String>) -> Result<Option<GlobMatcher>> {
    match pattern {
        Some(p) => {
            let glob = Glob::new(p).with_context(|| format!("Invalid glob pattern '{p}'"))?;
            Ok(Some(glob.compile_matcher()))
        }
        None => Ok(None),
    }
}

fn normalize_display_path(path: &Path) -> String {
    let s = path.to_string_lossy();
    if s == "." {
        return ".".to_string();
    }
    if let Some(stripped) = s.strip_prefix("./") {
        if !stripped.is_empty() {
            return stripped.to_string();
        }
    }
    s.to_string()
}

fn matches_glob(matcher: &GlobMatcher, path_str: &str) -> bool {
    if matcher.is_match(path_str) {
        return true;
    }
    if let Some(file_name) = Path::new(path_str).file_name() {
        return matcher.is_match(file_name);
    }
    false
}

/// Resolve an operand that can be either a register reference (`@r0`, `r0`, `@last`, `r0[1]`)
/// or a literal filesystem path (file or directory).
fn resolve_source_files(store: &ShmStore, target: &str) -> Result<(String, Vec<String>)> {
    if RegRef::looks_like_reg(target) {
        let reg_ref = RegRef::parse(target)?;
        let rec = store.resolve(&reg_ref)?;
        let paths = rec.value.extract_paths();
        return Ok((rec.name, paths));
    }

    let path = Path::new(target);
    if !path.exists() {
        // If it looks like a register reference that simply wasn't allocated yet, return that error
        if let Ok(reg_ref) = RegRef::parse(target) {
            let rec = store.resolve(&reg_ref)?;
            return Ok((rec.name, rec.value.extract_paths()));
        }
        bail!("Target '{}' is neither an allocated register nor an existing path", target);
    }

    if path.is_file() {
        return Ok((
            normalize_display_path(path),
            vec![normalize_display_path(path)],
        ));
    }

    // Directory target: collect files deterministically
    let mut files = Vec::new();
    for entry in WalkBuilder::new(path).hidden(false).build().flatten() {
        let p = entry.path();
        if p.is_file() {
            files.push(normalize_display_path(p));
        }
    }
    files.sort();
    files.dedup();
    Ok((normalize_display_path(path), files))
}

/// `SCAN`: Deterministic filesystem walk allocating a `PathSet` register.
pub fn op_scan(
    store: &ShmStore,
    explicit_id: Option<u32>,
    opts: &ScanOpts,
) -> Result<RegisterRecord> {
    if !opts.root.exists() {
        bail!("SCAN root '{}' does not exist", opts.root.display());
    }

    let glob_matcher = build_glob(&opts.glob)?;

    let mut builder = WalkBuilder::new(&opts.root);
    builder.hidden(!opts.hidden);
    if let Some(depth) = opts.max_depth {
        builder.max_depth(Some(depth));
    }

    let mut entries = Vec::new();
    for result in builder.build() {
        let dent = result.with_context(|| format!("Error walking {}", opts.root.display()))?;
        let path = dent.path();
        if path == opts.root && path.is_dir() {
            continue;
        }
        let meta = match dent.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let is_dir = meta.is_dir();
        if is_dir && !opts.include_dirs {
            continue;
        }

        let norm = normalize_display_path(path);
        if let Some(ref matcher) = glob_matcher {
            if !matches_glob(matcher, &norm) {
                continue;
            }
        }

        entries.push(PathEntry {
            path: norm,
            size: if is_dir { 0 } else { meta.len() },
            is_dir,
        });
    }

    entries.sort_by(|a, b| a.path.cmp(&b.path));
    entries.dedup_by(|a, b| a.path == b.path);

    let origin = match &opts.glob {
        Some(g) => format!("{} (glob: {g})", normalize_display_path(&opts.root)),
        None => normalize_display_path(&opts.root),
    };

    store.allocate(explicit_id, "SCAN", origin, RegValue::PathSet(entries))
}

/// `FILTER`: Deterministic subset selection on `PathSet` or `MatchSet`.
pub fn op_filter(
    store: &ShmStore,
    explicit_id: Option<u32>,
    source_reg: &str,
    opts: &FilterOpts,
) -> Result<RegisterRecord> {
    let reg_ref = RegRef::parse(source_reg)?;
    let src = store.resolve(&reg_ref)?;
    let glob_matcher = build_glob(&opts.glob)?;
    let regex_matcher = match &opts.regex {
        Some(pat) => Some(Regex::new(pat).with_context(|| format!("Invalid filter regex '{pat}'"))?),
        None => None,
    };

    let filtered_val = match src.value {
        RegValue::PathSet(items) => {
            let kept: Vec<PathEntry> = items
                .into_iter()
                .filter(|item| {
                    if let Some(ref gm) = glob_matcher {
                        if !matches_glob(gm, &item.path) {
                            return false;
                        }
                    }
                    if let Some(ref re) = regex_matcher {
                        if !re.is_match(&item.path) {
                            return false;
                        }
                    }
                    if let Some(min_s) = opts.min_size {
                        if item.size < min_s {
                            return false;
                        }
                    }
                    if let Some(max_s) = opts.max_size {
                        if item.size > max_s {
                            return false;
                        }
                    }
                    true
                })
                .collect();
            RegValue::PathSet(kept)
        }
        RegValue::MatchSet(items) => {
            let kept: Vec<SpanMatch> = items
                .into_iter()
                .filter(|m| {
                    if let Some(ref gm) = glob_matcher {
                        if !matches_glob(gm, &m.path) {
                            return false;
                        }
                    }
                    if let Some(ref re) = regex_matcher {
                        if !re.is_match(&m.line_text) && !re.is_match(&m.path) {
                            return false;
                        }
                    }
                    true
                })
                .collect();
            RegValue::MatchSet(kept)
        }
        other => bail!(
            "FILTER operates on PathSet or MatchSet registers, but {} is {}",
            src.name,
            other.type_name()
        ),
    };

    store.allocate(explicit_id, "FILTER", src.name, filtered_val)
}

/// `MATCH`: Deterministic regex or fixed-string search producing a `MatchSet` register.
pub fn op_match(
    store: &ShmStore,
    explicit_id: Option<u32>,
    target: &str,
    pattern: &str,
    fixed: bool,
) -> Result<RegisterRecord> {
    let compiled_pattern = if fixed {
        regex::escape(pattern)
    } else {
        pattern.to_string()
    };
    let re = Regex::new(&compiled_pattern)
        .with_context(|| format!("Invalid match pattern '{pattern}'"))?;

    // Check if target is a TextBuf register first (can match in-memory slices directly!)
    if RegRef::looks_like_reg(target) {
        let reg_ref = RegRef::parse(target)?;
        let rec = store.resolve(&reg_ref)?;
        if let RegValue::TextBuf(slices) = &rec.value {
            let mut matches = Vec::new();
            for slice in slices {
                for (offset, line_str) in slice.content.lines().enumerate() {
                    let line_no = slice.start_line + offset;
                    if let Some(m) = re.find(line_str) {
                        matches.push(SpanMatch {
                            path: slice.path.clone(),
                            line: line_no,
                            col: m.start() + 1,
                            matched: m.as_str().to_string(),
                            line_text: line_str.to_string(),
                        });
                    }
                }
            }
            return store.allocate(
                explicit_id,
                "MATCH",
                format!("{} (pat: {pattern})", rec.name),
                RegValue::MatchSet(matches),
            );
        }
    }

    let (origin_name, files) = resolve_source_files(store, target)?;
    let mut matches = Vec::new();

    for file_path in files {
        let content = match fs::read_to_string(&file_path) {
            Ok(c) => c,
            Err(_) => continue, // Skip binary or unreadable files deterministically
        };
        for (idx, line_str) in content.lines().enumerate() {
            if let Some(m) = re.find(line_str) {
                matches.push(SpanMatch {
                    path: file_path.clone(),
                    line: idx + 1,
                    col: m.start() + 1,
                    matched: m.as_str().to_string(),
                    line_text: line_str.to_string(),
                });
            }
        }
    }

    store.allocate(
        explicit_id,
        "MATCH",
        format!("{origin_name} (pat: {pattern})"),
        RegValue::MatchSet(matches),
    )
}

/// `LOAD`: Loads file contents or line ranges into a `TextBuf` register.
pub fn op_load(
    store: &ShmStore,
    explicit_id: Option<u32>,
    target: &str,
    start_line: Option<usize>,
    end_line: Option<usize>,
) -> Result<RegisterRecord> {
    let (origin_name, files) = resolve_source_files(store, target)?;
    let mut slices = Vec::new();

    for file_path in files {
        let raw = fs::read_to_string(&file_path)
            .with_context(|| format!("LOAD failed to read '{file_path}' as UTF-8 text"))?;
        let lines: Vec<&str> = raw.lines().collect();
        let total = lines.len();
        let start = start_line.unwrap_or(1).max(1);
        let end = end_line.unwrap_or(total).min(total);

        let (selected_content, actual_start, actual_end) = if total == 0 || start > end || start > total {
            (String::new(), start, end)
        } else {
            let joined = lines[start - 1..end].join("\n");
            (joined, start, end)
        };

        slices.push(FileSlice {
            path: file_path,
            start_line: actual_start,
            end_line: actual_end,
            content: selected_content,
        });
    }

    store.allocate(explicit_id, "LOAD", origin_name, RegValue::TextBuf(slices))
}

/// `SUB`: Pure SSA in-memory regex/literal substitution producing a `DiffSet` register without mutating disk.
pub fn op_sub(
    store: &ShmStore,
    explicit_id: Option<u32>,
    target: &str,
    pattern: &str,
    replacement: &str,
    fixed: bool,
) -> Result<RegisterRecord> {
    let compiled_pattern = if fixed {
        regex::escape(pattern)
    } else {
        pattern.to_string()
    };
    let re = Regex::new(&compiled_pattern)
        .with_context(|| format!("Invalid substitution pattern '{pattern}'"))?;

    let (origin_name, files) = resolve_source_files(store, target)?;
    let mut patches = Vec::new();

    for file_path in files {
        let original = match fs::read_to_string(&file_path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let count = re.find_iter(&original).count();
        if count == 0 {
            continue;
        }
        let modified = if fixed {
            re.replace_all(&original, regex::NoExpand(replacement))
                .into_owned()
        } else {
            re.replace_all(&original, replacement).into_owned()
        };

        if modified != original {
            patches.push(FilePatch {
                path: file_path,
                replacements: count,
                original,
                modified,
            });
        }
    }

    store.allocate(
        explicit_id,
        "SUB",
        format!("{origin_name} ({pattern} -> {replacement})"),
        RegValue::DiffSet(patches),
    )
}

/// `COMMIT`: Atomically writes all staged patches in a `DiffSet` register to disk.
pub fn op_commit(
    store: &ShmStore,
    explicit_id: Option<u32>,
    diff_reg: &str,
) -> Result<RegisterRecord> {
    let reg_ref = RegRef::parse(diff_reg)?;
    let rec = store.resolve(&reg_ref)?;

    let patches = match rec.value {
        RegValue::DiffSet(p) => p,
        other => bail!(
            "COMMIT requires a DiffSet register, but {} is {}",
            rec.name,
            other.type_name()
        ),
    };

    let pid = unsafe { libc::getpid() };
    let mut committed_paths = Vec::with_capacity(patches.len());

    for patch in &patches {
        let target_path = Path::new(&patch.path);
        let parent = target_path.parent().unwrap_or_else(|| Path::new("."));
        let file_name = target_path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow!("Invalid target filename '{}'", patch.path))?;
        let tmp_path = parent.join(format!(".{file_name}.axon-commit.{pid}"));

        let existing_perms = fs::metadata(target_path).ok().map(|m| m.permissions());

        {
            let mut tmp_file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp_path)
                .with_context(|| format!("Failed to create staging file {}", tmp_path.display()))?;
            tmp_file.write_all(patch.modified.as_bytes())?;
            tmp_file.flush()?;
        }

        if let Some(perms) = existing_perms {
            let _ = fs::set_permissions(&tmp_path, perms);
        }

        fs::rename(&tmp_path, target_path).with_context(|| {
            format!(
                "Failed to atomically rename {} -> {}",
                tmp_path.display(),
                target_path.display()
            )
        })?;

        committed_paths.push(patch.path.clone());
    }

    store.allocate(
        explicit_id,
        "COMMIT",
        rec.name,
        RegValue::Tombstone(committed_paths),
    )
}

/// `PURGE`: Deletes files referenced by a `PathSet` register when `force` is true (or dry-run lists targets).
pub fn op_purge(
    store: &ShmStore,
    explicit_id: Option<u32>,
    target_reg: &str,
    force: bool,
) -> Result<RegisterRecord> {
    let reg_ref = RegRef::parse(target_reg)?;
    let rec = store.resolve(&reg_ref)?;

    let paths = match &rec.value {
        RegValue::PathSet(_) => rec.value.extract_paths(),
        other => bail!(
            "PURGE requires a PathSet register, but {} is {}",
            rec.name,
            other.type_name()
        ),
    };

    let mut affected = Vec::with_capacity(paths.len());
    for p in paths {
        let path_obj = Path::new(&p);
        if force {
            if path_obj.is_dir() {
                fs::remove_dir_all(path_obj)
                    .with_context(|| format!("Failed to remove directory '{p}'"))?;
            } else if path_obj.exists() {
                fs::remove_file(path_obj)
                    .with_context(|| format!("Failed to remove file '{p}'"))?;
            }
        }
        affected.push(p);
    }

    let opcode = if force { "PURGE" } else { "PURGE_DRY" };
    store.allocate(explicit_id, opcode, rec.name, RegValue::Tombstone(affected))
}

/// `XEXEC`: Structured replacement for `xargs` over paths in a register.
pub fn op_xexec(
    store: &ShmStore,
    explicit_id: Option<u32>,
    target_reg: &str,
    cmd_parts: &[String],
) -> Result<RegisterRecord> {
    if cmd_parts.is_empty() {
        bail!("XEXEC requires a command template");
    }

    let reg_ref = RegRef::parse(target_reg)?;
    let rec = store.resolve(&reg_ref)?;
    let paths = rec.value.extract_paths();

    let has_placeholder = cmd_parts.iter().any(|part| part.contains("{}"));
    let mut receipts = Vec::new();

    if has_placeholder {
        for p in &paths {
            let expanded: Vec<String> = cmd_parts
                .iter()
                .map(|arg| arg.replace("{}", p))
                .collect();
            let prog = &expanded[0];
            let args = &expanded[1..];
            let output = Command::new(prog)
                .args(args)
                .output()
                .with_context(|| format!("XEXEC failed to spawn '{prog}'"))?;
            receipts.push(CmdReceipt {
                command: expanded.join(" "),
                target: Some(p.clone()),
                exit_code: output.status.code().unwrap_or(-1),
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
    } else if !paths.is_empty() {
        let prog = &cmd_parts[0];
        let mut args: Vec<String> = cmd_parts[1..].to_vec();
        args.extend(paths.iter().cloned());
        let output = Command::new(prog)
            .args(&args)
            .output()
            .with_context(|| format!("XEXEC failed to spawn '{prog}'"))?;
        let mut full_cmd = vec![prog.clone()];
        full_cmd.extend(args);
        receipts.push(CmdReceipt {
            command: full_cmd.join(" "),
            target: None,
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }

    store.allocate(
        explicit_id,
        "XEXEC",
        format!("{} ({})", rec.name, cmd_parts.join(" ")),
        RegValue::ExecResult(receipts),
    )
}
