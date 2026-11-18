use crate::reg::{
    fnv1a_64, CmdReceipt, FilePatch, FileSlice, PathEntry, RegRef, RegValue, RegisterRecord,
    SpanMatch,
};
use crate::shm::ShmStore;
use anyhow::{anyhow, bail, Context, Result};
use globset::{Glob, GlobMatcher};
use ignore::WalkBuilder;
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetOp {
    Union,
    Intersect,
    Diff,
}

impl SetOp {
    pub fn opcode_name(self) -> &'static str {
        match self {
            SetOp::Union => "UNION",
            SetOp::Intersect => "INTERSECT",
            SetOp::Diff => "DIFF",
        }
    }
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

/// Write bytes atomically to a target file via a sibling temporary file in the same directory.
fn write_file_atomic_preserving_perms(target_path: &Path, content: &[u8], tag: &str) -> Result<()> {
    let pid = unsafe { libc::getpid() };
    let parent = target_path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = target_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow!("Invalid target filename '{}'", target_path.display()))?;
    let tmp_path = parent.join(format!(".{file_name}.{tag}.{pid}"));

    let existing_perms = fs::metadata(target_path).ok().map(|m| m.permissions());

    {
        let mut tmp_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)
            .with_context(|| format!("Failed to create staging file {}", tmp_path.display()))?;
        tmp_file.write_all(content)?;
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
    Ok(())
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
        if let Ok(reg_ref) = RegRef::parse(target) {
            let rec = store.resolve(&reg_ref)?;
            return Ok((rec.name, rec.value.extract_paths()));
        }
        bail!(
            "Target '{}' is neither an allocated register nor an existing path",
            target
        );
    }

    if path.is_file() {
        return Ok((
            normalize_display_path(path),
            vec![normalize_display_path(path)],
        ));
    }

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
        Some(pat) => {
            Some(Regex::new(pat).with_context(|| format!("Invalid filter regex '{pat}'"))?)
        }
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

/// `UNION` / `INTERSECT` / `DIFF`: SSA register set algebra.
pub fn op_set_algebra(
    store: &ShmStore,
    explicit_id: Option<u32>,
    op: SetOp,
    reg_a_str: &str,
    reg_b_str: &str,
) -> Result<RegisterRecord> {
    let rec_a = store.resolve(&RegRef::parse(reg_a_str)?)?;
    let rec_b = store.resolve(&RegRef::parse(reg_b_str)?)?;
    let origin = format!("{} {} {}", rec_a.name, op.opcode_name(), rec_b.name);

    let result_val = match (&rec_a.value, &rec_b.value) {
        (RegValue::PathSet(items_a), RegValue::PathSet(items_b)) => {
            let map_b: BTreeMap<&str, &PathEntry> =
                items_b.iter().map(|e| (e.path.as_str(), e)).collect();
            let mut out = Vec::new();
            match op {
                SetOp::Union => {
                    let mut merged: BTreeMap<String, PathEntry> = BTreeMap::new();
                    for item in items_a.iter().chain(items_b.iter()) {
                        merged
                            .entry(item.path.clone())
                            .or_insert_with(|| item.clone());
                    }
                    out.extend(merged.into_values());
                }
                SetOp::Intersect => {
                    for item in items_a {
                        if map_b.contains_key(item.path.as_str()) {
                            out.push(item.clone());
                        }
                    }
                }
                SetOp::Diff => {
                    for item in items_a {
                        if !map_b.contains_key(item.path.as_str()) {
                            out.push(item.clone());
                        }
                    }
                }
            }
            RegValue::PathSet(out)
        }
        (RegValue::PathSet(items_a), other_b) => {
            let b_paths: BTreeSet<String> = other_b.extract_paths().into_iter().collect();
            let mut out = Vec::new();
            match op {
                SetOp::Union => {
                    let mut merged: BTreeMap<String, PathEntry> = items_a
                        .iter()
                        .map(|e| (e.path.clone(), e.clone()))
                        .collect();
                    for p in b_paths {
                        merged.entry(p.clone()).or_insert_with(|| {
                            let meta = fs::metadata(&p).ok();
                            let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
                            let size = meta
                                .as_ref()
                                .map(|m| if is_dir { 0 } else { m.len() })
                                .unwrap_or(0);
                            PathEntry {
                                path: p,
                                size,
                                is_dir,
                            }
                        });
                    }
                    out.extend(merged.into_values());
                }
                SetOp::Intersect => {
                    for item in items_a {
                        if b_paths.contains(&item.path) {
                            out.push(item.clone());
                        }
                    }
                }
                SetOp::Diff => {
                    for item in items_a {
                        if !b_paths.contains(&item.path) {
                            out.push(item.clone());
                        }
                    }
                }
            }
            RegValue::PathSet(out)
        }
        (RegValue::MatchSet(matches_a), RegValue::MatchSet(matches_b)) => {
            let b_keys: BTreeSet<(&str, usize)> = matches_b
                .iter()
                .map(|m| (m.path.as_str(), m.line))
                .collect();
            let mut out = Vec::new();
            match op {
                SetOp::Union => {
                    let mut seen = BTreeSet::new();
                    for m in matches_a.iter().chain(matches_b.iter()) {
                        if seen.insert((m.path.clone(), m.line, m.col)) {
                            out.push(m.clone());
                        }
                    }
                    out.sort_by(|a, b| {
                        a.path
                            .cmp(&b.path)
                            .then(a.line.cmp(&b.line))
                            .then(a.col.cmp(&b.col))
                    });
                }
                SetOp::Intersect => {
                    for m in matches_a {
                        if b_keys.contains(&(m.path.as_str(), m.line)) {
                            out.push(m.clone());
                        }
                    }
                }
                SetOp::Diff => {
                    for m in matches_a {
                        if !b_keys.contains(&(m.path.as_str(), m.line)) {
                            out.push(m.clone());
                        }
                    }
                }
            }
            RegValue::MatchSet(out)
        }
        (RegValue::MatchSet(matches_a), other_b) => {
            let b_paths: BTreeSet<String> = other_b.extract_paths().into_iter().collect();
            let out: Vec<SpanMatch> = match op {
                SetOp::Intersect => matches_a
                    .iter()
                    .filter(|m| b_paths.contains(&m.path))
                    .cloned()
                    .collect(),
                SetOp::Diff => matches_a
                    .iter()
                    .filter(|m| !b_paths.contains(&m.path))
                    .cloned()
                    .collect(),
                SetOp::Union => bail!(
                    "UNION requires compatible register types, got {} and {}",
                    rec_a.value.type_name(),
                    rec_b.value.type_name()
                ),
            };
            RegValue::MatchSet(out)
        }
        (other_a, other_b) => bail!(
            "{} is supported on PathSet or MatchSet registers, got {} and {}",
            op.opcode_name(),
            other_a.type_name(),
            other_b.type_name()
        ),
    };

    store.allocate(explicit_id, op.opcode_name(), origin, result_val)
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
            Err(_) => continue,
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

/// `OUTLINE`: Extracts structural symbol declarations (fn, struct, enum, trait, impl, class, def, etc.) into a `MatchSet`.
pub fn op_outline(
    store: &ShmStore,
    explicit_id: Option<u32>,
    target: &str,
) -> Result<RegisterRecord> {
    let re = Regex::new(
        r"^\s*(?:pub(?:\([^)]+\))?\s+)?(?:async\s+)?(?:unsafe\s+)?(?:const\s+)?(?:export\s+)?(fn|struct|enum|trait|impl|mod|type|class|def|interface|func)\b|^(#{1,6})\s+\S+",
    )
    .expect("Valid outline regex");

    let (origin_name, files) = resolve_source_files(store, target)?;
    let mut symbols = Vec::new();

    for file_path in files {
        let content = match fs::read_to_string(&file_path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        for (idx, line_str) in content.lines().enumerate() {
            if let Some(caps) = re.captures(line_str) {
                let kind_match = caps.get(1).or_else(|| caps.get(2)).unwrap();
                symbols.push(SpanMatch {
                    path: file_path.clone(),
                    line: idx + 1,
                    col: kind_match.start() + 1,
                    matched: kind_match.as_str().to_string(),
                    line_text: line_str.trim().to_string(),
                });
            }
        }
    }

    store.allocate(
        explicit_id,
        "OUTLINE",
        origin_name,
        RegValue::MatchSet(symbols),
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
    op_load_with_context(store, explicit_id, target, start_line, end_line, None)
}

/// `LOAD` with optional context window (`--context <N>`) around `MatchSet` entries.
pub fn op_load_with_context(
    store: &ShmStore,
    explicit_id: Option<u32>,
    target: &str,
    start_line: Option<usize>,
    end_line: Option<usize>,
    context: Option<usize>,
) -> Result<RegisterRecord> {
    // If target is a MatchSet and context is requested (and no explicit start/end override),
    // load merged ±context windows around each match!
    if let Some(ctx) = context {
        if start_line.is_none() && end_line.is_none() && RegRef::looks_like_reg(target) {
            let reg_ref = RegRef::parse(target)?;
            let rec = store.resolve(&reg_ref)?;
            if let RegValue::MatchSet(matches) = &rec.value {
                let mut per_file_lines: BTreeMap<String, Vec<usize>> = BTreeMap::new();
                for m in matches {
                    per_file_lines
                        .entry(m.path.clone())
                        .or_default()
                        .push(m.line);
                }

                let mut slices = Vec::new();
                for (file_path, mut match_lines) in per_file_lines {
                    let raw = fs::read_to_string(&file_path).with_context(|| {
                        format!("LOAD failed to read '{file_path}' as UTF-8 text")
                    })?;
                    let lines: Vec<&str> = raw.lines().collect();
                    let total = lines.len();
                    if total == 0 {
                        continue;
                    }

                    match_lines.sort_unstable();
                    match_lines.dedup();

                    // Build and merge overlapping or adjacent [start..=end] windows
                    let mut windows: Vec<(usize, usize)> = Vec::new();
                    for line_no in match_lines {
                        let w_start = line_no.saturating_sub(ctx).max(1).min(total);
                        let w_end = (line_no + ctx).min(total).max(w_start);
                        if let Some(last) = windows.last_mut() {
                            if w_start <= last.1 + 1 {
                                last.1 = last.1.max(w_end);
                                continue;
                            }
                        }
                        windows.push((w_start, w_end));
                    }

                    for (w_start, w_end) in windows {
                        let content = lines[w_start - 1..w_end].join("\n");
                        slices.push(FileSlice {
                            path: file_path.clone(),
                            start_line: w_start,
                            end_line: w_end,
                            content,
                        });
                    }
                }

                return store.allocate(
                    explicit_id,
                    "LOAD",
                    format!("{} (context: ±{ctx})", rec.name),
                    RegValue::TextBuf(slices),
                );
            }
        }
    }

    let (origin_name, files) = resolve_source_files(store, target)?;
    let mut slices = Vec::new();

    for file_path in files {
        let raw = fs::read_to_string(&file_path)
            .with_context(|| format!("LOAD failed to read '{file_path}' as UTF-8 text"))?;
        let lines: Vec<&str> = raw.lines().collect();
        let total = lines.len();
        let (start, end) = match (start_line, end_line, context) {
            (Some(center), None, Some(ctx)) => (
                center.saturating_sub(ctx).max(1),
                (center + ctx).min(total),
            ),
            (s, e, _) => (s.unwrap_or(1).max(1), e.unwrap_or(total).min(total)),
        };

        let (selected_content, actual_start, actual_end) =
            if total == 0 || start > end || start > total {
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
            patches.push(FilePatch::new(file_path, count, original, modified));
        }
    }

    store.allocate(
        explicit_id,
        "SUB",
        format!("{origin_name} ({pattern} -> {replacement})"),
        RegValue::DiffSet(patches),
    )
}

/// `PATCH`: Pure SSA line-range surgical replacement producing a `DiffSet` register without mutating disk.
pub fn op_patch(
    store: &ShmStore,
    explicit_id: Option<u32>,
    target: &str,
    start_line: usize,
    end_line: usize,
    replacement: &str,
) -> Result<RegisterRecord> {
    if start_line == 0 || end_line < start_line {
        bail!(
            "Invalid PATCH line range {start_line}..={end_line} (lines are 1-based and start <= end)"
        );
    }

    let (origin_name, files) = resolve_source_files(store, target)?;
    let mut patches = Vec::new();

    for file_path in files {
        let original = fs::read_to_string(&file_path)
            .with_context(|| format!("PATCH failed to read '{file_path}'"))?;
        let had_trailing_newline = original.ends_with('\n');
        let lines: Vec<&str> = original.lines().collect();
        if start_line > lines.len() || end_line > lines.len() {
            bail!(
                "PATCH line range {start_line}..={end_line} out of bounds for '{file_path}' ({} lines)",
                lines.len()
            );
        }

        let mut new_lines: Vec<&str> = Vec::new();
        new_lines.extend_from_slice(&lines[..start_line - 1]);
        if !replacement.is_empty() {
            new_lines.extend(replacement.lines());
        }
        new_lines.extend_from_slice(&lines[end_line..]);

        let mut modified = new_lines.join("\n");
        if had_trailing_newline && !modified.ends_with('\n') {
            modified.push('\n');
        }

        if modified != original {
            patches.push(FilePatch::new(file_path, 1, original, modified));
        }
    }

    store.allocate(
        explicit_id,
        "PATCH",
        format!("{origin_name} (lines {start_line}..={end_line})"),
        RegValue::DiffSet(patches),
    )
}

/// `COMMIT`: Verifies CAS base hashes on disk, then atomically writes all staged patches in a `DiffSet` register.
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

    // Phase 1: Pre-flight Compare-And-Swap (CAS) verification across all target files
    for patch in &patches {
        let current_bytes = fs::read(&patch.path).with_context(|| {
            format!(
                "CAS_CONFLICT: failed to read '{}' before COMMIT",
                patch.path
            )
        })?;
        let current_hash = fnv1a_64(&current_bytes);
        if current_hash != patch.base_hash {
            bail!(
                "CAS_CONFLICT: file '{}' was modified on disk since {} was staged (expected hash {:016x}, found {:016x})",
                patch.path,
                rec.name,
                patch.base_hash,
                current_hash
            );
        }
    }

    // Phase 2: Atomic write-and-rename
    let mut committed_paths = Vec::with_capacity(patches.len());
    for patch in &patches {
        write_file_atomic_preserving_perms(
            Path::new(&patch.path),
            patch.modified.as_bytes(),
            "axon-commit",
        )?;
        committed_paths.push(patch.path.clone());
    }

    store.allocate(
        explicit_id,
        "COMMIT",
        rec.name,
        RegValue::Tombstone(committed_paths),
    )
}

/// `UNDO`: Atomically rolls back a `COMMIT` register (or its source `DiffSet` register) using the SSA snapshot in `/dev/shm`.
pub fn op_undo(
    store: &ShmStore,
    explicit_id: Option<u32>,
    target_reg: &str,
    force: bool,
) -> Result<RegisterRecord> {
    let reg_ref = RegRef::parse(target_reg)?;
    let rec = store.resolve(&reg_ref)?;

    // Resolve the underlying DiffSet whether the user passed the COMMIT register or the DiffSet register directly
    let (diff_name, patches) = match rec.value {
        RegValue::DiffSet(p) => (rec.name, p),
        RegValue::Tombstone(_) if rec.opcode == "COMMIT" => {
            let origin_ref = RegRef::parse(&rec.origin).with_context(|| {
                format!(
                    "Cannot resolve origin DiffSet '{}' for COMMIT register {}",
                    rec.origin, rec.name
                )
            })?;
            let origin_rec = store.resolve(&origin_ref)?;
            match origin_rec.value {
                RegValue::DiffSet(p) => (format!("{} -> {}", rec.name, origin_rec.name), p),
                other => bail!(
                    "Origin register {} is {}, expected DiffSet",
                    origin_rec.name,
                    other.type_name()
                ),
            }
        }
        other => bail!(
            "UNDO requires a COMMIT or DiffSet register, but {} is {} (op: {})",
            rec.name,
            other.type_name(),
            rec.opcode
        ),
    };

    if !force {
        for patch in &patches {
            let current_bytes = fs::read(&patch.path).with_context(|| {
                format!("CAS_CONFLICT: failed to read '{}' before UNDO", patch.path)
            })?;
            let current_hash = fnv1a_64(&current_bytes);
            if current_hash != patch.modified_hash {
                bail!(
                    "CAS_CONFLICT: file '{}' was modified after COMMIT (expected hash {:016x}, found {:016x}); pass --force to override",
                    patch.path,
                    patch.modified_hash,
                    current_hash
                );
            }
        }
    }

    let mut restored_paths = Vec::with_capacity(patches.len());
    for patch in &patches {
        write_file_atomic_preserving_perms(
            Path::new(&patch.path),
            patch.original.as_bytes(),
            "axon-undo",
        )?;
        restored_paths.push(patch.path.clone());
    }

    store.allocate(
        explicit_id,
        "UNDO",
        diff_name,
        RegValue::Tombstone(restored_paths),
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
