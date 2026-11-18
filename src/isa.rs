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
fn write_file_atomic_preserving_perms(
    target_path: &Path,
    content: &[u8],
    tag: &str,
) -> Result<()> {
    let pid = unsafe { libc::getpid() };
    let parent = target_path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.as_os_str().is_empty() && !parent.exists() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "Failed to create parent directory {} for {}",
                parent.display(),
                target_path.display()
            )
        })?;
    }
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

/// `DIRTY`: Queries `git status --porcelain -uall` to allocate a `PathSet` of modified/untracked working-tree files.
pub fn op_dirty(
    store: &ShmStore,
    explicit_id: Option<u32>,
    root: &Path,
) -> Result<RegisterRecord> {
    if !root.exists() {
        bail!("DIRTY root '{}' does not exist", root.display());
    }

    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["status", "--porcelain", "-uall"])
        .output()
        .context("DIRTY failed to execute 'git status --porcelain'")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("DIRTY git status failed: {}", stderr.trim());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut entries = Vec::new();

    for line in stdout.lines() {
        if line.len() < 4 {
            continue;
        }
        let raw_path = line[3..].trim();
        let effective_rel = if let Some((_, renamed_to)) = raw_path.split_once(" -> ") {
            renamed_to.trim().trim_matches('"')
        } else {
            raw_path.trim_matches('"')
        };

        let joined = if root == Path::new(".") {
            PathBuf::from(effective_rel)
        } else {
            root.join(effective_rel)
        };

        if let Ok(meta) = fs::metadata(&joined) {
            if meta.is_file() {
                entries.push(PathEntry {
                    path: normalize_display_path(&joined),
                    size: meta.len(),
                    is_dir: false,
                });
            }
        }
    }

    entries.sort_by(|a, b| a.path.cmp(&b.path));
    entries.dedup_by(|a, b| a.path == b.path);

    store.allocate(
        explicit_id,
        "DIRTY",
        normalize_display_path(root),
        RegValue::PathSet(entries),
    )
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

/// `SLICE`: Deterministic pagination of any register (`[start..end)`) into a new SSA register.
pub fn op_slice(
    store: &ShmStore,
    explicit_id: Option<u32>,
    source_reg: &str,
    start: usize,
    end: usize,
) -> Result<RegisterRecord> {
    let reg_ref = RegRef::parse(source_reg)?;
    let src = store.resolve(&reg_ref)?;
    let sliced = src.value.slice_range(start, end)?;
    store.allocate(
        explicit_id,
        "SLICE",
        format!("{}[{start}..{end}]", src.name),
        sliced,
    )
}

/// Compose two `FilePatch` structs targeting the exact same file path.
fn compose_same_file_patches(a: &FilePatch, b: &FilePatch) -> Result<FilePatch> {
    // Case 1: b was staged directly on top of a's output
    if b.base_hash == a.modified_hash && !b.created_new {
        return Ok(FilePatch {
            path: a.path.clone(),
            replacements: a.replacements + b.replacements,
            base_hash: a.base_hash,
            modified_hash: b.modified_hash,
            original: a.original.clone(),
            modified: b.modified.clone(),
            created_new: a.created_new,
        });
    }

    // Case 2: Both a and b were staged independently against the same base file on disk
    if !a.created_new && !b.created_new && a.base_hash == b.base_hash && a.original == b.original {
        // Isolate the changed span in b relative to original
        let orig_bytes = b.original.as_bytes();
        let mod_b_bytes = b.modified.as_bytes();
        let mut prefix = 0;
        while prefix < orig_bytes.len()
            && prefix < mod_b_bytes.len()
            && orig_bytes[prefix] == mod_b_bytes[prefix]
        {
            prefix += 1;
        }
        let mut orig_end = orig_bytes.len();
        let mut mod_b_end = mod_b_bytes.len();
        while orig_end > prefix
            && mod_b_end > prefix
            && orig_bytes[orig_end - 1] == mod_b_bytes[mod_b_end - 1]
        {
            orig_end -= 1;
            mod_b_end -= 1;
        }

        // Expand to line boundaries so anchor matching inside a.modified is context-safe
        let line_start = b.original[..prefix]
            .rfind('\n')
            .map(|idx| idx + 1)
            .unwrap_or(0);
        let orig_line_end = b.original[orig_end..]
            .find('\n')
            .map(|idx| orig_end + idx + 1)
            .unwrap_or(b.original.len());
        let delta_len = b.modified.len() as isize - b.original.len() as isize;
        let mod_b_line_end = ((orig_line_end as isize) + delta_len) as usize;

        if line_start <= orig_line_end && line_start <= mod_b_line_end && mod_b_line_end <= b.modified.len() {
            let old_span = &b.original[line_start..orig_line_end];
            let new_span = &b.modified[line_start..mod_b_line_end];
            if !old_span.is_empty() && a.modified.matches(old_span).count() == 1 {
                let composed_mod = a.modified.replacen(old_span, new_span, 1);
                return Ok(FilePatch::new(
                    a.path.clone(),
                    a.replacements + b.replacements,
                    a.original.clone(),
                    composed_mod,
                ));
            }
        }
    }

    bail!(
        "DIFF_MERGE_CONFLICT: cannot compose overlapping or incompatible patches for file '{}'",
        a.path
    )
}

/// `UNION` / `INTERSECT` / `DIFF`: SSA register set algebra (including `DiffSet` composition on `UNION`).
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
        (RegValue::DiffSet(patches_a), RegValue::DiffSet(patches_b)) => {
            match op {
                SetOp::Union => {
                    let mut merged: BTreeMap<String, FilePatch> = BTreeMap::new();
                    for p in patches_a {
                        merged.insert(p.path.clone(), p.clone());
                    }
                    for p in patches_b {
                        if let Some(existing) = merged.get(&p.path) {
                            let composed = compose_same_file_patches(existing, p)?;
                            merged.insert(p.path.clone(), composed);
                        } else {
                            merged.insert(p.path.clone(), p.clone());
                        }
                    }
                    RegValue::DiffSet(merged.into_values().collect())
                }
                SetOp::Diff => {
                    let b_paths: BTreeSet<&str> =
                        patches_b.iter().map(|p| p.path.as_str()).collect();
                    let kept = patches_a
                        .iter()
                        .filter(|p| !b_paths.contains(p.path.as_str()))
                        .cloned()
                        .collect();
                    RegValue::DiffSet(kept)
                }
                SetOp::Intersect => {
                    let b_paths: BTreeSet<&str> =
                        patches_b.iter().map(|p| p.path.as_str()).collect();
                    let kept = patches_a
                        .iter()
                        .filter(|p| b_paths.contains(p.path.as_str()))
                        .cloned()
                        .collect();
                    RegValue::DiffSet(kept)
                }
            }
        }
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
            "{} is supported on PathSet, MatchSet, or DiffSet registers, got {} and {}",
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

/// `EDIT`: Unique-anchor exact block replacement producing a `DiffSet` register.
/// Fails with `ANCHOR_NOT_FOUND` if `<old_block>` is absent, or `AMBIGUOUS_ANCHOR` (with line numbers)
/// if `<old_block>` appears more than once in a target file.
pub fn op_edit(
    store: &ShmStore,
    explicit_id: Option<u32>,
    target: &str,
    old_block: &str,
    new_block: &str,
) -> Result<RegisterRecord> {
    if old_block.is_empty() {
        bail!("EDIT old_block anchor cannot be empty");
    }

    let (origin_name, files) = resolve_source_files(store, target)?;
    let mut patches = Vec::new();

    for file_path in &files {
        let original = match fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let match_offsets: Vec<usize> = original
            .match_indices(old_block)
            .map(|(idx, _)| idx)
            .collect();

        if match_offsets.is_empty() {
            continue;
        }

        if match_offsets.len() > 1 {
            let line_numbers: Vec<usize> = match_offsets
                .iter()
                .map(|&byte_idx| original[..byte_idx].bytes().filter(|&b| b == b'\n').count() + 1)
                .collect();
            bail!(
                "AMBIGUOUS_ANCHOR: anchor matched {} times in '{}' at lines {:?}; include more surrounding lines to make it unique",
                match_offsets.len(),
                file_path,
                line_numbers
            );
        }

        let modified = original.replacen(old_block, new_block, 1);
        if modified != original {
            patches.push(FilePatch::new(file_path.clone(), 1, original, modified));
        }
    }

    if patches.is_empty() {
        bail!(
            "ANCHOR_NOT_FOUND: exact anchor block was not found in {}",
            origin_name
        );
    }

    store.allocate(
        explicit_id,
        "EDIT",
        origin_name,
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

/// `WRITE`: Pure SSA staging of a new file creation (or full file replacement) into a `DiffSet` register.
pub fn op_write(
    store: &ShmStore,
    explicit_id: Option<u32>,
    target_path: &str,
    content: &str,
) -> Result<RegisterRecord> {
    let norm_path = normalize_display_path(Path::new(target_path));
    let mut normalized_content = content.to_string();
    if !normalized_content.is_empty() && !normalized_content.ends_with('\n') {
        normalized_content.push('\n');
    }

    let patch = if Path::new(&norm_path).exists() {
        let original = fs::read_to_string(&norm_path)
            .with_context(|| format!("WRITE failed to read existing file '{norm_path}'"))?;
        FilePatch::new(norm_path.clone(), 1, original, normalized_content)
    } else {
        FilePatch::new_created(norm_path.clone(), normalized_content)
    };

    store.allocate(
        explicit_id,
        "WRITE",
        norm_path,
        RegValue::DiffSet(vec![patch]),
    )
}

fn verify_cas_and_apply_patches(diff_name: &str, patches: &[FilePatch]) -> Result<Vec<String>> {
    for patch in patches {
        let p = Path::new(&patch.path);
        if patch.created_new {
            if p.exists() {
                bail!(
                    "CAS_CONFLICT: file '{}' already exists on disk, but {} staged it as a newly created file",
                    patch.path,
                    diff_name
                );
            }
        } else {
            let current_bytes = fs::read(p).with_context(|| {
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
                    diff_name,
                    patch.base_hash,
                    current_hash
                );
            }
        }
    }

    let mut committed_paths = Vec::with_capacity(patches.len());
    for patch in patches {
        write_file_atomic_preserving_perms(
            Path::new(&patch.path),
            patch.modified.as_bytes(),
            "axon-commit",
        )?;
        committed_paths.push(patch.path.clone());
    }
    Ok(committed_paths)
}

fn revert_patches_to_disk(patches: &[FilePatch], force: bool) -> Result<Vec<String>> {
    if !force {
        for patch in patches {
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
    for patch in patches {
        let p = Path::new(&patch.path);
        if patch.created_new {
            if p.exists() {
                fs::remove_file(p).with_context(|| {
                    format!("UNDO failed to remove created file '{}'", patch.path)
                })?;
            }
        } else {
            write_file_atomic_preserving_perms(p, patch.original.as_bytes(), "axon-undo")?;
        }
        restored_paths.push(patch.path.clone());
    }
    Ok(restored_paths)
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

    let committed_paths = verify_cas_and_apply_patches(&rec.name, &patches)?;

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

    let restored_paths = revert_patches_to_disk(&patches, force)?;

    store.allocate(
        explicit_id,
        "UNDO",
        diff_name,
        RegValue::Tombstone(restored_paths),
    )
}

/// `VERIFY`: Transactional `COMMIT -> Run Verification Command -> Auto-UNDO on Non-Zero Exit`.
pub fn op_verify(
    store: &ShmStore,
    explicit_id: Option<u32>,
    diff_reg: &str,
    cmd_parts: &[String],
) -> Result<RegisterRecord> {
    if cmd_parts.is_empty() {
        bail!("VERIFY requires a verification command (e.g. VERIFY r2 cargo check)");
    }

    let reg_ref = RegRef::parse(diff_reg)?;
    let rec = store.resolve(&reg_ref)?;
    let patches = match rec.value {
        RegValue::DiffSet(p) => p,
        other => bail!(
            "VERIFY requires a DiffSet register, but {} is {}",
            rec.name,
            other.type_name()
        ),
    };

    let _committed = verify_cas_and_apply_patches(&rec.name, &patches)?;

    let prog = &cmd_parts[0];
    let args = &cmd_parts[1..];
    let cmd_str = cmd_parts.join(" ");

    match Command::new(prog).args(args).output() {
        Ok(output) => {
            let exit_code = output.status.code().unwrap_or(-1);
            let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

            if exit_code == 0 {
                let receipt = CmdReceipt {
                    command: cmd_str.clone(),
                    target: Some(format!("{} (committed: true)", rec.name)),
                    exit_code,
                    stdout,
                    stderr,
                };
                store.allocate(
                    explicit_id,
                    "VERIFY_OK",
                    format!("{} ({cmd_str})", rec.name),
                    RegValue::ExecResult(vec![receipt]),
                )
            } else {
                let _ = revert_patches_to_disk(&patches, true);
                let receipt = CmdReceipt {
                    command: cmd_str.clone(),
                    target: Some(format!("{} (rolled_back: true)", rec.name)),
                    exit_code,
                    stdout,
                    stderr,
                };
                store.allocate(
                    explicit_id,
                    "VERIFY_ROLLBACK",
                    format!("{} ({cmd_str})", rec.name),
                    RegValue::ExecResult(vec![receipt]),
                )
            }
        }
        Err(spawn_err) => {
            let _ = revert_patches_to_disk(&patches, true);
            Err(spawn_err).with_context(|| {
                format!(
                    "VERIFY failed to spawn '{prog}' (changes from {} were rolled back)",
                    rec.name
                )
            })
        }
    }
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

/// `SCHEMA`: Returns a compact, token-efficient EBNF ISA specification ready for LLM / Tiny-LM system prompts.
pub fn schema_spec() -> String {
    r#"# AXON (`ax`) — Shared-Memory SSA Register VM & Agent ISA
program ::= stmt (";" | "\n" stmt)*
stmt    ::= (reg "=")? op
reg     ::= "r" DIGIT+ | "@r" DIGIT+ | "@last" | reg "[" DIGIT+ "]"

## Register Types (/dev/shm/axon-<uid>)
- PathSet    : Deterministic sorted file paths + byte sizes
- MatchSet   : File/line/col regex or symbol matches
- TextBuf    : Line-numbered file slices or merged ±N context windows
- DiffSet    : Staged in-memory patches with 64-bit FNV-1a CAS hashes & Unified Diff
- ExecResult : Structured command receipts (exit_code, stdout, stderr)
- Tombstone  : Audit receipt of COMMIT, UNDO, or PURGE paths

## Orthogonal Opcodes (`ax run "<program>"` or `ax <subcommand>`)
- SCAN [path] [glob] [--max-depth N] [--hidden]      -> PathSet
- DIRTY [path]                                       -> PathSet (git modified/untracked)
- FILTER <reg> [--glob G] [--regex R] [--max-size B] -> PathSet | MatchSet
- SLICE <reg> <start> <end>                          -> Same type [start..end)
- UNION | INTERSECT | DIFF <regA> <regB>             -> PathSet | MatchSet | DiffSet
- MATCH <reg|path> <pattern> [--fixed]               -> MatchSet
- OUTLINE [reg|path]                                 -> MatchSet (fn/struct/enum/impl/def)
- LOAD <reg|path> [-s A] [-e B] [--context N]        -> TextBuf
- EDIT <reg|path> <old_unique_block> <new_block>     -> DiffSet (exact unique anchor)
- PATCH <reg|path> -s <A> -e <B> -w <replacement>    -> DiffSet (1-based lines A..=B)
- SUB <reg|path> <pattern> <replacement> [--fixed]   -> DiffSet
- WRITE <file_path> <content>                        -> DiffSet (create/overwrite)
- COMMIT <diff_reg>                                  -> Tombstone (CAS-checked atomic write)
- VERIFY <diff_reg> <cmd> [args...]                  -> ExecResult (COMMIT + test + auto-UNDO on fail)
- UNDO [commit_or_diff_reg] [--force]                -> Tombstone (atomic rollback)
- PURGE <pathset_reg> [--force]                      -> Tombstone
- XEXEC <reg> <cmd> [args...]                        -> ExecResult
- INSPECT [reg] [--limit N] [--max-chars M]          -> Formatted payload
- REGS | STATS | TRACE | GC [keep_N] | RESET         -> Control & telemetry
"#
    .trim()
    .to_string()
}

/// `TRACE`: Reconstructs the chronological SSA lineage graph of registers in `/dev/shm`.
pub fn trace_lineage(store: &ShmStore) -> Result<String> {
    let entries = store.list()?;
    if entries.is_empty() {
        return Ok(format!(
            "No SSA lineage in {} (0 registers)",
            store.root().display()
        ));
    }

    let mut out = String::new();
    out.push_str(&format!(
        "# Axon SSA Lineage Trace ({})\n",
        store.root().display()
    ));
    for e in entries {
        out.push_str(&format!(
            "{:<4} <- {:<15} {:<10} ({:>3} items) | origin: {}\n",
            e.name, e.opcode, e.reg_type, e.items, e.origin
        ));
    }
    Ok(out)
}
