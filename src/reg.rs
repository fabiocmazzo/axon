use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

/// Parsed reference to a register in the SSA register file, optionally with an item index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegRef {
    /// Refers to a specific register number, e.g. `r0` or `@r0`, with optional `[index]`.
    Id { id: u32, index: Option<usize> },
    /// Refers to the most recently allocated register (`@last` or `last`), with optional `[index]`.
    Last { index: Option<usize> },
}

impl RegRef {
    /// Parse a register reference such as `r0`, `@r0`, `@last`, `r2[1]`, or `@last[0]`.
    pub fn parse(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            bail!("Empty register reference");
        }

        let (base, index) = if let Some(open_idx) = trimmed.find('[') {
            if !trimmed.ends_with(']') {
                bail!("Malformed register index syntax in '{trimmed}'");
            }
            let idx_str = &trimmed[open_idx + 1..trimmed.len() - 1];
            let parsed_idx: usize = idx_str
                .parse()
                .map_err(|_| anyhow!("Invalid register element index '{idx_str}' in '{trimmed}'"))?;
            (&trimmed[..open_idx], Some(parsed_idx))
        } else {
            (trimmed, None)
        };

        let normalized = base.strip_prefix('@').unwrap_or(base);
        if normalized.eq_ignore_ascii_case("last") {
            return Ok(RegRef::Last { index });
        }

        if let Some(num_str) = normalized
            .strip_prefix('r')
            .or_else(|| normalized.strip_prefix('R'))
        {
            if !num_str.is_empty() && num_str.chars().all(|c| c.is_ascii_digit()) {
                let id: u32 = num_str
                    .parse()
                    .map_err(|_| anyhow!("Invalid register number in '{trimmed}'"))?;
                return Ok(RegRef::Id { id, index });
            }
        }

        bail!("Invalid register reference '{trimmed}' (expected e.g. r0, @r0, @last, or r0[0])")
    }

    /// Returns true if the string looks like a valid register reference rather than a filesystem path.
    pub fn looks_like_reg(input: &str) -> bool {
        let trimmed = input.trim();
        if trimmed.starts_with('@') {
            return Self::parse(trimmed).is_ok();
        }
        // Only treat unprefixed `r<digits>` (or `r<digits>[idx]`) as a register reference
        // if it parses cleanly and does not exist as a literal path on disk.
        if (trimmed.starts_with('r') || trimmed.starts_with('R') || trimmed.eq_ignore_ascii_case("last"))
            && Self::parse(trimmed).is_ok()
        {
            return !std::path::Path::new(trimmed).exists();
        }
        false
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PathEntry {
    pub path: String,
    pub size: u64,
    pub is_dir: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpanMatch {
    pub path: String,
    pub line: usize,
    pub col: usize,
    pub matched: String,
    pub line_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileSlice {
    pub path: String,
    pub start_line: usize,
    pub end_line: usize,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FilePatch {
    pub path: String,
    pub replacements: usize,
    pub original: String,
    pub modified: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CmdReceipt {
    pub command: String,
    pub target: Option<String>,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RegValue {
    PathSet(Vec<PathEntry>),
    MatchSet(Vec<SpanMatch>),
    TextBuf(Vec<FileSlice>),
    DiffSet(Vec<FilePatch>),
    ExecResult(Vec<CmdReceipt>),
    Tombstone(Vec<String>),
}

impl RegValue {
    pub fn type_name(&self) -> &'static str {
        match self {
            RegValue::PathSet(_) => "PathSet",
            RegValue::MatchSet(_) => "MatchSet",
            RegValue::TextBuf(_) => "TextBuf",
            RegValue::DiffSet(_) => "DiffSet",
            RegValue::ExecResult(_) => "ExecResult",
            RegValue::Tombstone(_) => "Tombstone",
        }
    }

    pub fn len(&self) -> usize {
        match self {
            RegValue::PathSet(v) => v.len(),
            RegValue::MatchSet(v) => v.len(),
            RegValue::TextBuf(v) => v.len(),
            RegValue::DiffSet(v) => v.len(),
            RegValue::ExecResult(v) => v.len(),
            RegValue::Tombstone(v) => v.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Project a single element by index as a single-element `RegValue` of the same variant.
    pub fn slice_index(&self, index: usize) -> Result<RegValue> {
        let len = self.len();
        if index >= len {
            bail!(
                "Index [{index}] out of bounds for {} with {len} item(s)",
                self.type_name()
            );
        }
        Ok(match self {
            RegValue::PathSet(v) => RegValue::PathSet(vec![v[index].clone()]),
            RegValue::MatchSet(v) => RegValue::MatchSet(vec![v[index].clone()]),
            RegValue::TextBuf(v) => RegValue::TextBuf(vec![v[index].clone()]),
            RegValue::DiffSet(v) => RegValue::DiffSet(vec![v[index].clone()]),
            RegValue::ExecResult(v) => RegValue::ExecResult(vec![v[index].clone()]),
            RegValue::Tombstone(v) => RegValue::Tombstone(vec![v[index].clone()]),
        })
    }

    /// Extract deduplicated, deterministically ordered file paths referenced by this register.
    pub fn extract_paths(&self) -> Vec<String> {
        let mut set = BTreeSet::new();
        match self {
            RegValue::PathSet(entries) => {
                for e in entries {
                    if !e.is_dir {
                        set.insert(e.path.clone());
                    }
                }
            }
            RegValue::MatchSet(matches) => {
                for m in matches {
                    set.insert(m.path.clone());
                }
            }
            RegValue::TextBuf(slices) => {
                for s in slices {
                    set.insert(s.path.clone());
                }
            }
            RegValue::DiffSet(patches) => {
                for p in patches {
                    set.insert(p.path.clone());
                }
            }
            RegValue::ExecResult(receipts) => {
                for r in receipts {
                    if let Some(t) = &r.target {
                        set.insert(t.clone());
                    }
                }
            }
            RegValue::Tombstone(paths) => {
                for p in paths {
                    set.insert(p.clone());
                }
            }
        }
        set.into_iter().collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterRecord {
    pub id: u32,
    pub name: String,
    pub opcode: String,
    pub origin: String,
    pub created_unix_ms: u64,
    pub value: RegValue,
}

impl RegisterRecord {
    pub fn summary_line(&self) -> String {
        format!(
            "{} = {}({} items) [op: {}, origin: {}]",
            self.name,
            self.value.type_name(),
            self.value.len(),
            self.opcode,
            self.origin
        )
    }

    pub fn format_inspect(&self, limit: Option<usize>) -> String {
        let mut out = String::new();
        out.push_str(&self.summary_line());
        out.push('\n');
        let max_items = limit.unwrap_or(usize::MAX);

        match &self.value {
            RegValue::PathSet(items) => {
                for (i, item) in items.iter().take(max_items).enumerate() {
                    let kind = if item.is_dir { "dir " } else { "file" };
                    out.push_str(&format!(
                        "  [{i}] {kind} ({:>8} B) {}\n",
                        item.size, item.path
                    ));
                }
            }
            RegValue::MatchSet(items) => {
                for (i, m) in items.iter().take(max_items).enumerate() {
                    out.push_str(&format!(
                        "  [{i}] {}:{}:{}: {} (matched {:?})\n",
                        m.path,
                        m.line,
                        m.col,
                        m.line_text.trim_end(),
                        m.matched
                    ));
                }
            }
            RegValue::TextBuf(items) => {
                for (i, slice) in items.iter().take(max_items).enumerate() {
                    out.push_str(&format!(
                        "  [{i}] {} (lines {}..={}):\n",
                        slice.path, slice.start_line, slice.end_line
                    ));
                    for line in slice.content.lines() {
                        out.push_str(&format!("      | {line}\n"));
                    }
                }
            }
            RegValue::DiffSet(items) => {
                for (i, patch) in items.iter().take(max_items).enumerate() {
                    out.push_str(&format!(
                        "  [{i}] {} ({} replacement(s))\n",
                        patch.path, patch.replacements
                    ));
                }
            }
            RegValue::ExecResult(items) => {
                for (i, rec) in items.iter().take(max_items).enumerate() {
                    out.push_str(&format!(
                        "  [{i}] cmd={:?} exit={} stdout={:?} stderr={:?}\n",
                        rec.command,
                        rec.exit_code,
                        rec.stdout.trim_end(),
                        rec.stderr.trim_end()
                    ));
                }
            }
            RegValue::Tombstone(items) => {
                for (i, path) in items.iter().take(max_items).enumerate() {
                    out.push_str(&format!("  [{i}] {path}\n"));
                }
            }
        }

        if self.value.len() > max_items {
            out.push_str(&format!(
                "  ... ({} more item(s) omitted)\n",
                self.value.len() - max_items
            ));
        }

        out
    }
}

impl fmt::Display for RegisterRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary_line())
    }
}
