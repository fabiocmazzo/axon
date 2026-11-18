# SYSTEM SPECIFICATION: `axon` (Binary: `ax`) — Agent Execution Axon & Register VM

## 1. Context & Objective
You are a Senior Systems Architect and Rust Engineer. Your task is to build `axon` (compiled binary name: `ax`), a high-performance, deterministic command-line utility and Register-based Virtual Machine in Rust. 

`axon` acts as the deterministic motor pathway between human terminal usage / Tiny Language Models (15M-50M params) and the operating system. It replaces irregular POSIX pipelines (`find`, `grep`, `sed`, `cat`, `rm`, `xargs`) with an orthogonal Instruction Set Architecture (ISA) backed by a persistent Static Single Assignment (SSA) register file stored in shared memory (`/dev/shm`).

Build a complete, compiling, warning-free, and fully tested Rust project implementing the MVP.

---

## 2. Technical Stack & `Cargo.toml`
Initialize a Rust package named `axon` that outputs the binary `ax` (Edition 2021 or 2024). Use strictly synchronous, ultra-fast Rust (no `tokio` runtime overhead needed for local filesystem/register operations):

```toml
[package]
name = "axon"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "ax"
path = "src/main.rs"

[dependencies]
clap = { version = "4.5", features = ["derive"] }
serde = { version = "1.0", features = ["derive"] }
bincode = "1.3"
serde_json = "1.0"
ignore = "0.4"
globset = "0.4"
regex = "1.11"
anyhow = "1.0"
libc = "0.2"

[dev-dependencies]
tempfile = "3.13"
```

---

## 3. Shared-Memory SSA Register File (`/dev/shm`)

- **Default Store Path**: `/dev/shm/axon-<uid>` (falling back to `$TMPDIR/axon-<uid>` if `/dev/shm` is unavailable, and configurable via `AXON_SHM_DIR` or `--shm-dir` for isolated namespaces/tests).
- **Static Single Assignment (SSA) Invariant**:
  - Registers are named `r0`, `r1`, `r2`, ... (accepting `r0` or `@r0`, plus `@last` as an alias for the highest allocated register).
  - Once a register `rN` is allocated and committed to shared memory, it is **immutable**. Attempting to overwrite an existing register in VM assembly returns an `SSA_VIOLATION` error.
  - Each register stores metadata (`id`, `opcode`, `origin`, `created_unix_ms`) and a strongly typed `RegValue`:
    - `PathSet(Vec<PathEntry>)` — deterministic, lexicographically sorted file/directory records.
    - `MatchSet(Vec<SpanMatch>)` — line/column regex, literal, or structural symbol matches across files.
    - `TextBuf(Vec<FileSlice>)` — loaded file contents, line ranges, or merged `±N` context windows around matches.
    - `DiffSet(Vec<FilePatch>)` — pure in-memory staged text substitutions or line-range patches with FNV-1a 64-bit CAS hashes (`base_hash`, `modified_hash`) and Unified Diff inspection.
    - `ExecResult(Vec<CmdReceipt>)` — structured execution output (command, exit code, stdout, stderr).
    - `Tombstone(Vec<String>)` — audit receipt of committed, undone, or purged filesystem paths.

---

## 4. Orthogonal Instruction Set Architecture (ISA)

1. **`scan`** (replaces `find`):
   - `ax scan [PATH] [--glob <GLOB>] [--max-depth <N>] [--hidden]`
2. **`filter`** (subset selection on `PathSet` or `MatchSet`):
   - `ax filter <REG> [--glob <GLOB>] [--regex <PATTERN>] [--min-size <BYTES>] [--max-size <BYTES>]`
3. **`union` / `intersect` / `diff`** (SSA register set algebra):
   - `ax union <REG_A> <REG_B>`, `ax intersect <REG_A> <REG_B>`, `ax diff <REG_A> <REG_B>`
4. **`match`** (replaces `grep` / `rg`):
   - `ax match <REG_OR_PATH> <PATTERN> [--fixed]`
5. **`outline`** (structural symbol extraction):
   - `ax outline [REG_OR_PATH]`
6. **`load`** (replaces `cat` / `head` / `tail` + merged context windows around `MatchSet`):
   - `ax load <REG_OR_PATH> [--start-line <N>] [--end-line <M>] [--context <K>]`
7. **`sub` & `patch`** (replaces `sed` — pure SSA staging with FNV-1a CAS hashes & Unified Diffs):
   - `ax sub <REG_OR_PATH> <PATTERN> <REPLACEMENT> [--fixed]`
   - `ax patch <REG_OR_PATH> --start-line <A> [--end-line <B>] --with <TEXT>`
8. **`commit` & `undo`** (CAS-verified atomic disk write & instant rollback from `/dev/shm`):
   - `ax commit <DIFF_REG>`
   - `ax undo [COMMIT_OR_DIFF_REG] [--force]`
9. **`purge`** (replaces `rm` / `find -delete`):
   - `ax purge <PATHSET_REG> [--force]`
10. **`xexec`** (replaces `xargs`):
    - `ax xexec <REG> <CMD> [ARGS...]`
11. **`run`** (Batch Register VM execution):
    - `ax run <SCRIPT_OR_INLINE>`
12. **Register File Control (`regs`, `inspect`, `reset`)**:
    - `ax regs`, `ax inspect [REG] [--limit <N>]`, `ax reset`
