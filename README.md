# Axon (`ax`) — Deterministic Agent Execution Motor Pathway & Shared-Memory SSA Register VM

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-2021_Edition-orange.svg)](Cargo.toml)

**Axon** (compiled binary: `ax`) is an ultra-fast, synchronous Rust command-line utility and **Static Single Assignment (SSA) Register Virtual Machine** backed by POSIX shared memory (`/dev/shm`).

It acts as the deterministic execution layer between human terminal operators, coding agents, or Tiny Language Models (15M–50M parameters) and the operating system—replacing fragile, irregular POSIX pipelines (`find`, `grep`, `sed`, `cat`, `rm`, `xargs`) with a strongly typed, orthogonal **Instruction Set Architecture (ISA)** and Compare-And-Swap (CAS) transactional file mutations.

---

## Why Axon?

Traditional shell pipelines force language models to deal with complex quoting, unvalidated in-place mutations (`sed -i`), high token overhead from full-file dumps (`cat`), and non-transactional edits that leave repositories broken when a compiler check fails.

Axon solves this through four core design principles:

1. **Shared-Memory SSA Register File (`/dev/shm/axon-<uid>`)**:
   - Every data-producing instruction allocates an immutable SSA register (`r0`, `r1`, `r2`, ...) serialized in RAM via `bincode` and protected by `flock` + atomic rename.
   - Subsequent instructions reference prior results by register ID (`r0`, `@r0`, `@last`, or indexed `r0[2]`) without re-emitting file paths or re-scanning disk.
   - **Per-Execution Virtual SSA Renaming**: Agents can always emit scripts starting at `r0 = ...; r1 = ...`. If `r0` is already allocated in `/dev/shm` from a prior turn, `ax run` transparently maps local virtual `r0` to the next monotonic physical register (`r5 (local r0)`) while strictly forbidding duplicate reassignments within the same script (`SSA_VIOLATION`).
2. **Token-Minimal Contextual Reading (`OUTLINE`, `LOAD --context N`, `SLICE`, `--max-chars`)**:
   - Extract structural symbol signatures (`fn`, `struct`, `enum`, `trait`, `impl`, `class`, `def`) with `OUTLINE`.
   - Load only `±N` lines around regex/symbol matches (`LOAD r1 --context 3`), automatically merging overlapping or adjacent windows.
3. **Two-Phase Staged Mutations with 64-bit FNV-1a CAS & Unified Diffs (`EDIT`, `PATCH`, `SUB`, `WRITE`)**:
   - File mutations are staged purely in SSA shared memory (`DiffSet`) and rendered as Unified Diffs (`ax inspect`).
   - `EDIT` enforces **exact unique anchor matching** (`ANCHOR_NOT_FOUND` if 0 matches; `AMBIGUOUS_ANCHOR` with line numbers if `>1` matches).
   - `UNION` (or `MERGE`) composes multiple `DiffSet` registers (across different files or non-overlapping spans in the same file) into a single atomic change set.
4. **Transactional Verification & Instant Rollback (`VERIFY`, `COMMIT`, `UNDO`)**:
   - `COMMIT` verifies 64-bit FNV-1a `base_hash` values before writing atomically via sibling temporary files, aborting with `CAS_CONFLICT` if any target file was modified externally.
   - `VERIFY <diff_reg> <cmd...>` applies a `DiffSet`, runs a verification command (e.g., `cargo check` or `cargo test`), and **automatically rolls back all modified/created files on disk if the command exits non-zero**.
   - `UNDO` restores any committed `DiffSet` from its immutable `/dev/shm` snapshot in sub-millisecond time.

---

## Architecture Overview

```text
+-----------------------------------------------------------------------+
|                Agent / Tiny LM / Human Operator                       |
|        ax run "r0 = SCAN src '*.rs'; r1 = OUTLINE r0; ..."            |
+-----------------------------------+-----------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------+
|                    Axon Orthogonal ISA & VM Engine                    |
|  Discovery : SCAN | DIRTY | FILTER | SLICE | UNION | INTERSECT | DIFF |
|  Inspection: MATCH | OUTLINE | LOAD (--context N) | INSPECT | TRACE   |
|  Staging   : EDIT (unique anchor) | PATCH (lines) | SUB | WRITE       |
|  Commit/Tx : COMMIT (CAS) | VERIFY (auto-UNDO on fail) | UNDO | PURGE |
+-----------------------------------+-----------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------+
|         /dev/shm/axon-<uid> (flock + Atomic Bincode SSA Store)        |
|   manifest.bin  |  r0.bin (PathSet)  |  r1.bin (MatchSet)  |  r2.bin  |
+-----------------------------------------------------------------------+
```

---

## Installation

Build from source with a standard Rust toolchain (Rust 1.75+):

```sh
cargo build --release
```

The compiled binary is placed at `target/release/ax` (or install globally via `cargo install --path .`).

---

## Quickstart

### 1. Discovery, Structural Outline & Merged Context Windows

Execute a multi-instruction VM program in a single invocation:

```sh
ax run "
  r0 = SCAN src '*.rs'
  r1 = OUTLINE r0
  r2 = MATCH r0 'CAS_CONFLICT' --fixed
  r3 = LOAD r2 --context 2
  INSPECT r3
"
```

### 2. Unique-Anchor Surgical Edit & Multi-File Transactional `VERIFY`

Stage a new module file (`WRITE`), register it in `src/lib.rs` (`EDIT`), merge both `DiffSet` registers (`UNION`), inspect the combined Unified Diff, and transactionally verify with `cargo check`:

```sh
ax run "
  r0 = WRITE 'src/helper.rs' 'pub fn Answer() -> i32 { 42 }'
  r1 = EDIT 'src/lib.rs' 'pub mod vm;' 'pub mod helper;\npub mod vm;'
  r2 = UNION r0 r1
  INSPECT r2
  r3 = VERIFY r2 cargo check
  INSPECT r3
"
```

If `cargo check` exits with a non-zero status, `VERIFY` automatically removes `src/helper.rs` and restores `src/lib.rs` to its exact pre-commit bytes while recording the compiler diagnostics in `r3` (`VERIFY_ROLLBACK`).

### 3. Instant Rollback (`UNDO`)

Even after a successful `COMMIT` or `VERIFY`, any change can be rolled back atomically from `/dev/shm`:

```sh
ax undo @last
```

---

## Instruction Set Architecture (ISA)

Every instruction is available both as an opcode inside `ax run "<program>"` and as a direct CLI subcommand (`ax <subcommand>`). Pass `--json` globally for structured JSON telemetry.

| Opcode / Subcommand | Output Register | Description |
| :--- | :--- | :--- |
| `SCAN [path] [glob] [--max-depth N] [--hidden]` | `PathSet` | Deterministic, `.gitignore`-aware directory traversal (replaces `find`). |
| `DIRTY [path]` | `PathSet` | Collects modified and untracked files from `git status --porcelain`. |
| `FILTER <reg> [--glob G] [--regex R] [--min-size B] [--max-size B]` | `PathSet` \| `MatchSet` | Narrows an existing `PathSet` or `MatchSet` into a new SSA register. |
| `SLICE <reg> <start> <end>` | Same as `<reg>` | Paginates items in `[start..end)` (0-based) into a new SSA register. |
| `UNION <regA> <regB>` (alias: `MERGE`) | `PathSet` \| `MatchSet` \| `DiffSet` | Set union on `PathSet`/`MatchSet`, or **composes two `DiffSet` registers** into a multi-patch transaction. |
| `INTERSECT <regA> <regB>` | `PathSet` \| `MatchSet` \| `DiffSet` | Set intersection (supports cross-type filtering, e.g. `PathSet` $\cap$ `MatchSet`). |
| `DIFF <regA> <regB>` | `PathSet` \| `MatchSet` \| `DiffSet` | Set difference (`regA \ regB`, e.g. files in `r0` that did not match in `r1`). |
| `MATCH <reg\|path> <pattern> [--fixed]` | `MatchSet` | Regex or literal search across `PathSet`, `TextBuf`, or path (replaces `grep`). |
| `OUTLINE [reg\|path]` | `MatchSet` | Extracts structural declarations (`fn`, `struct`, `enum`, `trait`, `impl`, `mod`, `type`, `class`, `def`, `interface`, `func`, Markdown headings). |
| `LOAD <reg\|path> [-s A] [-e B] [--context N]` | `TextBuf` | Loads line ranges or merged `±N` context windows around `MatchSet` hits. |
| `EDIT <reg\|path> <old_block> <new_block>` | `DiffSet` | Pure SSA unique-anchor replacement (`ANCHOR_NOT_FOUND` / `AMBIGUOUS_ANCHOR`). |
| `PATCH <reg\|path> -s <A> -e <B> -w <text>` | `DiffSet` | Pure SSA 1-based line-range (`A..=B`) replacement. |
| `SUB <reg\|path> <pattern> <replacement> [--fixed]` | `DiffSet` | Pure SSA regex or fixed substitution across files (replaces `sed`). |
| `WRITE <file_path> <content>` | `DiffSet` | Pure SSA staged file creation (or full overwrite) with `UNDO` unlinking support. |
| `COMMIT <diff_reg>` | `Tombstone` | Verifies 64-bit FNV-1a CAS hashes on disk and writes patches atomically. |
| `VERIFY <diff_reg> <cmd> [args...]` | `ExecResult` | Applies `<diff_reg>`, runs `<cmd>`, and **auto-runs `UNDO` if `exit_code != 0`**. |
| `UNDO [commit_or_diff_reg] [--force]` | `Tombstone` | Atomically restores pre-commit file contents (or unlinks newly created files) from `/dev/shm`. |
| `PURGE <pathset_reg> [--force]` | `Tombstone` | Deletes files in `<pathset_reg>` (dry-run audit unless `--force` is passed). |
| `XEXEC <reg> <cmd> [args...]` | `ExecResult` | Structured replacement for `xargs` (`{}` placeholder per path or batch invocation). |
| `INSPECT [reg] [--limit N] [--max-chars M]` | *(stdout)* | Formats register contents (or single element `r0[i]`) within an optional character budget. |
| `REGS` / `TRACE` / `STATS` / `GC [--keep N]` / `RESET` | *(stdout)* | Lists registers, prints SSA lineage graph, reports `/dev/shm` usage, garbage-collects old registers, or resets the namespace. |
| `SCHEMA` | *(stdout)* | Emits the compact EBNF grammar and opcode reference for LLM system prompts. |

---

## Agent & Tiny-LM System Prompt Integration

Run `ax schema` to output a compact, self-contained grammar specification ready to embed in an agent's system prompt:

```sh
ax schema
```

To isolate parallel agent workers or test suites into separate shared-memory namespaces, set `AXON_SHM_DIR` or pass `--shm-dir <PATH>`:

```sh
ax --shm-dir /dev/shm/axon-worker-1 run "r0 = DIRTY; INSPECT r0"
```

---

## Testing

Run the full integration and CLI end-to-end test suite:

```sh
cargo test
```

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
