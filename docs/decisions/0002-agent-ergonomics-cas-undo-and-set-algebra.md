# 0002. Agent Ergonomics: Contextual LOAD, CAS-Protected PATCH/COMMIT/UNDO, Set Algebra, and OUTLINE

- **Status:** Accepted
- **Date:** 2026-11-18

## Context and Problem Statement

To make `axon` (`ax`) genuinely effective for code-editing agents and Tiny Language Models operating under strict token budgets and concurrency constraints, raw file reading and global regex substitution are insufficient. Agents need:
1. Minimal-token context windows around search hits.
2. Line-range surgical edits (`PATCH`) with readable Unified Diff inspection, optimistic concurrency verification before disk mutation, and instant atomic rollback (`UNDO`) if downstream verification fails.
3. Zero-I/O set operations across SSA registers.
4. Structural file outlines without reading function bodies.

## Decision Outcome

We extended the Axon ISA with four orthogonal capabilities while preserving the existing `RegValue` variants and SSA immutability in `/dev/shm`:

1. **Merged Context Windows (`LOAD <MatchSet> --context N`)**:
   - When loading from a `MatchSet` with `--context N`, `ax` computes `[line - N ..= line + N]` per match, merges overlapping or adjacent windows per file, and emits one `FileSlice` per merged window.
2. **Surgical `PATCH`, Unified Diffs, FNV-1a 64-bit CAS Verification, and Atomic `UNDO`**:
   - Every `FilePatch` in a `DiffSet` (produced by `SUB` or `PATCH`) records `base_hash` and `modified_hash` using deterministic 64-bit FNV-1a (`fnv1a_64`).
   - `INSPECT` on a `DiffSet` renders a compact Unified Diff (`--- a/...`, `+++ b/...`, `@@ ... @@`).
   - `COMMIT` verifies that every target file on disk still matches `base_hash` before performing any atomic rename; on mismatch, it aborts with `CAS_CONFLICT`.
   - `UNDO <commit_or_diff_reg>` resolves the immutable `DiffSet` from `/dev/shm` (following `COMMIT.origin` when given a `COMMIT` register), verifies `modified_hash` (unless `--force`), and atomically restores `original` bytes to disk.
3. **Cross-Register Set Algebra (`UNION`, `INTERSECT`, `DIFF`)**:
   - Operates directly on SSA registers in shared memory, allowing e.g. `DIFF <PathSet> <MatchSet>` to filter out files that matched a pattern without re-scanning the filesystem.
4. **Structural Symbol Extraction (`OUTLINE`)**:
   - Extracts top-level declarations (`fn`, `struct`, `enum`, `trait`, `impl`, `mod`, `type`, `class`, `def`, `interface`, `func`, markdown headings) into a `MatchSet`.
