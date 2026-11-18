# 0004. Unique-Anchor EDIT, Multi-File DiffSet Composition (UNION), Git DIRTY, and Prompt SCHEMA

- **Status:** Accepted
- **Date:** 2026-11-18

## Context and Problem Statement

Line-number-based edits (`PATCH`) are prone to off-by-one errors from language models, whereas global regex replacements (`SUB`) affect every match in a file. Furthermore, real-world agent tasks often span multiple files (e.g., creating a module and importing it in `src/lib.rs`) that must be compiled and verified together as a single atomic transaction (`VERIFY`).

## Decision Outcome

1. **Unique-Anchor Surgical Replacement (`EDIT <target> <old_block> <new_block>`)**:
   - Locates `<old_block>` across `<target>` and verifies it appears **exactly once** per matched file.
   - Returns `ANCHOR_NOT_FOUND` if absent, or `AMBIGUOUS_ANCHOR` (reporting all 1-based line numbers where `<old_block>` matched) if it appears more than once, prompting the agent to include more surrounding context lines.
2. **Composable `DiffSet` Algebra (`UNION` / `MERGE` on `DiffSet`)**:
   - Extends `UNION` to merge two `DiffSet` registers:
     - Patches targeting distinct files are combined into a single multi-file `DiffSet`.
     - Patches targeting the same file are composed either sequentially (when `b.base_hash == a.modified_hash`) or in parallel (when both were staged against the same `base_hash` and their modified line spans do not overlap, failing with `DIFF_MERGE_CONFLICT` on overlap).
   - Enables multi-file atomic `VERIFY <merged_diff> cargo check` with full multi-file rollback on failure.
3. **Working-Tree Discovery (`DIRTY [path]`)**:
   - Queries `git status --porcelain -uall` to populate a `PathSet` of modified and untracked files in the active repository.
4. **System-Prompt Grammar & Lineage (`SCHEMA`, `TRACE`)**:
   - `ax schema` emits a compact EBNF grammar and opcode reference for LLM/Tiny-LM system prompts.
   - `ax trace` prints the chronological SSA dataflow lineage in `/dev/shm`.
