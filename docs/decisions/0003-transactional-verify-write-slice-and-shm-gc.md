# 0003. Transactional VERIFY, Staged WRITE, Register SLICE/Budgets, and Shared-Memory GC

- **Status:** Accepted
- **Date:** 2026-11-18

## Context and Problem Statement

In autonomous coding loops, applying a patch (`COMMIT`) and running a compiler/test check (`XEXEC`) as separate non-transactional commands risks leaving the working tree in a broken state if the agent crashes or loses context after a failed check. Additionally, agents need staged file creation (`WRITE`), pagination over large registers (`SLICE`), strict character budgets (`--max-chars`), and garbage collection (`GC` / `STATS`) for long-running `/dev/shm` sessions.

## Decision Outcome

1. **Transactional `VERIFY <diff_reg> <cmd...>`**:
   - Atomically applies `<diff_reg>` after verifying FNV-1a CAS hashes, executes `<cmd...>`, and inspects the exit status.
   - On exit status `0`, persists the changes on disk and allocates `VERIFY_OK` (`ExecResult`).
   - On non-zero exit status (or command spawn error), automatically reverts every patch in `<diff_reg>` (restoring original contents or unlinking newly created files) and allocates `VERIFY_ROLLBACK` (`ExecResult`) containing the compiler/test output.
2. **Staged File Creation (`WRITE <path> <content>`)**:
   - Extends `FilePatch` with `created_new: bool`. If `<path>` does not exist when `WRITE` runs, `created_new` is set to `true` (`base_hash = 0`).
   - `COMMIT` verifies the file still does not exist before creating parent directories and writing atomically; `UNDO` (and `VERIFY` rollback) unlinks the newly created file.
3. **Pagination (`SLICE <reg> <start> <end>`) and Context Budgets (`INSPECT --max-chars <N>`)**:
   - Projects `[start..end)` of any `RegValue` into a new SSA register, and truncates `INSPECT` output deterministically when `--max-chars` is specified.
4. **Shared-Memory Telemetry & Garbage Collection (`STATS`, `GC --keep <N>`)**:
   - `STATS` reports total registers, bytes in `/dev/shm`, `next_id`, and counts by `RegValue` variant.
   - `GC` unlinks older register files while retaining the `N` most recent registers and preserving monotonic `next_id`.
