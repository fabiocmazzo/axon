---
name: shm-ssa-isolation
description: SSA registers live in /dev/shm/axon-<uid> by default; tests and isolated sessions must pass --shm-dir or AXON_SHM_DIR
type: convention
updated: 2026-11-18
---
By default, `ax` persists its SSA register file (`manifest.bin` and `r<N>.bin`) inside `/dev/shm/axon-<uid>`.

When writing tests or running parallel agent sessions that must not share or clobber the user's interactive register table (`r0`, `r1`, ...), always isolate the register file via `--shm-dir <path>` or the `AXON_SHM_DIR` environment variable.

**Why:** SSA register IDs are monotonically increasing and immutable once allocated; sharing the default `/dev/shm/axon-<uid>` across concurrent test runs would cause `SSA_VIOLATION` collisions on explicit bindings like `r0 = SCAN ...`.
