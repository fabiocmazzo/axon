---
name: shm-ssa-isolation
description: SSA registers live in /dev/shm/axon-<uid>; ax run automatically renames local virtual registers (r0 -> rK) across runs while enforcing intra-script SSA
type: convention
updated: 2026-11-18
---
By default, `ax` persists its physical SSA register file (`manifest.bin` and `r<N>.bin`) inside `/dev/shm/axon-<uid>`.

- Within `ax run "<script>"`, explicit register bindings like `r0 = SCAN ...; r1 = MATCH r0 ...` act as **script-local virtual SSA registers**:
  - Reassigning the same register twice inside the **same** `ax run` script (`r0 = ...; r0 = ...`) fails with `SSA_VIOLATION`.
  - If `r0` is already allocated in `/dev/shm` from a previous invocation, `ax run` transparently renames virtual `r0` to the next free physical register (e.g. `r5 (local r0)`) and remaps subsequent references to `r0` within that script to `@r5`.
- When writing tests that check exact physical register IDs (`r0`, `r1`, ...), isolate the register store via `--shm-dir <path>` or `AXON_SHM_DIR`.

**Why:** Agents and Tiny Language Models naturally emit scripts starting at `r0`; transparent virtual-to-physical SSA renaming makes scripts idempotent across repeated invocations without losing previous registers in `/dev/shm`.
