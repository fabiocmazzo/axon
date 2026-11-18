# 0001. Shared-Memory SSA Register File and Two-Phase Mutation ISA

- **Status:** Accepted
- **Date:** 2026-11-18

## Context and Problem Statement

`axon` (`ax`) provides a deterministic execution layer between human terminal operators / Tiny Language Models (15M–50M parameters) and the operating system, replacing irregular POSIX pipelines (`find`, `grep`, `sed`, `cat`, `rm`, `xargs`). We needed to decide how state is passed across steps, serialized in shared memory (`/dev/shm`), and how file mutations are executed safely.

## Considered Options

1. **Stateless JSON pipes over stdout/stdin**
2. **Mutable named registers in SQLite or disk database**
3. **Immutable Static Single Assignment (SSA) registers serialized with `bincode` in `/dev/shm/axon-<uid>` + Two-Phase `SUB` / `COMMIT` mutations**

## Decision Outcome

Chosen option: **Option 3 (Immutable SSA register file in `/dev/shm/axon-<uid>` with `bincode` + `flock` and two-phase `SUB`/`COMMIT` mutation)**.

### Consequences

- **Good:** Every instruction allocates an immutable register (`r0`, `r1`, ...), guaranteeing referential transparency and allowing Tiny LMs or human operators to inspect any intermediate result (`ax inspect rN` or indexed `rN[i]`) without re-running pipelines.
- **Good:** `SUB` stages replacements purely in SSA memory (`DiffSet`), and `COMMIT` writes atomically via sibling temp files + `rename`, preventing half-written files or accidental destructive edits.
- **Good:** `libc::flock` on `.axon.lock` combined with atomic write-and-rename on `rN.bin` and `manifest.bin` ensures concurrency safety across parallel invocations with zero async runtime overhead.
- **Neutral:** Shared memory contents in `/dev/shm/axon-<uid>` are ephemeral across OS reboots by design.
