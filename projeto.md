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

[dev-dependencies]/
tempfile = "3.13"