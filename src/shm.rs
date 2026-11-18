use crate::reg::{RegRef, RegValue, RegisterRecord};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ShmManifest {
    next_id: u32,
    allocated_ids: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegTableEntry {
    pub id: u32,
    pub name: String,
    pub reg_type: String,
    pub items: usize,
    pub opcode: String,
    pub origin: String,
    pub created_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShmStats {
    pub shm_dir: String,
    pub total_registers: usize,
    pub total_bytes: u64,
    pub next_id: u32,
    pub by_type: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcReport {
    pub removed_registers: usize,
    pub freed_bytes: u64,
    pub retained_registers: usize,
    pub next_id: u32,
}

/// Shared-memory SSA Register Store backed by `/dev/shm`.
#[derive(Debug, Clone)]
pub struct ShmStore {
    root: PathBuf,
}

struct FlockGuard {
    file: File,
}

impl FlockGuard {
    fn acquire(lock_path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .open(lock_path)
            .with_context(|| format!("Failed to open shm lockfile {}", lock_path.display()))?;

        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("flock failed on {}", lock_path.display()));
        }
        Ok(Self { file })
    }
}

impl Drop for FlockGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

impl ShmStore {
    /// Resolve the default shared-memory directory (`AXON_SHM_DIR`, or `/dev/shm/axon-<uid>`).
    pub fn default_dir() -> PathBuf {
        if let Ok(custom) = std::env::var("AXON_SHM_DIR") {
            let trimmed = custom.trim();
            if !trimmed.is_empty() {
                return PathBuf::from(trimmed);
            }
        }
        let uid = unsafe { libc::geteuid() };
        let shm_base = Path::new("/dev/shm");
        if shm_base.is_dir() {
            shm_base.join(format!("axon-{uid}"))
        } else {
            std::env::temp_dir().join(format!("axon-{uid}"))
        }
    }

    pub fn open(custom_dir: Option<PathBuf>) -> Result<Self> {
        let root = custom_dir.unwrap_or_else(Self::default_dir);
        fs::create_dir_all(&root)
            .with_context(|| format!("Failed to initialize shm store at {}", root.display()))?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Check whether a physical SSA register ID is currently present in shared memory.
    pub fn is_allocated(&self, id: u32) -> Result<bool> {
        let _guard = self.lock()?;
        let manifest = self.read_manifest_unlocked()?;
        Ok(manifest.allocated_ids.contains(&id) || self.reg_path(id).exists())
    }

    /// Check whether an SSA register ID has already been allocated in this session (including IDs retired by GC).
    pub fn is_used_or_retired(&self, id: u32) -> Result<bool> {
        let _guard = self.lock()?;
        let manifest = self.read_manifest_unlocked()?;
        Ok(id < manifest.next_id
            || manifest.allocated_ids.contains(&id)
            || self.reg_path(id).exists())
    }

    fn lock(&self) -> Result<FlockGuard> {
        FlockGuard::acquire(&self.root.join(".axon.lock"))
    }

    fn manifest_path(&self) -> PathBuf {
        self.root.join("manifest.bin")
    }

    fn reg_path(&self, id: u32) -> PathBuf {
        self.root.join(format!("r{id}.bin"))
    }

    fn read_manifest_unlocked(&self) -> Result<ShmManifest> {
        let path = self.manifest_path();
        if !path.exists() {
            return Ok(ShmManifest::default());
        }
        let mut bytes = Vec::new();
        File::open(&path)
            .with_context(|| format!("Failed to open manifest {}", path.display()))?
            .read_to_end(&mut bytes)?;
        bincode::deserialize(&bytes).context("Corrupted SSA manifest in shared memory")
    }

    fn write_atomic(target: &Path, bytes: &[u8]) -> Result<()> {
        let pid = unsafe { libc::getpid() };
        let tmp_name = format!(
            ".{}.tmp.{pid}",
            target
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("blob")
        );
        let tmp_path = target.with_file_name(tmp_name);
        {
            let mut f = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp_path)
                .with_context(|| format!("Failed to create temp file {}", tmp_path.display()))?;
            f.write_all(bytes)?;
            f.flush()?;
        }
        fs::rename(&tmp_path, target).with_context(|| {
            format!(
                "Failed to atomically commit {} to {}",
                tmp_path.display(),
                target.display()
            )
        })?;
        Ok(())
    }

    /// Allocate a new immutable SSA register (or bind an explicit SSA register ID if not yet assigned).
    pub fn allocate(
        &self,
        explicit_id: Option<u32>,
        opcode: impl Into<String>,
        origin: impl Into<String>,
        value: RegValue,
    ) -> Result<RegisterRecord> {
        let _guard = self.lock()?;
        let mut manifest = self.read_manifest_unlocked()?;

        let id = match explicit_id {
            Some(req_id) => {
                if manifest.allocated_ids.contains(&req_id) || self.reg_path(req_id).exists() {
                    bail!(
                        "SSA_VIOLATION: register r{req_id} is already assigned and immutable in {}",
                        self.root.display()
                    );
                }
                req_id
            }
            None => manifest.next_id,
        };

        let created_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let record = RegisterRecord {
            id,
            name: format!("r{id}"),
            opcode: opcode.into(),
            origin: origin.into(),
            created_unix_ms,
            value,
        };

        let encoded_reg =
            bincode::serialize(&record).context("Failed to serialize register record")?;
        Self::write_atomic(&self.reg_path(id), &encoded_reg)?;

        manifest.allocated_ids.push(id);
        manifest.allocated_ids.sort_unstable();
        manifest.allocated_ids.dedup();
        if id >= manifest.next_id {
            manifest.next_id = id + 1;
        }

        let encoded_manifest =
            bincode::serialize(&manifest).context("Failed to serialize SSA manifest")?;
        Self::write_atomic(&self.manifest_path(), &encoded_manifest)?;

        Ok(record)
    }

    /// Read a register by reference (`r0`, `@r0`, `@last`, `r0[1]`, etc.).
    pub fn resolve(&self, reg_ref: &RegRef) -> Result<RegisterRecord> {
        let _guard = self.lock()?;
        let manifest = self.read_manifest_unlocked()?;

        let (id, index) = match reg_ref {
            RegRef::Id { id, index } => (*id, *index),
            RegRef::Last { index } => {
                let last_id = manifest.allocated_ids.last().copied().ok_or_else(|| {
                    anyhow!("No registers allocated yet in {}", self.root.display())
                })?;
                (last_id, *index)
            }
        };

        let mut record = self.read_reg_unlocked(id)?;
        if let Some(idx) = index {
            record.value = record.value.slice_index(idx)?;
            record.name = format!("r{id}[{idx}]");
        }
        Ok(record)
    }

    fn read_reg_unlocked(&self, id: u32) -> Result<RegisterRecord> {
        let path = self.reg_path(id);
        if !path.exists() {
            bail!("Register r{id} is not allocated in {}", self.root.display());
        }
        let mut bytes = Vec::new();
        File::open(&path)
            .with_context(|| format!("Failed to open register r{id} at {}", path.display()))?
            .read_to_end(&mut bytes)?;
        bincode::deserialize(&bytes)
            .with_context(|| format!("Failed to deserialize register r{id}"))
    }

    /// List all allocated registers in deterministic ascending order.
    pub fn list(&self) -> Result<Vec<RegTableEntry>> {
        let _guard = self.lock()?;
        let manifest = self.read_manifest_unlocked()?;
        let mut out = Vec::with_capacity(manifest.allocated_ids.len());
        for id in manifest.allocated_ids {
            if let Ok(rec) = self.read_reg_unlocked(id) {
                out.push(RegTableEntry {
                    id: rec.id,
                    name: rec.name,
                    reg_type: rec.value.type_name().to_string(),
                    items: rec.value.len(),
                    opcode: rec.opcode,
                    origin: rec.origin,
                    created_unix_ms: rec.created_unix_ms,
                });
            }
        }
        Ok(out)
    }

    /// Compute telemetry and memory usage statistics for the active `/dev/shm` namespace.
    pub fn stats(&self) -> Result<ShmStats> {
        let _guard = self.lock()?;
        let manifest = self.read_manifest_unlocked()?;
        let mut total_bytes = fs::metadata(self.manifest_path())
            .map(|m| m.len())
            .unwrap_or(0);
        let mut by_type: BTreeMap<String, usize> = BTreeMap::new();

        for &id in &manifest.allocated_ids {
            let p = self.reg_path(id);
            if let Ok(meta) = fs::metadata(&p) {
                total_bytes += meta.len();
            }
            if let Ok(rec) = self.read_reg_unlocked(id) {
                *by_type
                    .entry(rec.value.type_name().to_string())
                    .or_insert(0) += 1;
            }
        }

        Ok(ShmStats {
            shm_dir: self.root.to_string_lossy().into_owned(),
            total_registers: manifest.allocated_ids.len(),
            total_bytes,
            next_id: manifest.next_id,
            by_type,
        })
    }

    /// Garbage-collect older registers, keeping only the `keep_last` most recent SSA registers
    /// while preserving `next_id` monotonicity.
    pub fn gc(&self, keep_last: usize) -> Result<GcReport> {
        let _guard = self.lock()?;
        let mut manifest = self.read_manifest_unlocked()?;
        let total = manifest.allocated_ids.len();
        if total <= keep_last {
            return Ok(GcReport {
                removed_registers: 0,
                freed_bytes: 0,
                retained_registers: total,
                next_id: manifest.next_id,
            });
        }

        let split_at = total - keep_last;
        let to_remove: Vec<u32> = manifest.allocated_ids[..split_at].to_vec();
        manifest.allocated_ids = manifest.allocated_ids[split_at..].to_vec();

        let mut freed_bytes = 0u64;
        for id in &to_remove {
            let p = self.reg_path(*id);
            if let Ok(meta) = fs::metadata(&p) {
                freed_bytes += meta.len();
            }
            if p.exists() {
                let _ = fs::remove_file(&p);
            }
        }

        let encoded_manifest =
            bincode::serialize(&manifest).context("Failed to serialize SSA manifest after GC")?;
        Self::write_atomic(&self.manifest_path(), &encoded_manifest)?;

        Ok(GcReport {
            removed_registers: to_remove.len(),
            freed_bytes,
            retained_registers: manifest.allocated_ids.len(),
            next_id: manifest.next_id,
        })
    }

    /// Clear all registers and reset the SSA counter to `r0`.
    pub fn reset(&self) -> Result<usize> {
        let _guard = self.lock()?;
        let manifest = self.read_manifest_unlocked()?;
        let count = manifest.allocated_ids.len();
        for id in &manifest.allocated_ids {
            let p = self.reg_path(*id);
            if p.exists() {
                let _ = fs::remove_file(p);
            }
        }
        let m_path = self.manifest_path();
        if m_path.exists() {
            let _ = fs::remove_file(m_path);
        }
        Ok(count)
    }
}
