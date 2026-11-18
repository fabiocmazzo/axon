use axon::isa::{
    op_commit, op_filter, op_load, op_load_with_context, op_match, op_outline, op_patch, op_purge,
    op_scan, op_set_algebra, op_sub, op_undo, op_xexec, FilterOpts, ScanOpts, SetOp,
};
use axon::reg::{RegRef, RegValue};
use axon::shm::ShmStore;
use axon::vm::execute_program;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_ssa_register_lifecycle_and_immutability() {
    let shm_tmp = tempdir().unwrap();
    let work_tmp = tempdir().unwrap();

    fs::write(work_tmp.path().join("alpha.rs"), "fn alpha() {}\n").unwrap();
    fs::write(work_tmp.path().join("beta.rs"), "fn beta() {}\n").unwrap();

    let store = ShmStore::open(Some(shm_tmp.path().to_path_buf())).unwrap();

    // Allocate r0 via SCAN
    let r0 = op_scan(
        &store,
        Some(0),
        &ScanOpts {
            root: work_tmp.path().to_path_buf(),
            glob: Some("*.rs".to_string()),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(r0.name, "r0");
    assert_eq!(r0.value.len(), 2);

    // Attempting to reassign r0 must fail with SSA_VIOLATION
    let err = op_scan(
        &store,
        Some(0),
        &ScanOpts {
            root: work_tmp.path().to_path_buf(),
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("SSA_VIOLATION"),
        "Expected SSA_VIOLATION, got: {err}"
    );

    // Resolve @last and indexed r0[1]
    let last = store.resolve(&RegRef::parse("@last").unwrap()).unwrap();
    assert_eq!(last.id, 0);

    let elem1 = store.resolve(&RegRef::parse("r0[1]").unwrap()).unwrap();
    assert_eq!(elem1.name, "r0[1]");
    assert_eq!(elem1.value.len(), 1);
    let paths = elem1.value.extract_paths();
    assert!(paths[0].ends_with("beta.rs"));
}

#[test]
fn test_orthogonal_isa_pipeline_scan_match_load_sub_commit_purge() {
    let shm_tmp = tempdir().unwrap();
    let work_tmp = tempdir().unwrap();

    let f1 = work_tmp.path().join("a.txt");
    let f2 = work_tmp.path().join("b.txt");
    let f3 = work_tmp.path().join("ignore.log");

    fs::write(&f1, "hello world\nTODO: fix bug 1\n").unwrap();
    fs::write(&f2, "nothing here\nTODO: fix bug 2\n").unwrap();
    fs::write(&f3, "TODO: should be filtered out\n").unwrap();

    let store = ShmStore::open(Some(shm_tmp.path().to_path_buf())).unwrap();

    // r0: SCAN all files
    let r0 = op_scan(
        &store,
        None,
        &ScanOpts {
            root: work_tmp.path().to_path_buf(),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(r0.name, "r0");
    assert_eq!(r0.value.len(), 3);

    // r1: FILTER only *.txt
    let r1 = op_filter(
        &store,
        None,
        "r0",
        &FilterOpts {
            glob: Some("*.txt".to_string()),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(r1.name, "r1");
    assert_eq!(r1.value.len(), 2);

    // r2: MATCH "TODO: fix bug \d+" on r1
    let r2 = op_match(&store, None, "@r1", r"TODO: fix bug \d+", false).unwrap();
    assert_eq!(r2.name, "r2");
    assert_eq!(r2.value.len(), 2);

    // r3: LOAD line 2 from r2
    let r3 = op_load(&store, None, "r2", Some(2), Some(2)).unwrap();
    assert_eq!(r3.name, "r3");
    if let RegValue::TextBuf(slices) = &r3.value {
        assert_eq!(slices.len(), 2);
        assert_eq!(slices[0].content, "TODO: fix bug 1");
        assert_eq!(slices[1].content, "TODO: fix bug 2");
    } else {
        panic!("Expected TextBuf");
    }

    // r4: SUB pure SSA staging (does NOT mutate disk yet!)
    let r4 = op_sub(&store, None, "r1", "TODO:", "DONE:", true).unwrap();
    assert_eq!(r4.name, "r4");
    assert_eq!(r4.value.len(), 2);
    assert!(
        fs::read_to_string(&f1).unwrap().contains("TODO:"),
        "SUB must stage in SSA memory without modifying disk before COMMIT"
    );

    // r5: COMMIT r4 to disk atomically
    let r5 = op_commit(&store, None, "r4").unwrap();
    assert_eq!(r5.name, "r5");
    assert!(fs::read_to_string(&f1).unwrap().contains("DONE: fix bug 1"));
    assert!(fs::read_to_string(&f2).unwrap().contains("DONE: fix bug 2"));

    // r6: FILTER *.log from r0 and PURGE
    let r6 = op_filter(
        &store,
        None,
        "r0",
        &FilterOpts {
            glob: Some("*.log".to_string()),
            ..Default::default()
        },
    )
    .unwrap();
    // Dry-run purge first
    let _r7 = op_purge(&store, None, &r6.name, false).unwrap();
    assert!(f3.exists(), "Dry-run purge must not delete file");

    // Force purge
    let _r8 = op_purge(&store, None, &r6.name, true).unwrap();
    assert!(!f3.exists(), "Force purge must unlink file");
}

#[test]
fn test_vm_batch_execution_and_xexec() {
    let shm_tmp = tempdir().unwrap();
    let work_tmp = tempdir().unwrap();

    let file_a = work_tmp.path().join("mod_a.rs");
    let file_b = work_tmp.path().join("mod_b.rs");
    fs::write(&file_a, "pub fn compute() -> i32 { 41 }\n").unwrap();
    fs::write(&file_b, "pub fn helper() -> i32 { 1 }\n").unwrap();

    let store = ShmStore::open(Some(shm_tmp.path().to_path_buf())).unwrap();
    let root_str = work_tmp.path().to_string_lossy();

    let program = format!(
        r#"
        r0 = SCAN "{root_str}" --glob "*.rs"
        r1 = MATCH r0 "compute" --fixed
        r2 = SUB r1 "41" "42" --fixed
        r3 = COMMIT r2
        r4 = XEXEC r1 echo "verified:{{}}"
        INSPECT r4
        "#
    );

    let steps = execute_program(&store, &program).unwrap();
    assert_eq!(steps.len(), 6);

    let updated = fs::read_to_string(&file_a).unwrap();
    assert_eq!(updated, "pub fn compute() -> i32 { 42 }\n");

    let r4 = store.resolve(&RegRef::parse("r4").unwrap()).unwrap();
    if let RegValue::ExecResult(receipts) = r4.value {
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].exit_code, 0);
        assert!(receipts[0].stdout.contains("verified:"));
        assert!(receipts[0].stdout.contains("mod_a.rs"));
    } else {
        panic!("Expected ExecResult");
    }

    // Direct op_xexec call without `{}` placeholder (batch mode)
    let r5 = op_xexec(&store, None, "r0", &["echo".to_string(), "batch".to_string()]).unwrap();
    assert_eq!(r5.name, "r5");
    assert_eq!(r5.value.len(), 1);
}

#[test]
fn test_ax_cli_binary_end_to_end() {
    use std::process::Command;

    let shm_tmp = tempdir().unwrap();
    let work_tmp = tempdir().unwrap();
    let sample_file = work_tmp.path().join("hello.rs");
    fs::write(&sample_file, "fn main() {\n    println!(\"v1\");\n}\n").unwrap();

    let bin = env!("CARGO_BIN_EXE_ax");
    let shm_arg = shm_tmp.path().to_str().unwrap();
    let work_arg = work_tmp.path().to_str().unwrap();

    // 1. ax scan
    let out = Command::new(bin)
        .args(["--shm-dir", shm_arg, "scan", work_arg, "--glob", "*.rs"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("r0 = PathSet(1 items)"));

    // 2. ax match
    let out = Command::new(bin)
        .args(["--shm-dir", shm_arg, "match", "r0", "v1", "--fixed"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("r1 = MatchSet(1 items)"));

    // 3. ax sub + ax commit
    let out = Command::new(bin)
        .args(["--shm-dir", shm_arg, "sub", "r1", "v1", "v2", "--fixed"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("r2 = DiffSet(1 items)"));

    let out = Command::new(bin)
        .args(["--shm-dir", shm_arg, "commit", "r2"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(fs::read_to_string(&sample_file).unwrap().contains("v2"));

    // 4. ax regs --json
    let out = Command::new(bin)
        .args(["--shm-dir", shm_arg, "--json", "regs"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let json_val: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json_val.as_array().unwrap().len(), 4);

    // 5. ax reset
    let out = Command::new(bin)
        .args(["--shm-dir", shm_arg, "reset"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("Cleared 4 SSA register(s)"));
}

#[test]
fn test_contextual_load_around_matches_with_window_merging() {
    let shm_tmp = tempdir().unwrap();
    let work_tmp = tempdir().unwrap();
    let file_p = work_tmp.path().join("service.rs");

    // 10-line file with matches at lines 2, 3 (adjacent) and line 9 (distant)
    let content = (1..=10)
        .map(|i| {
            if i == 2 || i == 3 || i == 9 {
                format!("line {i} TARGET_TOKEN")
            } else {
                format!("line {i} normal")
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&file_p, content).unwrap();

    let store = ShmStore::open(Some(shm_tmp.path().to_path_buf())).unwrap();
    let r0 = op_match(
        &store,
        None,
        file_p.to_str().unwrap(),
        "TARGET_TOKEN",
        true,
    )
    .unwrap();
    assert_eq!(r0.value.len(), 3);

    // Load ±1 context around matches in r0:
    // Matches at lines 2 and 3 with ±1 -> [1..=3] and [2..=4] -> merged into [1..=4]
    // Match at line 9 with ±1 -> [8..=10]
    let r1 = op_load_with_context(&store, None, &r0.name, None, None, Some(1)).unwrap();
    if let RegValue::TextBuf(slices) = &r1.value {
        assert_eq!(slices.len(), 2, "Expected 2 merged context windows");
        assert_eq!((slices[0].start_line, slices[0].end_line), (1, 4));
        assert_eq!((slices[1].start_line, slices[1].end_line), (8, 10));
    } else {
        panic!("Expected TextBuf");
    }
}

#[test]
fn test_patch_unified_diff_cas_conflict_and_atomic_undo() {
    let shm_tmp = tempdir().unwrap();
    let work_tmp = tempdir().unwrap();
    let file_p = work_tmp.path().join("calc.rs");
    let original = "fn a() {}\nfn b() {\n    let x = 1;\n}\nfn c() {}\n";
    fs::write(&file_p, original).unwrap();

    let store = ShmStore::open(Some(shm_tmp.path().to_path_buf())).unwrap();

    // Stage surgical PATCH on lines 2..=4
    let r0 = op_patch(
        &store,
        None,
        file_p.to_str().unwrap(),
        2,
        4,
        "fn b() {\n    let x = 99;\n}",
    )
    .unwrap();

    // Verify unified diff rendering in inspect output
    let inspect_txt = r0.format_inspect(None);
    assert!(inspect_txt.contains("--- a/"));
    assert!(inspect_txt.contains("+++ b/"));
    assert!(inspect_txt.contains("-     let x = 1;"));
    assert!(inspect_txt.contains("+     let x = 99;"));

    // Simulate concurrent modification on disk before COMMIT -> must trigger CAS_CONFLICT
    fs::write(&file_p, "fn a() { /* concurrent edit */ }\n").unwrap();
    let conflict_err = op_commit(&store, None, &r0.name).unwrap_err();
    assert!(
        conflict_err.to_string().contains("CAS_CONFLICT"),
        "Expected CAS_CONFLICT, got: {conflict_err}"
    );

    // Restore original file on disk so COMMIT succeeds
    fs::write(&file_p, original).unwrap();
    let r1_commit = op_commit(&store, None, &r0.name).unwrap();
    assert!(fs::read_to_string(&file_p).unwrap().contains("let x = 99;"));

    // Roll back via UNDO on the COMMIT register r1
    let r2_undo = op_undo(&store, None, &r1_commit.name, false).unwrap();
    assert_eq!(r2_undo.opcode, "UNDO");
    assert_eq!(fs::read_to_string(&file_p).unwrap(), original);
}

#[test]
fn test_ssa_set_algebra_and_outline() {
    let shm_tmp = tempdir().unwrap();
    let work_tmp = tempdir().unwrap();

    let f_safe = work_tmp.path().join("safe.rs");
    let f_unsafe = work_tmp.path().join("raw.rs");
    fs::write(
        &f_safe,
        "pub struct SafeEngine;\npub fn run_safe() -> bool { true }\n",
    )
    .unwrap();
    fs::write(
        &f_unsafe,
        "pub unsafe fn run_raw_ptr() {\n    // unsafe block\n}\n",
    )
    .unwrap();

    let store = ShmStore::open(Some(shm_tmp.path().to_path_buf())).unwrap();

    // r0 = all *.rs files (2 files)
    let r0 = op_scan(
        &store,
        None,
        &ScanOpts {
            root: work_tmp.path().to_path_buf(),
            glob: Some("*.rs".to_string()),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(r0.value.len(), 2);

    // r1 = files matching "unsafe" (1 file: raw.rs)
    let r1 = op_match(&store, None, &r0.name, "unsafe", true).unwrap();
    assert_eq!(r1.value.extract_paths().len(), 1);

    // r2 = DIFF r0 r1 -> only safe.rs
    let r2 = op_set_algebra(&store, None, SetOp::Diff, &r0.name, &r1.name).unwrap();
    assert_eq!(r2.value.len(), 1);
    assert!(r2.value.extract_paths()[0].ends_with("safe.rs"));

    // r3 = INTERSECT r0 r1 -> only raw.rs
    let r3 = op_set_algebra(&store, None, SetOp::Intersect, &r0.name, &r1.name).unwrap();
    assert_eq!(r3.value.len(), 1);
    assert!(r3.value.extract_paths()[0].ends_with("raw.rs"));

    // r4 = UNION r2 r3 -> both files again
    let r4 = op_set_algebra(&store, None, SetOp::Union, &r2.name, &r3.name).unwrap();
    assert_eq!(r4.value.len(), 2);

    // r5 = OUTLINE r2 -> extracts `pub struct SafeEngine;` and `pub fn run_safe()`
    let r5 = op_outline(&store, None, &r2.name).unwrap();
    assert_eq!(r5.opcode, "OUTLINE");
    assert_eq!(r5.value.len(), 2);
}

#[test]
fn test_vm_virtual_ssa_renaming_across_runs_and_intra_run_ssa_violation() {
    let shm_tmp = tempdir().unwrap();
    let work_tmp = tempdir().unwrap();

    fs::write(work_tmp.path().join("one.rs"), "pub fn first() {}\n").unwrap();
    let store = ShmStore::open(Some(shm_tmp.path().to_path_buf())).unwrap();
    let root_str = work_tmp.path().to_string_lossy();

    let script = format!(
        r#"
        r0 = SCAN "{root_str}" "*.rs"
        r1 = OUTLINE r0
        INSPECT r1
        "#
    );

    // Run 1: binds physical r0 and r1
    let run1 = execute_program(&store, &script).unwrap();
    assert_eq!(run1[0].register.as_ref().unwrap().name, "r0");
    assert_eq!(run1[0].virtual_reg, None);
    assert_eq!(run1[1].register.as_ref().unwrap().name, "r1");
    assert_eq!(run1[1].virtual_reg, None);

    // Run 2 (identical script with r0 and r1): automatically renames virtual r0 -> r2, r1 -> r3
    let run2 = execute_program(&store, &script).unwrap();
    assert_eq!(run2[0].register.as_ref().unwrap().name, "r2");
    assert_eq!(run2[0].virtual_reg.as_deref(), Some("r0"));
    assert_eq!(run2[1].register.as_ref().unwrap().name, "r3");
    assert_eq!(run2[1].virtual_reg.as_deref(), Some("r1"));
    assert_eq!(run2[1].register.as_ref().unwrap().origin, "r2");

    // Intra-run duplicate assignment (`r0 = ...; r0 = ...` in the SAME script) must still fail with SSA_VIOLATION
    let bad_script = format!(
        r#"
        r0 = SCAN "{root_str}" "*.rs"
        r0 = OUTLINE r0
        "#
    );
    let err = execute_program(&store, &bad_script).unwrap_err();
    assert!(
        err.to_string().contains("SSA_VIOLATION"),
        "Expected intra-script SSA_VIOLATION, got: {err}"
    );
}
