//! unproven: for each check in code an AI wrote, what happens when it is
//! deleted.
//!
//! A `unproven.toml` lists the checks, how to delete each one, and what
//! should notice: the fuzzer finds it, a test fails, or something else
//! refuses the call instead. unproven deletes each check in turn, rebuilds,
//! runs the tests (and the fuzzer and the probe, if there are any), and fails
//! if a row no longer reads the way the file says. A check that nothing
//! notices is unproven: the code would behave the same without it, as far as
//! anything in the repository can tell.
//!
//!     unproven <unproven.toml> [--only <text>] [--no-baseline]
//!
//! Exit codes: 0 every row holds, 1 a row does not, 2 something could not
//! run (a command failed, a fuzzer never started, a deletion did not apply).

use serde::Deserialize;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{mpsc, Mutex};
use std::time::{Duration, Instant};

#[derive(Deserialize)]
struct Claims {
    /// The repository root, relative to this file. Every path and
    /// command below is taken from there.
    root: String,
    /// Pages that print the table; every `row` must appear in each.
    #[serde(default)]
    docs: Vec<String>,
    /// Run once before anything else (building a fuzz harness, say).
    #[serde(default)]
    prepare: Vec<String>,
    /// Rebuilds the program after each deletion.
    build: String,
    /// Runs the tests, in `cargo test`'s output format: failures are read
    /// from `test <path::name> ... FAILED`.
    test: String,
    /// Runs the fuzzer; findings are lines starting `[FUZZ_FINDING] [`.
    fuzz: Option<String>,
    #[serde(default = "default_fuzz_seconds")]
    fuzz_seconds: u64,
    /// A line the fuzzer prints while it runs. A run that never prints it
    /// did not fuzz, and its "no finding" means nothing.
    #[serde(default = "default_fuzz_alive")]
    fuzz_alive: String,
    /// Prints how each call ended, one line each:
    /// `PROBE <spec> | <variant> | ok=<bool> | <log> ...`.
    probe: Option<String>,
    claim: Vec<Claim>,
}

#[derive(Deserialize)]
struct Claim {
    /// The row as the chapter prints it.
    row: String,
    /// The same row in a translation, where it reads differently.
    #[serde(default)]
    also: Vec<String>,
    file: String,
    /// Text that occurs once in the file, at the start of the function the
    /// deletion is made in; the function ends at its matching closing brace.
    in_fn: String,
    /// Text that occurs once inside that function.
    find: String,
    replace: String,
    /// Text one of the fuzzer's findings must contain, every piece of it;
    /// absent means no finding.
    fuzz: Option<Vec<String>>,
    /// Tests that must fail, by full path or by the last segment if that is
    /// unambiguous; every other test must pass.
    #[serde(default)]
    tests_fail: Vec<String>,
    /// For a check something else stands in for: what refused the call.
    refused: Option<Refused>,
}

#[derive(Deserialize)]
struct Refused {
    /// Picks the probe line: `<spec> | <variant>`, matched exactly.
    probe: String,
    /// Text the rest of that line must contain.
    log: String,
}

struct Outcome {
    findings: Vec<String>,
    failed_tests: Vec<String>,
    probe: Vec<String>,
}

/// The file being edited, so a failure or a signal can put it back.
static EDITING: Mutex<Option<PathBuf>> = Mutex::new(None);
/// The fuzzer's process group, so a signal can stop it.
static FUZZ_PGID: AtomicI32 = AtomicI32::new(0);

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(path) = args.first() else {
        eprintln!("usage: unproven <unproven.toml> [--only <text>] [--no-baseline]");
        std::process::exit(2);
    };
    let only = args.iter().position(|a| a == "--only").and_then(|i| args.get(i + 1));
    let baseline = !args.iter().any(|a| a == "--no-baseline");

    // Ctrl-C, a cancelled CI job or a panic must not leave a check deleted.
    // These keep the backup: the main thread may still be writing.
    ctrlc::set_handler(|| {
        stop_fuzzer();
        put_back(true);
        std::process::exit(130);
    })
    .unwrap_or_else(|e| die(&format!("signal handler: {e}")));
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        stop_fuzzer();
        put_back(true);
        default_hook(info);
    }));

    let text = std::fs::read_to_string(path).unwrap_or_else(|e| die(&format!("{path}: {e}")));
    let claims: Claims = toml::from_str(&text).unwrap_or_else(|e| die(&format!("{path}: {e}")));
    let root = Path::new(path).parent().unwrap_or(Path::new(".")).join(&claims.root);
    let root = root.canonicalize().unwrap_or_else(|e| die(&format!("{}: {e}", root.display())));

    for c in &claims.claim {
        if c.fuzz.is_some() && claims.fuzz.is_none() {
            die(&format!("{}: expects a fuzz finding, but there is no `fuzz` command", c.row));
        }
        if c.refused.is_some() && claims.probe.is_none() {
            die(&format!("{}: names what refused it, but there is no `probe` command", c.row));
        }
    }

    // A run killed half-way leaves a backup; put the original back first.
    for c in &claims.claim {
        restore_backup(&root.join(&c.file));
    }
    // Every deletion must apply before anything runs.
    for c in &claims.claim {
        let src = std::fs::read_to_string(root.join(&c.file)).unwrap_or_else(|e| die(&format!("{}: {e}", c.file)));
        delete_check(&src, c).unwrap_or_else(|e| die(&format!("{}: {e}", c.row)));
    }

    let mut bad = 0;
    for doc in &claims.docs {
        let body = std::fs::read_to_string(root.join(doc)).unwrap_or_else(|e| die(&format!("{doc}: {e}")));
        for c in claims.claim.iter().filter(|c| !std::iter::once(&c.row).chain(&c.also).any(|r| body.contains(r.as_str()))) {
            println!("MISSING  {doc} has no row {}", c.row);
            bad += 1;
        }
    }

    for cmd in &claims.prepare {
        run_ok(&root, cmd);
    }
    if baseline {
        run_ok(&root, &claims.build);
        let out = measure(&root, &claims, None);
        if !out.findings.is_empty() || !out.failed_tests.is_empty() {
            println!("BASELINE the code as it is: findings {:?}, failed tests {:?}", out.findings, out.failed_tests);
            std::process::exit(1);
        }
        println!("baseline: no finding, every test passes");
    }

    let mut tally = [0usize; 4];
    for c in claims.claim.iter().filter(|c| only.is_none_or(|o| c.row.contains(o.as_str()))) {
        let file = root.join(&c.file);
        let original = std::fs::read_to_string(&file).unwrap_or_else(|e| die(&format!("{}: {e}", c.file)));
        let mutated = delete_check(&original, c).unwrap_or_else(|e| die(&format!("{}: {e}", c.row)));
        set_aside(&file, &original);
        std::fs::write(&file, mutated).unwrap_or_else(|e| die(&format!("{}: {e}", c.file)));
        run_ok(&root, &claims.build);
        let out = measure(&root, &claims, Some(c));
        put_back(false);

        let problems = compare(c, &out);
        tally[kind(c) as usize] += 1;
        if problems.is_empty() {
            println!("ok       {}  [{}]", c.row, kind(c).label());
        } else {
            bad += 1;
            println!("MISMATCH {}", c.row);
            for p in problems {
                println!("           {p}");
            }
        }
    }
    // Leave the code built as it is in the repository.
    run_ok(&root, &claims.build);

    println!(
        "{} by the fuzzer, {} by a test only, {} refused by something else, {} unproven",
        tally[Kind::Fuzz as usize], tally[Kind::Test as usize], tally[Kind::Refused as usize], tally[Kind::Unproven as usize]
    );

    if bad > 0 {
        println!("{bad} row(s) no longer read the way the file says");
        std::process::exit(1);
    }
}

/// What a row says notices the deletion, the strongest first.
#[derive(Clone, Copy)]
enum Kind {
    Fuzz,
    Test,
    Refused,
    Unproven,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Kind::Fuzz => "fuzzer",
            Kind::Test => "test",
            Kind::Refused => "refused elsewhere",
            Kind::Unproven => "UNPROVEN",
        }
    }
}

fn kind(c: &Claim) -> Kind {
    if c.fuzz.is_some() {
        Kind::Fuzz
    } else if !c.tests_fail.is_empty() {
        Kind::Test
    } else if c.refused.is_some() {
        Kind::Refused
    } else {
        Kind::Unproven
    }
}

/// Replaces `find` inside the function that starts at `in_fn`. Both must
/// occur exactly once, so a row cannot quietly delete some other check.
fn delete_check(src: &str, c: &Claim) -> Result<String, String> {
    let starts: Vec<usize> = src.match_indices(&c.in_fn).map(|(i, _)| i).collect();
    let [start] = starts[..] else {
        return Err(format!("`{}` occurs {} times in {}, not once", c.in_fn, starts.len(), c.file));
    };
    let end = function_end(src, start + c.in_fn.len()).ok_or(format!("no closing brace for `{}`", c.in_fn))?;
    let body = &src[start..end];
    let hits: Vec<usize> = body.match_indices(&c.find).map(|(i, _)| i).collect();
    let [at] = hits[..] else {
        return Err(format!("`{}` occurs {} times in `{}`, not once", c.find, hits.len(), c.in_fn));
    };
    let at = start + at;
    Ok(format!("{}{}{}", &src[..at], c.replace, &src[at + c.find.len()..]))
}

/// The end of the block whose `{` is the first one at or after `from`,
/// skipping braces in comments, string literals and char literals. Raw
/// strings are not understood; a `{` or `}` in one can end the block early.
fn function_end(src: &str, from: usize) -> Option<usize> {
    let b = src.as_bytes();
    let mut i = from;
    let mut depth = 0usize;
    let mut opened = false;
    while i < b.len() {
        match b[i] {
            b'/' if b.get(i + 1) == Some(&b'/') => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                    i += 1;
                }
                i += 1;
            }
            b'"' => {
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    if b[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            // A char literal ('{', '\''), not a lifetime ('a).
            b'\'' if b.get(i + 2) == Some(&b'\'') => i += 2,
            b'\'' if b.get(i + 1) == Some(&b'\\') => {
                i += 2;
                while i < b.len() && b[i] != b'\'' {
                    i += 1;
                }
            }
            b'{' => {
                depth += 1;
                opened = true;
            }
            b'}' if opened => {
                depth -= 1;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn measure(root: &Path, claims: &Claims, c: Option<&Claim>) -> Outcome {
    let (ok, tests) = output(root, &claims.test);
    if !tests.contains("test result:") {
        die(&format!("the tests did not run:\n{tests}"));
    }
    let failed_tests: Vec<String> = tests
        .lines()
        .filter_map(|l| l.strip_prefix("test ")?.strip_suffix(" ... FAILED"))
        .map(String::from)
        .collect();
    // A failing command with no failing test is a build error or a crash,
    // not a measurement.
    if !ok && failed_tests.is_empty() {
        die(&format!("`{}` failed without a failing test:\n{tests}", claims.test));
    }
    let expect = c.and_then(|c| c.fuzz.clone());
    let findings = match &claims.fuzz {
        Some(cmd) => fuzz(root, cmd, claims.fuzz_seconds, &claims.fuzz_alive, expect.as_deref()),
        None => vec![],
    };
    let probe = match (c.and_then(|c| c.refused.as_ref()), &claims.probe) {
        (Some(_), Some(cmd)) => {
            let (ok, out) = output(root, cmd);
            if !ok {
                die(&format!("`{cmd}` failed:\n{out}"));
            }
            out.lines().filter(|l| l.starts_with("PROBE ")).map(String::from).collect()
        }
        _ => vec![],
    };
    Outcome { findings, failed_tests, probe }
}

fn compare(c: &Claim, out: &Outcome) -> Vec<String> {
    let mut problems = vec![];
    match &c.fuzz {
        Some(want) if !out.findings.iter().any(|f| matches(f, want)) => {
            problems.push(format!("expected a finding with {want:?}, got {:?}", out.findings));
        }
        None if !out.findings.is_empty() => {
            problems.push(format!("expected no finding, got {:?}", out.findings));
        }
        _ => {}
    }
    // Each expected test names exactly one failed test; no other test failed.
    let mut matched = vec![false; out.failed_tests.len()];
    for want in &c.tests_fail {
        let hits: Vec<usize> = (0..out.failed_tests.len()).filter(|&i| test_is(&out.failed_tests[i], want)).collect();
        match hits[..] {
            [i] => matched[i] = true,
            [] => problems.push(format!("expected test `{want}` to fail; failed: {:?}", out.failed_tests)),
            _ => problems.push(format!("`{want}` names several failed tests: {:?}", out.failed_tests)),
        }
    }
    let unexpected: Vec<&String> = out.failed_tests.iter().zip(&matched).filter(|(_, m)| !**m).map(|(t, _)| t).collect();
    if !unexpected.is_empty() {
        problems.push(format!("tests failed that the row does not name: {unexpected:?}"));
    }
    if let Some(r) = &c.refused {
        let lines: Vec<(&str, Vec<&str>)> = out.probe.iter().filter_map(|l| probe_line(l, &r.probe)).collect();
        match &lines[..] {
            [] => problems.push(format!("no probe line `{}`", r.probe)),
            [(_, rest)] => {
                if rest.first() != Some(&"ok=false") {
                    problems.push(format!("`{}` was not refused: {rest:?}", r.probe));
                } else if !rest[1..].iter().any(|f| f.contains(r.log.as_str())) {
                    problems.push(format!("`{}` refused, but not with `{}`: {rest:?}", r.probe, r.log));
                }
            }
            _ => problems.push(format!("{} probe lines `{}`", lines.len(), r.probe)),
        }
    }
    problems
}

fn test_is(full: &str, want: &str) -> bool {
    full == want || full.ends_with(&format!("::{want}"))
}

/// `PROBE <spec> | <variant> | ...` for exactly this `<spec> | <variant>`;
/// returns the line and its remaining fields.
fn probe_line<'a>(line: &'a str, select: &str) -> Option<(&'a str, Vec<&'a str>)> {
    let fields: Vec<&str> = line.strip_prefix("PROBE ")?.split(" | ").map(str::trim).collect();
    let want: Vec<&str> = select.split('|').map(str::trim).collect();
    (fields.len() > want.len() && fields[..want.len()] == want[..]).then(|| (line, fields[want.len()..].to_vec()))
}

fn matches(finding: &str, want: &[String]) -> bool {
    want.iter().all(|w| finding.contains(w.as_str()))
}

/// Runs the fuzzer for up to `seconds`, stopping early at the finding the
/// row expects. Crucible checks its own `--timeout` only every 1,000
/// iterations (asymmetric-research/crucible#25), so the clock is kept here.
fn fuzz(root: &Path, cmd: &str, seconds: u64, alive_marker: &str, expect: Option<&[String]>) -> Vec<String> {
    use std::os::unix::process::CommandExt;
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(format!("{cmd} 2>&1"))
        .current_dir(root)
        .stdout(Stdio::piped())
        .process_group(0)
        .spawn()
        .unwrap_or_else(|e| die(&format!("{cmd}: {e}")));
    FUZZ_PGID.store(child.id() as i32, Ordering::SeqCst);
    let stdout = child.stdout.take().expect("piped");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut findings = vec![];
    let mut alive = false;
    let mut tail: Vec<String> = vec![];
    let mut hit = false;
    let mut exited = false;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(line) if line.starts_with("[FUZZ_FINDING] [") => {
                hit = expect.is_some_and(|e| matches(&line, e)) || expect.is_none();
                findings.push(line);
                if hit {
                    break;
                }
            }
            Ok(line) => {
                alive |= line.contains(alive_marker);
                tail.push(line);
                if tail.len() > 20 {
                    tail.remove(0);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => break,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                exited = true;
                break;
            }
        }
    }
    stop_fuzzer();
    let status = child.wait().ok();
    FUZZ_PGID.store(0, Ordering::SeqCst);
    // A fuzzer that stopped on its own before the clock, or never showed
    // it was running, measured nothing; its silence is not "no finding".
    if !hit {
        if exited && !status.is_some_and(|s| s.success()) {
            die(&format!("`{cmd}` exited early ({status:?}):\n{}", tail.join("\n")));
        }
        if !alive {
            die(&format!("`{cmd}` never printed `{alive_marker}`:\n{}", tail.join("\n")));
        }
    }
    findings.sort();
    findings.dedup();
    findings
}

/// Interrupts the fuzzer's process group, then kills whatever is left.
fn stop_fuzzer() {
    let pgid = FUZZ_PGID.load(Ordering::SeqCst);
    if pgid <= 0 {
        return;
    }
    let group = format!("-{pgid}");
    let _ = Command::new("kill").args(["-INT", "--", &group]).stderr(Stdio::null()).status();
    let stop = Instant::now() + Duration::from_secs(10);
    // The group is gone when `kill -0` finds no process in it.
    while Instant::now() < stop {
        let gone = !Command::new("kill").args(["-0", "--", &group]).stderr(Stdio::null()).status().is_ok_and(|s| s.success());
        if gone {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = Command::new("kill").args(["-KILL", "--", &group]).stderr(Stdio::null()).status();
}

fn output(root: &Path, cmd: &str) -> (bool, String) {
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!("{cmd} 2>&1"))
        .current_dir(root)
        .output()
        .unwrap_or_else(|e| die(&format!("{cmd}: {e}")));
    (out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned())
}

fn run_ok(root: &Path, cmd: &str) {
    let (ok, out) = output(root, cmd);
    if !ok {
        die(&format!("`{cmd}` failed:\n{out}"));
    }
}

fn backup_of(file: &Path) -> PathBuf {
    let mut name = file.as_os_str().to_owned();
    name.push(".unproven-orig");
    PathBuf::from(name)
}

fn restore_backup(file: &Path) {
    let backup = backup_of(file);
    if backup.exists() {
        std::fs::rename(&backup, file).unwrap_or_else(|e| {
            eprintln!("unproven: could not put {} back from {}: {e}", file.display(), backup.display());
            std::process::exit(2);
        });
        println!("restored {} from an interrupted run", file.display());
    }
}

/// Writes the original next to the file before it is changed. The backup is
/// removed only once the original is back and reads back the same.
fn set_aside(file: &Path, original: &str) {
    let backup = backup_of(file);
    if backup.exists() {
        die(&format!("{} already exists; refusing to overwrite it", backup.display()));
    }
    std::fs::write(&backup, original).unwrap_or_else(|e| die(&format!("{}: {e}", backup.display())));
    *EDITING.lock().unwrap_or_else(|e| e.into_inner()) = Some(file.to_path_buf());
}

/// Puts the file being edited back from its backup. On failure the backup
/// stays on disk and the run stops: no later row may start from a file that
/// is not the original. `keep_backup` leaves it for the next run as well.
fn put_back(keep_backup: bool) {
    let Some(file) = EDITING.lock().unwrap_or_else(|e| e.into_inner()).take() else {
        return;
    };
    let backup = backup_of(&file);
    let restored = std::fs::read(&backup)
        .and_then(|original| std::fs::write(&file, &original).map(|_| original))
        .and_then(|original| std::fs::read(&file).map(|now| now == original));
    match restored {
        Ok(true) if keep_backup => {}
        Ok(true) => {
            let _ = std::fs::remove_file(&backup);
        }
        _ => {
            eprintln!(
                "unproven: could not put {} back; the original is in {}",
                file.display(),
                backup.display()
            );
            std::process::exit(2);
        }
    }
}

fn default_fuzz_seconds() -> u64 {
    45
}

fn default_fuzz_alive() -> String {
    "[FUZZ_PULSE]".into()
}

fn die(msg: &str) -> ! {
    eprintln!("unproven: {msg}");
    stop_fuzzer();
    put_back(false);
    std::process::exit(2);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(in_fn: &str, find: &str) -> Claim {
        Claim {
            row: "r".into(),
            also: vec![],
            file: "f.rs".into(),
            in_fn: in_fn.into(),
            find: find.into(),
            replace: "X".into(),
            fuzz: None,
            tests_fail: vec![],
            refused: None,
        }
    }

    #[test]
    fn deletion_stays_in_its_function() {
        // `a` closes on its own line; the check in `b` must not be reachable.
        let src = "fn a() { }\nfn b() {\n    check();\n}\n";
        assert!(delete_check(src, &claim("fn a(", "check();")).is_err());
        assert_eq!(delete_check(src, &claim("fn b(", "check();")).unwrap(), "fn a() { }\nfn b() {\n    X\n}\n");
    }

    #[test]
    fn braces_in_strings_comments_and_chars_do_not_end_the_function() {
        let src = "fn a() {\n    let s = \"}\"; // }\n    /* } */ let c = '}';\n    check();\n}\nfn b() { check(); }\n";
        assert!(delete_check(src, &claim("fn a(", "check();")).unwrap().starts_with("fn a() {\n    let s"));
        assert!(delete_check(src, &claim("fn a(", "check();")).unwrap().contains("    X\n}\nfn b() { check(); }"));
    }

    #[test]
    fn ambiguous_text_is_refused() {
        let src = "fn a() { check(); check(); }\n";
        assert!(delete_check(src, &claim("fn a(", "check();")).is_err());
        let src = "fn a() { check(); }\n// fn a(\n";
        assert!(delete_check(src, &claim("fn a(", "check();")).is_err());
    }

    #[test]
    fn test_names_match_by_path_or_unambiguous_last_segment() {
        assert!(test_is("tests::a::rejects", "rejects"));
        assert!(test_is("tests::a::rejects", "a::rejects"));
        assert!(!test_is("tests::a::rejects_more", "rejects"));
        let mut c = claim("fn a(", "x");
        c.tests_fail = vec!["rejects".into()];
        let out = Outcome { findings: vec![], failed_tests: vec!["a::rejects".into(), "b::rejects".into()], probe: vec![] };
        assert!(compare(&c, &out).iter().any(|p| p.contains("several")));
    }

    #[test]
    fn probe_lines_are_selected_exactly() {
        let mut c = claim("fn a(", "x");
        c.refused = Some(Refused { probe: "open | signer off".into(), log: "unauthorized".into() });
        let out = |lines: &[&str]| Outcome { findings: vec![], failed_tests: vec![], probe: lines.iter().map(|l| l.to_string()).collect() };
        // A different spec whose name contains the selector does not count.
        assert!(!compare(&c, &out(&["PROBE open_position | signer off | ok=false | - | unauthorized"])).is_empty());
        assert!(compare(&c, &out(&["PROBE open | signer off | ok=false | - | unauthorized signer"])).is_empty());
        assert!(!compare(&c, &out(&["PROBE open | signer off | ok=true | - | unauthorized signer"])).is_empty());
    }
}
