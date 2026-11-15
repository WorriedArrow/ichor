//! Enforcement of the unsafe-code policy (ADR-0001):
//!
//! * every kernel crate other than `kernel/frame` declares
//!   `#![forbid(unsafe_code)]` at its crate root;
//! * `kernel/frame` stays within the line and unsafe-site budget recorded in
//!   `kernel/frame/audit.toml`.

use std::fs;
use std::path::{Path, PathBuf};

use crate::{Result, workspace_root};

/// Size metrics of the frame crate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FrameMetrics {
    /// Non-blank lines that are not pure comments.
    pub code_lines: usize,
    /// `unsafe` blocks, fns, impls, extern blocks and attributes.
    pub unsafe_sites: usize,
}

/// The budget from `kernel/frame/audit.toml`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameBudget {
    pub max_code_lines: usize,
    pub max_unsafe_sites: usize,
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let entries = fs::read_dir(dir).map_err(|e| format!("reading {}: {e}", dir.display()))?;
    for entry in entries {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.is_dir() {
            rust_files(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    out.sort();
    Ok(())
}

/// Strips `//` comments and the contents of string literals from one line.
/// Good enough for counting: frame does not use raw strings or block
/// comments, and `audit` would only over-count if it did.
fn code_part(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    let mut in_str = false;
    while let Some(c) = chars.next() {
        if in_str {
            match c {
                '\\' => {
                    chars.next();
                }
                '"' => {
                    in_str = false;
                    out.push('"');
                }
                _ => {}
            }
            continue;
        }
        match c {
            '"' => {
                in_str = true;
                out.push('"');
            }
            '/' if chars.peek() == Some(&'/') => break,
            _ => out.push(c),
        }
    }
    out
}

/// Counts `unsafe` keyword sites in a line of code.
fn count_unsafe(code: &str) -> usize {
    let bytes = code.as_bytes();
    let mut count = 0;
    let mut i = 0;
    while let Some(off) = code[i..].find("unsafe") {
        let start = i + off;
        let end = start + "unsafe".len();
        let ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
        let before_ok = start == 0 || !ident(bytes[start - 1]);
        let after_ok = end >= bytes.len() || !ident(bytes[end]);
        // Exclude the lint name `unsafe_code`/`unsafe_op_in_unsafe_fn` etc.
        if before_ok && after_ok {
            count += 1;
        }
        i = end;
    }
    count
}

/// Measures the frame crate.
pub fn frame_metrics() -> Result<FrameMetrics> {
    let mut files = Vec::new();
    rust_files(&workspace_root().join("kernel/frame/src"), &mut files)?;
    let mut m = FrameMetrics::default();
    for file in files {
        let text = fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display()))?;
        for line in text.lines() {
            let code = code_part(line);
            if code.trim().is_empty() {
                continue;
            }
            m.code_lines += 1;
            m.unsafe_sites += count_unsafe(&code);
        }
    }
    Ok(m)
}

/// Reads `kernel/frame/audit.toml` (a flat `key = integer` file).
pub fn frame_budget() -> Result<FrameBudget> {
    let path = workspace_root().join("kernel/frame/audit.toml");
    let text = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let get = |key: &str| -> Result<usize> {
        text.lines()
            .map(|l| l.split('#').next().unwrap_or("").trim())
            .filter_map(|l| l.split_once('='))
            .find(|(k, _)| k.trim() == key)
            .ok_or_else(|| format!("{}: missing {key}", path.display()))?
            .1
            .trim()
            .replace('_', "")
            .parse()
            .map_err(|e| format!("{}: {key}: {e}", path.display()))
    };
    Ok(FrameBudget {
        max_code_lines: get("max_code_lines")?,
        max_unsafe_sites: get("max_unsafe_sites")?,
    })
}

/// Fails if frame exceeds its budget.
pub fn check_frame_budget() -> Result<FrameMetrics> {
    let m = frame_metrics()?;
    let b = frame_budget()?;
    println!(
        "frame: {} code lines (budget {}), {} unsafe sites (budget {})",
        m.code_lines, b.max_code_lines, m.unsafe_sites, b.max_unsafe_sites
    );
    let mut errors = Vec::new();
    if m.code_lines > b.max_code_lines {
        errors.push(format!(
            "frame has {} code lines, budget is {}",
            m.code_lines, b.max_code_lines
        ));
    }
    if m.unsafe_sites > b.max_unsafe_sites {
        errors.push(format!(
            "frame has {} unsafe sites, budget is {}",
            m.unsafe_sites, b.max_unsafe_sites
        ));
    }
    if errors.is_empty() {
        Ok(m)
    } else {
        Err(format!(
            "{}\nGrowing frame requires an ADR; update kernel/frame/audit.toml in the same change.",
            errors.join("\n")
        ))
    }
}

/// Fails unless every kernel crate except frame forbids unsafe code.
pub fn check_forbid_unsafe() -> Result<usize> {
    let root = workspace_root();
    let mut manifests = Vec::new();
    find_manifests(&root.join("kernel"), &mut manifests)?;
    if root.join("services").is_dir() {
        find_manifests(&root.join("services"), &mut manifests)?;
    }
    let mut checked = 0;
    let mut errors = Vec::new();
    for manifest in manifests {
        let dir = manifest.parent().unwrap_or(&root).to_path_buf();
        if dir == root.join("kernel/frame") {
            continue;
        }
        for crate_root in ["src/lib.rs", "src/main.rs"] {
            let path = dir.join(crate_root);
            let Ok(text) = fs::read_to_string(&path) else {
                continue;
            };
            checked += 1;
            let has_forbid = text
                .lines()
                .map(|l| code_part(l).replace(' ', ""))
                .any(|l| l == "#![forbid(unsafe_code)]");
            if !has_forbid {
                errors.push(format!("{} lacks #![forbid(unsafe_code)]", path.display()));
            }
        }
    }
    if errors.is_empty() {
        println!("forbid(unsafe_code): {checked} crate roots checked");
        Ok(checked)
    } else {
        Err(errors.join("\n"))
    }
}

fn find_manifests(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let entries = fs::read_dir(dir).map_err(|e| format!("reading {}: {e}", dir.display()))?;
    for entry in entries {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            find_manifests(&path, out)?;
        } else if path.file_name().is_some_and(|n| n == "Cargo.toml") {
            out.push(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_unsafe_keywords_not_identifiers() {
        assert_eq!(count_unsafe("unsafe { x }"), 1);
        assert_eq!(count_unsafe("unsafe fn f() { unsafe { g() } }"), 2);
        assert_eq!(count_unsafe("#[unsafe(no_mangle)]"), 1);
        assert_eq!(count_unsafe("#![forbid(unsafe_code)]"), 0);
        assert_eq!(count_unsafe("unsafe_op_in_unsafe_fn"), 0);
        assert_eq!(count_unsafe("not_unsafe"), 0);
    }

    #[test]
    fn strips_comments_and_strings() {
        assert_eq!(code_part("let x = 1; // unsafe"), "let x = 1; ");
        assert_eq!(code_part(r#"f("unsafe // no")"#), r#"f("")"#);
        assert_eq!(code_part(r#"f("a\"b") // c"#), r#"f("") "#);
        assert_eq!(code_part("/// docs"), "");
    }

    #[test]
    fn frame_is_measurable() {
        let m = frame_metrics().unwrap();
        assert!(m.code_lines > 0);
    }
}
