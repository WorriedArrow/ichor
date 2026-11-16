//! Scores `services/x509`'s path validation against x509-limbo (C2SP's
//! suite of certificate path-validation cases, pinned in
//! `artifact::X509_LIMBO`) and writes `docs/x509-limbo.md`.
//!
//! The control plane validates TLS *server* certificates for DNS names, so
//! those cases are scored. Client validation, IP and email peer names, and
//! revocation (CRLs) are not implemented; their cases are counted as not
//! applicable, by reason. A scored case passes when our verdict (accept or
//! refuse) matches the expected one. Accepting what should be refused is
//! the dangerous direction and is reported apart. The run fails if either
//! direction falls below its floor (`FLOORS`): raise the floors with the
//! change that earns it.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;

use oci::json::{self, Value};

use crate::{Result, artifact, workspace_root};

const DOC: &str = "docs/x509-limbo.md";

/// The least share (in tenths of a percent) of cases that must agree:
/// `(must accept, must refuse)`.
const FLOORS: (u64, u64) = (984, 994);

#[derive(Default)]
struct Score {
    accept_ok: u64,
    accept_total: u64,
    refuse_ok: u64,
    refuse_total: u64,
    skipped: BTreeMap<&'static str, u64>,
    /// Wrongly refused, by our error: case ids.
    refused: BTreeMap<String, Vec<String>>,
    /// Wrongly accepted: case ids (the dangerous direction).
    accepted: Vec<String>,
}

/// `YYYY-MM-DDTHH:MM:SS(Z|+00:00)` as Unix seconds.
fn rfc3339(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' {
        return None;
    }
    let n = |r: std::ops::Range<usize>| s.get(r)?.parse::<u16>().ok();
    civil::Civil {
        year: n(0..4)?,
        month: n(5..7)? as u8,
        day: n(8..10)? as u8,
        hour: n(11..13)? as u8,
        minute: n(14..16)? as u8,
        second: n(17..19)? as u8,
    }
    .unix_seconds()
}

fn pems(v: Option<&Value>) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for p in v.and_then(Value::as_array).unwrap_or(&[]) {
        out.extend(x509::pem_certificates(p.as_str().unwrap_or("")));
    }
    out
}

fn score(case: &Value, now: u64, s: &mut Score) {
    let id = case
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("?")
        .to_string();
    if case.get("validation_kind").and_then(Value::as_str) != Some("SERVER") {
        *s.skipped.entry("client validation").or_default() += 1;
        return;
    }
    let features = case
        .get("features")
        .and_then(Value::strings)
        .unwrap_or_default();
    if features.iter().any(|f| f == "has-crl") {
        *s.skipped.entry("revocation (CRLs)").or_default() += 1;
        return;
    }
    if case
        .get("max_chain_depth")
        .and_then(Value::as_u64)
        .is_some()
    {
        *s.skipped.entry("caller-chosen depth limits").or_default() += 1;
        return;
    }
    let name = case.get("expected_peer_name");
    let host = match name.and_then(|n| n.get("kind")).and_then(Value::as_str) {
        Some("DNS") => name
            .and_then(|n| n.get("value"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        Some("IP") => {
            *s.skipped.entry("IP address peer names").or_default() += 1;
            return;
        }
        Some(_) => {
            *s.skipped.entry("email peer names").or_default() += 1;
            return;
        }
        None => {
            *s.skipped.entry("no peer name to check").or_default() += 1;
            return;
        }
    };
    let expect_ok = case.get("expected_result").and_then(Value::as_str) == Some("SUCCESS");
    let at = case
        .get("validation_time")
        .and_then(Value::as_str)
        .and_then(rfc3339)
        .unwrap_or(now);
    let mut roots = String::new();
    for p in case
        .get("trusted_certs")
        .and_then(Value::as_array)
        .unwrap_or(&[])
    {
        roots.push_str(p.as_str().unwrap_or(""));
    }
    let roots = x509::RootStore::from_pem(&roots);
    let peer = case
        .get("peer_certificate")
        .and_then(Value::as_str)
        .unwrap_or("");
    let mut chain = x509::pem_certificates(peer);
    chain.extend(pems(case.get("untrusted_intermediates")));
    let refs: Vec<&[u8]> = chain.iter().map(Vec::as_slice).collect();
    let got = if refs.is_empty() {
        Err(x509::Error::Malformed)
    } else {
        x509::verify_chain(&refs, &roots, &host, at)
    };
    match (expect_ok, got) {
        (true, Ok(())) => {
            s.accept_ok += 1;
            s.accept_total += 1;
        }
        (true, Err(e)) => {
            s.accept_total += 1;
            s.refused.entry(format!("{e:?}")).or_default().push(id);
        }
        (false, Err(_)) => {
            s.refuse_ok += 1;
            s.refuse_total += 1;
        }
        (false, Ok(())) => {
            s.refuse_total += 1;
            s.accepted.push(id);
        }
    }
}

fn permille(ok: u64, total: u64) -> u64 {
    (ok * 1000).checked_div(total).unwrap_or(1000)
}

fn pct(ok: u64, total: u64) -> String {
    let p = permille(ok, total);
    format!("{}.{}%", p / 10, p % 10)
}

/// `cargo xtask x509-limbo`.
pub fn run() -> Result<()> {
    let bytes = artifact::X509_LIMBO.bytes()?;
    let suite = json::parse(&bytes).ok_or("limbo.json does not parse")?;
    let cases = suite
        .get("testcases")
        .and_then(Value::as_array)
        .ok_or("limbo.json has no testcases")?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut s = Score::default();
    for c in cases {
        score(c, now, &mut s);
    }
    let mut doc = String::new();
    let _ = writeln!(doc, "# x509-limbo results\n");
    let _ = writeln!(
        doc,
        "Generated by `cargo xtask x509-limbo` from x509-limbo at commit \
         `519f4bcf` ({} cases). Do not edit by hand.\n",
        cases.len()
    );
    let _ = writeln!(
        doc,
        "`services/x509` validates TLS server certificates for DNS names (the control \
         plane's registry pulls). A case passes when its verdict matches the suite's.\n"
    );
    let _ = writeln!(
        doc,
        "| Expected | Cases | Agree | Rate |\n|---|---:|---:|---:|"
    );
    let _ = writeln!(
        doc,
        "| accept | {} | {} | {} |",
        s.accept_total,
        s.accept_ok,
        pct(s.accept_ok, s.accept_total)
    );
    let _ = writeln!(
        doc,
        "| refuse | {} | {} | {} |\n",
        s.refuse_total,
        s.refuse_ok,
        pct(s.refuse_ok, s.refuse_total)
    );
    let _ = writeln!(doc, "## Not applicable\n\n| Why | Cases |\n|---|---:|");
    for (why, n) in &s.skipped {
        let _ = writeln!(doc, "| {why} | {n} |");
    }
    let _ = writeln!(
        doc,
        "\n## Accepted, should have been refused ({})\n",
        s.accepted.len()
    );
    for id in &s.accepted {
        let _ = writeln!(doc, "- `{id}`");
    }
    let _ = writeln!(doc, "\n## Refused, should have been accepted\n");
    for (why, ids) in &s.refused {
        let _ = writeln!(doc, "### {why} ({})\n", ids.len());
        for id in ids {
            let _ = writeln!(doc, "- `{id}`");
        }
        let _ = writeln!(doc);
    }
    let path = workspace_root().join(DOC);
    fs::write(&path, doc).map_err(|e| format!("{}: {e}", path.display()))?;
    let (a, r) = (
        permille(s.accept_ok, s.accept_total),
        permille(s.refuse_ok, s.refuse_total),
    );
    println!(
        "x509-limbo: accept {} of {} ({}), refuse {} of {} ({}); wrote {DOC}",
        s.accept_ok,
        s.accept_total,
        pct(s.accept_ok, s.accept_total),
        s.refuse_ok,
        s.refuse_total,
        pct(s.refuse_ok, s.refuse_total)
    );
    if a < FLOORS.0 || r < FLOORS.1 {
        return Err(format!(
            "x509-limbo fell below its floors ({} / {} per mille)",
            FLOORS.0, FLOORS.1
        ));
    }
    Ok(())
}
