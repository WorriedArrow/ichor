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
const FLOORS: (u64, u64) = (1000, 1000);

/// Cases that contradict another case: no one validator can agree with
/// both. Each names the case we agree with instead, and why. `services/x509`
/// follows the Web PKI's profile (CABF Baseline Requirements) where it and
/// RFC 5280 differ, as browsers and rustls do: it verifies public TLS
/// servers against Mozilla's roots. A conflict is checked on every run: the
/// case must still disagree with us, and its opposite agree.
const CONFLICTS: &[(&str, &str, &str)] = &[
    (
        "rfc5280::eku::ee-without-eku",
        "webpki::eku::ee-without-eku",
        "the Web PKI requires a leaf's extKeyUsage (CABF 7.1.2.7.6)",
    ),
    (
        "rfc5280::ca-as-leaf",
        "webpki::ca-as-leaf",
        "the Web PKI forbids a CA certificate as a TLS server's leaf (CABF 7.1.2.7.8)",
    ),
    (
        "pathlen::validation-ignores-pathlen-in-leaf",
        "webpki::ca-as-leaf",
        "its leaf is a CA certificate, which the Web PKI forbids as a leaf",
    ),
    (
        "rfc5280::nc::permitted-dns-match-noncritical",
        "webpki::nc::permitted-dns-match-noncritical",
        "the Web PKI allows non-critical name constraints (CABF 7.1.2.5.2); limbo marks it rfc5280-incompatible-with-webpki",
    ),
    (
        "rfc5280::aki::cross-signed-root-missing-aki",
        "cve::cve-2024-0567",
        "a trust anchor is a name and a key (RFC 5280 6.1.1); its own AKI is not checked, and the CVE case trusts a cross-signed root without one",
    ),
    (
        "webpki::cn::not-in-san",
        "bettertls::nameconstraints::tc1708",
        "the commonName is ignored, as in Chrome, Go and rustls: only SANs name the host, and bettertls's leaves carry unrelated CNs",
    ),
    (
        "webpki::cn::case-mismatch",
        "bettertls::nameconstraints::tc1708",
        "the commonName is ignored (see webpki::cn::not-in-san)",
    ),
    (
        "webpki::cn::punycode-not-in-san",
        "bettertls::nameconstraints::tc1708",
        "the commonName is ignored (see webpki::cn::not-in-san)",
    ),
    (
        "webpki::cn::utf8-vs-punycode-mismatch",
        "bettertls::nameconstraints::tc1708",
        "the commonName is ignored (see webpki::cn::not-in-san)",
    ),
    (
        "webpki::san::public-suffix-private-namespace-wildcard-san",
        "online::s3.amazonaws.com",
        "Amazon's real S3 certificate is *.s3.amazonaws.com, a suffix in the list's private section; only its ICANN section is used, as in Chrome",
    ),
];

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
    /// Every scored case's id and whether we agreed with it.
    agreed: BTreeMap<String, bool>,
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

fn score(case: &Value, now: u64, suffixes: &str, s: &mut Score) {
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
    // As on the boot volume: the roots, then the Public Suffix List.
    roots.push('\n');
    roots.push_str(suffixes);
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
    s.agreed.insert(id.clone(), expect_ok == got.is_ok());
    if CONFLICTS.iter().any(|(c, ..)| *c == id) {
        return;
    }
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
    let suffixes = artifact::public_suffix_block()?;
    let mut s = Score::default();
    for c in cases {
        score(c, now, &suffixes, &mut s);
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
        "| contradicts another case (below) | {} |",
        CONFLICTS.len()
    );
    let _ = writeln!(
        doc,
        "\n## Cases that contradict another\n\nNo one validator can agree with both cases of a pair; \
         `services/x509` follows the Web PKI's profile where it and RFC 5280 differ. Each is checked \
         on every run: we disagree with the first and agree with the second.\n\n\
         | Case | We agree instead with | Why |\n|---|---|---|"
    );
    let mut stale = Vec::new();
    for (case, other, why) in CONFLICTS {
        let _ = writeln!(doc, "| `{case}` | `{other}` | {why} |");
        if s.agreed.get(*case) != Some(&false) || s.agreed.get(*other) != Some(&true) {
            stale.push(*case);
        }
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
    if !stale.is_empty() {
        return Err(format!(
            "x509-limbo: these listed conflicts no longer hold (we agree with the case, or not with its opposite): {stale:?}"
        ));
    }
    if a < FLOORS.0 || r < FLOORS.1 {
        return Err(format!(
            "x509-limbo fell below its floors ({} / {} per mille)",
            FLOORS.0, FLOORS.1
        ));
    }
    Ok(())
}
