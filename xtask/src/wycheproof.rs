//! Runs Wycheproof's ML-DSA verification vectors (C2SP, pinned in
//! `artifact::WYCHEPROOF_MLDSA`) through `crypto::mldsa`: every vector
//! must get the verdict it expects, valid or invalid. Its invalid ones are
//! what a verifier tested only on good signatures misses: keys and
//! signatures a byte short or long, hints out of order, repeated or past
//! omega, non-zero padding after the hints, z over its norm bound, a
//! context over 255 bytes. BoringSSL and OpenSSL run the same files.

use oci::json::{self, Value};

use crate::{Result, artifact};

fn hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// `cargo xtask wycheproof`.
pub fn run() -> Result<()> {
    let params = [
        ("ML-DSA-44", &crypto::mldsa::ML_DSA_44),
        ("ML-DSA-65", &crypto::mldsa::ML_DSA_65),
        ("ML-DSA-87", &crypto::mldsa::ML_DSA_87),
    ];
    let mut wrong = Vec::new();
    for (artifact, (name, p)) in artifact::WYCHEPROOF_MLDSA.iter().zip(params) {
        let bytes = artifact.bytes()?;
        let suite =
            json::parse(&bytes).ok_or_else(|| format!("{}: does not parse", artifact.file))?;
        if suite.get("algorithm").and_then(Value::as_str) != Some(name) {
            return Err(format!("{}: not {name}", artifact.file));
        }
        let expected = suite.get("numberOfTests").and_then(Value::as_u64);
        let (mut valid, mut invalid) = (0u64, 0u64);
        for group in suite
            .get("testGroups")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("{}: no testGroups", artifact.file))?
        {
            let pk = group
                .get("publicKey")
                .and_then(Value::as_str)
                .and_then(hex)
                .ok_or_else(|| format!("{}: a group has no publicKey", artifact.file))?;
            for t in group.get("tests").and_then(Value::as_array).unwrap_or(&[]) {
                let field = |k: &str| t.get(k).and_then(Value::as_str).and_then(hex);
                let id = t.get("tcId").and_then(Value::as_u64).unwrap_or(0);
                let (Some(msg), Some(sig)) = (field("msg"), field("sig")) else {
                    return Err(format!("{}: test {id} is malformed", artifact.file));
                };
                let ctx = field("ctx").unwrap_or_default();
                let want = match t.get("result").and_then(Value::as_str) {
                    Some("valid") => true,
                    Some("invalid") => false,
                    other => {
                        return Err(format!("{}: test {id} has result {other:?}", artifact.file));
                    }
                };
                if want {
                    valid += 1;
                } else {
                    invalid += 1;
                }
                if crypto::mldsa::verify_with_context(p, &pk, &msg, &ctx, &sig) != want {
                    let comment = t.get("comment").and_then(Value::as_str).unwrap_or("");
                    wrong.push(format!(
                        "{name} test {id} ({comment}): expected {}",
                        if want { "valid" } else { "invalid" }
                    ));
                }
            }
        }
        if expected != Some(valid + invalid) {
            return Err(format!(
                "{}: ran {} tests, the file says {expected:?}",
                artifact.file,
                valid + invalid
            ));
        }
        println!("wycheproof: {name}: {valid} valid and {invalid} invalid vectors");
    }
    if wrong.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "wycheproof: {} ML-DSA vectors got the wrong verdict:\n  {}",
            wrong.len(),
            wrong.join("\n  ")
        ))
    }
}
