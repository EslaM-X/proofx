use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::{Verifier, VerifyingKey as PublicKey, SIGNATURE_LENGTH, PUBLIC_KEY_LENGTH};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::model::*;

fn detail_of(result: &Result<(), String>, ok_msg: &str) -> String {
    match result {
        Ok(()) => ok_msg.to_string(),
        Err(e) => e.clone(),
    }
}

#[derive(Debug)]
pub struct VerifyResult {
    pub valid: bool,
    pub proof_id: String,
    pub checks: Vec<Check>,
    pub coverage: Coverage,
    pub claims: Vec<ClaimResult>,
}

#[derive(Debug)]
pub struct Check {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug)]
pub struct ClaimResult {
    pub id: String,
    pub valid: bool,
    pub detail: String,
}

pub fn verify(proof: &Proof) -> VerifyResult {
    let mut checks = Vec::new();

    // 1. Schema validation
    let schema_result = validate_schema(proof);
    let schema_ok = schema_result.is_ok();
    checks.push(Check {
        name: "schema".into(),
        passed: schema_ok,
        detail: detail_of(&schema_result, "v0.4 proof structure valid"),
    });
    if !schema_ok {
        return make_result(proof, checks, false, false, false);
    }

    // 2. Evidence digests
    let ev_result = verify_evidence_digests(proof);
    let ev_ok = ev_result.is_ok();
    checks.push(Check {
        name: "evidence".into(),
        passed: ev_ok,
        detail: detail_of(&ev_result, &format!("{} evidence digests verified", proof.evidence.len())),
    });
    if !ev_ok {
        return make_result(proof, checks, false, false, false);
    }

    // 3. Binding root
    let bind_result = verify_binding(proof);
    let bind_ok = bind_result.is_ok();
    checks.push(Check {
        name: "binding".into(),
        passed: bind_ok,
        detail: detail_of(&bind_result, "merkle root matches evidence+relations+claims"),
    });
    if !bind_ok {
        return make_result(proof, checks, true, false, false);
    }

    // 4. Signature
    let sig_result = verify_signature(proof);
    let sig_ok = sig_result.is_ok();
    checks.push(Check {
        name: "signature".into(),
        passed: sig_ok,
        detail: detail_of(&sig_result, "ed25519 over v2 commitment"),
    });
    if !sig_ok {
        return make_result(proof, checks, true, true, false);
    }

    // 5. Claims
    let claim_results = verify_claims(proof);
    let claims_ok = claim_results.iter().all(|c| c.valid);
    checks.push(Check {
        name: "claims".into(),
        passed: claims_ok,
        detail: format!(
            "{}/{} claims verified",
            claim_results.iter().filter(|c| c.valid).count(),
            claim_results.len()
        ),
    });

    let mut result = make_result(proof, checks, true, true, claims_ok);
    result.valid = claims_ok;
    result.claims = claim_results;
    result
}

fn validate_schema(p: &Proof) -> Result<(), String> {
    if p.proof_version != PROOF_VERSION_V2 {
        return Err(format!(
            "proofVersion must be \"{}\", got \"{}\"",
            PROOF_VERSION_V2, p.proof_version
        ));
    }
    if p.execution.id.is_empty() {
        return Err("execution.id must not be empty".into());
    }
    if p.execution.exec_type.is_empty() {
        return Err("execution.type must not be empty".into());
    }

    // Check evidence IDs unique
    let mut seen = std::collections::HashSet::new();
    for e in &p.evidence {
        if e.id.is_empty() {
            return Err("evidence.id must not be empty".into());
        }
        if !seen.insert(&e.id) {
            return Err(format!("duplicate evidence.id: {}", e.id));
        }
    }

    // Check relation IDs unique and reference existing nodes
    let mut node_ids = std::collections::HashSet::new();
    node_ids.insert(&p.execution.id);
    for e in &p.evidence {
        node_ids.insert(&e.id);
    }
    for c in &p.claims {
        node_ids.insert(&c.id);
    }

    let mut seen_rel = std::collections::HashSet::new();
    for r in &p.relations {
        if r.id.is_empty() {
            return Err("relation.id must not be empty".into());
        }
        if !seen_rel.insert(&r.id) {
            return Err(format!("duplicate relation.id: {}", r.id));
        }
        if !node_ids.contains(&r.from) {
            return Err(format!(
                "relation[{}].from references nonexistent node: {}",
                r.id, r.from
            ));
        }
        if !node_ids.contains(&r.to) {
            return Err(format!(
                "relation[{}].to references nonexistent node: {}",
                r.id, r.to
            ));
        }
    }

    // Check claims
    let ev_ids: std::collections::HashSet<_> = p.evidence.iter().map(|e| &e.id).collect();
    let supported: std::collections::HashSet<_> = p
        .relations
        .iter()
        .filter(|r| r.kind == "supports")
        .map(|r| &r.to)
        .collect();

    for c in &p.claims {
        if c.id.is_empty() {
            return Err("claim.id must not be empty".into());
        }
        if c.supported_by.is_empty() {
            return Err(format!("claim[{}].supportedBy must not be empty", c.id));
        }
        for ref_id in &c.supported_by {
            if !ev_ids.contains(ref_id) {
                return Err(format!(
                    "claim[{}].supportedBy references nonexistent evidence: {}",
                    c.id, ref_id
                ));
            }
        }
        if !supported.contains(&c.id) {
            return Err(format!(
                "claim[{}] has no supports relation",
                c.id
            ));
        }
    }

    Ok(())
}

/// EvidenceDigest computes hex(SHA-256("proofx/evidence/v1\x00" + id + ":" + payload))
pub fn evidence_digest(id: &str, payload: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_EVIDENCE_V1);
    hasher.update(id.as_bytes());
    hasher.update(b":");
    hasher.update(payload.as_bytes());
    hex::encode(hasher.finalize())
}

/// RelationDigest computes hex(SHA-256(canonical_json({from, to, kind})))
///
/// Go's json.Marshal outputs struct fields in declaration order: From, To, Kind.
pub fn relation_digest(r: &Relation) -> String {
    let canonical = format!(
        "{{\"from\":\"{}\",\"to\":\"{}\",\"kind\":\"{}\"}}",
        escape_json(&r.from),
        escape_json(&r.to),
        escape_json(&r.kind),
    );
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hex::encode(hasher.finalize())
}

/// ClaimDigest computes hex(SHA-256(canonical_json({type, subject, statement, status, supportedBy})))
///
/// Go's json.Marshal outputs struct fields in declaration order.
pub fn claim_digest(c: &Claim) -> String {
    let supported_by_json: Vec<String> = c
        .supported_by
        .iter()
        .map(|s| format!("\"{}\"", escape_json(s)))
        .collect();
    let canonical = format!(
        "{{\"type\":\"{}\",\"subject\":\"{}\",\"statement\":\"{}\",\"status\":\"{}\",\"supportedBy\":[{}]}}",
        escape_json(&c.claim_type),
        escape_json(&c.subject),
        escape_json(&c.statement),
        escape_json(&c.status),
        supported_by_json.join(","),
    );
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out
}

fn verify_evidence_digests(p: &Proof) -> Result<(), String> {
    for e in &p.evidence {
        let want = evidence_digest(&e.id, &e.payload);
        if want != e.digest {
            return Err(format!(
                "evidence {}: digest mismatch: computed={} stored={}",
                e.id, want, e.digest
            ));
        }
    }
    Ok(())
}

/// V4BindingEntries builds the sorted entry list (ev: + rel: + claim:)
pub fn v4_binding_entries(p: &Proof) -> Vec<BindingEntry> {
    let mut entries = Vec::new();

    for e in &p.evidence {
        entries.push(BindingEntry {
            id: format!("ev:{}", e.id),
            digest: e.digest.clone(),
        });
    }

    for r in &p.relations {
        entries.push(BindingEntry {
            id: format!("rel:{}", r.id),
            digest: relation_digest(r),
        });
    }

    for c in &p.claims {
        entries.push(BindingEntry {
            id: format!("claim:{}", c.id),
            digest: claim_digest(c),
        });
    }

    entries.sort_by(|a, b| a.id.cmp(&b.id));
    entries
}

/// V4Root computes the Merkle root over binding entries.
///
/// Leaf:  SHA-256(DOMAIN_LEAF_V2 + id + ":" + digest)   [32 bytes]
/// Node:  SHA-256(DOMAIN_NODE_V2 + left_32 + right_32)  [78 bytes]
/// Odd:   promote unchanged
pub fn v4_root(entries: &[BindingEntry]) -> String {
    if entries.is_empty() {
        return String::new();
    }

    let mut sorted = entries.to_vec();
    sorted.sort_by(|a, b| a.id.cmp(&b.id));

    // Level 0: leaf hashes
    let mut level: Vec<[u8; 32]> = sorted
        .iter()
        .map(|e| {
            let mut hasher = Sha256::new();
            hasher.update(DOMAIN_LEAF_V2);
            hasher.update(e.id.as_bytes());
            hasher.update(b":");
            hasher.update(e.digest.as_bytes());
            hasher.finalize().into()
        })
        .collect();

    // Build tree
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                let mut hasher = Sha256::new();
                hasher.update(DOMAIN_NODE_V2);
                hasher.update(&level[i]);
                hasher.update(&level[i + 1]);
                next.push(hasher.finalize().into());
                i += 2;
            } else {
                // Odd node: promote unchanged
                next.push(level[i]);
                i += 1;
            }
        }
        level = next;
    }

    hex::encode(level[0])
}

fn verify_binding(p: &Proof) -> Result<(), String> {
    if p.binding.algorithm != "sha256" {
        return Err(format!(
            "unsupported binding algorithm: {}",
            p.binding.algorithm
        ));
    }
    let entries = v4_binding_entries(p);
    let want = v4_root(&entries);
    if want != p.binding.root {
        return Err(format!(
            "binding root mismatch: computed={} stored={}",
            want, p.binding.root
        ));
    }
    Ok(())
}

/// V4CommitmentDigest computes the NUL-separated commitment hash.
pub fn v4_commitment_digest(p: &Proof) -> String {
    let mut hasher = Sha256::new();

    hasher.update(p.proof_version.as_bytes());
    hasher.update([0x00]);
    hasher.update(p.project.name.as_bytes());
    hasher.update([0x00]);
    hasher.update(p.project.repository.as_bytes());
    hasher.update([0x00]);
    hasher.update(p.subject.commit.as_bytes());
    hasher.update([0x00]);
    hasher.update(p.subject.branch.as_bytes());
    hasher.update([0x00]);
    hasher.update(p.subject.repository.as_bytes());
    hasher.update([0x00]);

    // Execution
    hasher.update(p.execution.id.as_bytes());
    hasher.update([0x00]);
    hasher.update(p.execution.exec_type.as_bytes());
    hasher.update([0x00]);
    hasher.update(p.execution.started_at.as_bytes());
    hasher.update([0x00]);
    hasher.update(p.execution.completed_at.as_bytes());
    hasher.update([0x00]);

    // Claims sorted by ID
    let mut sorted_claims = p.claims.clone();
    sorted_claims.sort_by(|a, b| a.id.cmp(&b.id));
    for c in &sorted_claims {
        hasher.update(c.id.as_bytes());
        hasher.update([0x00]);
        hasher.update(c.claim_type.as_bytes());
        hasher.update([0x00]);
        hasher.update(c.statement.as_bytes());
        hasher.update([0x00]);
        hasher.update(c.status.as_bytes());
        hasher.update([0x00]);
    }

    hasher.update(p.binding.algorithm.as_bytes());
    hasher.update([0x00]);
    hasher.update(p.binding.root.as_bytes());

    hex::encode(hasher.finalize())
}

/// V4SigningPayload returns "proofx/sign/v2\x00" + commitmentDigest
pub fn v4_signing_payload(p: &Proof) -> Vec<u8> {
    let digest = v4_commitment_digest(p);
    let mut payload = Vec::with_capacity(DOMAIN_SIGN_V2.len() + digest.len());
    payload.extend_from_slice(DOMAIN_SIGN_V2);
    payload.extend_from_slice(digest.as_bytes());
    payload
}

fn verify_signature(p: &Proof) -> Result<(), String> {
    if p.signature.algorithm != "ed25519" {
        return Err(format!(
            "unsupported signature algorithm: {}",
            p.signature.algorithm
        ));
    }

    let pub_bytes = BASE64
        .decode(&p.signature.public_key)
        .map_err(|e| format!("bad public key: {}", e))?;
    if pub_bytes.len() != PUBLIC_KEY_LENGTH {
        return Err(format!(
            "bad public key length: {} (expected {})",
            pub_bytes.len(),
            PUBLIC_KEY_LENGTH
        ));
    }

    let sig_bytes = BASE64
        .decode(&p.signature.value)
        .map_err(|e| format!("bad signature: {}", e))?;
    if sig_bytes.len() != SIGNATURE_LENGTH {
        return Err(format!(
            "bad signature length: {} (expected {})",
            sig_bytes.len(),
            SIGNATURE_LENGTH
        ));
    }

    let mut pub_array = [0u8; PUBLIC_KEY_LENGTH];
    pub_array.copy_from_slice(&pub_bytes);
    let vk = PublicKey::from_bytes(&pub_array)
        .map_err(|e| format!("invalid public key: {}", e))?;

    let mut sig_array = [0u8; SIGNATURE_LENGTH];
    sig_array.copy_from_slice(&sig_bytes);
    let sig = ed25519_dalek::Signature::from_bytes(&sig_array);

    let payload = v4_signing_payload(p);
    vk.verify(&payload, &sig)
        .map_err(|e| format!("signature verification failed: {}", e))
}

fn verify_claims(p: &Proof) -> Vec<ClaimResult> {
    let ev_ids: std::collections::HashSet<_> = p.evidence.iter().map(|e| &e.id).collect();

    // Build supports map: claim_id -> [evidence_ids from relations]
    let mut supports_map: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for r in &p.relations {
        if r.kind == "supports" {
            supports_map.entry(&r.to).or_default().push(&r.from);
        }
    }

    p.claims
        .iter()
        .map(|c| {
            // Check supporting evidence exists
            if c.supported_by.is_empty() {
                return ClaimResult {
                    id: c.id.clone(),
                    valid: false,
                    detail: "no supporting evidence declared".into(),
                };
            }
            for ref_id in &c.supported_by {
                if !ev_ids.contains(ref_id) {
                    return ClaimResult {
                        id: c.id.clone(),
                        valid: false,
                        detail: format!("supporting evidence {} not found", ref_id),
                    };
                }
            }

            // Check supports relation exists
            if !supports_map.contains_key(c.id.as_str()) {
                return ClaimResult {
                    id: c.id.clone(),
                    valid: false,
                    detail: "no supports relation found".into(),
                };
            }

            ClaimResult {
                id: c.id.clone(),
                valid: true,
                detail: format!("backed by {} evidence nodes", c.supported_by.len()),
            }
        })
        .collect()
}

fn make_result(p: &Proof, checks: Vec<Check>, ev_ok: bool, bind_ok: bool, claim_ok: bool) -> VerifyResult {
    let ev_total = p.evidence.len() as u32;
    let ev_verified = if ev_ok { ev_total } else { 0 };
    let rel_total = p.relations.len() as u32;
    let rel_verified = if ev_ok && bind_ok { rel_total } else { 0 };
    let cl_total = p.claims.len() as u32;
    let cl_verified = if claim_ok { cl_total } else { 0 };

    let score = if ev_total + rel_total + cl_total > 0 {
        (ev_verified + rel_verified + cl_verified) * 100 / (ev_total + rel_total + cl_total)
    } else {
        0
    };

    let valid = checks.iter().all(|c| c.passed);

    VerifyResult {
        valid,
        proof_id: p.id.clone(),
        checks,
        coverage: Coverage {
            evidence: CoverageDim {
                total: ev_total,
                verified: ev_verified,
            },
            relations: CoverageDim {
                total: rel_total,
                verified: rel_verified,
            },
            claims: CoverageDim {
                total: cl_total,
                verified: cl_verified,
            },
            score,
        },
        claims: Vec::new(),
    }
}
