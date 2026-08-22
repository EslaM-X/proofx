pub mod model;
pub mod verify;

pub use model::*;
pub use verify::*;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn load_proof(name: &str) -> Proof {
        let path = format!("../conformance/golden/{}", name);
        let data = fs::read_to_string(&path).expect("failed to read golden vector");
        serde_json::from_str(&data).expect("failed to parse golden vector")
    }

    #[test]
    fn golden_valid() {
        let proof = load_proof("golden-v04-valid.json");
        let result = verify(&proof);
        assert!(result.valid, "valid proof should pass: {:?}", result.checks);
        assert_eq!(result.coverage.score, 100);
        assert_eq!(result.claims.len(), 2);
        assert!(result.claims.iter().all(|c| c.valid));
    }

    #[test]
    fn golden_tampered_sig() {
        let proof = load_proof("golden-v04-tampered-sig.json");
        let result = verify(&proof);
        assert!(!result.valid);
        let sig_check = result.checks.iter().find(|c| c.name == "signature").unwrap();
        assert!(!sig_check.passed, "signature should fail");
    }

    #[test]
    fn golden_tampered_claim() {
        let proof = load_proof("golden-v04-tampered-claim.json");
        let result = verify(&proof);
        assert!(!result.valid);
        let bind_check = result.checks.iter().find(|c| c.name == "binding").unwrap();
        assert!(!bind_check.passed, "binding should fail");
    }

    #[test]
    fn golden_missing_relation() {
        let proof = load_proof("golden-v04-missing-relation.json");
        let result = verify(&proof);
        assert!(!result.valid);
        let schema_check = result.checks.iter().find(|c| c.name == "schema").unwrap();
        assert!(!schema_check.passed, "schema should fail");
    }

    #[test]
    fn golden_wrong_version() {
        let proof = load_proof("golden-v04-wrong-version.json");
        let result = verify(&proof);
        assert!(!result.valid);
        let schema_check = result.checks.iter().find(|c| c.name == "schema").unwrap();
        assert!(!schema_check.passed, "schema should fail");
    }

    #[test]
    fn relation_digest_deterministic() {
        let r = Relation { id: "r1".into(), from: "git".into(), to: "c1".into(), kind: "supports".into() };
        let d1 = verify::relation_digest(&r);
        let d2 = verify::relation_digest(&r);
        assert_eq!(d1, d2);
        assert_eq!(d1.len(), 64); // SHA-256 hex
    }

    #[test]
    fn claim_digest_deterministic() {
        let c = Claim {
            id: "c1".into(),
            claim_type: "assertion".into(),
            subject: "proof:ci".into(),
            statement: "commit is correct".into(),
            status: "pass".into(),
            supported_by: vec!["git".into(), "tests".into()],
        };
        let d1 = verify::claim_digest(&c);
        let d2 = verify::claim_digest(&c);
        assert_eq!(d1, d2);
        assert_eq!(d1.len(), 64);
    }

    #[test]
    fn root_deterministic_regardless_of_input_order() {
        let entries = vec![
            BindingEntry { id: "ev:b".into(), digest: "bb".into() },
            BindingEntry { id: "ev:a".into(), digest: "aa".into() },
            BindingEntry { id: "ev:c".into(), digest: "cc".into() },
        ];
        let r1 = verify::v4_root(&entries);
        let mut reversed = entries.clone();
        reversed.reverse();
        let r2 = verify::v4_root(&reversed);
        assert_eq!(r1, r2, "root must be order-independent");
    }

    #[test]
    fn root_single_entry() {
        let entries = vec![BindingEntry { id: "ev:only".into(), digest: "deadbeef".into() }];
        let root = verify::v4_root(&entries);
        assert_eq!(root.len(), 64);
        assert!(!root.is_empty());
    }

    #[test]
    fn root_empty() {
        let entries: Vec<BindingEntry> = vec![];
        let root = verify::v4_root(&entries);
        assert!(root.is_empty());
    }
}
