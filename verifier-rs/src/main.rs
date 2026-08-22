use std::env;
use std::fs;
use std::process;

use proofx_verifier::{verify, Proof};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: proofx-verify <proof.json>");
        process::exit(1);
    }

    let path = &args[1];
    let data = fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("Error reading {}: {}", path, e);
        process::exit(1);
    });

    let proof: Proof = serde_json::from_str(&data).unwrap_or_else(|e| {
        eprintln!("Error parsing proof: {}", e);
        process::exit(1);
    });

    let result = verify(&proof);

    // Print results
    println!("PROOFX VERIFY — {}", result.proof_id);
    println!();

    for check in &result.checks {
        let status = if check.passed { "PASS" } else { "FAIL" };
        println!("  [{}] {}: {}", status, check.name, check.detail);
    }

    println!();
    println!(
        "Coverage: evidence={}/{} relations={}/{} claims={}/{} score={}",
        result.coverage.evidence.verified,
        result.coverage.evidence.total,
        result.coverage.relations.verified,
        result.coverage.relations.total,
        result.coverage.claims.verified,
        result.coverage.claims.total,
        result.coverage.score,
    );

    if !result.claims.is_empty() {
        println!();
        for cr in &result.claims {
            let status = if cr.valid { "PASS" } else { "FAIL" };
            println!("  [{}] {}: {}", status, cr.id, cr.detail);
        }
    }

    println!();
    if result.valid {
        println!("RESULT: VALID");
    } else {
        println!("RESULT: INVALID");
        process::exit(1);
    }
}
