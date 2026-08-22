# ProofX Attack Scenarios

> Catalog of known adversarial strategies against v0.4 proofs.
> Each scenario has a PoC test in `verifycore/v2_attack_test.go`.

## Status

| # | Scenario | Severity | Mitigated | PoC |
|---|----------|----------|-----------|-----|
| 1 | Cross-key signature forgery | High | ✅ | `TestAttack_CrossKeySignature` |
| 2 | Evidence node swap | High | ✅ | `TestAttack_EvidenceSwap` |
| 3 | Version downgrade | High | ✅ | `TestAttack_VersionDowngrade` |
| 4 | Signature truncation | Medium | ✅ | `TestAttack_SignatureTruncated` |
| 5 | Empty proof rejection | Low | ✅ | `TestAttack_EmptyProof` |
| 6 | Empty binding root | Medium | ✅ | `TestAttack_EmptyBindingRoot` |
| 7 | Self-referencing claim | Medium | ✅ | `TestAttack_SelfRefClaim` |
| 8 | v1→v2 domain label confusion | High | ✅ | `TestAttack_DomainLabelConfusion` |
| 9 | Replay with mutation | High | ✅ | `TestAttack_ReplayMutation` |
| 10 | Signature value swap | High | ✅ | `TestAttack_SignatureSwap` |
| 11 | Public key byte flip | High | ✅ | `TestAttack_PublicKeyFlip` |
| 12 | Proof ID manipulation | High | ✅ | `TestAttack_ProofIDManipulation` |
| 13 | Unicode normalization evasion | Medium | ✅ | `TestAttack_UnicodeNormalization` |
| 14 | Binding root reuse across proofs | High | ✅ | `TestAttack_BindingRootReuse` |

## Detailed Scenarios

### 1. Cross-key signature forgery
**Attack:** Sign a proof with the attacker's key but leave the victim's public key in the proof document.
**Expected:** Signature verification fails because the signed payload doesn't match the embedded public key.
**Defense:** Ed25519 binds the public key to the signature cryptographically.

### 2. Evidence node swap
**Attack:** Move evidence from node A to node B (keep the digest). The Merkle leaf ID changes (`ev:A` → `ev:B`), so the root no longer matches.
**Expected:** Binding root mismatch.
**Defense:** Merkle leaves include the full ID prefix (`ev:` + id), not just the digest.

### 3. Version downgrade
**Attack:** Change `proofVersion` from `"2.0"` to `"1.0"` to bypass v0.4 validation.
**Expected:** Parser rejects the proof (`V4ParseProof` enforces `"2.0"`).
**Defense:** Version gate at parse time; commitment digest includes version string.

### 4. Signature truncation
**Attack:** Remove trailing bytes from the base64-encoded signature.
**Expected:** Base64 decode succeeds (padding adjusts), but Ed25519 Verify returns false (wrong length or invalid signature).
**Defense:** Ed25519 signature must be exactly 64 bytes.

### 5. Empty proof rejection
**Attack:** Submit an empty JSON object `{}`.
**Expected:** Schema validation fails (missing required fields: proofVersion, id, etc.).
**Defense:** `model.Validate()` enforces structural invariants.

### 6. Empty binding root
**Attack:** Set `binding.root` to empty string while keeping valid-looking entries.
**Expected:** Binding check fails — recomputed root ≠ empty string.
**Defense:** Merkle root computation is deterministic; empty root only valid for zero entries.

### 7. Self-referencing claim
**Attack:** A claim declares `supportedBy` referencing itself (circular dependency).
**Expected:** Schema validation fails — claim IDs are not evidence IDs; `evIDs` set doesn't contain claim IDs.
**Defense:** Claims must reference evidence nodes; self-reference is a schema violation.

### 8. v1→v2 domain label confusion
**Attack:** Use `proofx/leaf/v1` domain labels in a v0.4 Merkle tree.
**Expected:** Different hash output → root mismatch → binding fails.
**Defense:** Domain separation: `v1` and `v2` produce completely different hashes for the same input.

### 9. Replay with mutation
**Attack:** Take a valid proof, modify one field, keep the old signature.
**Expected:** Commitment digest changes (field is included) → signature fails.
**Defense:** Commitment covers all structural fields; any mutation breaks the signature.

### 10. Signature value swap
**Attack:** Take two valid proofs A and B; swap their signature values.
**Expected:** Each signature is over a different commitment digest → neither verifies.
**Defense:** Signature is over `proofx/sign/v2\x00` + commitment, which includes all proof-specific data.

### 11. Public key byte flip
**Attack:** Flip one bit in the public key (keeping signature unchanged).
**Expected:** Ed25519 Verify returns false — the key doesn't match the signing key.
**Defense:** Ed25519 binding is bit-exact.

### 12. Proof ID manipulation
**Attack:** Change `proof.id` (e.g., `PX-abc` → `PX-xyz`) while keeping the signature.
**Expected:** Commitment digest includes `proof.id` → signature fails.
**Defense:** ID is part of the signed commitment.

### 13. Unicode normalization evasion
**Attack:** Use Unicode characters in evidence payloads that normalize differently under NFC/NFD.
**Expected:** Canonical JSON serialization normalizes to a single form; digest is deterministic.
**Defense:** Go's `encoding/json` produces NFC-normalized output; canonicalization is deterministic.

### 14. Binding root reuse across proofs
**Attack:** Copy the binding root from proof A into proof B (different evidence).
**Expected:** Proof B's recomputed root ≠ copied root → binding fails.
**Defense:** Root is a hash of the actual binding entries; can't be reused across different content.

## Running the Attack Tests

```bash
go test -v -run TestAttack ./verifycore/
```

## Adding New Scenarios

1. Document the scenario above with status `⏳ Pending`
2. Add a `TestAttack_*` function in `v2_attack_test.go`
3. Verify the attack is defeated (test asserts `res.Valid == false`)
4. Update the table with `✅` and the test name
