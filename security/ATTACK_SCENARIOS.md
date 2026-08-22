# ProofX v0.4 — Adversarial Test Corpus

> This document catalogs known adversarial strategies against v0.4 proofs.
> Each scenario has a corresponding PoC test in `verifycore/v2_attack_test.go`.
>
> **Scope:** These tests verify that the v0.4 verification pipeline rejects
> structurally invalid or tampered proofs. They are a necessary but not
> sufficient condition for security. Attack coverage is not proof of security.

---

## Corpus Summary

| Metric | Count |
|--------|-------|
| Documented attack scenarios | 14 |
| PoC tests (TestAttack_*) | 14 |
| All scenarios rejected | Yes |
| Cross-language verification | Go, Rust, WASM |

---

## Attack Catalog

### 1. Cross-key signature forgery

- **PoC:** `TestAttack_CrossKeySignature`
- **Threat:** Attacker signs a proof with their own private key but embeds the victim's public key in the proof document. A naive verifier might trust the embedded key and accept the forged signature.
- **Expected invariant:** The embedded public key must correspond to the private key that produced the signature. Substituting either component without re-signing must invalidate the proof.
- **Mechanism:** Ed25519 verification computes `Verify(publicKey, payload, signature)`. The payload includes `proofx/sign/v2\x00` + commitment digest, which covers the entire proof structure. If the attacker signs with their key but embeds the victim's key, `Verify(victimKey, payload, attackerSignature)` returns false — the key and signature are cryptographically mismatched.
- **Result:** REJECTED

### 2. Evidence node swap

- **PoC:** `TestAttack_EvidenceSwap`
- **Threat:** Attacker moves evidence from node A to node B (keeping the original digest), hoping the Merkle root will still match because the digest is unchanged.
- **Expected invariant:** The Merkle binding root must commit to both the digest AND the identity of each evidence node. Changing a node's ID without recomputing its digest must break the root.
- **Mechanism:** Merkle leaves are computed as `H(DomainLeafV2 || "ev:" + id || ":" || digest)`. Changing the ID from `"git"` to `"tests"` produces a different leaf hash (`"ev:git"` vs `"ev:tests"`), even with the same digest. The recomputed root diverges from the stored root.
- **Result:** REJECTED

### 3. Version downgrade

- **PoC:** `TestAttack_VersionDowngrade`
- **Threat:** Attacker changes `proofVersion` from `"2.0"` to `"1.0"` to bypass v0.4-specific validation rules, potentially exploiting weaker v0.3 verification logic.
- **Expected invariant:** The parser must enforce the exact proof version. A proof claiming version `"1.0"` must not be accepted by the v0.4 verification pipeline.
- **Mechanism:** `V4ParseProof` checks `p.ProofVersion != "2.0"` and returns an error before any verification occurs. Additionally, the commitment digest includes the version string — even if parsing were bypassed, the signature would fail.
- **Result:** REJECTED

### 4. Signature truncation

- **PoC:** `TestAttack_SignatureTruncated`
- **Threat:** Attacker truncates the base64-encoded signature to fewer bytes, hoping a partial signature might still pass verification or that the verifier might be lenient about signature length.
- **Expected invariant:** An Ed25519 signature must be exactly 64 bytes. Any truncation, padding, or extension must cause verification failure.
- **Mechanism:** After base64 decoding, `ed25519.Verify` checks that the signature is exactly `ed25519.SignatureSize` (64 bytes). A 32-byte truncated signature fails this check before any cryptographic computation occurs.
- **Result:** REJECTED

### 5. Empty proof rejection

- **PoC:** `TestAttack_EmptyProof`
- **Threat:** Attacker submits an empty JSON object `{}` or a minimal structure, hoping the verifier will accept it as a valid (albeit empty) proof.
- **Expected invariant:** A proof must contain all mandatory structural fields: `proofVersion`, `id`, `project`, `subject`, `execution`, `evidence`, `binding`, `signature`, `coverage`. An empty object must be rejected.
- **Mechanism:** `model.Validate()` enforces structural invariants: non-empty `proofVersion`, non-empty `id`, non-empty `binding.algorithm`, non-empty `signature.algorithm`. An empty object fails all of these checks.
- **Result:** REJECTED

### 6. Empty binding root

- **PoC:** `TestAttack_EmptyBindingRoot`
- **Threat:** Attacker sets `binding.root` to an empty string while keeping valid-looking entries, hoping the verifier might accept an empty root as a special case.
- **Expected invariant:** The binding root must equal the recomputed Merkle root over all binding entries. An empty root is only valid when there are zero entries. If entries exist, the root must be non-empty.
- **Mechanism:** `V4BindingEntries` produces the canonical entry list. `V4Root` hashes these entries into a Merkle root. If entries exist but `binding.root` is empty, `computedRoot != ""` → binding check fails.
- **Result:** REJECTED

### 7. Self-referencing claim

- **PoC:** `TestAttack_SelfRefClaim`
- **Threat:** Attacker creates a claim that declares `supportedBy` referencing itself, creating a circular dependency. The claim appears to have supporting evidence, but the "evidence" is the claim itself.
- **Expected invariant:** Claims must reference evidence nodes, not other claims or themselves. The set of valid supporting references is restricted to evidence IDs that exist in the proof.
- **Mechanism:** `verifyV4Claims` builds a set of evidence IDs (`evIDs`). When checking `supportedBy`, it verifies each reference exists in `evIDs`. A claim ID is not in `evIDs` → "supporting evidence not found" → claim fails → verification fails.
- **Result:** REJECTED

### 8. v1 to v2 domain label confusion

- **PoC:** `TestAttack_DomainLabelConfusion`
- **Threat:** Attacker constructs a Merkle tree using v1 domain labels (`proofx/leaf/v1`, `proofx/node/v1`) in a v0.4 proof, hoping the root will be accepted by a verifier that doesn't check domain separation.
- **Expected invariant:** Domain labels must be version-specific. The same data hashed with v1 labels must produce a different root than v2 labels. A v0.4 verifier must only accept roots computed with v2 labels.
- **Mechanism:** `V4Root` uses `DomainLeafV2 = "proofx/leaf/v2\x00"` and `DomainNodeV2 = "proofx/node/v2\x00"`. These labels are prepended to every hash input. Using v1 labels produces completely different leaf hashes → different root → binding fails. The test also verifies root determinism: calling `V4Root` twice with the same entries produces identical results.
- **Result:** REJECTED

### 9. Replay with mutation

- **PoC:** `TestAttack_ReplayMutation`
- **Threat:** Attacker takes a valid proof, modifies a single field (e.g., `project.name`), and resubmits it — keeping the original signature unchanged.
- **Expected invariant:** The commitment digest must cover all structural fields. Any mutation to any field must change the commitment digest, invalidating the original signature.
- **Mechanism:** `V4CommitmentDigest` hashes `proofVersion`, `project.name`, `project.repository`, `subject.commit`, `subject.branch`, `subject.repository`, `execution.id`, `execution.type`, `execution.startedAt`, `execution.completedAt`, all claims, `binding.algorithm`, and `binding.root` — separated by NUL bytes. Changing `project.name` changes the commitment → `V4SigningPayload` changes → original signature fails `ed25519.Verify`.
- **Result:** REJECTED

### 10. Signature value swap

- **PoC:** `TestAttack_SignatureSwap`
- **Threat:** Attacker takes two valid proofs A and B, swaps their signature values, hoping each proof might verify with the other's signature.
- **Expected invariant:** A signature is bound to a specific commitment digest. Two different proofs produce different commitment digests. Swapping signatures means each proof now carries a signature over a different commitment.
- **Mechanism:** Proof A has signature over `commitment_A`. Proof B has signature over `commitment_B`. After swap: A carries `signature_B` (over `commitment_B`) but its commitment is `commitment_A`. `ed25519.Verify(pubKey_A, payload_A, signature_B)` fails because `signature_B` was produced for `payload_B`, not `payload_A`.
- **Result:** REJECTED (both proofs)

### 11. Public key byte flip

- **PoC:** `TestAttack_PublicKeyFlip`
- **Threat:** Attacker flips a single bit in the embedded public key, hoping the signature might still verify or that the change might go undetected.
- **Expected invariant:** Ed25519 verification is bit-exact. Flipping any bit in the public key must cause verification failure, because the key no longer corresponds to the signing key.
- **Mechanism:** Ed25519 public key derivation is deterministic: `publicKey = scalarBasePoint(privateKey)`. Flipping one bit produces a different point on the curve. `ed25519.Verify(flippedKey, payload, signature)` returns false because `flippedKey` is not the public key that produced `signature`.
- **Result:** REJECTED

### 12. Proof ID manipulation

- **PoC:** `TestAttack_ProofIDManipulation`
- **Threat:** Attacker changes `proof.id` (e.g., from `PX-abc123` to `PX-FORGED`) and modifies `binding.root` without re-signing, hoping the proof will be accepted under the forged identity.
- **Expected invariant:** The binding root must be recomputed from the actual binding entries. A forged root that doesn't match the entries must be rejected. Additionally, even if re-signed, the proof's identity is bound to its content through the commitment.
- **Mechanism:** Two checks: (1) If the root is forged without re-signing, the original signature fails because the commitment includes the root. (2) If the attacker changes both ID and root and re-signs, the proof is self-consistent but has different content — the consumer must verify the content matches expectations. The test specifically checks that changing ID + root without re-signing fails.
- **Result:** REJECTED

### 13. Unicode normalization evasion

- **PoC:** `TestAttack_UnicodeNormalization`
- **Threat:** Attacker uses Unicode characters in evidence payloads that have multiple representations (NFC vs NFD), hoping to produce different digests for logically identical content, or to bypass digest comparison.
- **Expected invariant:** Evidence digests must be deterministic for a given payload. Different byte sequences must produce different digests. The same payload must always produce the same digest.
- **Mechanism:** `EvidenceDigest(id, payload)` computes `H("proofx/evidence/v1\x00" + id + ":" + payload)`. The hash operates on raw bytes — NFC `e + acute` (2 bytes) differs from NFD `e + combining acute` (3 bytes). Both produce valid but different digests. The test verifies: (1) NFC and NFD produce different digests, and (2) each digest is deterministic across calls.
- **Result:** REJECTED (different digests; each internally consistent)

### 14. Binding root reuse across proofs

- **PoC:** `TestAttack_BindingRootReuse`
- **Threat:** Attacker copies the binding root from proof A into proof B (which has different evidence), hoping proof B will verify because the root is "valid."
- **Expected invariant:** The binding root must be a hash of the actual binding entries in the proof. A root computed from proof A's entries cannot be valid for proof B's entries.
- **Mechanism:** `V4Root` hashes the specific entries provided. Proof A's entries hash to `root_A`. Proof B's entries hash to `root_B`. If proof B stores `root_A` but its entries produce `root_B`, the binding check computes `root_B != root_A` → fails.
- **Result:** REJECTED

---

## Running the Attack Tests

```bash
go test -v -run TestAttack ./verifycore/
```

## Adding New Scenarios

1. Document the scenario in this file using the format above
2. Add a `TestAttack_*` function in `verifycore/v2_attack_test.go`
3. Verify the attack is defeated (test asserts `res.Valid == false`)
4. Update the summary table
5. Run `go test -v -run TestAttack ./verifycore/` to confirm
