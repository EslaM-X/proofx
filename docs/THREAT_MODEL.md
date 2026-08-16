# ProofX Threat Model

> **The single most important sentence in this document:**
> **"ProofX Verified" means "the claims match the recorded evidence" — it does
> NOT mean "the software is safe".**

This document defines exactly what ProofX protects against, what it cannot
protect against, and the assumptions every proof depends on. Read it before
you rely on ProofX for anything.

---

## 1. Assets

ProofX's assets are **integrity properties**, not confidentiality:

| Asset | Description |
|-------|-------------|
| **Claim integrity** | A proof's claims truthfully describe what was evidenced |
| **Evidence integrity** | Evidence nodes cannot be silently modified |
| **Binding integrity** | The Merkle root truly commits all evidence |
| **Signature authenticity** | The proof was signed by the advertised key |
| **Artifact integrity** | A released artifact's content matches its recorded digest |
| **Non-repudiation** | A signer cannot deny having signed a proof (ed25519) |

ProofX does **not** protect confidentiality — evidence is public by design.

## 2. Threat model summary

| # | Threat | Protects? | Mechanism |
|---|--------|-----------|-----------|
| 1 | Artifact tampering after proof creation | ✅ | sha256 digest comparison on verify |
| 2 | Evidence node modification | ✅ | canonical payload digest + Merkle binding |
| 3 | Proof document modification | ✅ | binding root recomputation + signature |
| 4 | Digest mismatch / substitution | ✅ | domain-separated SHA-256 commitments |
| 5 | Signature forgery | ✅ | ed25519 (RFC 8032) |
| 6 | Evidence reordering | ✅ | leaves sorted by id before Merkle hashing |
| 7 | Wrong-version proof smuggling | ✅ | `proofVersion` enforced on parse |
| 8 | Malicious source code | ❌ | out of scope — ProofX is not a code auditor |
| 9 | Compromised GitHub account | ❌ | out of scope — trust anchor is the key |
| 10 | Compromised CI runner | ❌ | out of scope — evidence is recorded by the runner |
| 11 | False evidence generated before signing | ❌ | out of scope — ProofX hashes what exists |
| 12 | Malicious maintainer | ❌ | out of scope — signer is trusted to sign truthfully |
| 13 | Compromised signing key | ❌ | out of scope — key rotation procedure in SECURITY.md |
| 14 | Bad test methodology | ❌ | out of scope — ProofX records results, not quality |

## 3. What ProofX protects against (in scope)

### 3.1 Artifact tampering
If an artifact is modified after a proof is created, `proofx verify
--artifact <file> --proof <proof.json>` recomputes its SHA-256 and compares
it to the recorded digest. Any change → verification fails.

### 3.2 Evidence modification
Every evidence node hashes its canonical payload (domain-separated SHA-256).
Modify any byte of the payload → the digest changes → the binding root no
longer matches.

### 3.3 Proof modification
A proof has two independent integrity layers:
- **Binding**: recomputing the Merkle root from the embedded evidence must
  equal the recorded root.
- **Signature**: the root is signed with ed25519; the public key is embedded
  in the proof.

Tampering with the evidence, the root, or the signature independently fails
at least one layer.

### 3.4 Digest mismatch / substitution
Domain separation labels (`proofx/leaf/v1`, `proofx/node/v1`,
`proofx/evidence/v1`, `proofx/sign/v1`) prevent a digest produced in one
protocol step from being reinterpreted as another. See
[docs/CRYPTOGRAPHY.md](CRYPTOGRAPHY.md).

### 3.5 Signature forgery
ed25519 signatures are computationally unforgeable without the private key.
An attacker who modifies the proof cannot produce a valid signature.

## 4. What ProofX does NOT protect against (out of scope)

These are **by design** and stated explicitly so ProofX is never
misrepresented.

### 4.1 Malicious source code
A proof can truthfully attest that `commit abc123` was built into an artifact
while that commit contains a backdoor. ProofX records **what was built**, not
**whether it is safe**.

### 4.2 Compromised GitHub account / CI runner
If an attacker gains control of the CI runner, they control the evidence
collectors and can generate evidence about *their* modified tree, then sign
it with the (compromised) CI key. ProofX records the environment node so
consumers can see **who** produced the evidence, but cannot detect
compromise of the producer itself.

### 4.3 False evidence generated before signing
If the producer deliberately runs tests in a rigged environment or hashes a
fake artifact, ProofX faithfully records that fake evidence. ProofX is
honest about **what exists**, not **whether it is good**.

### 4.4 Malicious maintainer
The signer is trusted to sign truthfully. A maintainer can always create a
new proof for a different tree. ProofX provides **evidence**, not **trust**.

### 4.5 Compromised signing key
With the private key, an attacker can sign arbitrary proofs. Mitigation is
operational (see SECURITY.md "Key compromise procedure"), not cryptographic.

### 4.6 Bad test methodology
ProofX records test results but does not judge their quality. A "verified"
test evidence node does not mean the tests are meaningful.

## 5. Assumptions

Every ProofX verification silently relies on these assumptions. If any is
violated, the guarantees weaken:

1. **The signing key was uncompromised** at sign time.
2. **The evidence collectors ran in an environment** that reflects the real
   build/test/release process (not a rigged one).
3. **The canonicalization is deterministic** — Go's `encoding/json` sorts map
   keys, so identical logical objects hash identically. This is asserted by
   tests, but it is a Go implementation detail.
4. **SHA-256 and ed25519 remain secure** (standard cryptanalysis horizon
   assumptions).
5. **Consumers run an up-to-date ProofX** that enforces `proofVersion`.

## 6. Trust boundaries

```text
┌───────────────────────────────────────────────────────────────┐
│  Trusted (assumed honest & uncompromised)                    │
│  ┌─────────────────┐  ┌───────────────────┐  ┌────────────┐  │
│  │ Maintainer      │  │ Signing key       │  │ CI runner  │  │
│  └─────────────────┘  └───────────────────┘  └────────────┘  │
└───────────────────────────────────────────────────────────────┘
                              │ signs / produces
                              ▼
┌───────────────────────────────────────────────────────────────┐
│  Semi-trusted boundary (ProofX validates)                    │
│   artifact files, evidence payloads, proof documents          │
│   → digests, Merkle binding, ed25519 signatures              │
└───────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌───────────────────────────────────────────────────────────────┐
│  Untrusted (anything from the network / release page)        │
│   ─ verified only after signature + binding + digest checks  │
└───────────────────────────────────────────────────────────────┘
```

The network and release artifacts are **fully untrusted** until verified.
The maintainer, key, and CI runner are **trusted** — and that trust is the
boundary ProofX explicitly does not defend.

## 7. Example attack walkthroughs

### 7.1 Attacker modifies a released binary
1. Attacker edits `myapp-linux-amd64`.
2. User runs `proofx verify --artifact myapp-linux-amd64 --proof proof.json`.
3. Digest mismatch detected → verification fails → **attack defeated**.

### 7.2 Attacker edits an evidence node in proof.json
1. Attacker changes the `tests` payload from `"passed": 100` to `"passed": 900`.
2. `proofx verify` recomputes the tests digest → differs from the recorded
   digest → binding root mismatch → **attack defeated**.

### 7.3 Attacker swaps the public key in proof.json
1. Attacker replaces `signature.publicKey` with their own key and re-signs.
2. The proof's public key is part of the signed payload check: the new
   signature is over a *different* root than recorded, and binding fails
   against the original evidence. An attacker who also modifies evidence
   changes the root → original signature becomes invalid.
3. **Attack defeated** — unless the attacker also compromises the private
   key (out of scope, see §4.5).

### 7.4 Malicious maintainer ships a proof for a backdoored commit
1. Maintainer adds a backdoor to `commit xyz`.
2. Maintainer runs the real build, generates honest evidence, signs it.
3. `proofx verify` says VERIFIED — and it *is* verifiable evidence.
4. **This is out of scope** (§4.1). ProofX recorded the truth; it does not
   judge the truth's safety. Consumers must still review code.

## 8. Residual risk

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Go canonicalization changes in a future Go version | Low | Pinned tests assert determinism; protocol pins `proofVersion` |
| SHA-256 cryptanalytic break | Very low | Protocol is versioned; can migrate algorithms |
| Private key exfiltration | Low | Key rotation procedure, `0600` perms, secrets in CI |
| Supply-chain attack on deps | Low | `go.sum` pinned; CI runs vulnerability tooling |
| User trusts VERIFIED too much | Medium | This document + SECURITY.md + README messaging |

## 9. Reporting

Found a gap in this model or the implementation? Follow the private
disclosure process in [SECURITY.md](../SECURITY.md).
