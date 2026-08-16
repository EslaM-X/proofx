# ProofX — Product Specification (v0.1)

> **Tagline:** Evidence you can verify.
> **Claim:** ProofX turns "trust me." into "verify it yourself."

## 1. Problem

Software projects routinely make claims in READMEs, release notes and CI badges:

- "100% tests passed"
- "Built from commit `abc123`"
- "Dependency scan clean"
- "Release is authentic"
- "Reproducible build"
- "Benchmark: 98.4%"

A verifier (an auditor, a downstream maintainer, a supply-chain reviewer, a future
employer) cannot distinguish these from marketing. The infrastructure to *prove* them
exists (SLSA, Sigstore, in-toto, GitHub Artifact Attestations) but it is:

1. **Low-level** — provenance statements and DSSE envelopes are not human-friendly.
2. **Fragmented** — git, CI, tests, SBOM, signatures live in different tools/formats.
3. **Not composable** — no single document answers "what is this claim, what evidence
   backs it, and does it re-verify?"

**ProofX is the missing developer-facing layer** — a unified, human-readable, verifiable
document that wraps standard cryptography.

## 2. Non-goals

- Invent a signature scheme, hash, or attestation format. (We reuse sha256 + ed25519.)
- Replace SLSA/Sigstore/in-toto. We *consume* them as attestation providers later.
- Issue "security scores". We report *verification coverage* only.
- Require a server or login for the core flow. Everything works offline.

## 3. Terminology

| Term | Definition |
|------|-----------|
| Claim | a human statement a project makes |
| Evidence | an independently checkable fact (node in the Evidence Graph) |
| Proof | a signed document binding claims to evidence (`proof.json`) |
| Verification | re-collecting current evidence and comparing every digest |
| Coverage | fraction of evidence nodes that re-verify (0–100) |

## 4. Evidence Graph

A proof is a set of evidence **nodes**. Each node has:

- `id` (stable identifier, e.g. `git`, `artifact`, `tests`)
- `type` (git | artifact | dependencies | tests | environment)
- `source` (human-readable provenance pointer)
- `timestamp` (RFC3339)
- `payload` (canonical JSON of the observed fact)
- `digest` (sha256 hex of the payload)

```text
commit ──▶ build ──▶ artifact ──▶ release ──▶ proof
```

## 5. Binding & signature (no invented crypto)

1. Sort evidence nodes by id.
2. Each leaf = `sha256("<id>:<digest>")`.
3. Merkle-style pairwise hashing produces a single **binding root**.
4. `proofx prove` signs the root with **ed25519**; the public key is embedded.

Verification recomputes the root from the stored digests and checks the signature —
so *anyone* can verify without trusting the prover or a central server.

## 6. Proof document

`proof.json` (schema: `schema/proof.schema.json`, version `1.0`):

```json
{
  "proofVersion": "1.0",
  "id": "PX-eea90562",
  "project": { "name": "proofx", "repository": "EslaM-X/proofx" },
  "subject": { "commit": "<40-hex>", "branch": "main", "repository": "EslaM-X/proofx" },
  "claims": [ { "id": "c1", "text": "Built from the recorded commit", "status": "evidenced" } ],
  "evidence": [ { "id": "git", "type": "git", "source": "git metadata",
                  "timestamp": "...", "payload": "{...}", "digest": "<64-hex>" } ],
  "binding": { "algorithm": "sha256", "root": "<64-hex>", "entries": [...] },
  "signature": { "algorithm": "ed25519", "publicKey": "<b64>", "value": "<b64>" },
  "coverage": { "total": 3, "verified": 3, "score": 100 },
  "createdAt": "...",
  "builder": { "name": "proofx", "version": "0.1.0" }
}
```

## 7. Threat model

The proof is only as strong as the environment that produced it.

**In scope (detected by ProofX):**
- Claim misrepresentation → evidence is bound to real observed facts.
- Artifact/README tampering after proof → per-node digest mismatch on verify.
- Evidence-level tampering → binding root recomputation fails.
- Signature forgery → ed25519 verification fails.

**Out of scope / documented caveats:**
- A malicious CI environment can produce evidence about itself. ProofX records the
  environment node (toolchain, OS, commit) so consumers can judge trustworthiness.
- `key.pem` must be kept secret; it is never committed. Rotate keys by re-running `keygen`.
- File hashes cover *contents*, not authorship. Combine with signed commits and
  Sigstore identity for stronger provenance.

## 8. CLI

```
proofx init       scaffold proofx.yaml
proofx keygen     generate ed25519 key pair
proofx collect    gather evidence -> .proofx/evidence.json
proofx prove      bind + sign -> proof.json
proofx verify     re-verify proof against current repo
proofx inspect    human-readable dump
proofx version
```

Exit codes: `0` verified / success, `1` verification failure, `2` usage error.

## 9. GitHub Action

`EslaM-X/proofx@v0.1.0` (composite action):

- downloads the matching release binary per runner OS/arch
- runs `collect` + `prove` (or `verify` / `collect` / `keygen`)
- uploads `proof.json` as a workflow artifact
- optional `policy` gate: fails the job if coverage drops below the threshold

## 10. Repo layout

```
proofx/
├── cmd/proofx/          main entrypoint
├── cli/                 command implementations
├── model/               proof data structures
├── evidence/            collectors + hashing
├── proof/               binding + signing + verification
├── config/              proofx.yaml parsing
├── schema/              proof.schema.json
├── docs/                this spec + sample proof
├── .github/workflows/   ci.yml, proofx-dogfood.yml
└── action.yml           GitHub Action definition
```

## 11. Roadmap

- v0.1 — CLI + proof.json + schema + action + policy gate *(this release)*
- v0.2 — `explain`, `diff`, public verifier (`proofx.dev/v/<id>`)
- v0.3 — Sigstore/in-toto attestation integration; npm/PyPI/Docker collectors
- v1.0 — Evidence Graph as first-class output; Go/JS/Python SDKs

## 12. Adoption milestones

1. 10 external users verified the demo
2. 10 repositories emitting ProofX proofs
3. 100 external verifications
4. 100 GitHub stars
5. 50 repositories using the Action
6. 1,000 verifications → then monetization (Pro: private repos, dashboards, retention)
