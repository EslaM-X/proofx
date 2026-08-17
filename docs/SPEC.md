# ProofX — Product Specification (v0.2)

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
- Judge code quality, test methodology, or the signer's honesty. See the
  [Threat Model](THREAT_MODEL.md) for the precise boundary.

## 3. Terminology

| Term | Definition |
|------|-----------|
| Claim | a human statement a project makes |
| Evidence | an independently checkable fact (node in the Evidence Graph) |
| Proof | a signed document binding claims to evidence (`proof.json`) |
| Verification | re-collecting current evidence and comparing every digest |
| Coverage | fraction of evidence nodes that re-verify (0–100) |
| Binding root | order-independent sha256 Merkle root over sorted evidence digests |
| Domain separation | per-step labels preventing hash type-confusion |

## 4. Evidence Graph

A proof is a set of evidence **nodes**. Each node has:

- `id` (stable identifier, e.g. `git`, `artifact`, `tests`)
- `type` (git | artifact | dependencies | tests | environment)
- `source` (human-readable provenance pointer)
- `timestamp` (RFC3339)
- `payload` (canonical JSON of the observed fact)
- `digest` (sha256 hex of the domain-separated payload)

`proofx graph` renders the graph as ASCII or emits it as a JSON data model
(`--json`): nodes, directed relationships (`evidenceOf`, `binds`, `signedBy`),
claims, and the proof reference. The graph is the machine-readable shape of a
proof, not a fixed report.

## 5. Binding & signature — cryptographic construction

The authoritative, formal construction is **docs/CRYPTOGRAPHY.md**. Summary:

1. **Canonicalization** — evidence payloads are compact JSON with sorted keys,
   so identical logical objects hash identically.
2. **Evidence digest** — `sha256("proofx/evidence/v1\x00" || payload)`.
3. **Leaves** — entries are sorted by `id`; each leaf is
   `sha256("proofx/leaf/v1\x00" || id || "\x00" || digest)`. Sorting happens
   inside the root computation, so input order never matters.
4. **Merkle tree** — internal nodes are `sha256("proofx/node/v1\x00" || left || right)`;
   an odd node is promoted unchanged; the root of a single leaf is the leaf itself.
5. **Signature** — `proofx prove` computes a commitment digest over the full
   proof content (version, project, subject, claims, binding root) and signs
   `"proofx/sign/v1\x00" || commitmentDigest` with **ed25519**; the raw 32-byte
   public key is embedded in the proof. This binds the signature to the
   complete semantic content, not just the evidence root.

Verification recomputes the root from the stored digests and checks the signature —
so *anyone* can verify without trusting the prover or a central server. The domain
separation labels mean a digest produced in one protocol step can never be reused
as another (leaf vs root vs evidence vs sign).

## 6. Proof document

`proof.json` (schema: `schema/proof.schema.json`, version `1.0`):

```json
{
  "proofVersion": "1.0",
  "id": "PX-56b79e75",
  "project": { "name": "EslaM-X/proofx", "repository": "EslaM-X/proofx" },
  "subject": { "commit": "<40-hex>", "branch": "main", "repository": "EslaM-X/proofx" },
  "claims": [ { "id": "c1", "text": "Built from the recorded commit", "status": "evidenced" } ],
  "evidence": [ { "id": "git", "type": "git", "source": "git metadata",
                  "timestamp": "...", "payload": "{...}", "digest": "<64-hex>" } ],
  "binding": { "algorithm": "sha256", "root": "<64-hex>", "entries": [...] },
  "signature": { "algorithm": "ed25519", "publicKey": "<b64>", "value": "<b64>" },
  "coverage": { "total": 4, "verified": 4, "score": 100 },
  "createdAt": "...",
  "builder": { "name": "proofx", "version": "0.2.0" }
}
```

The public key is **inside** the proof, so verification is self-contained and
works offline with no trusted server.

## 7. Threat model

The proof is only as strong as the environment that produced it. The full model
is **docs/THREAT_MODEL.md**. Summary:

**In scope (detected by ProofX):**
- Claim misrepresentation → evidence is bound to real observed facts.
- Artifact tampering after proof → digest mismatch on `verify --artifact` or repo verify.
- Evidence-node modification → domain-separated digest + binding root mismatch.
- Proof document modification → binding recomputation and/or signature fails.
- Signature forgery → ed25519 verification fails.
- Evidence reordering → leaves are sorted by id, so order is irrelevant.

**Out of scope / documented caveats:**
- A malicious CI environment can produce evidence about itself. ProofX records the
  environment node (toolchain, OS, commit) so consumers can judge trustworthiness.
- A compromised signing key, a malicious maintainer, malicious source code, or
  rigged test methodology are **not** detectable by ProofX — it is honest about
  *what exists*, not *whether it is good*.
- `key.pem` must be kept secret; it is never committed. Rotate keys by re-running `keygen`.
- File hashes cover *contents*, not authorship. Combine with signed commits and
  Sigstore identity for stronger provenance.

## 8. CLI

```
proofx init       scaffold proofx.yaml (keeps existing config)
proofx keygen     generate ed25519 key pair
proofx collect    gather evidence -> .proofx/evidence.json
proofx prove      bind + sign -> proof.json
proofx verify     re-verify proof against current repo,
                  or --artifact <file> --proof <proof> (portable, repo-free)
proofx explain    why each node passes/fails + likely causes + fixes
proofx diff       compare two proofs evidence-node by evidence-node
proofx graph      render the Evidence Graph (--json for the data model)
proofx inspect    human-readable dump
proofx version
proofx help
```

Exit codes: `0` verified / success, `1` verification failure, `2` usage error.

## 9. GitHub Action

`EslaM-X/proofx@v0.2.0` (composite action):

- downloads the matching release binary per runner OS/arch
- runs `collect` + `prove` (or `verify` / `collect` / `keygen`)
- uploads `proof.json` as a workflow artifact
- optional `policy` gate: fails the job if coverage drops below the threshold

## 10. Repo layout

```
proofx/
├── cmd/proofx/          main entrypoint
├── cli/                 command implementations (verify, explain, diff, graph, ...)
├── model/               proof data structures
├── evidence/            collectors + canonical JSON + domain-separated hashing
├── proof/               binding + signing + verification (+ property/fuzz tests)
├── config/              proofx.yaml parsing
├── schema/              proof.schema.json
├── docs/                SPEC, CRYPTOGRAPHY, THREAT_MODEL, sample proof
├── .github/             CODEOWNERS, workflows (ci.yml, proofx-dogfood.yml)
├── SECURITY.md          disclosure policy
├── AUTHORS.md           credits
└── action.yml           GitHub Action definition
```

## 11. Roadmap

- v0.1 — CLI + proof.json + schema + action + policy gate *(released)*
- v0.2 — domain-separated protocol, `explain`, `diff`, `graph`, portable
  `verify --artifact`, property + fuzz tests, crypto spec, security docs,
  signed checksums, Docker package *(this release)*
- v0.3 — public verifier (`proofx.dev/v/<id>`), dynamic verification badge,
  Sigstore/attestation integration; npm/PyPI/Docker collectors
- v1.0 — Evidence Graph as first-class output; Go/JS/Python SDKs

## 12. Adoption milestones

1. 10 external users verified the demo
2. 10 repositories emitting ProofX proofs
3. 100 external verifications
4. 100 GitHub stars
5. 50 repositories using the Action
6. 1,000 verifications → then monetization (Pro: private repos, dashboards, retention)
