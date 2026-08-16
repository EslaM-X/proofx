# ProofX

**Evidence you can verify.**

> Turn "trust me." into "verify it yourself."

ProofX is Evidence Infrastructure for Software — a CLI, a GitHub Action and an open format that turn your project's claims (tests passed, built from commit X, artifact untampered, dependencies pinned) into **cryptographically bound evidence** anyone can independently re-verify.

[![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/EslaM-X/proofx/actions/workflows/ci.yml/badge.svg)](https://github.com/EslaM-X/proofx/actions/workflows/ci.yml)
[![ProofX Verified](https://img.shields.io/badge/ProofX-Verified-FFB627?logo=shield&logoColor=white)](https://github.com/EslaM-X/proofx/blob/main/docs/proof.md)

---

## Why

When a project says:

```
✅ 100% tests passed
✅ Built from commit abc123
✅ Dependency scan clean
✅ Release is authentic
```

The honest question is: **"Prove it."**

GitHub, SLSA and Sigstore already provide strong cryptography for provenance and signatures. ProofX does **not** re-invent that. ProofX sits **on top** and makes it:

- **easy** — 3 commands from clone to proof
- **unified** — one open document for claims + evidence + signature
- **human-readable** — `proofx verify` tells you *why*, not just a boolean
- **composable** — an Evidence Graph, not a one-off report

```
Claim              Evidence               Proof               Verification
"release v1.4.2    commit + workflow +    sha256 Merkle       proofx verify
 built from        builder + digest +     root, ed25519       release.tar.gz
 commit abc123"    tests + deps +         signed bundle
                   timestamp
```

## Dogfooding — ProofX verifies ProofX

ProofX is used in production on the repositories below. Every push runs the
`proofx-dogfood` workflow: collect evidence → bind → sign → verify.

| Repository | Badge | Proof |
|------------|-------|-------|
| [proofx](https://github.com/EslaM-X/proofx) | [![ProofX Verified](https://img.shields.io/badge/ProofX-Verified-FFB627?logo=shield&logoColor=white)](https://github.com/EslaM-X/proofx) | self-verifying |
| [ai-agent-automation-platform](https://github.com/EslaM-X/ai-agent-automation-platform) | [![ProofX Verified](https://img.shields.io/badge/ProofX-Verified-FFB627?logo=shield&logoColor=white)](https://github.com/EslaM-X/proofx) | GitHub Actions artifacts |
| [production-systems-lab](https://github.com/EslaM-X/production-systems-lab) | [![ProofX Verified](https://img.shields.io/badge/ProofX-Verified-FFB627?logo=shield&logoColor=white)](https://github.com/EslaM-X/proofx) | GitHub Actions artifacts |
| [robot-sim-policy-lab](https://github.com/EslaM-X/robot-sim-policy-lab) | [![ProofX Verified](https://img.shields.io/badge/ProofX-Verified-FFB627?logo=shield&logoColor=white)](https://github.com/EslaM-X/proofx) | GitHub Actions artifacts |

Want your repo here? Open a PR that adds `proofx init && proofx collect && proofx prove && proofx verify proof.json` to your CI.

## Quickstart — 5 minutes from clone to proof

```bash
# 1. install (any of)
go install github.com/EslaM-X/proofx/cmd/proofx@latest
# or download a release binary from GitHub Releases

# 2. inside any git repository
proofx init          # writes proofx.yaml
proofx keygen        # ed25519 signing key
proofx collect       # gathers evidence nodes -> .proofx/evidence.json
proofx prove         # binds + signs -> proof.json
proofx verify proof.json
```

```text
ProofX Verification — PX-eea90562
────────────────────────────────────────────────
✓  binding  (merkle root matches evidence digests)
✓  artifact  (0ba612403ed0)
✓  environment  (417314ad5a29)
✓  git  (4601e333efdc)
✓  signature  (ed25519 over binding root)
────────────────────────────────────────────────
✓ VERIFIED — 3/3 evidence nodes match current repo
Verification coverage: 100/100
```

Tamper with a tracked artifact and verify again: the mismatch is reported per-node, with a non-zero exit code your CI can enforce.

## GitHub Action

```yaml
- uses: EslaM-X/proofx@v0.1.0
  with:
    command: prove
    policy: 90        # fail the job if coverage < 90
```

What it produces in CI:

```
ProofX Verification
✓ Source integrity     ✓ Build provenance
✓ Test evidence        ✓ Dependency evidence
✓ Artifact integrity   ✓ Environment metadata
Proof: PX-8F4A-91C2...
```

## The Evidence Graph

Every proof bundles evidence **nodes**, each with an id, type, source, timestamp, canonical payload and a sha256 digest:

```
commit ──▶ build ──▶ artifact ──▶ release ──▶ proof
 │           │           │            │
 ├─ files    ├─ SBOM     ├─ digest     └─ signed bundle
 ├─ tests    ├─ builder
 ├─ deps     └─ env
 └─ workflow
```

The **binding root** is a Merkle root over the sorted evidence digests; the **signature** is ed25519 over that root. Verification recomputes both — no trusted server required.

## Concepts

| Term | Meaning |
|------|---------|
| **Claim** | a human statement a project makes (e.g. "built from commit X") |
| **Evidence** | an independently checkable fact (git state, file digests, test summary, lockfile hash, toolchain) |
| **Proof** | a signed document binding claims to evidence (`proof.json`) |
| **Verification** | re-collecting current evidence and comparing every digest |
| **Coverage** | the share of evidence nodes that re-verify — **not** a security score |

ProofX reports **Verification Coverage**, never "your project is secure". It states: *these claims have been verified against these evidence sources* — and nothing more.

## CLI reference

```
proofx init       scaffold proofx.yaml
proofx collect    gather evidence nodes into .proofx/evidence.json
proofx prove      bind + sign evidence into proof.json
proofx verify     re-verify a proof against the current repository
proofx inspect    print a proof in human-readable form
proofx keygen     generate an ed25519 signing key pair
proofx version    print the proofx version
```

## Design principles

- **No invented crypto.** sha256 (FIPS 180-4) + ed25519 (RFC 8032) + standard PEM/PKCS#8. Sigstore/SLSA/DSSE can be layered on as attestation providers.
- **No trust in the prover.** Anyone with `proof.json` and the repository can verify.
- **Deterministic.** Evidence payloads are canonicalized; the root is order-independent.
- **Honest coverage.** Missing sources are reported as skipped, never as pass.
- **MIT licensed.** The core — CLI, verifier, schema, action — is free and open.

## Roadmap

- **v0.1 (this release)** — CLI: init / keygen / collect / prove / verify / inspect; proof.json + JSON schema; GitHub Action; policy (coverage) gate.
- **v0.2** — `proofx explain` (why a node failed, likely causes), `proofx diff` (evidence between releases), public verifier `proofx.dev/v/<id>`.
- **v0.3** — Sigstore/attestation integration, npm/PyPI/Docker evidence collectors.
- **v1.0** — Evidence Graph as a first-class output, SDKs (Go/JS/Python).

## Related work

ProofX builds on — and does not compete with — [SLSA](https://slsa.dev), [Sigstore](https://sigstore.dev), [in-toto](https://in-toto.io) and [GitHub Artifact Attestations](https://docs.github.com/actions/security-guides/using-artifact-attestations). They provide the cryptographic backbone; ProofX provides the developer-facing layer that makes provenance actually usable.

---

**Star the project if you want open, verifiable software evidence to become a standard.**
