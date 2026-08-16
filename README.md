<div align="center">

# 🛡️ ProofX

**Evidence Infrastructure for Software**

*Turn "trust me." into "verify it yourself."*

[![Go](https://img.shields.io/badge/Go-1.23%2B-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/EslaM-X/proofx?logo=github&color=6A5ACD)](https://github.com/EslaM-X/proofx/releases)
[![CI](https://github.com/EslaM-X/proofx/actions/workflows/ci.yml/badge.svg)](https://github.com/EslaM-X/proofx/actions/workflows/ci.yml)
[![Dogfood](https://github.com/EslaM-X/proofx/actions/workflows/proofx-dogfood.yml/badge.svg)](https://github.com/EslaM-X/proofx/actions/workflows/proofx-dogfood.yml)
[![Coverage](https://img.shields.io/badge/coverage-100%25-success)](https://github.com/EslaM-X/proofx)
[![Security](https://img.shields.io/badge/security-policy-brightgreen.svg)](SECURITY.md)
[![Made in Egypt](https://img.shields.io/badge/Made%20with%20%E2%9D%A4%20in-Egypt-white?logo=github&logoColor=white)](https://github.com/EslaM-X)

[Releases](https://github.com/EslaM-X/proofx/releases) · [Packages](https://github.com/EslaM-X/proofx/pkgs) · [Docs](docs/SPEC.md) · [Crypto Spec](docs/CRYPTOGRAPHY.md) · [Threat Model](docs/THREAT_MODEL.md) · [Discussions](https://github.com/EslaM-X/proofx/discussions) · [Issues](https://github.com/EslaM-X/proofx/issues) · [Security](SECURITY.md)

---

</div>

> 🇪🇬 Built by **[EslaM](https://github.com/EslaM-X)** — where the Nile meets the blockchain. ProofX is a gift from Egypt to the open-source world: proof for every release, evidence for every claim.

## ✨ What is ProofX?

**ProofX** is a CLI, a GitHub Action, and an open document format that turn your project's claims into **cryptographically bound evidence** anyone can independently re-verify.

When a project says:

```
✅ 100% tests passed
✅ Built from commit abc123
✅ Dependency scan clean
✅ Release is authentic
```

The honest question is: **"Prove it."**

ProofX answers it. Three commands from clone to proof:

```bash
proofx init     # scaffold proofx.yaml
proofx collect  # gather evidence nodes
proofx prove    # bind + sign into proof.json
proofx verify proof.json
```

## 🎯 What makes ProofX different

| | ProofX | Traditional badges |
|---|---|---|
| 🔐 **Cryptographic binding** | sha256 Merkle root + ed25519 signature | A static image |
| 🔄 **Independently verifiable** | anyone with `proof.json` re-verifies, no server | Trust the badge host |
| 📦 **One open document** | claims + evidence + signature in `proof.json` | Scattered reports |
| 🧩 **Composable** | Evidence Graph data model | One-off snapshots |
| 🩺 **Human-readable** | `explain` tells you *why*, not just a boolean | Green/red only |

ProofX does **not** re-invent cryptography. It sits **on top** of proven primitives — [SHA-256](docs/CRYPTOGRAPHY.md) (FIPS 180-4) and [Ed25519](docs/CRYPTOGRAPHY.md) (RFC 8032) — and layers on [SLSA](https://slsa.dev), [Sigstore](https://sigstore.dev) and [in-toto](https://in-toto.io) as attestation providers.

```
Claim              Evidence               Proof               Verification
"release v1.4.2    commit + workflow +    sha256 Merkle       proofx verify
 built from        builder + digest +     root, ed25519       release.tar.gz
 commit abc123"    tests + deps +         signed bundle
                   timestamp
```

## 🚀 Quickstart — 5 minutes from clone to proof

### 1. Install

```bash
# Option A — Go (recommended)
go install github.com/EslaM-X/proofx/cmd/proofx@latest

# Option B — download a pre-built release binary
#   https://github.com/EslaM-X/proofx/releases/latest
#   (linux / darwin / windows × amd64 / arm64)
```

### 2. Create a proof

```bash
# inside any git repository
proofx init          # writes proofx.yaml (keeps existing config)
proofx keygen        # ed25519 signing key -> .proofx/key.pem
proofx collect       # gathers evidence nodes -> .proofx/evidence.json
proofx prove         # binds + signs -> proof.json
proofx verify proof.json
```

### 3. See it work

```text
ProofX Verification — PX-56b79e75
────────────────────────────────────────────────
✓  binding  (merkle root matches evidence digests)
✓  artifact  (cc34d874ec91)
✓  dependencies  (7b81e355f9a3)
✓  environment  (d79f8e69b353)
✓  git  (d9035c066fbb)
✓  signature  (ed25519 over binding root)
────────────────────────────────────────────────
✓ VERIFIED — 4/4 evidence nodes match current repo
Verification coverage: 100/100
```

Tamper with a tracked artifact and verify again — the mismatch is reported **per node**, with a non-zero exit code your CI can enforce.

## 🧪 Verify an artifact without a repository

ProofX's most powerful feature: **portable verification**. Verify a release binary against a proof **with no git repository present** — perfect for `curl`-and-check workflows:

```bash
proofx verify --artifact myapp-linux-amd64 --proof proof.json
```

```text
✓ VERIFIED — 1/1 evidence nodes match current repo
Verification coverage: 100/100
✓ artifact app.bin matches proof PX-56b79e75
```

Anyone downloading your release can verify it came from the exact build you signed — the strongest guarantee a supply chain can offer.

## 🤖 GitHub Action

```yaml
- uses: EslaM-X/proofx@v0.2.0
  with:
    command: prove
    policy: 90        # fail the job if verification coverage < 90
```

What it produces in CI:

```
ProofX Verification
✓ Source integrity     ✓ Build provenance
✓ Test evidence        ✓ Dependency evidence
✓ Artifact integrity   ✓ Environment metadata
Proof: PX-56B79E75
```

## 🧠 Understanding your proof

| Command | What it does |
|---|---|
| `proofx verify proof.json` | re-verify against the current repository |
| `proofx verify --artifact FILE --proof proof.json` | portable, repo-free artifact check |
| `proofx explain proof.json` | *why* each node passes/fails, likely causes + fixes |
| `proofx diff v1.json v2.json` | evidence changes between releases |
| `proofx graph proof.json` | render the Evidence Graph (ASCII) |
| `proofx graph --json proof.json` | the Evidence Graph as a data model |
| `proofx inspect proof.json` | human-readable dump |

```text
$ proofx explain proof.json

ProofX Explain — PX-56b79e75
──────────────────────────────────────────────────────────
✓ signature  [OK]
    signature is a valid ed25519 over the binding root.
✓ binding  [OK]
    merkle root matches the recorded evidence digests.
✓ artifact  [OK]
    cc34d874ec91
    current state matches the recorded evidence.
✗ git  [FAIL]
    expected d9035c066fbb actual 49b08f038c17
    the current state differs from the recorded evidence.
    Likely cause: the repository advanced to a new commit since the proof.
    Recommended:  checkout the recorded commit and re-verify, or create a new proof.
```

## 🕸️ The Evidence Graph

Every proof bundles evidence **nodes** — id, type, source, timestamp, canonical payload, sha256 digest — into a directed graph:

```text
  commit
    │
    ├── artifact
    ├── dependencies
    ├── environment
    └── git
    │
    ▼
  PROOF  (PX-56b79e75)
    │
    ▼
  SIGNATURE (ed25519)
```

The **binding root** is an order-independent Merkle root over the sorted, domain-separated evidence digests; the **signature** is ed25519 over that root. Verification recomputes both — **no trusted server required**. The full construction is specified in [docs/CRYPTOGRAPHY.md](docs/CRYPTOGRAPHY.md).

## 📐 Concepts

| Term | Meaning |
|------|---------|
| **Claim** | a human statement a project makes (e.g. "built from commit X") |
| **Evidence** | an independently checkable fact (git state, file digests, test summary, lockfile hash, toolchain) |
| **Proof** | a signed document binding claims to evidence (`proof.json`) |
| **Verification** | re-collecting current evidence and comparing every digest |
| **Coverage** | the share of evidence nodes that re-verify — **not** a security score |
| **Binding root** | order-independent sha256 Merkle root over evidence digests |
| **Signature** | ed25519 over the binding root, key embedded in the proof |

> ⚠️ ProofX reports **Verification Coverage**, never "your project is secure". It states: *these claims have been verified against these evidence sources* — and nothing more. Read the [Threat Model](docs/THREAT_MODEL.md) for the exact guarantees and their boundaries.

## 📦 Proof document format

`proof.json` is versioned, schema-validated, and self-contained — the public key lives inside the proof, so verification works offline:

```json
{
  "proofVersion": "1.0",
  "id": "PX-56b79e75",
  "project": { "name": "EslaM-X/proofx", "repository": "EslaM-X/proofx" },
  "subject": { "commit": "c51daaf9…", "branch": "main", "repository": "EslaM-X/proofx" },
  "claims": [ { "id": "c1", "text": "Built from the recorded git commit", "status": "evidenced" } ],
  "evidence": [ /* nodes: id, type, source, timestamp, payload, digest */ ],
  "binding": { "algorithm": "sha256", "root": "56b79e75…", "entries": [ /* sorted */ ] },
  "signature": { "algorithm": "ed25519", "publicKey": "JcArfc+P…", "value": "…" },
  "coverage": { "total": 4, "verified": 4, "score": 100 },
  "builder": { "name": "proofx", "version": "0.2.0" }
}
```

JSON Schema: [`schema/proof.schema.json`](schema/proof.schema.json) · Sample: [`docs/proof.md`](docs/proof.md)

## 📚 Documentation

| Doc | Contents |
|-----|----------|
| [SPEC.md](docs/SPEC.md) | full project specification & architecture |
| [CRYPTOGRAPHY.md](docs/CRYPTOGRAPHY.md) | formal cryptographic construction (canonicalization, Merkle, domain separation, signature payload) |
| [THREAT_MODEL.md](docs/THREAT_MODEL.md) | exactly what ProofX protects — and what it does **not** |
| [SECURITY.md](SECURITY.md) | vulnerability reporting, response times, key compromise procedure |
| [proof.md](docs/proof.md) | a real, verifiable ProofX proof of the ProofX repository |

## 🏗️ Design principles

- **No invented crypto.** sha256 (FIPS 180-4) + ed25519 (RFC 8032) + standard PEM/PKCS#8. Domain separation prevents type-confusion between protocol steps.
- **No trust in the prover.** Anyone with `proof.json` and the repository can verify.
- **Deterministic.** Evidence payloads are canonicalized; the Merkle root is order-independent — asserted by property tests and fuzzers.
- **Honest coverage.** Missing sources are reported as *skipped*, never as pass.
- **Open & MIT licensed.** The core — CLI, verifier, schema, action — is free and open forever.

## 🐾 Dogfooding — ProofX verifies ProofX

ProofX is used in production on the repositories below. Every push runs the `proofx-dogfood` workflow: collect evidence → bind → sign → verify.

| Repository | Badge | Proof |
|------------|-------|-------|
| [proofx](https://github.com/EslaM-X/proofx) | [![ProofX Verified](https://img.shields.io/badge/ProofX-Verified-FFB627?logo=shield&logoColor=white)](https://github.com/EslaM-X/proofx/blob/main/docs/proof.md) | self-verifying |
| [ai-agent-automation-platform](https://github.com/EslaM-X/ai-agent-automation-platform) | [![ProofX Verified](https://img.shields.io/badge/ProofX-Verified-FFB627?logo=shield&logoColor=white)](https://github.com/EslaM-X/proofx) | GitHub Actions artifacts |
| [production-systems-lab](https://github.com/EslaM-X/production-systems-lab) | [![ProofX Verified](https://img.shields.io/badge/ProofX-Verified-FFB627?logo=shield&logoColor=white)](https://github.com/EslaM-X/proofx) | GitHub Actions artifacts |
| [robot-sim-policy-lab](https://github.com/EslaM-X/robot-sim-policy-lab) | [![ProofX Verified](https://img.shields.io/badge/ProofX-Verified-FFB627?logo=shield&logoColor=white)](https://github.com/EslaM-X/proofx) | GitHub Actions artifacts |

Want your repo here? Open a PR that adds `proofx init && proofx collect && proofx prove && proofx verify proof.json` to your CI.

## 🛡️ Security

- **Report vulnerabilities privately** — see [SECURITY.md](SECURITY.md) for the disclosure policy, response times and the key-compromise procedure.
- **Formal guarantees** — the [Threat Model](docs/THREAT_MODEL.md) states precisely what ProofX can and cannot protect.
- **Defense in depth** — CI runs `go vet`, `golangci-lint`, `go test -race -cover`, property-based tests and fuzzers on every push.

## 🗺️ Roadmap

- **v0.1** ✅ — CLI (init/keygen/collect/prove/verify/inspect), proof format + JSON schema, GitHub Action, policy gate, 6 platform binaries, dogfooding.
- **v0.2** 🔄 — `explain`, `diff`, `graph`, portable `verify --artifact`, property + fuzz tests, formal crypto spec, checksums + signed releases, Docker package.
- **v0.3** — public verifier `proofx.dev/v/<id>`, dynamic verification badge, Sigstore/attestation integration, npm/PyPI/Docker collectors.
- **v1.0** — SDKs (Go/JS/Python), Evidence Graph as a first-class output, certified compliance packs.

## 🤝 Contributing

1. Read [docs/SPEC.md](docs/SPEC.md) and the [Threat Model](docs/THREAT_MODEL.md) first.
2. Open an issue to discuss the change before writing code.
3. Branch → implement → test → open a PR (requires review before merge).

- [Open Discussions](https://github.com/EslaM-X/proofx/discussions) — ask questions, share ideas
- [Report a bug](https://github.com/EslaM-X/proofx/issues/new?labels=bug) — *good first issue* and *help wanted* tags available

## 📜 License & Credits

- **MIT** — see [LICENSE](LICENSE).
- **Author** — [EslaM-X](https://github.com/EslaM-X) 🇪🇬 (EslaM, Cairo, Egypt). *"Made with ❤️ where the Nile meets the code."*
- ProofX builds on the shoulders of [Go](https://go.dev), [SLSA](https://slsa.dev), [Sigstore](https://sigstore.dev), [in-toto](https://in-toto.io) and GitHub Artifact Attestations.

---

<div align="center">

**⭐ Star the project if you want open, verifiable software evidence to become a standard.**

*Trust is good. Proof is better. ProofX is both.*

</div>
