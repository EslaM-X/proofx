<div align="center">

<p align="center">
  <img src="brand/logo/proofx-logo-dark.svg" width="400" alt="ProofX">
</p>

**ProofX turns software execution into a proof that anyone can independently verify.**

*No trust required. No server. Just math.*

[![Go](https://img.shields.io/badge/Go-1.23%2B-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/EslaM-X/proofx?logo=github&color=6A5ACD)](https://github.com/EslaM-X/proofx/releases)
[![CI](https://github.com/EslaM-X/proofx/actions/workflows/ci.yml/badge.svg)](https://github.com/EslaM-X/proofx/actions/workflows/ci.yml)
[![Dogfood](https://github.com/EslaM-X/proofx/actions/workflows/proofx-dogfood.yml/badge.svg)](https://github.com/EslaM-X/proofx/actions/workflows/proofx-dogfood.yml)
[![Coverage](https://img.shields.io/badge/coverage-100%25-success)](https://github.com/EslaM-X/proofx)
[![Security](https://img.shields.io/badge/security-policy-brightgreen.svg)](SECURITY.md)
<img src="brand/badges/proof-verified-badge.svg" alt="Proof Verified">
[![Made in Egypt](https://img.shields.io/badge/Made%20with%20%E2%9D%A4%20in-Egypt-white?logo=github&logoColor=white)](https://github.com/EslaM-X)

[Releases](https://github.com/EslaM-X/proofx/releases) · [Packages](https://github.com/EslaM-X/proofx/pkgs) · [Docs](docs/SPEC.md) · [Crypto Spec](docs/CRYPTOGRAPHY.md) · [Threat Model](docs/THREAT_MODEL.md) · [Discussions](https://github.com/EslaM-X/proofx/discussions) · [Issues](https://github.com/EslaM-X/proofx/issues) · [Security](SECURITY.md)

---

</div>

## The Idea

```text
  Execution              Evidence              Relations              Claims
  ──────────             ────────              ─────────              ──────
  CI pipeline runs   →   commit + deps +   →   evidence supports  →  "built from
  tests + build           builder + env         claims                 commit X"
                         + results
                              │                      │
                              ▼                      ▼
                         sha256 Merkle         Merkle root
                         root                  + ed25519
                         (binding)             (signature)
                              │
                              ▼
                         proof.json
```

**Execution** happens. **Evidence** is collected. **Relations** bind them. **Claims** state what happened. **Proof** ties it all together with a signature. Anyone can verify — no server, no trust, just math.

## 2-Minute Quick Start

From zero to cryptographic proof in 4 commands.

### Step 1 — Install

```bash
npm install -g @eslamx/proofx
```

Or:

```bash
pip install proofx        # Python
brew install proofx       # macOS/Linux
go install github.com/EslaM-X/proofx/cmd/proofx@latest  # Go
# Or download a binary: https://github.com/EslaM-X/proofx/releases/latest
```

### Step 2 — Create your first proof

```bash
cd your-project        # any git repository
proofx init            # creates proofx.yaml
proofx keygen          # generates signing key
proofx collect         # gathers evidence (git, deps, environment)
proofx prove           # binds + signs → proof.json
```

### Step 3 — Verify

```bash
proofx verify proof.json
```

**Output:**

```
✓ PROOF VERIFIED

Evidence:  3/3
Relations: 1/1
Claims:    2/2
Coverage:  100%
Binding:   PASS
Signature: PASS
```

That's it. You now have a **cryptographically signed, independently verifiable** proof of your project's state.

---

### Step 4 — Verify in your browser (zero trust)

Open [**proofx.dev**](https://proofx.dev) → drag-and-drop `proof.json`.

Verification runs **entirely in your browser** using WebAssembly. No data leaves your machine. No server to trust.

### Step 5 — Add to CI

```yaml
# .github/workflows/proof.yml
- uses: EslaM-X/proofx-action@v0.4.0
  with:
    collect: true
    prove: true
    verify: true
```

Every push now generates a signed proof. Every PR can verify it.

### Step 6 — Add the verification badge

Add this to your README to show your project is verified:

```markdown
[![Proof Verified](https://proofx.dev/badge/PX-your-proof-id)](https://proofx.dev/v/PX-your-proof-id)
```

Replace `PX-your-proof-id` with the proof ID from your `proof.json`.

**What happens when someone clicks the badge:**
1. Badge shows: `✓ ProofX Verified`
2. Click opens: `proofx.dev/v/PX-your-proof-id`
3. WASM verification runs **in their browser**
4. They see the full evidence breakdown — no trust required

---

## What makes ProofX different

| | ProofX | Traditional badges |
|---|---|---|
| **Execution model** | capture execution → extract evidence → verify | sign a result |
| **Cryptographic binding** | sha256 Merkle root + ed25519 signature | A static image |
| **Independently verifiable** | anyone with `proof.json` re-verifies, no server | Trust the badge host |
| **Relations** | evidence supports claims (not just co-exists) | No structure |
| **Coverage** | 3 dimensions: evidence, relations, claims | Boolean only |
| **Human-readable** | `explain` tells you *why*, not just a boolean | Green/red only |

ProofX does **not** re-invent cryptography. It sits **on top** of proven primitives — [SHA-256](docs/CRYPTOGRAPHY.md) (FIPS 180-4) and [Ed25519](docs/CRYPTOGRAPHY.md) (RFC 8032) — and layers on [SLSA](https://slsa.dev), [Sigstore](https://sigstore.dev) and [in-toto](https://in-toto.io) as attestation providers.

## The Execution Proof Model (v0.4)

v0.4 introduces **relations** — the missing link between evidence and claims.

```json
{
  "proofVersion": "2.0",
  "execution": {
    "action": { "tool": "proofx", "version": "0.4.0" },
    "environment": { "os": "linux", "arch": "amd64", "engine": "github-actions" }
  },
  "evidence": [
    { "id": "e1", "type": "git.commit", "digest": "aabb1122..." },
    { "id": "e2", "type": "test.results", "digest": "ccdd3344..." }
  ],
  "relations": [
    { "from": "e2", "to": "c1", "type": "supports" },
    { "from": "e1", "to": "c1", "type": "supports" }
  ],
  "claims": [
    { "id": "c1", "text": "All tests pass on the recorded commit", "status": "evidenced" }
  ],
  "binding": { "algorithm": "sha256", "root": "..." },
  "signature": { "algorithm": "ed25519", "value": "..." }
}
```

**What changed from v0.3:**
- **Evidence must have a `supports` relation to a claim.** Unlinked evidence is flagged as *present but not used*.
- **Relations are part of the signature.** Mutating a relation breaks the proof.
- **Coverage is 3-dimensional.** Evidence coverage, relation coverage, claim coverage — each measured independently.

**Backward compatible:** v0.4 verifier reads v0.3 proofs via compatibility layer. v0.3 verifiers reject v0.4 proofs (new fields, new protocol version).

## Verify an artifact without a repository

ProofX's most powerful feature: **portable verification**. Verify a release binary against a proof **with no git repository present** — perfect for `curl`-and-check workflows:

```bash
proofx verify --artifact myapp-linux-amd64 --proof proof.json
```

```
✓ VERIFIED — 1/1 evidence nodes match current repo
Verification coverage: 100/100
✓ artifact app.bin matches proof PX-56b79e75
```

Anyone downloading your release can verify it came from the exact build you signed — the strongest guarantee a supply chain can offer.

## Understanding your proof

| Command | What it does |
|---|---|
| `proofx verify proof.json` | re-verify against the current repository |
| `proofx verify --artifact FILE --proof proof.json` | portable, repo-free artifact check |
| `proofx explain proof.json` | *why* each node passes/fails, likely causes + fixes |
| `proofx claims proof.json` | extract and display all claims with their status |
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
✓ e1 git.commit  [OK]
    current state matches the recorded evidence.
✓ e2 test.results  [OK]
    current state matches the recorded evidence.
✗ e3 deps.lock  [FAIL]
    expected aabb1122 actual ccdd3344
    the current state differs from the recorded evidence.
    Likely cause: dependencies changed since the proof was created.
    Recommended:  re-run `proofx collect` and create a new proof.
✓ c1  [EVIDENCED]
    supported by: e1, e2
✗ c2  [UNSUPPORTED]
    no evidence supports this claim.
```

## Coverage: 3 Dimensions

v0.4 coverage is **not a single score**. It's three measurements:

```text
Evidence:  4/5 nodes verified
Relations: 3/4 relations valid
Claims:    2/3 claims evidenced
Overall:   73%
```

- **Evidence coverage:** how many evidence nodes re-verify against the current state
- **Relation coverage:** how many relations point to valid evidence-claim pairs
- **Claim coverage:** how many claims are supported by at least one valid relation

This prevents the "100% coverage with unused evidence" problem. Every evidence node must have a purpose.

## Concepts

| Term | Meaning |
|------|---------|
| **Execution** | the action that produced evidence (CI run, build, test suite) |
| **Evidence** | an independently checkable fact (commit, file digests, test results, deps) |
| **Relation** | a directed link from evidence to claim (e.g. "e1 supports c1") |
| **Claim** | a human statement backed by evidence ("all tests pass on this commit") |
| **Proof** | a signed document: execution + evidence + relations + claims + signature |
| **Verification** | recomputing every digest and checking every relation |
| **Coverage** | 3-dimensional: evidence verified, relations valid, claims evidenced |
| **Binding root** | order-independent sha256 Merkle root over evidence + relations + claims |
| **Signature** | ed25519 over a commitment digest (execution + binding root + claims), key embedded in the proof |

> ProofX reports **Verification Coverage**, never "your project is secure". It states: *these claims have been verified against these evidence sources* — and nothing more. Read the [Threat Model](docs/THREAT_MODEL.md) for the exact guarantees and their boundaries.

## Documentation

| Doc | Contents |
|-----|----------|
| [V0.4-SPEC.md](docs/V0.4-SPEC.md) | Execution Proof Model specification |
| [SPEC.md](docs/SPEC.md) | full project specification & architecture |
| [CRYPTOGRAPHY.md](docs/CRYPTOGRAPHY.md) | formal cryptographic construction |
| [THREAT_MODEL.md](docs/THREAT_MODEL.md) | exactly what ProofX protects — and what it does **not** |
| [SECURITY.md](SECURITY.md) | vulnerability reporting, response times, key compromise procedure |
| [RELEASE_KEY.md](docs/RELEASE_KEY.md) | release signing key + how to verify downloads |
| [proof.md](docs/proof.md) | a real, verifiable ProofX proof of the ProofX repository |

## Design principles

- **No invented crypto.** sha256 (FIPS 180-4) + ed25519 (RFC 8032) + standard PEM/PKCS#8. Domain separation prevents type-confusion between protocol steps.
- **No trust in the prover.** Anyone with `proof.json` and the repository can verify.
- **Deterministic.** Evidence payloads are canonicalized; the Merkle root is order-independent — asserted by property tests and fuzzers.
- **Relations required.** Every evidence node must have a purpose. Unlinked evidence is flagged.
- **Honest coverage.** Missing sources are reported as *skipped*, never as pass.
- **Open & MIT licensed.** The core — CLI, verifier, schema, action — is free and open forever.

## Dogfooding — ProofX verifies ProofX

ProofX is used in production on the repositories below. Every push runs the `proofx-dogfood` workflow: collect evidence → bind → sign → verify.

| Repository | Badge | Proof |
|------------|-------|-------|
| [proofx](https://github.com/EslaM-X/proofx) | [![ProofX Verified](https://img.shields.io/badge/ProofX-Verified-FFB627?logo=shield&logoColor=white)](https://github.com/EslaM-X/proofx/blob/main/docs/proof.md) | self-verifying |
| [ai-agent-automation-platform](https://github.com/EslaM-X/ai-agent-automation-platform) | [![ProofX Verified](https://img.shields.io/badge/ProofX-Verified-FFB627?logo=shield&logoColor=white)](https://github.com/EslaM-X/proofx) | GitHub Actions artifacts |
| [production-systems-lab](https://github.com/EslaM-X/production-systems-lab) | [![ProofX Verified](https://img.shields.io/badge/ProofX-Verified-FFB627?logo=shield&logoColor=white)](https://github.com/EslaM-X/proofx) | GitHub Actions artifacts |
| [robot-sim-policy-lab](https://github.com/EslaM-X/robot-sim-policy-lab) | [![ProofX Verified](https://img.shields.io/badge/ProofX-Verified-FFB627?logo=shield&logoColor=white)](https://github.com/EslaM-X/proofx) | GitHub Actions artifacts |

Want your repo here? Open a PR that adds `proofx init && proofx collect && proofx prove && proofx verify proof.json` to your CI.

## Security

- **Report vulnerabilities privately** — see [SECURITY.md](SECURITY.md) for the disclosure policy, response times and the key-compromise procedure.
- **Formal guarantees** — the [Threat Model](docs/THREAT_MODEL.md) states precisely what ProofX can and cannot protect.
- **Defense in depth** — CI runs `go vet`, `golangci-lint`, `go test -race -cover`, property-based tests and fuzzers on every push.

## Roadmap

- **v0.1** ✅ — CLI (init/keygen/collect/prove/verify/inspect), proof format + JSON schema, GitHub Action, policy gate, 6 platform binaries, dogfooding.
- **v0.2** ✅ — `explain`, `diff`, `graph`, portable `verify --artifact`, property + fuzz tests, formal crypto spec, checksums + signed releases, Docker package.
- **v0.3** ✅ — independent browser verification via `proofx.wasm`, 18-case conformance suite, differential native/WASM testing, GitHub Pages verifier at proofx.dev, `.gitattributes` for deterministic corpus, CI toolchain guard.
- **v0.4** ✅ — Execution Proof Model: `supports` relations, 3-dimensional coverage, v0.4 proof format, backward-compatible verifier, 102-case conformance suite, cross-language verification (Go/WASM/Rust), 0-difference native↔WASM.
- **v1.0** — SDKs (Go/JS/Python), Evidence Graph as a first-class output, dynamic verification badge, Sigstore/attestation integration, npm/PyPI/Docker collectors, certified compliance packs.

## Contributing

1. Read [CONTRIBUTING.md](CONTRIBUTING.md), [docs/SPEC.md](docs/SPEC.md) and the [Threat Model](docs/THREAT_MODEL.md) first.
2. Open an issue to discuss the change before writing code.
3. Branch → implement → test → open a PR (requires review before merge).

- [Open Discussions](https://github.com/EslaM-X/proofx/discussions) — ask questions, share ideas
- [Report a bug](https://github.com/EslaM-X/proofx/issues/new?labels=bug) — *good first issue* and *help wanted* tags available

## License & Credits

- **MIT** — see [LICENSE](LICENSE).
- **Author** — [EslaM-X](https://github.com/EslaM-X) 🇪🇬 (EslaM, Cairo, Egypt). *"Made with ❤️ where the Nile meets the code."*
- ProofX builds on the shoulders of [Go](https://go.dev), [SLSA](https://slsa.dev), [Sigstore](https://sigstore.dev), [in-toto](https://in-toto.io) and GitHub Artifact Attestations.

---

<div align="center">

**⭐ Star the project if you want open, verifiable software evidence to become a standard.**

*Execution happens. Proof makes it verifiable. ProofX makes it simple.*

</div>
