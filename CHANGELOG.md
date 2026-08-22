# Changelog

All notable changes to ProofX are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/).

## [0.4.0] - Execution Proof Model

### Added

- **Protocol v2** (`proofVersion: "2.0"`). New execution proof model with
  Execution, Relations, and Claims as first-class objects.
- **Merkle v2 binding**. Binding root now commits over evidence, relations,
  and claims using `/v2/` domain labels.
- **Extended commitment digest**. Signature covers execution context,
  binding root, and claims.
- **3-dimensional coverage**. Evidence, relations, and claims each measured
  independently.
- **CLI v4 commands**. `proofx verify` (v4 pipeline), `proofx inspect`
  (evidence graph), `proofx claims` (structured claims), `proofx explain`
  (verification diagnostics), `proofx diff` (proof comparison).
- **Backward compatibility**. v0.4 verifier reads v0.3 proofs via
  `V3ToV4()` compatibility layer.
- **Golden vectors**. 5 deterministic protocol fixtures (valid, tampered-sig,
  tampered-claim, missing-relation, wrong-version) as protocol contract.
- **RC gates**. 6-gate release qualification: CLI/WASM differential, real
  v0.4 self-proof, cross-version interop, golden vectors, clean-install
  matrix, release artifact validation.
- **102-case conformance suite**. Cross-language corpus covering valid proofs
  (41), invalid proofs (46), and malformed bytes (15) — verified identically
  by Go, WASM, and Rust implementations.
- **Independent Rust verifier** (`verifier-rs/`). Standalone v0.4 verifier
  in Rust, verifying Go-produced proofs with identical semantics.
- **Attack lab** (`verifycore/v2_attack_test.go`). 14 adversarial test
  scenarios covering cross-key forgery, evidence swap, version downgrade,
  domain label confusion, and more.
- **ProofX GitHub Action** generates v0.4 proofs natively.

### Changed

- Evidence digests now use `EvidenceDigest(id, payload)` format.
- Signature is now over an extended commitment digest (not just binding root).
- Coverage is 3-dimensional (evidence × relations × claims).

### Fixed

- npm postinstall: corrected `https` module import for Windows compatibility.

### Security

- Attack lab with 14 adversarial test scenarios covering key forgery, evidence
  swap, version downgrade, signature truncation, domain label confusion, and
  more. Each scenario documents the threat, expected invariant, mechanism, and
  result. Coverage of attack scenarios is not a claim of complete security.

## [0.3.0] - Independent Verification

### Added

- **Independent verification core** (`verifycore/`). Standalone engine
  with zero external dependencies — no CLI, no filesystem, no network.
- **Browser-native WASM verifier** (`cmd/proofx-wasm`). Exposes
  `verifyProof(jsonString)` as a global JS function. 3.47 MB.
- **18-case conformance suite** (`conformance/`). Deterministic corpus
  with valid (5), invalid (10), and malformed (3) proof documents.
- **Native/WASM differential verification** (`conformance/diff.js`).
  Every case produces identical results on native Go and WASM.
- **ProofX self-verification**. ProofX verifies its own proofs end-to-end.
- **GitHub Pages verifier** at `proofx.dev`. Drag/drop a proof file —
  verification happens entirely in your browser.
- **`.gitattributes`** for cross-platform LF enforcement on conformance
  corpus, JSON, YAML, JS, and Go files.
- **CI toolchain guard**. wasm_exec.js must match the Go installation
  via diff against GOROOT.
- **Deterministic key generation** in conformance generator. Shared
  stateful reader ensures reproducible corpus across runs and platforms.

### Changed

- **CI Go 1.26** for conformance and release builds.
- **Release workflow** now builds WASM binary and wasm_exec.js as
  release assets with checksums.

### Security

- Deterministic conformance corpus prevents non-reproducible CI failures.
- Diff-based wasm_exec.js check prevents version skew between compiler
  and runtime support file.

### Changed

- **Strengthened Ed25519 signature binding.** Signatures now bind the
  complete proof commitment: version, project, subject, claims, algorithm,
  and Merkle root. Previously only the root was signed, leaving claims,
  project, and subject unprotected against post-signature modification.
- **Removed `working_dir` from environment evidence.** Absolute paths
  broke portable verification across machines. The environment node now
  contains only toolchain and OS information.
- **Strict artifact verification.** The verifier now requires the artifact
  file to be declared by its exact name in the proof. The previous fallback
  that accepted any file with a matching digest regardless of name has
  been removed.

### Added

- **Regression tests for signature binding.** Ten new tests prove that
  modifying claims, project, subject, version, algorithm, root, or
  signature after signing causes verification failure.
- **Automated publish workflow** (`.github/workflows/publish.yml`).
  Triggered on release publication. Publishes to npm, PyPI, and updates
  the Homebrew tap automatically.
- **Compatibility policy** (`docs/COMPATIBILITY.md`). Documents proof
  format versions, migration path, and backward compatibility guarantees.
- **CHANGELOG.md** (this file).

### Compatibility

- Proofs generated with the pre-0.2.1 signature-binding scheme are
  **not accepted** by the current verifier. They must be regenerated
  with v0.2.1+.
- Existing legacy proofs are valid under the legacy signing scheme but
  incompatible with the strengthened v0.2.1 verification rules.

### Security

- Prevents post-signature modification of proof metadata (claims, project,
  subject) without breaking the ed25519 signature.
- Improves proof portability by removing machine-specific paths from
  signed evidence.
- Eliminates artifact verification bypass via digest-matching fallback.

## [0.2.0] - Evidence Infrastructure

### Added

- Domain-separated cryptographic protocol (SHA-256 + Ed25519).
- `explain` command: human-readable failure analysis with likely causes.
- `diff` command: evidence-node-by-evidence-node comparison.
- `graph` command: Evidence Graph rendering (ASCII + JSON).
- Portable artifact verification: `proofx verify --artifact <file>`.
- Property-based and fuzz tests.
- Cryptography specification (`docs/CRYPTOGRAPHY.md`).
- Threat model (`docs/THREAT_MODEL.md`).
- Security policy (`SECURITY.md`).
- Signed release checksums.
- Docker image (`ghcr.io/eslam-x/proofx`).
- npm, PyPI, and Homebrew packages.
- GitHub Topics, Discussions, and community scaffolding.

## [0.1.0] - Initial Release

### Added

- CLI: `init`, `collect`, `prove`, `verify`, `inspect`, `keygen`.
- `proof.json` format with evidence graph, binding, and signature.
- GitHub Action (`EslaM-X/proofx@v0.1.0`).
- Policy gate: fail CI if coverage drops below threshold.
- JSON schema for proof validation.
