# PR Templates for ProofX Adoption

## Template 1 — 256lights/zb (Reproducible Builds)

**Title:** `ci: add ProofX workflow to cryptographically attest test/build results`

**Description:**
zb promises hermetic, reproducible builds — this PR makes the claim verifiable.

Adds a ProofX attestation job alongside the existing test matrix: on every push/PR, test results and artifact digests are bound to the commit SHA in a signed ProofX attestation uploaded as a workflow artifact.

**What this adds:**
- `.github/workflows/proofx.yml` — new workflow file
- No changes to existing workflows

**What this proves:**
- Test results are authentic (not fabricated)
- Build artifacts correspond to the exact commit
- Anyone can verify independently without trusting GitHub's status API

**Verification:**
After merging, anyone can verify the proof:
```bash
proofx verify proof.json
# Or in browser: proofx.dev/v/PX-your-proof-id
```

Docs: https://github.com/EslaM-X/proofx

---

## Template 2 — cycodehq/cycode-cli (Security Scanning)

**Title:** `ci: sign release artifacts with ProofX build provenance attestations`

**Description:**
Security tooling should be held to the highest supply-chain standard.

This adds a ProofX attestation step that cryptographically binds every released cycode-cli executable and image digest to its source commit and build workflow. Users verifying scan results can now confirm the scanner binary itself hasn't been tampered with.

**What this adds:**
- `.github/workflows/proofx.yml` — new workflow file
- No changes to existing workflows

**What this proves:**
- Release executables were built from the tagged commit
- The build pipeline produced specific artifact digests
- No binary substitution occurred between build and release

**Why this matters:**
A security scanner's reports are only as trustworthy as the binary that produced them. ProofX closes the gap.

Docs: https://github.com/EslaM-X/proofx

---

## Template 3 — doiito/gliding_horse (AI Agent Framework)

**Title:** `ci: add ProofX provenance attestations for glidingcode release binaries`

**Description:**
For enterprise adoption of an autonomous-agent runtime, binary provenance matters.

This PR adds a ProofX workflow that signs each multi-target release artifact (linux-x86_64/aarch64 musl, macOS-aarch64, windows-msvc) with a cryptographic proof linking artifact digest → git tag → build workflow run.

**What this adds:**
- `.github/workflows/proofx.yml` — new workflow file
- No changes to existing release pipeline

**What this proves:**
- Each platform binary corresponds to the tagged source
- The build workflow produced specific artifacts
- Security teams can verify releases out-of-band before deploying agents

**Verification:**
```bash
proofx verify proof.json
# Or: proofx.dev/v/PX-your-proof-id
```

Docs: https://github.com/EslaM-X/proofx

---

## Template 4 — BarisYazici/libfranka-sim (Robotics Simulation)

**Title:** `ci: attach ProofX cryptographic attestations to franka-sim PyPI releases`

**Description:**
franka-sim bridges simulation and physical Franka hardware, so artifact integrity is a safety-adjacent concern.

This adds a ProofX job that signs every wheel/sdist published from the release matrix with a verifiable proof of build provenance (commit, test pass, builder matrix).

**What this adds:**
- `.github/workflows/proofx.yml` — new workflow file
- No changes to existing publish flow

**What this proves:**
- PyPI wheels were built from the tagged commit
- Tests passed before release
- The build matrix produced specific artifact digests

**Why this matters:**
Researchers and industrial users can verify their installed package matches the audited source before running control code on physical hardware.

Docs: https://github.com/EslaM-X/proofx

---

## Template 5 — TamizhSK/YEET (CI/CD Infrastructure)

**Title:** `feat(ci): prove local CI runs with ProofX attestations`

**Description:**
YEET's pitch is "run CI locally with confidence" — this makes that confidence cryptographic.

Adds a ProofX workflow that signs each run's test results and release-artifact digests, binding them to the commit and workflow definition.

**What this adds:**
- `.github/workflows/proofx.yml` — new workflow file
- No changes to existing workflows

**What this proves:**
- Test results are authentic
- Built artifacts correspond to the commit
- Local runs can be verified against the canonical pipeline

**Why this matters:**
Users get tamper-evident evidence that their local YEET execution matches the canonical pipeline. YEET gains a flagship dogfooding story: a CI runner that proves its own runs.

Docs: https://github.com/EslaM-X/proofx
