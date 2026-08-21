# ProofX Adoption

Projects using ProofX to generate cryptographically verifiable evidence of their CI/build results.

## Active Adopters

| Project | Category | Proof ID | Verification |
|---------|----------|----------|--------------|
| [proofx](https://github.com/EslaM-X/proofx) | Self-verification | PX-e2cc6779 | [Verify](https://proofx.dev/v/PX-e2cc6779) |
| [proofx-action](https://github.com/EslaM-X/proofx-action) | GitHub Action | — | CI-verified |

## Adoption Experiments

Each experiment tests a different hypothesis about which use case makes ProofX valuable enough for a maintainer to keep.

### Experiment #1 — Reproducible Builds

| Field | Value |
|-------|-------|
| Repository | [256lights/zb](https://github.com/256lights/zb) |
| Category | Reproducible builds |
| PR | [#355](https://github.com/256lights/zb/pull/355) |
| Status | Open |
| CI | Passing |
| Proof ID | PX-814c8087 |

**Hypothesis:**
Can an external repository understand and adopt ProofX with a single workflow file and no application changes?

**Observed:**
- CI passed on first try (after v0.3.2 fix)
- No maintainer feedback yet
- Evidence collected: artifact, environment, git (3 nodes, 100% coverage)

**Learned:**
- _Pending maintainer feedback_

---

### Experiment #2 — Security Scanning

| Field | Value |
|-------|-------|
| Repository | [cycodehq/cycode-cli](https://github.com/cycodehq/cycode-cli) |
| Category | Security scanning |
| PR | Not opened |
| Status | Prepared |

**Hypothesis:**
Does a security project care about proving their scan binary is authentic and untampered?

**Learned:**
- _Not started_

---

### Experiment #3 — AI Agent Provenance

| Field | Value |
|-------|-------|
| Repository | [doiito/gliding_horse](https://github.com/doiito/gliding_horse) |
| Category | AI agent framework |
| PR | Not opened |
| Status | Prepared |

**Hypothesis:**
Does an AI project care about proving their build/runtime binary is signed and verifiable?

**Learned:**
- _Not started_

---

### Experiment #4 — Robotics Simulation

| Field | Value |
|-------|-------|
| Repository | [BarisYazici/libfranka-sim](https://github.com/BarisYazici/libfranka-sim) |
| Category | Robotics simulation |
| PR | Not opened |
| Status | Prepared |

**Hypothesis:**
Does a safety-adjacent project care about artifact integrity proofs?

**Learned:**
- _Not started_

---

### Experiment #5 — CI Infrastructure

| Field | Value |
|-------|-------|
| Repository | [TamizhSK/YEET](https://github.com/TamizhSK/YEET) |
| Category | CI/CD infrastructure |
| PR | Not opened |
| Status | Prepared |

**Hypothesis:**
Does a CI tool care about proving local runs match canonical pipelines?

**Learned:**
- _Not started_

---

## How to Add Your Project

1. Add the ProofX GitHub Action to your workflow:
```yaml
- uses: EslaM-X/proofx-action@v0.3.2
  with:
    collect: true
    prove: true
    verify: true
```

2. Add the verification badge to your README:
```markdown
[![Proof Verified](https://proofx.dev/badge/PX-your-proof-id)](https://proofx.dev/v/PX-your-proof-id)
```

3. Open a PR adding your project to this list.

## Verification Flow

```
GitHub README badge
    ↓
proofx.dev/badge/PX-xxxxx
    ↓
proofx.dev/v/PX-xxxxx
    ↓
WASM verification in browser
    ↓
✓ PROOF VERIFIED
```

## Metrics

- **Repositories using ProofX:** 2 (internal)
- **Experiments running:** 1 (zb — CI passing, pending review)
- **Experiments prepared:** 4 (cycode-cli, gliding_horse, libfranka-sim, YEET)
- **Total proofs generated:** 2
- **First external proof:** PX-814c8087 (zb, 2026-08-21)
- **Independent verifications:** —
