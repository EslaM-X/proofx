# ProofX Adoption

Projects using ProofX to generate cryptographically verifiable evidence of their CI/build results.

## Active Adopters

| Project | Category | Proof ID | Verification |
|---------|----------|----------|--------------|
| [proofx](https://github.com/EslaM-X/proofx) | Self-verification | PX-e2cc6779 | [Verify](https://proofx.dev/v/PX-e2cc6779) |
| [proofx-action](https://github.com/EslaM-X/proofx-action) | GitHub Action | — | CI-verified |

## External Adopters (Pending)

| Project | Category | Status | Proof ID | PR |
|---------|----------|--------|----------|-----|
| [256lights/zb](https://github.com/256lights/zb) | Reproducible builds | CI Passing | PX-814c8087 | [#355](https://github.com/256lights/zb/pull/355) |
| [cycodehq/cycode-cli](https://github.com/cycodehq/cycode-cli) | Security scanning | Pending | — | — |
| [doiito/gliding_horse](https://github.com/doiito/gliding_horse) | AI agent framework | Pending | — | — |
| [BarisYazici/libfranka-sim](https://github.com/BarisYazici/libfranka-sim) | Robotics simulation | Pending | — | — |
| [TamizhSK/YEET](https://github.com/TamizhSK/YEET) | CI/CD infrastructure | Pending | — | — |

## Why These Projects?

Each project was chosen because ProofX solves a real problem:

- **Reproducible builds** — zb promises hermetic builds; ProofX makes the claim verifiable
- **Security tooling** — cycode-cli produces scan reports; ProofX proves the scanner binary is authentic
- **AI agents** — gliding_horse orchestrates autonomous actions; ProofX proves the runtime binary is untampered
- **Robotics** — libfranka-sim bridges sim and physical hardware; artifact integrity is safety-adjacent
- **CI infrastructure** — YEET runs CI locally; ProofX proves local runs match canonical pipelines

## How to Add Your Project

1. Add the ProofX GitHub Action to your workflow:
```yaml
- uses: EslaM-X/proofx-action@v0.3.0
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
- **External repositories:** 1 (zb — CI passing, pending review)
- **Total proofs generated:** 2
- **First external proof:** PX-814c8087 (zb, 2026-08-21)
- **Independent verifications:** —
