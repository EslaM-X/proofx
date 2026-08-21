# Add ProofX verification to CI

## What this does

Adds a [ProofX](https://github.com/EslaM-X/proofx) workflow that records and cryptographically binds the evidence produced by the CI run into a signed `proof.json`.

The workflow runs after tests pass and:
1. Collects evidence (commit SHA, git state, test results, environment)
2. Binds the evidence using a SHA-256 Merkle root
3. Signs the binding with ed25519
4. Uploads `proof.json` as a workflow artifact

## What this proves

- The evidence was collected from this specific commit
- The evidence was bound together using a Merkle root
- The binding was signed with an ed25519 key
- Anyone can independently verify the proof: `proofx verify proof.json`

## What this does NOT prove

- That the build is reproducible (zb has its own mechanisms for that)
- That the tests are comprehensive
- Any external claim beyond the evidence collected by the protocol

## Why this might be useful for zb

zb already has ed25519 signing for realizations (issues #159, #160, PR #307). ProofX provides a similar mechanism for CI results — a portable, independently verifiable attestation that doesn't depend on GitHub's status API.

This is additive only. No existing workflows are modified.

## Verification

After merging, anyone can verify:
```bash
proofx verify proof.json
```

Or in the browser (no install needed):
```
proofx.dev/v/<PROOF_ID>
```

## Questions

I'm not sure this is the right fit for zb. Happy to:
- Modify the workflow to collect different evidence
- Change the integration approach
- Close this PR if it doesn't align with zb's goals

Docs: https://github.com/EslaM-X/proofx
