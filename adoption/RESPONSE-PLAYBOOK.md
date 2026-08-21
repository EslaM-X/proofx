# ProofX Response Playbook

Quick-reference answers for maintainer questions during adoption.

## "What exactly does ProofX prove?"

ProofX cryptographically binds the collected evidence to the repository/commit context using a Merkle root and signs the resulting commitment with Ed25519. Verification checks that the proof and referenced evidence have not been altered. It does not claim that the underlying build or test itself is correct.

## "Why do we need this?"

The goal is to make CI-generated evidence independently verifiable after the workflow completes, rather than relying only on the CI log.

## "Why another dependency?"

The workflow uses the ProofX GitHub Action, which downloads the pinned CLI release and verifies its SHA-256 checksum before execution.

## "Is this sending our source/evidence anywhere?"

No server-side verification is required. Verification can be performed locally through the ProofX CLI or browser-side WASM verifier.

## "Can I verify locally?"

Yes. Install the CLI and run:

```bash
proofx verify proof.json
```

Or visit `https://proofx.dev/v/PX-<your-proof-id>` for browser-based WASM verification.

## "What evidence is collected?"

Three nodes by default:
- **artifact** — SHA-256 of configured output files
- **environment** — OS, Go/Node version, build toolchain
- **git** — repository URL, commit SHA, branch

## "What if I don't want to add badges?"

Badges are optional. The PR only adds the workflow. You can add badges later or never — the proof is still verifiable.

## "What if I want to remove it later?"

Delete the workflow file and the `.proofx/` directory. No persistent changes to your project.

## "What if CI fails?"

The action fails the step if verification fails, so you'll see it immediately. The proof is only uploaded on success.

## Notes

- Keep answers concise. Don't over-explain.
- If the maintainer asks something not covered here, pause and ask the team before responding.
- The goal is clarity, not persuasion. If they're not convinced, that's valuable data.
