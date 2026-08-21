# ProofX Adoption Patch for cycode-cli

## Files to add

### .github/workflows/proofx.yml
See `cycode-cli-proofx.yml` in this directory.

### README.md addition
Add after the existing badges:
```markdown
[![Proof Verified](https://proofx.dev/badge/PX-your-proof-id)](https://proofx.dev/v/PX-your-proof-id)
```

## Notes
- This is a PREPARED patch. Do NOT open PR until Experiment #1 (zb) feedback is received.
- The hypothesis being tested: "Does a security project care about proving their scan binary is authentic?"
- The workflow runs tests first, then generates proof — same pattern as zb.
- No application changes required.
