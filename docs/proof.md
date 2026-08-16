# Sample Proof

This document shows a real ProofX proof produced by `proofx collect && proofx prove`
inside the proofx repository itself. **ProofX verifies ProofX.**

## Generate your own

```bash
git clone https://github.com/EslaM-X/proofx.git
cd proofx

go build -o proofx ./cmd/proofx
./proofx init          # keeps existing proofx.yaml
./proofx keygen
./proofx collect
./proofx prove
./proofx verify proof.json
```

## Proof document

`proof.json` written by `proofx prove`:

```json
{
  "proofVersion": "1.0",
  "id": "PX-56b79e75",
  "project": {
    "name": "EslaM-X/proofx",
    "repository": "EslaM-X/proofx"
  },
  "subject": {
    "commit": "c51daaf9034aa588d2887c39db44b48c4a9b3f7c",
    "branch": "main",
    "repository": "EslaM-X/proofx"
  },
  "claims": [
    { "id": "c1", "text": "Built from the recorded git commit", "status": "evidenced" },
    { "id": "c2", "text": "Artifacts have known sha256 digests", "status": "evidenced" },
    { "id": "c3", "text": "Dependency lockfile is committed", "status": "evidenced" }
  ],
  "evidence": [
    {
      "id": "artifact",
      "type": "artifact",
      "source": "sha256 of configured artifacts",
      "timestamp": "2026-08-16T07:24:32Z",
      "payload": "{\"files\":{\"LICENSE\":\"...\",\"README.md\":\"...\",\"schema/proof.schema.json\":\"...\"}}",
      "digest": "cc34d874ec91212017ac35d4b1f5616e4322e4f3af1059d43f70331ea1c54898"
    },
    {
      "id": "dependencies",
      "type": "dependencies",
      "source": "dependency lockfile digest",
      "timestamp": "2026-08-16T07:24:32Z",
      "payload": "{\"lockfiles\":{\"go.sum\":\"...\"}}",
      "digest": "7b81e355f9a39eb6b237c4124eb2ce5dd68467afec9ee2420f3f887fd4a77aae"
    },
    {
      "id": "environment",
      "type": "environment",
      "source": "build toolchain + os",
      "timestamp": "2026-08-16T07:24:32Z",
      "payload": "{\"go_version\":\"go version go1.26.5 windows/amd64\",\"node_version\":\"v24.18.0\",\"os\":\"windows\",\"working_dir\":\".\"}",
      "digest": "d79f8e69b3539b53d245cc01d951581ad6c6b77c3072806f22a1c64fb815eeba"
    },
    {
      "id": "git",
      "type": "git",
      "source": "git: https://github.com/EslaM-X/proofx.git",
      "timestamp": "2026-08-16T07:24:32Z",
      "payload": "{\"branch\":\"main\",\"commit\":\"c51daaf9034aa588d2887c39db44b48c4a9b3f7c\",\"commit_time\":\"2026-08-16T09:59:46+03:00\",\"dirty\":true,\"repository\":\"https://github.com/EslaM-X/proofx.git\"}",
      "digest": "d9035c066fbb20c76e9addf84ecc103078959d9b0ee7689f842e395ebbf5c284"
    }
  ],
  "binding": {
    "algorithm": "sha256",
    "root": "56b79e75fc29f766d506576238dda28e0325b39f809086eca1d79269ccd77628",
    "entries": [
      { "id": "artifact",     "digest": "cc34d874ec91212017ac35d4b1f5616e4322e4f3af1059d43f70331ea1c54898" },
      { "id": "dependencies", "digest": "7b81e355f9a39eb6b237c4124eb2ce5dd68467afec9ee2420f3f887fd4a77aae" },
      { "id": "environment",  "digest": "d79f8e69b3539b53d245cc01d951581ad6c6b77c3072806f22a1c64fb815eeba" },
      { "id": "git",          "digest": "d9035c066fbb20c76e9addf84ecc103078959d9b0ee7689f842e395ebbf5c284" }
    ]
  },
  "signature": {
    "algorithm": "ed25519",
    "publicKey": "JcArfc+P1JzIUMRi5HP/gH7AuYBa2RWdsEIUTmnwfnY=",
    "value": "..."
  },
  "coverage": { "total": 4, "verified": 4, "score": 100 },
  "createdAt": "2026-08-16T07:24:48Z",
  "builder": { "name": "proofx", "version": "0.1.0" }
}
```

## Verify the sample

```bash
# from a fresh clone of the repo (as above)
./proofx verify proof.json   # after generating your own proof
```

You can also use the **GitHub Action** to produce and upload a proof on every push:

```yaml
- uses: EslaM-X/proofx@v0.1.0
  with:
    command: prove
    policy: 90
```
