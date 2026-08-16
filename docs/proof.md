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
  "id": "PX-7d611a48",
  "project": {
    "name": "EslaM-X/proofx",
    "repository": "EslaM-X/proofx"
  },
  "subject": {
    "commit": "d874e63d523d1160f6a64c4501524c41a2f96e39",
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
      "timestamp": "2026-08-16T06:40:17Z",
      "payload": "{\"files\":{\"LICENSE\":\"...\",\"README.md\":\"...\",\"schema/proof.schema.json\":\"...\"}}",
      "digest": "5ca123409745fe38077ac5aad482443f9c207481d9e51a3a1132fb63ebc97032"
    },
    {
      "id": "dependencies",
      "type": "dependencies",
      "source": "dependency lockfile digest",
      "timestamp": "2026-08-16T06:40:17Z",
      "payload": "{\"lockfiles\":{\"go.sum\":\"...\"}}",
      "digest": "5d591bec0deaf9e41c7401a5671b21cb84042f78db4cb45cdad8c65dbc4a6acc"
    },
    {
      "id": "environment",
      "type": "environment",
      "source": "build toolchain + os",
      "timestamp": "2026-08-16T06:40:17Z",
      "payload": "{\"go_version\":\"go version go1.26.5 windows/amd64\",\"os\":\"windows\"}",
      "digest": "417314ad5a296ae23e9ef5b1df8ff4bbf138df91c8f5e2add29c9a1c1291e269"
    },
    {
      "id": "git",
      "type": "git",
      "source": "git: https://github.com/EslaM-X/proofx.git",
      "timestamp": "2026-08-16T06:40:17Z",
      "payload": "{\"branch\":\"main\",\"commit\":\"d874e63d523d1160f6a64c4501524c41a2f96e39\",\"dirty\":true,\"repository\":\"https://github.com/EslaM-X/proofx.git\"}",
      "digest": "929d6f01fe7dcdb0b9d666ab38e13abb8a1d2ca389d2b6dadde7110537424594"
    }
  ],
  "binding": {
    "algorithm": "sha256",
    "root": "7d611a485af943b4fef935726d9de8d3fbd2d7765ea11caa3ec64bca8aa7fb7d",
    "entries": [
      { "id": "artifact",     "digest": "5ca123409745fe38077ac5aad482443f9c207481d9e51a3a1132fb63ebc97032" },
      { "id": "dependencies", "digest": "5d591bec0deaf9e41c7401a5671b21cb84042f78db4cb45cdad8c65dbc4a6acc" },
      { "id": "environment",  "digest": "417314ad5a296ae23e9ef5b1df8ff4bbf138df91c8f5e2add29c9a1c1291e269" },
      { "id": "git",          "digest": "929d6f01fe7dcdb0b9d666ab38e13abb8a1d2ca389d2b6dadde7110537424594" }
    ]
  },
  "signature": {
    "algorithm": "ed25519",
    "publicKey": "QqERgxcqZx6DXvMkAS1oB1PdZlkMGl3UVH1whC+xNVo=",
    "value": "..."
  },
  "coverage": { "total": 4, "verified": 4, "score": 100 },
  "createdAt": "2026-08-16T06:40:18Z",
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
