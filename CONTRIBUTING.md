# Contributing to ProofX

Thanks for considering a contribution! ProofX is open source because we
believe **verifiable software is a right, not a privilege**. Every
contribution moves that forward.

## Code of conduct

Be respectful. ProofX is a welcoming project regardless of experience level,
background, or opinions about Merkle trees.

## Getting started

```bash
git clone https://github.com/EslaM-X/proofx.git
cd proofx
go build ./...
go test ./...          # unit + property + fuzz seeds
go vet ./...
```

Requirements: Go 1.23+ (CI tests 1.24 and 1.25).

## Where to start

- Issues labeled [`good first issue`](https://github.com/EslaM-X/proofx/labels/good%20first%20issue)
- Issues labeled [`help wanted`](https://github.com/EslaM-X/proofx/labels/help%20wanted)
- Check the [roadmap](docs/SPEC.md#11-roadmap) for the current milestone

## Before you code

1. Read [`docs/SPEC.md`](docs/SPEC.md), [`docs/CRYPTOGRAPHY.md`](docs/CRYPTOGRAPHY.md)
   and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — the protocol is
   deliberate, and the threat model defines the security boundary.
2. Open an issue or start a Discussion to align on the approach. For big
   changes, agree on design *before* writing code.

## Coding conventions

- Go style: `gofmt` + `go vet` are enforced in CI (`gofmt -l .` must be empty).
- **No invented crypto.** Only sha256 + ed25519, per the crypto spec.
- Every source file carries the SPDX header:
  ```go
  // SPDX-License-Identifier: MIT
  // Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
  ```
- Comments explain *why*, not *what*.
- New behavior needs tests. Cryptographic logic needs property tests
  (`*_property_test.go`) or fuzz targets (`Fuzz*`).

## Testing

```bash
go test ./...                # unit + property
go test -race -cover ./...
go test ./proof -fuzz=FuzzParseProof -fuzztime=1m
```

The proof format, Merkle construction and canonicalization have **no tolerance
for regressions** — they are pinned by property tests.

## Submitting a change

1. Create a branch from `main`.
2. Make your change with tests.
3. Run the full suite above.
4. Open a PR. `main` is protected: at least one review (from a code owner)
   and a green `ci` check are required.

## Release process (maintainers)

Releases are automated via tags:

```bash
git tag v0.2.1 && git push origin v0.2.1
```

`.github/workflows/release.yml` builds 6 binaries, computes `checksums.txt`,
signs it with the release key, creates the GitHub release, and publishes the
Docker image to `ghcr.io/EslaM-X/proofx`.

## Getting help

- [Discussions](https://github.com/EslaM-X/proofx/discussions) — questions and ideas
- [Issues](https://github.com/EslaM-X/proofx/issues) — bugs and feature requests
- Security issues: **never** open a public issue — see [SECURITY.md](SECURITY.md)

**ProofX is a gift from Egypt to the open-source world. 🇪🇬 Build with us.**
