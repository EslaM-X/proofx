# Release Signing Key

ProofX releases are verified two ways:

1. **Binary digests** — each release ships `checksums.txt` listing the
   sha256 of every binary.
2. **Signature over the checksums** — `checksums.txt.sig` is an ed25519
   signature over `checksums.txt`, produced with the release signing key.

> The signing is performed by the release pipeline on GitHub; the private key
> lives only in the `RELEASE_SIGNING_KEY` repository secret and is never
> stored or displayed anywhere else.

## Public key

```
rf7Y6zk+bDQAfNnFrhBPf2zfHCBDqYUIR0GP9VUO2wg=
```

Algorithm: **ed25519** (raw 32-byte public key, base64).

## Verify a release

```bash
# 1. download the artifacts
curl -fsSL -O https://github.com/EslaM-X/proofx/releases/latest/download/checksums.txt
curl -fsSL -O https://github.com/EslaM-X/proofx/releases/latest/download/checksums.txt.sig
curl -fsSL -O https://github.com/EslaM-X/proofx/releases/latest/download/proofx-linux-amd64

# 2. check the binary digest matches the checksums
sha256sum -c checksums.txt

# 3. verify the signature over checksums.txt
#    (with any ed25519 tool; here using the proofx release-sign helper)
go run github.com/EslaM-X/proofx/tools/release-sign@latest <(echo '-----BEGIN PRIVATE KEY-----
...your-local-verification...') checksums.txt
```

The simplest practical check for most users: **the digest check (step 2) is
the critical one** — it guarantees the binary you downloaded is byte-identical
to what was built and released. The signature check additionally confirms the
checksums themselves were not tampered with.

## Rotation & compromise

If this key is ever believed compromised, the procedure in
[SECURITY.md](../SECURITY.md) (Key compromise procedure) applies: rotate,
re-sign new releases, publish the new fingerprint, and disclose publicly.
