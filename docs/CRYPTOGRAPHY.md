# ProofX Cryptography Specification

> **Protocol version 1.0** (matches `proofVersion: "1.0"` in every proof).

This document is the **authoritative, formal** description of ProofX's
cryptographic construction. It exists so that independent implementations can
be written, audited, and proven interoperable. ProofX deliberately uses only
standard primitives — **SHA-256 (FIPS 180-4)** and **Ed25519 (RFC 8032)** —
and adds explicit **domain separation** so that no hash output can be
confused with another.

---

## 1. Notation

- `H(x)` — SHA-256 digest of byte string `x`.
- `hex(x)` — lowercase hexadecimal encoding of bytes `x`.
- `canon(x)` — canonical JSON serialization of value `x` (see §2).
- `||` — byte-string concatenation.
- `\x00` — the single NUL byte (0x00), used as a field separator.
- All IDs, digests, algorithms are ASCII byte strings.
- All hashes are 32 bytes / 64 hex chars.

## 2. Canonicalization

Every evidence payload is serialized to **canonical JSON** before hashing.

Rules:
- JSON object keys are **sorted lexicographically by byte value**.
- No insignificant whitespace (compact JSON).
- Strings use UTF-8 encoding; numbers are Go `encoding/json` numbers.
- Nested objects and arrays recurse with the same rules.

Go's `encoding/json` marshals `map[string]any` with sorted keys, which
satisfies these rules. This is asserted by tests
(`TestPropertyCanonicalizationIsKeyOrderIndependent`). An independent
implementation may use any canonical JSON that produces byte-identical output
for the same logical value.

## 3. Domain-separation labels

ProofX binds every hash step to a fixed label so that a value hashed in one
protocol position can never collide with a value hashed in another.

| Label (bytes) | Used for |
|---------------|----------|
| `proofx/evidence/v1\x00` | Evidence payload digest (§4) |
| `proofx/leaf/v1\x00` | Merkle leaf (§5.2) |
| `proofx/node/v1\x00` | Merkle internal node (§5.3) |
| `proofx/sign/v1\x00` | Signed payload (§6) |

The labels include the string `v1` matching `proofVersion`, so any future
protocol change introduces new labels.

## 4. Evidence node digest

For an evidence node with canonical payload `p`:

```
evidenceDigest = hex( H( "proofx/evidence/v1\x00" || p ) )
```

The stored `evidence[].digest` field is exactly this value. It is a
**commitment** to the payload: any change to `p` changes the digest
(collision resistance), and the digest cannot be reused as a Merkle leaf or a
file hash because those use different labels.

## 5. Binding root (Merkle construction)

The binding root commits all evidence digests in an order-independent way.

### 5.1 Input

```
entries = [ { id_i, digest_i } for each evidence node ]
```

`digest_i` is the domain-separated evidence digest from §4. (No re-hashing of
the payload here — the leaf layer below provides domain separation.)

### 5.2 Leaf layer

Entries are **sorted ascending by `id`** (byte order). Sorting happens inside
`Root()`, so the caller's input order never matters.

For each entry in sorted order:

```
leaf_i = H( "proofx/leaf/v1\x00" || id_i || "\x00" || digest_i )
```

### 5.3 Tree construction (binary Merkle)

- Level 0 is the leaf list `[leaf_0, leaf_1, ...]`.
- While more than one node remains, pair nodes left-to-right:

```
node_j = H( "proofx/node/v1\x00" || left_32 || right_32 )
```

where `left_32`, `right_32` are the raw 32-byte outputs of the two children.

- **Odd-node handling:** if a level has an odd number of nodes, the last node
  is **promoted unchanged** to the next level (it is not re-hashed).
- The root is the single node of the final level.
- A tree with exactly one leaf roots to `leaf_0` itself.

### 5.4 Special cases

- **Zero evidence nodes** → root is the empty string; proof is structurally
  rejected by verification (empty evidence is not a meaningful proof).
- **One evidence node** → root = `hex(leaf_0)`.

### 5.5 Stored form

The proof stores:

```json
"binding": {
  "algorithm": "sha256",
  "root": "<64 hex chars>",
  "entries": [ { "id": "...", "digest": "..." } ]
}
```

`entries` must be the sorted list; `root` must equal `Root(entries)`.

## 6. Signature payload

The signed byte string is:

```
signedPayload = "proofx/sign/v1\x00" || algorithm || "\x00" || root
```

- `algorithm` = `"sha256"` (the binding algorithm).
- `root` = the 64-hex-char binding root string.

The signature is then:

```
signature = Ed25519_privateKey( signedPayload )
```

The proof stores:

```json
"signature": {
  "algorithm": "ed25519",
  "publicKey": "<base64 raw 32-byte ed25519 public key>",
  "value": "<base64 signature (64 bytes)>"
}
```

Note that the raw **public key bytes** (not the proof hash, not the
fingerprint) are embedded, so verification is self-contained.

## 7. Verification algorithm (exact)

`proofx verify` and any conforming implementation MUST perform, in order:

1. **Parse** `proof.json`; reject unless `proofVersion == "1.0"`.
2. **Recompute root**:
   - Build entries from `evidence[]`.
   - Sort by `id`.
   - Compute `root' = Root(entries)` per §5.
   - Assert `root' == binding.root`.
3. **Verify signature**:
   - Decode `signature.publicKey` (must be exactly 32 bytes).
   - Recompute `signedPayload` per §6 using `binding.root`.
   - Assert `Ed25519_verify(publicKey, signedPayload, signature.value)`.
4. **Re-collect current evidence** (repo mode) or **hash the artifact**
   (portable `--artifact` mode) and compare each node's digest.
5. **Report coverage** = verified nodes / total nodes.

Any mismatch at steps 2–4 is a hard verification failure (exit code 1).

## 8. Encoding rules

| Value | Encoding |
|-------|----------|
| Hash outputs | lowercase hex, 64 chars |
| ed25519 public key (in proof) | base64 (raw 32 bytes, no DER) |
| ed25519 signature | base64 (raw 64 bytes) |
| ed25519 private key (on disk) | PEM "PRIVATE KEY" (PKCS#8, RFC 5958) |
| Evidence payloads | canonical JSON (UTF-8) |
| Timestamps | RFC 3339 UTC |

## 9. Proof versioning

- `proofVersion: "1.0"` corresponds exactly to this specification.
- ProofX rejects any other `proofVersion`.
- Future protocol changes MUST bump `proofVersion` and change the domain
  labels from `v1` to the new version. Old proofs remain parseable only if
  the new version preserves them; otherwise they are rejected loudly.

## 10. Why domain separation matters

Without labels, these three values could be confused:

```
H(payload)                  — evidence digest
H(id || ":" || digest)      — leaf
H(root)                     — some other hash
```

With labels they are structurally different byte strings that share no
hash outputs (except with negligible probability). This prevents classic
**type-confusion** attacks: e.g. an attacker presenting an evidence digest as
if it were a leaf, or a leaf as if it were the root.

## 11. Test vectors & conformance

The repository ships property-based and fuzz tests that pin these
properties:

- **Determinism** — `Root(entries)` is stable across runs and input order.
- **Order independence** — permuting evidence changes nothing.
- **Tamper sensitivity** — flipping any bit of any digest or signature fails
  verification.
- **Canonicalization** — identical logical objects with different key order
  produce identical digests.
- **Parser safety** — arbitrary input never panics the parser or verifier.

Run them with:

```bash
go test ./...
go test ./proof/ -run FuzzParseProof -fuzz=FuzzParseProof -fuzztime=1m
```

## 12. Security considerations

- **No invented crypto.** Only SHA-256 and Ed25519, both standard.
- **No key transport.** The public key is embedded; the private key never
  leaves the signer.
- **Hash commitments are not secrets.** Evidence digests are public by
  design; confidentiality is out of scope.
- **Future-proofing.** All construction parameters are versioned; migration
  paths are documented in §9.

_This document is the specification. If code and spec ever disagree, the
code is a bug — report it via SECURITY.md._
