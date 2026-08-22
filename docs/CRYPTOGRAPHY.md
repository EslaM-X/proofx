# ProofX Cryptography Specification

> **Protocol version 1.0** (v0.3 proofs, `proofVersion: "1.0"`) and
> **Protocol version 2.0** (v0.4 proofs, `proofVersion: "2.0"`).
> Sections marked [v2] apply only to protocol version 2.0.

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

### Normative rules (implementation-independent):

1. **Key ordering**: Object keys are sorted lexicographically by Unicode
   code point (byte value for ASCII). Sort before encoding, not after.
2. **No insignificant whitespace**: No spaces, tabs, or newlines between
   tokens. The output is compact JSON.
3. **Strings**: UTF-8 encoded. No escape sequences for characters that
   don't require them (e.g. `\u002F` → `/`). Strings containing only
   ASCII characters use no escapes.
4. **Numbers**: Represented as JSON numbers. No leading zeros (except `0`
   itself). No trailing zeros after decimal point. No scientific notation
   unless the value requires it.
5. **Booleans**: lowercase `true` / `false`.
6. **Null**: lowercase `null`.
7. **Arrays**: Elements in their original order. No trailing commas.
8. **Nesting**: Recurse with the same rules at every depth.

### Canonical form is unique

For any given logical value, exactly one byte sequence satisfies these rules.
An independent implementation MUST produce byte-identical output.

### Implementation note (Go)

Go's `encoding/json.Marshal` on `map[string]any` produces sorted keys and
compact output. However, ProofX does NOT rely on this directly. The
`Canonicalize()` function in `model/canonical.go` parses and re-encodes to
guarantee conformance. An independent implementation may use any method that
produces the same bytes.

### Canonical form examples

Input: `{"b": 2, "a": 1}`
Canonical: `{"a":1,"b":2}`

Input: `{"name": "proofx", "version": "2.0"}`
Canonical: `{"name":"proofx","version":"2.0"}`

Input: `[{"id": "e1"}, {"id": "e2"}]`
Canonical: `[{"id":"e1"},{"id":"e2"}]`

## 3. Domain-separation labels

ProofX binds every hash step to a fixed label so that a value hashed in one
protocol position can never collide with a value hashed in another.

| Label (bytes) | Used for |
|---------------|----------|
| `proofx/evidence/v1\x00` | Evidence payload digest (§4) |
| `proofx/leaf/v1\x00` | Merkle leaf (§5.2) |
| `proofx/node/v1\x00` | Merkle internal node (§5.3) |
| `proofx/sign/v1\x00` | Signed payload (§6) |
| `proofx/evidence/v2\x00` | [v2] Evidence payload digest |
| `proofx/leaf/v2\x00` | [v2] Merkle leaf |
| `proofx/node/v2\x00` | [v2] Merkle internal node |
| `proofx/sign/v2\x00` | [v2] Signed payload |

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

The binding root commits all entries in an order-independent way.

### 5.1 Input

```
entries = [ { id_i, digest_i } for each entry ]
```

**v1**: entries come from `evidence[]` only.
**v2**: entries come from `evidence[]`, `relations[]`, and `claims[]` per §5.1.1.

`digest_i` is the domain-separated evidence digest from §4 (v1) or the
pre-computed digest from §5.1.1 (v2).

### 5.1.1 [v2] Extended binding entries

In protocol v2.0, the binding root commits over **three types** of entries:
evidence, relations, and claims. Each type uses a prefix to prevent
cross-type collisions:

```
entries = [
    { id: "ev:<evidence_id>",    digest: <evidence_digest> },
    ...
    { id: "rel:<relation_id>",   digest: H("proofx/relation/v2\x00" || from || "\x00" || to || "\x00" || kind) },
    ...
    { id: "claim:<claim_id>",    digest: H("proofx/claim/v2\x00" || statement || "\x00" || status) },
    ...
]
```

### 5.2 Leaf layer

Entries are **sorted ascending by `id`** (byte order). Sorting happens inside
`Root()`, so the caller's input order never matters.

For each entry in sorted order:

```
leaf_i = H( label || id_i || ":" || digest_i )
```

where `label` is:
- v1: `"proofx/leaf/v1\x00"`
- v2: `"proofx/leaf/v2\x00"`

Both versions use `:` as the separator between `id` and `digest`.

### 5.3 Tree construction (binary Merkle)

- Level 0 is the leaf list `[leaf_0, leaf_1, ...]`.
- While more than one node remains, pair nodes left-to-right:

```
node_j = H( label || left_32 || right_32 )
```

where `label` is:
- v1: `"proofx/node/v1\x00"`
- v2: `"proofx/node/v2\x00"`

and `left_32`, `right_32` are the **raw 32-byte** SHA-256 outputs (not hex).

**Normative node encoding**: The node hash is SHA-256 of: domain label (14 bytes)
+ left child (32 bytes raw) + right child (32 bytes raw) = 78 bytes total.

- **Odd-node handling**: if a level has an odd number of nodes, the last node
  is **promoted unchanged** to the next level (it is not re-hashed).
- The root is the single node of the final level.
- A tree with exactly one leaf roots to `leaf_0` itself.

### 5.4 Special cases

- **Zero entries** → root is the empty string; proof is structurally
  rejected by verification (empty entries is not a meaningful proof).
- **One entry** → root = `hex(leaf_0)`.

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

### 5.6 Determinism guarantee

For any set of entries, `Root(entries)` produces the same 64-character
hex string regardless of:
- Input order of entries
- Implementation language
- Platform (32-bit vs 64-bit)

This is because:
1. Entries are sorted by `id` before hashing
2. All hashes use SHA-256 (32 bytes)
3. Domain labels prevent cross-type collisions
4. Odd nodes are promoted, not re-hashed

## 6. Signature payload

The signature commits the **full proof commitment** — not just the binding
root — so that claims, project, and subject cannot be modified without
breaking the signature.

### 6.1 Commitment digest

A stable digest is computed over the non-redundant proof content:

```
commitmentDigest = hex( H(
    proofVersion
  || \x00 || projectName
  || \x00 || projectRepository
  || \x00 || subjectCommit
  || \x00 || subjectBranch
  || \x00 || subjectRepository
  || \x00 || claim_1.id || \x00 || claim_1.text || \x00 || claim_1.status
  || \x00 || claim_2.id || \x00 || claim_2.text || \x00 || claim_2.status
  || ...
  || \x00 || bindingAlgorithm
  || \x00 || bindingRoot
))
```

### 6.1.1 [v2] Extended commitment digest

In protocol v2.0, the commitment digest also includes execution context:

```
commitmentDigest = hex( H(
    "2.0"
  || \x00 || projectName
  || \x00 || projectRepository
  || \x00 || execution.id
  || \x00 || execution.type
  || \x00 || subjectCommit
  || \x00 || subjectBranch
  || \x00 || subjectRepository
  || \x00 || claim_1.id || \x00 || claim_1.statement || \x00 || claim_1.status
  || \x00 || claim_2.id || \x00 || claim_2.statement || \x00 || claim_2.status
  || ...
  || \x00 || bindingAlgorithm
  || \x00 || bindingRoot
))
```

Key differences from v1:
- `execution.id` and `execution.type` are included
- `claim.text` is now `claim.statement`
- Claims use the `statement` field, not `text`

Fields are concatenated with NUL (`\x00`) separators in exactly the order
shown. Claims are included in the order they appear in `proof.claims[]`.
This is a **plain hash** (no domain-separation label) because it is never
compared to evidence digests or Merkle nodes.

### 6.2 Signed payload

The signed byte string is:

```
signedPayload = "proofx/sign/v1\x00" || commitmentDigest     [v1]
signedPayload = "proofx/sign/v2\x00" || commitmentDigest     [v2]
```

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

1. **Parse** `proof.json`; reject unless `proofVersion == "1.0"` or `"2.0"`.
   If `"1.0"`, use v1 domain labels (`/v1/`). If `"2.0"`, use v2 labels (`/v2/`).
2. **Recompute root**:
   - [v1] Build entries from `evidence[]`.
   - [v2] Build entries from `evidence[]`, `relations[]`, and `claims[]` per §5.1.1.
   - Sort by `id`.
   - Compute `root' = Root(entries)` per §5.
   - Assert `root' == binding.root`.
3. **Verify signature**:
   - Decode `signature.publicKey` (must be exactly 32 bytes).
   - Recompute `commitmentDigest` per §6.1 [v1] or §6.1.1 [v2].
   - Recompute `signedPayload` per §6.2 using the appropriate label.
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

- `proofVersion: "1.0"` corresponds to protocol v1 (v0.3 proofs).
- `proofVersion: "2.0"` corresponds to protocol v2 (v0.4 proofs).
- The v0.4 verifier accepts both `"1.0"` (via compatibility layer) and `"2.0"`.
- Older verifiers (v0.3 and earlier) reject `"2.0"` proofs.
- Future protocol changes MUST bump `proofVersion` and change the domain
  labels. Old proofs remain parseable only if the new version preserves them;
  otherwise they are rejected loudly.

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

The repository ships golden vectors in `conformance/golden/` that are
**part of the protocol contract**. Any conforming implementation MUST
produce the same verification result for each vector.

### Golden vectors (v0.4)

| Vector | Expected | Failing check |
|--------|----------|---------------|
| `golden-v04-valid.json` | PASS | — |
| `golden-v04-tampered-sig.json` | FAIL | signature |
| `golden-v04-tampered-claim.json` | FAIL | binding |
| `golden-v04-missing-relation.json` | FAIL | schema |
| `golden-v04-wrong-version.json` | FAIL | schema |

The `manifest.json` in the same directory describes each vector. These
vectors are generated by `TestGoldenVectors_Generate` and must not be
edited manually. Any change to these vectors requires a protocol version
bump.

### Property-based tests

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
