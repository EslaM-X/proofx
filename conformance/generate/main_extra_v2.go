package main

import (
	"crypto/ed25519"

	"github.com/EslaM-X/proofx/model"
	"github.com/EslaM-X/proofx/proof"
	"github.com/EslaM-X/proofx/verifycore"
)

// ============================================================================
// v0.4 extra valid cases (batch 2)
// ============================================================================

func v4ExtraValidCases2() []CaseV4 {
	return []CaseV4{
		v4ValidSbomEvidence(),
		v4ValidSastEvidence(),
		v4ValidTagSubject(),
		v4ValidLongCommit(),
		v4ValidOverlappingSupports(),
		v4ValidEmptyPayload(),
		v4ValidNestedPayload(),
		v4ValidCustomBuilder(),
		v4ValidAllFailClaims(),
		v4ValidManyRels(),
		v4ValidHexPayload(),
		v4ValidSingleRel(),
		v4ValidUnicodeEvPayload(),
	}
}

// ============================================================================
// Shared construction helpers
// ============================================================================

func evPair(id, typ, src, payload string) model.Evidence {
	e := model.Evidence{ID: id, Type: typ, Source: src, Payload: payload}
	e.Digest = model.EvidenceDigest(e.ID, e.Payload)
	return e
}

func rel(id, from, to, kind string) model.Relation {
	return model.Relation{ID: id, From: from, To: to, Kind: kind}
}

func claim(id, typ, stmt, status string, supportedBy []string) model.V4Claim {
	return model.V4Claim{
		ID:          id,
		Type:        typ,
		Subject:     "execution:exec-001",
		Statement:   stmt,
		Status:      status,
		SupportedBy: supportedBy,
	}
}

func v4MakeProofWithSubject(id string, subj model.Subject, ev []model.Evidence, rels []model.Relation, claims []model.V4Claim, priv ed25519.PrivateKey) *model.V4Proof {
	p := &model.V4Proof{
		ProofVersion: model.ProofVersionV2,
		ID:           id,
		Project:      model.Project{Name: "test", Repository: "https://example.com/test"},
		Subject:      subj,
		Execution:    model.Execution{ID: "exec-001", Type: model.ExecCIWorkflow, StartedAt: "2026-08-21T02:00:00Z", CompletedAt: "2026-08-21T02:05:00Z", Environment: model.Environment{OS: "ubuntu-24.04", Arch: "amd64", Runtime: "go1.26.5"}},
		Evidence:     ev,
		Relations:    rels,
		Claims:       claims,
		Coverage:     model.V4Coverage{Evidence: model.CoverageDim{Total: len(ev), Verified: len(ev)}, Relations: model.CoverageDim{Total: len(rels), Verified: len(rels)}, Claims: model.CoverageDim{Total: len(claims), Verified: len(claims)}, Score: 100},
		CreatedAt:    "2026-08-21T02:05:00Z",
		Builder:      model.Builder{Name: "proofx", Version: "0.4.0"},
	}
	entries := model.V4BindingEntries(p)
	p.Binding = model.Binding{Algorithm: "sha256", Root: model.V4Root(entries), Entries: entries}
	sigPayload := model.V4SigningPayload(p)
	sig, _ := proof.SignBytes(sigPayload, priv)
	pub := proof.PublicKeyOf(priv)
	p.Signature = model.Signature{Algorithm: "ed25519", PublicKey: proof.EncodePublicKey(pub), Value: sig}
	return p
}

func v4MakeProofWithExecution(id string, exec model.Execution, ev []model.Evidence, rels []model.Relation, claims []model.V4Claim, priv ed25519.PrivateKey) *model.V4Proof {
	p := &model.V4Proof{
		ProofVersion: model.ProofVersionV2,
		ID:           id,
		Project:      model.Project{Name: "test", Repository: "https://example.com/test"},
		Subject:      model.Subject{Commit: "abc123", Branch: "main", Repository: "https://example.com/test"},
		Execution:    exec,
		Evidence:     ev,
		Relations:    rels,
		Claims:       claims,
		Coverage:     model.V4Coverage{Evidence: model.CoverageDim{Total: len(ev), Verified: len(ev)}, Relations: model.CoverageDim{Total: len(rels), Verified: len(rels)}, Claims: model.CoverageDim{Total: len(claims), Verified: len(claims)}, Score: 100},
		CreatedAt:    "2026-08-21T02:05:00Z",
		Builder:      model.Builder{Name: "proofx", Version: "0.4.0"},
	}
	entries := model.V4BindingEntries(p)
	p.Binding = model.Binding{Algorithm: "sha256", Root: model.V4Root(entries), Entries: entries}
	sigPayload := model.V4SigningPayload(p)
	sig, _ := proof.SignBytes(sigPayload, priv)
	pub := proof.PublicKeyOf(priv)
	p.Signature = model.Signature{Algorithm: "ed25519", PublicKey: proof.EncodePublicKey(pub), Value: sig}
	return p
}

// ============================================================================
// Valid case bodies
// ============================================================================

func v4ValidSbomEvidence() CaseV4 {
	ev := []model.Evidence{
		evPair("sbom", "sbom", "syft", `{"format":"spdx-json","artifacts":42}`),
	}
	rels := []model.Relation{
		rel("r1", "exec-001", "sbom", model.RelProduces),
		rel("r2", "sbom", "claim.sbom", model.RelSupports),
	}
	claims := []model.V4Claim{
		claim("claim.sbom", "sbom_present", "SBOM generated", model.ClaimPass, []string{"sbom"}),
	}
	_, priv, _ := generateDeterministicKey()
	return v4MakeCase("v4-valid-sbom", "v0.4 valid with sbom evidence type from syft source",
		v4MakeProof("v4-valid-sbom", ev, rels, claims, priv),
		true, 1, 2, 1,
		[]verifycore.V4ClaimResult{
			{ID: "claim.sbom", Type: "sbom_present", Statement: "SBOM generated", Status: "pass", SupportedBy: []string{"sbom"}, Valid: true},
		})
}

func v4ValidSastEvidence() CaseV4 {
	ev := []model.Evidence{
		evPair("sast", "sast", "semgrep", `{"findings":0,"errors":0,"rules":312}`),
	}
	rels := []model.Relation{
		rel("r1", "exec-001", "sast", model.RelProduces),
		rel("r2", "sast", "claim.sast", model.RelSupports),
	}
	claims := []model.V4Claim{
		claim("claim.sast", "static_analysis", "No critical findings", model.ClaimPass, []string{"sast"}),
	}
	_, priv, _ := generateDeterministicKey()
	return v4MakeCase("v4-valid-sast", "v0.4 valid with sast evidence type from semgrep source",
		v4MakeProof("v4-valid-sast", ev, rels, claims, priv),
		true, 1, 2, 1,
		[]verifycore.V4ClaimResult{
			{ID: "claim.sast", Type: "static_analysis", Statement: "No critical findings", Status: "pass", SupportedBy: []string{"sast"}, Valid: true},
		})
}

func v4ValidTagSubject() CaseV4 {
	ev := []model.Evidence{
		evPair("git", "git", "git", `{"commit":"abc123","ref":"v1.2.3"}`),
	}
	rels := []model.Relation{
		rel("r1", "exec-001", "git", model.RelProduces),
		rel("r2", "git", "claim.tag", model.RelSupports),
	}
	claims := []model.V4Claim{
		claim("claim.tag", "build_passed", "Built from tag ref", model.ClaimPass, []string{"git"}),
	}
	subj := model.Subject{Commit: "abc123", Branch: "v1.2.3", Repository: "https://example.com/test"}
	_, priv, _ := generateDeterministicKey()
	p := v4MakeProofWithSubject("v4-valid-tag-subject", subj, ev, rels, claims, priv)
	return v4MakeCase("v4-valid-tag-subject", "v0.4 valid with tag-style subject branch (signed before sealing)",
		p, true, 1, 2, 1,
		[]verifycore.V4ClaimResult{
			{ID: "claim.tag", Type: "build_passed", Statement: "Built from tag ref", Status: "pass", SupportedBy: []string{"git"}, Valid: true},
		})
}

func v4ValidLongCommit() CaseV4 {
	longCommit := "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
	ev := []model.Evidence{
		evPair("git", "git", "git", `{"commit":"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"}`),
	}
	rels := []model.Relation{
		rel("r1", "exec-001", "git", model.RelProduces),
		rel("r2", "git", "claim.longcommit", model.RelSupports),
	}
	claims := []model.V4Claim{
		claim("claim.longcommit", "execution_bound", "Bound to full sha1 commit", model.ClaimPass, []string{"git"}),
	}
	subj := model.Subject{Commit: longCommit, Branch: "main", Repository: "https://example.com/test"}
	_, priv, _ := generateDeterministicKey()
	p := v4MakeProofWithSubject("v4-valid-long-commit", subj, ev, rels, claims, priv)
	return v4MakeCase("v4-valid-long-commit", "v0.4 valid with 40-character commit hash subject",
		p, true, 1, 2, 1,
		[]verifycore.V4ClaimResult{
			{ID: "claim.longcommit", Type: "execution_bound", Statement: "Bound to full sha1 commit", Status: "pass", SupportedBy: []string{"git"}, Valid: true},
		})
}

func v4ValidOverlappingSupports() CaseV4 {
	ev := []model.Evidence{
		evPair("git", "git", "git", `{"commit":"abc123"}`),
		evPair("tests", "tests", "jest", `{"passed":15}`),
	}
	rels := []model.Relation{
		rel("r1", "exec-001", "git", model.RelProduces),
		rel("r2", "exec-001", "tests", model.RelProduces),
		rel("r3", "git", "claim.release", model.RelSupports),
		rel("r4", "tests", "claim.release", model.RelSupports),
	}
	claims := []model.V4Claim{
		claim("claim.release", "release_ready", "Release verified by two evidence nodes", model.ClaimPass, []string{"git", "tests"}),
	}
	_, priv, _ := generateDeterministicKey()
	return v4MakeCase("v4-valid-overlapping-supports", "v0.4 valid with two evidence nodes supporting the same claim",
		v4MakeProof("v4-valid-overlapping-supports", ev, rels, claims, priv),
		true, 2, 4, 1,
		[]verifycore.V4ClaimResult{
			{ID: "claim.release", Type: "release_ready", Statement: "Release verified by two evidence nodes", Status: "pass", SupportedBy: []string{"git", "tests"}, Valid: true},
		})
}

func v4ValidEmptyPayload() CaseV4 {
	ev := []model.Evidence{
		evPair("void-evidence", "custom", "test", ""),
	}
	rels := []model.Relation{
		rel("r1", "exec-001", "void-evidence", model.RelProduces),
		rel("r2", "void-evidence", "claim.empty", model.RelSupports),
	}
	claims := []model.V4Claim{
		claim("claim.empty", "custom_check", "Empty payload accepted", model.ClaimPass, []string{"void-evidence"}),
	}
	_, priv, _ := generateDeterministicKey()
	return v4MakeCase("v4-valid-empty-payload", "v0.4 valid with empty evidence payload string",
		v4MakeProof("v4-valid-empty-payload", ev, rels, claims, priv),
		true, 1, 2, 1,
		[]verifycore.V4ClaimResult{
			{ID: "claim.empty", Type: "custom_check", Statement: "Empty payload accepted", Status: "pass", SupportedBy: []string{"void-evidence"}, Valid: true},
		})
}

func v4ValidNestedPayload() CaseV4 {
	ev := []model.Evidence{
		evPair("nested", "custom", "test", `{"level1":{"level2":{"level3":{"values":[1,2,{"deep":true}]}}}}`),
	}
	rels := []model.Relation{
		rel("r1", "exec-001", "nested", model.RelProduces),
		rel("r2", "nested", "claim.nested", model.RelSupports),
	}
	claims := []model.V4Claim{
		claim("claim.nested", "custom_check", "Nested JSON payload handled", model.ClaimPass, []string{"nested"}),
	}
	_, priv, _ := generateDeterministicKey()
	return v4MakeCase("v4-valid-nested-payload", "v0.4 valid with deeply nested JSON evidence payload",
		v4MakeProof("v4-valid-nested-payload", ev, rels, claims, priv),
		true, 1, 2, 1,
		[]verifycore.V4ClaimResult{
			{ID: "claim.nested", Type: "custom_check", Statement: "Nested JSON payload handled", Status: "pass", SupportedBy: []string{"nested"}, Valid: true},
		})
}

func v4ValidCustomBuilder() CaseV4 {
	ev := []model.Evidence{
		evPair("git", "git", "git", `{"commit":"abc123"}`),
	}
	rels := []model.Relation{
		rel("r1", "exec-001", "git", model.RelProduces),
		rel("r2", "git", "claim.builder", model.RelSupports),
	}
	claims := []model.V4Claim{
		claim("claim.builder", "provenance", "Produced by third-party prover", model.ClaimPass, []string{"git"}),
	}
	_, priv, _ := generateDeterministicKey()
	p := v4MakeProof("v4-valid-custom-builder", ev, rels, claims, priv)
	p.Builder = model.Builder{Name: "custom-prover", Version: "1.0.0"}
	return v4MakeCase("v4-valid-custom-builder", "v0.4 valid with non-default builder fields (outside signing payload)",
		p, true, 1, 2, 1,
		[]verifycore.V4ClaimResult{
			{ID: "claim.builder", Type: "provenance", Statement: "Produced by third-party prover", Status: "pass", SupportedBy: []string{"git"}, Valid: true},
		})
}

func v4ValidAllFailClaims() CaseV4 {
	ev := []model.Evidence{
		evPair("scan", "sast", "semgrep", `{"findings":3}`),
	}
	rels := []model.Relation{
		rel("r1", "exec-001", "scan", model.RelProduces),
		rel("r2", "scan", "c1", model.RelSupports),
		rel("r3", "scan", "c2", model.RelSupports),
	}
	claims := []model.V4Claim{
		claim("c1", "security_scan", "Scan found issues", model.ClaimFail, []string{"scan"}),
		claim("c2", "license_check", "License violation detected", model.ClaimFail, []string{"scan"}),
	}
	_, priv, _ := generateDeterministicKey()
	return v4MakeCase("v4-valid-all-fail-claims", "v0.4 valid where all claims report fail status (honest attestation)",
		v4MakeProof("v4-valid-all-fail-claims", ev, rels, claims, priv),
		true, 1, 3, 2,
		[]verifycore.V4ClaimResult{
			{ID: "c1", Type: "security_scan", Statement: "Scan found issues", Status: "fail", SupportedBy: []string{"scan"}, Valid: true},
			{ID: "c2", Type: "license_check", Statement: "License violation detected", Status: "fail", SupportedBy: []string{"scan"}, Valid: true},
		})
}

func v4ValidManyRels() CaseV4 {
	ev := []model.Evidence{
		evPair("src", "git", "git", `{"commit":"abc123"}`),
		evPair("libs", "deps", "npm", `{"locked":120}`),
		evPair("unit", "tests", "jest", `{"passed":87}`),
		evPair("manifest", "sbom", "syft", `{"components":120}`),
	}
	rels := []model.Relation{
		rel("r1", "exec-001", "src", model.RelProduces),
		rel("r2", "exec-001", "libs", model.RelProduces),
		rel("r3", "exec-001", "unit", model.RelProduces),
		rel("r4", "exec-001", "manifest", model.RelProduces),
		rel("r5", "src", "libs", model.RelDependsOn),
		rel("r6", "libs", "unit", model.RelDependsOn),
		rel("r7", "src", "c1", model.RelSupports),
		rel("r8", "unit", "c2", model.RelSupports),
		rel("r9", "libs", "c3", model.RelSupports),
		rel("r10", "manifest", "c4", model.RelSupports),
	}
	claims := []model.V4Claim{
		claim("c1", "build_passed", "Source committed", model.ClaimPass, []string{"src"}),
		claim("c2", "tests_passed", "Unit tests passed", model.ClaimPass, []string{"unit"}),
		claim("c3", "deps_locked", "Dependencies locked", model.ClaimPass, []string{"libs"}),
		claim("c4", "sbom_generated", "SBOM generated", model.ClaimPass, []string{"manifest"}),
	}
	_, priv, _ := generateDeterministicKey()
	return v4MakeCase("v4-valid-many-rels", "v0.4 valid with 4 evidence nodes and mixed relation kinds",
		v4MakeProof("v4-valid-many-rels", ev, rels, claims, priv),
		true, 4, 10, 4,
		[]verifycore.V4ClaimResult{
			{ID: "c1", Type: "build_passed", Statement: "Source committed", Status: "pass", SupportedBy: []string{"src"}, Valid: true},
			{ID: "c2", Type: "tests_passed", Statement: "Unit tests passed", Status: "pass", SupportedBy: []string{"unit"}, Valid: true},
			{ID: "c3", Type: "deps_locked", Statement: "Dependencies locked", Status: "pass", SupportedBy: []string{"libs"}, Valid: true},
			{ID: "c4", Type: "sbom_generated", Statement: "SBOM generated", Status: "pass", SupportedBy: []string{"manifest"}, Valid: true},
		})
}

func v4ValidHexPayload() CaseV4 {
	ev := []model.Evidence{
		evPair("hexdump", "custom", "tool", `{"blob":"deadbeefcafebabe0123456789abcdef","encoding":"hex"}`),
	}
	rels := []model.Relation{
		rel("r1", "exec-001", "hexdump", model.RelProduces),
		rel("r2", "hexdump", "claim.hex", model.RelSupports),
	}
	claims := []model.V4Claim{
		claim("claim.hex", "artifact_integrity", "Hex encoded artifact recorded", model.ClaimPass, []string{"hexdump"}),
	}
	_, priv, _ := generateDeterministicKey()
	return v4MakeCase("v4-valid-hex-payload", "v0.4 valid with hex encoded evidence payload",
		v4MakeProof("v4-valid-hex-payload", ev, rels, claims, priv),
		true, 1, 2, 1,
		[]verifycore.V4ClaimResult{
			{ID: "claim.hex", Type: "artifact_integrity", Statement: "Hex encoded artifact recorded", Status: "pass", SupportedBy: []string{"hexdump"}, Valid: true},
		})
}

func v4ValidSingleRel() CaseV4 {
	ev := []model.Evidence{
		evPair("git", "git", "git", `{"commit":"abc123"}`),
	}
	rels := []model.Relation{
		rel("r1", "git", "claim.min", model.RelSupports),
	}
	claims := []model.V4Claim{
		claim("claim.min", "minimal_check", "Minimal relation graph", model.ClaimPass, []string{"git"}),
	}
	_, priv, _ := generateDeterministicKey()
	return v4MakeCase("v4-valid-single-rel", "v0.4 minimal graph: one evidence, one supports relation, one claim",
		v4MakeProof("v4-valid-single-rel", ev, rels, claims, priv),
		true, 1, 1, 1,
		[]verifycore.V4ClaimResult{
			{ID: "claim.min", Type: "minimal_check", Statement: "Minimal relation graph", Status: "pass", SupportedBy: []string{"git"}, Valid: true},
		})
}

func v4ValidUnicodeEvPayload() CaseV4 {
	ev := []model.Evidence{
		evPair("uni-ev", "custom", "test", "{\"note\":\"caf\u00e9 \u65e5\u672c\u8a9e \u0442\u0435\u0441\u0442\"}"),
	}
	rels := []model.Relation{
		rel("r1", "exec-001", "uni-ev", model.RelProduces),
		rel("r2", "uni-ev", "claim.uni", model.RelSupports),
	}
	claims := []model.V4Claim{
		claim("claim.uni", "i18n_check", "Unicode evidence payload handled", model.ClaimPass, []string{"uni-ev"}),
	}
	_, priv, _ := generateDeterministicKey()
	return v4MakeCase("v4-valid-unicode-ev-payload", "v0.4 valid with unicode characters in evidence payload",
		v4MakeProof("v4-valid-unicode-ev-payload", ev, rels, claims, priv),
		true, 1, 2, 1,
		[]verifycore.V4ClaimResult{
			{ID: "claim.uni", Type: "i18n_check", Statement: "Unicode evidence payload handled", Status: "pass", SupportedBy: []string{"uni-ev"}, Valid: true},
		})
}
