package main

import (
	"fmt"

	"github.com/EslaM-X/proofx/model"
	"github.com/EslaM-X/proofx/proof"
	"github.com/EslaM-X/proofx/verifycore"
)

func v4ExtraValidCases() []CaseV4 {
	return []CaseV4{
		v4ValidUnicodeProject(),
		v4ValidPendingClaims(),
		v4ValidCustomExecType(),
		v4ValidTenEvidence(),
		v4ValidFiveClaims(),
		v4ValidSpecialChars(),
		v4ValidLongStrings(),
		v4ValidAllRelationKinds(),
		v4ValidEmptyEnvironment(),
		v4ValidNotApplicableClaims(),
		v4ValidSingleEvidenceMultiClaims(),
		v4ValidChainRelations(),
		v4ValidWithRevokedClaim(),
		v4ValidNotApplicableMixed(),
	}
}

func v4ExtraInvalidCases() []CaseV4 {
	return []CaseV4{
		v4InvalidEvidenceDigestMismatch(),
		v4InvalidEvidencePayloadTamper(),
		v4InvalidRelationFromTamper(),
		v4InvalidRelationToTamper(),
		v4InvalidClaimSupportedByMissing(),
		v4InvalidClaimStatusTamper(),
		v4InvalidClaimTypeTamper(),
		v4InvalidBindingAlgorithm(),
		v4InvalidSignatureAlgorithm(),
		v4InvalidProjectNameTamper(),
		v4InvalidSubjectCommitTamper(),
		v4InvalidSubjectBranchTamper(),
		v4InvalidEmptyEvidenceArray(),
		v4InvalidWrongBindingRoot(),
	}
}

func v4ValidUnicodeProject() CaseV4 {
	ev := []model.Evidence{
		{ID: "git", Type: "git", Source: "git", Payload: `{"commit":"abc123"}`, Digest: ""},
	}
	ev[0].Digest = model.EvidenceDigest(ev[0].ID, ev[0].Payload)
	rels := []model.Relation{
		{ID: "r1", From: "exec-001", To: "git", Kind: model.RelProduces},
		{ID: "r2", From: "git", To: "claim.build", Kind: model.RelSupports},
	}
	claims := []model.V4Claim{
		{ID: "claim.build", Type: "build_passed", Subject: "execution:exec-001", Statement: "Build passed", Status: model.ClaimPass, SupportedBy: []string{"git"}},
	}
	_, priv, _ := generateDeterministicKey()
	p := v4MakeProofWithProject("v4-valid-unicode-project", "\u041f\u0440\u043e\u0435\u043a\u0442-\u6d4b\u8bd5", ev, rels, claims, priv)
	return v4MakeCase("v4-valid-unicode-project", "v0.4 valid with unicode project name",
		p, true, 1, 2, 1,
		[]verifycore.V4ClaimResult{
			{ID: "claim.build", Type: "build_passed", Statement: "Build passed", Status: "pass", SupportedBy: []string{"git"}, Valid: true},
		})
}

func v4ValidPendingClaims() CaseV4 {
	ev := []model.Evidence{
		{ID: "git", Type: "git", Source: "git", Payload: `{"commit":"abc123"}`, Digest: ""},
	}
	ev[0].Digest = model.EvidenceDigest(ev[0].ID, ev[0].Payload)
	rels := []model.Relation{
		{ID: "r1", From: "exec-001", To: "git", Kind: model.RelProduces},
		{ID: "r2", From: "git", To: "claim.build", Kind: model.RelSupports},
		{ID: "r3", From: "git", To: "claim.deploy", Kind: model.RelSupports},
	}
	claims := []model.V4Claim{
		{ID: "claim.build", Type: "build_passed", Subject: "execution:exec-001", Statement: "Build passed", Status: model.ClaimPass, SupportedBy: []string{"git"}},
		{ID: "claim.deploy", Type: "deployment_ready", Subject: "execution:exec-001", Statement: "Deployment pending", Status: model.ClaimPending, SupportedBy: []string{"git"}},
	}
	_, priv, _ := generateDeterministicKey()
	return v4MakeCase("v4-valid-pending-claims", "v0.4 valid with pending claim",
		v4MakeProof("v4-valid-pending-claims", ev, rels, claims, priv),
		true, 1, 3, 2,
		[]verifycore.V4ClaimResult{
			{ID: "claim.build", Type: "build_passed", Statement: "Build passed", Status: "pass", SupportedBy: []string{"git"}, Valid: true},
			{ID: "claim.deploy", Type: "deployment_ready", Statement: "Deployment pending", Status: "pending", SupportedBy: []string{"git"}, Valid: true},
		})
}

func v4ValidCustomExecType() CaseV4 {
	ev := []model.Evidence{
		{ID: "git", Type: "git", Source: "git", Payload: `{"commit":"abc123"}`, Digest: ""},
	}
	ev[0].Digest = model.EvidenceDigest(ev[0].ID, ev[0].Payload)
	rels := []model.Relation{
		{ID: "r1", From: "exec-001", To: "git", Kind: model.RelProduces},
		{ID: "r2", From: "git", To: "claim.build", Kind: model.RelSupports},
	}
	claims := []model.V4Claim{
		{ID: "claim.build", Type: "build_passed", Subject: "execution:exec-001", Statement: "Local build passed", Status: model.ClaimPass, SupportedBy: []string{"git"}},
	}
	_, priv, _ := generateDeterministicKey()
	p := v4MakeProofWithType("v4-valid-custom-exec", model.ExecLocalBuild, ev, rels, claims, priv)
	return v4MakeCase("v4-valid-custom-exec", "v0.4 valid with local build exec type",
		p, true, 1, 2, 1,
		[]verifycore.V4ClaimResult{
			{ID: "claim.build", Type: "build_passed", Statement: "Local build passed", Status: "pass", SupportedBy: []string{"git"}, Valid: true},
		})
}

func v4ValidTenEvidence() CaseV4 {
	ev := make([]model.Evidence, 10)
	for i := range ev {
		ev[i] = model.Evidence{ID: fmt.Sprintf("ev-%d", i), Type: "custom", Source: "src", Payload: fmt.Sprintf(`{"seq":%d}`, i), Digest: ""}
		ev[i].Digest = model.EvidenceDigest(ev[i].ID, ev[i].Payload)
	}
	rels := make([]model.Relation, 11)
	for i := 0; i < 10; i++ {
		rels[i] = model.Relation{ID: fmt.Sprintf("r%d", i), From: "exec-001", To: fmt.Sprintf("ev-%d", i), Kind: model.RelProduces}
	}
	rels[10] = model.Relation{ID: "r10", From: "ev-0", To: "claim.all", Kind: model.RelSupports}
	ids := make([]string, 10)
	for i := range ids {
		ids[i] = fmt.Sprintf("ev-%d", i)
	}
	claims := []model.V4Claim{
		{ID: "claim.all", Type: "all_verified", Subject: "execution:exec-001", Statement: "All evidence present", Status: model.ClaimPass, SupportedBy: ids},
	}
	_, priv, _ := generateDeterministicKey()
	return v4MakeCase("v4-valid-ten-evidence", "v0.4 valid with 10 evidence nodes",
		v4MakeProof("v4-valid-ten-evidence", ev, rels, claims, priv),
		true, 10, 11, 1,
		[]verifycore.V4ClaimResult{
			{ID: "claim.all", Type: "all_verified", Statement: "All evidence present", Status: "pass", SupportedBy: ids, Valid: true},
		})
}

func v4ValidFiveClaims() CaseV4 {
	ev := []model.Evidence{
		{ID: "git", Type: "git", Source: "git", Payload: `{"commit":"abc123"}`, Digest: ""},
		{ID: "tests", Type: "tests", Source: "jest", Payload: `{"passed":42}`, Digest: ""},
		{ID: "lint", Type: "lint", Source: "eslint", Payload: `{"errors":0}`, Digest: ""},
	}
	for i := range ev {
		ev[i].Digest = model.EvidenceDigest(ev[i].ID, ev[i].Payload)
	}
	rels := []model.Relation{
		{ID: "r1", From: "exec-001", To: "git", Kind: model.RelProduces},
		{ID: "r2", From: "exec-001", To: "tests", Kind: model.RelProduces},
		{ID: "r3", From: "exec-001", To: "lint", Kind: model.RelProduces},
		{ID: "r4", From: "git", To: "c1", Kind: model.RelSupports},
		{ID: "r5", From: "tests", To: "c2", Kind: model.RelSupports},
		{ID: "r6", From: "lint", To: "c3", Kind: model.RelSupports},
		{ID: "r7", From: "git", To: "c4", Kind: model.RelSupports},
		{ID: "r8", From: "git", To: "c5", Kind: model.RelSupports},
	}
	claims := []model.V4Claim{
		{ID: "c1", Type: "build_passed", Subject: "execution:exec-001", Statement: "Build passed", Status: model.ClaimPass, SupportedBy: []string{"git"}},
		{ID: "c2", Type: "tests_passed", Subject: "execution:exec-001", Statement: "Tests passed", Status: model.ClaimPass, SupportedBy: []string{"tests"}},
		{ID: "c3", Type: "lint_clean", Subject: "execution:exec-001", Statement: "Lint clean", Status: model.ClaimPass, SupportedBy: []string{"lint"}},
		{ID: "c4", Type: "execution_bound", Subject: "execution:exec-001", Statement: "Bound to commit", Status: model.ClaimPass, SupportedBy: []string{"git"}},
		{ID: "c5", Type: "security_scan", Subject: "execution:exec-001", Statement: "No vulnerabilities", Status: model.ClaimPass, SupportedBy: []string{"git"}},
	}
	_, priv, _ := generateDeterministicKey()
	return v4MakeCase("v4-valid-five-claims", "v0.4 valid with 5 claims and 3 evidence",
		v4MakeProof("v4-valid-five-claims", ev, rels, claims, priv),
		true, 3, 8, 5,
		[]verifycore.V4ClaimResult{
			{ID: "c1", Type: "build_passed", Statement: "Build passed", Status: "pass", SupportedBy: []string{"git"}, Valid: true},
			{ID: "c2", Type: "tests_passed", Statement: "Tests passed", Status: "pass", SupportedBy: []string{"tests"}, Valid: true},
			{ID: "c3", Type: "lint_clean", Statement: "Lint clean", Status: "pass", SupportedBy: []string{"lint"}, Valid: true},
			{ID: "c4", Type: "execution_bound", Statement: "Bound to commit", Status: "pass", SupportedBy: []string{"git"}, Valid: true},
			{ID: "c5", Type: "security_scan", Statement: "No vulnerabilities", Status: "pass", SupportedBy: []string{"git"}, Valid: true},
		})
}

func v4ValidSpecialChars() CaseV4 {
	ev := []model.Evidence{
		{ID: "ev-special", Type: "custom", Source: "test", Payload: `{"key":"value with spaces & <special> chars"}`, Digest: ""},
	}
	ev[0].Digest = model.EvidenceDigest(ev[0].ID, ev[0].Payload)
	rels := []model.Relation{
		{ID: "r1", From: "exec-001", To: "ev-special", Kind: model.RelProduces},
		{ID: "r2", From: "ev-special", To: "claim.special", Kind: model.RelSupports},
	}
	claims := []model.V4Claim{
		{ID: "claim.special", Type: "custom_check", Subject: "execution:exec-001", Statement: "Special chars handled", Status: model.ClaimPass, SupportedBy: []string{"ev-special"}},
	}
	_, priv, _ := generateDeterministicKey()
	return v4MakeCase("v4-valid-special-chars", "v0.4 valid with special characters in payload",
		v4MakeProof("v4-valid-special-chars", ev, rels, claims, priv),
		true, 1, 2, 1,
		[]verifycore.V4ClaimResult{
			{ID: "claim.special", Type: "custom_check", Statement: "Special chars handled", Status: "pass", SupportedBy: []string{"ev-special"}, Valid: true},
		})
}

func v4ValidLongStrings() CaseV4 {
	longPayload := fmt.Sprintf(`{"data":"%s"}`, fmt.Sprintf("%01000d", 0))
	ev := []model.Evidence{
		{ID: "ev-long", Type: "custom", Source: "test", Payload: longPayload, Digest: ""},
	}
	ev[0].Digest = model.EvidenceDigest(ev[0].ID, ev[0].Payload)
	rels := []model.Relation{
		{ID: "r1", From: "exec-001", To: "ev-long", Kind: model.RelProduces},
		{ID: "r2", From: "ev-long", To: "claim.long", Kind: model.RelSupports},
	}
	claims := []model.V4Claim{
		{ID: "claim.long", Type: "custom_check", Subject: "execution:exec-001", Statement: "Long payload handled", Status: model.ClaimPass, SupportedBy: []string{"ev-long"}},
	}
	_, priv, _ := generateDeterministicKey()
	return v4MakeCase("v4-valid-long-strings", "v0.4 valid with long payload string",
		v4MakeProof("v4-valid-long-strings", ev, rels, claims, priv),
		true, 1, 2, 1,
		[]verifycore.V4ClaimResult{
			{ID: "claim.long", Type: "custom_check", Statement: "Long payload handled", Status: "pass", SupportedBy: []string{"ev-long"}, Valid: true},
		})
}

func v4ValidAllRelationKinds() CaseV4 {
	ev := []model.Evidence{
		{ID: "git", Type: "git", Source: "git", Payload: `{"commit":"abc123"}`, Digest: ""},
		{ID: "deps", Type: "deps", Source: "npm", Payload: `{"lockfile":"sha256:abcd"}`, Digest: ""},
	}
	for i := range ev {
		ev[i].Digest = model.EvidenceDigest(ev[i].ID, ev[i].Payload)
	}
	rels := []model.Relation{
		{ID: "r1", From: "exec-001", To: "git", Kind: model.RelProduces},
		{ID: "r2", From: "exec-001", To: "deps", Kind: model.RelProduces},
		{ID: "r3", From: "git", To: "deps", Kind: model.RelDependsOn},
		{ID: "r4", From: "git", To: "claim.build", Kind: model.RelSupports},
		{ID: "r5", From: "deps", To: "claim.deps", Kind: model.RelSupports},
	}
	claims := []model.V4Claim{
		{ID: "claim.build", Type: "build_passed", Subject: "execution:exec-001", Statement: "Build passed", Status: model.ClaimPass, SupportedBy: []string{"git"}},
		{ID: "claim.deps", Type: "deps_locked", Subject: "execution:exec-001", Statement: "Dependencies locked", Status: model.ClaimPass, SupportedBy: []string{"deps"}},
	}
	_, priv, _ := generateDeterministicKey()
	return v4MakeCase("v4-valid-all-relation-kinds", "v0.4 valid with produces/supports/dependsOn relations",
		v4MakeProof("v4-valid-all-relation-kinds", ev, rels, claims, priv),
		true, 2, 5, 2,
		[]verifycore.V4ClaimResult{
			{ID: "claim.build", Type: "build_passed", Statement: "Build passed", Status: "pass", SupportedBy: []string{"git"}, Valid: true},
			{ID: "claim.deps", Type: "deps_locked", Statement: "Dependencies locked", Status: "pass", SupportedBy: []string{"deps"}, Valid: true},
		})
}

func v4ValidEmptyEnvironment() CaseV4 {
	ev := []model.Evidence{
		{ID: "git", Type: "git", Source: "git", Payload: `{"commit":"abc123"}`, Digest: ""},
	}
	ev[0].Digest = model.EvidenceDigest(ev[0].ID, ev[0].Payload)
	rels := []model.Relation{
		{ID: "r1", From: "exec-001", To: "git", Kind: model.RelProduces},
		{ID: "r2", From: "git", To: "claim.build", Kind: model.RelSupports},
	}
	claims := []model.V4Claim{
		{ID: "claim.build", Type: "build_passed", Subject: "execution:exec-001", Statement: "Build passed", Status: model.ClaimPass, SupportedBy: []string{"git"}},
	}
	_, priv, _ := generateDeterministicKey()
	p := v4MakeProof("v4-valid-empty-env", ev, rels, claims, priv)
	p.Execution.Environment = model.Environment{}
	return v4MakeCase("v4-valid-empty-env", "v0.4 valid with empty environment fields",
		p, true, 1, 2, 1,
		[]verifycore.V4ClaimResult{
			{ID: "claim.build", Type: "build_passed", Statement: "Build passed", Status: "pass", SupportedBy: []string{"git"}, Valid: true},
		})
}

func v4ValidNotApplicableClaims() CaseV4 {
	ev := []model.Evidence{
		{ID: "git", Type: "git", Source: "git", Payload: `{"commit":"abc123"}`, Digest: ""},
	}
	ev[0].Digest = model.EvidenceDigest(ev[0].ID, ev[0].Payload)
	rels := []model.Relation{
		{ID: "r1", From: "exec-001", To: "git", Kind: model.RelProduces},
		{ID: "r2", From: "git", To: "claim.build", Kind: model.RelSupports},
		{ID: "r3", From: "git", To: "claim.na", Kind: model.RelSupports},
	}
	claims := []model.V4Claim{
		{ID: "claim.build", Type: "build_passed", Subject: "execution:exec-001", Statement: "Build passed", Status: model.ClaimPass, SupportedBy: []string{"git"}},
		{ID: "claim.na", Type: "security_scan", Subject: "execution:exec-001", Statement: "Not applicable", Status: model.ClaimNotApplicable, SupportedBy: []string{"git"}},
	}
	_, priv, _ := generateDeterministicKey()
	return v4MakeCase("v4-valid-na-claims", "v0.4 valid with not_applicable claim",
		v4MakeProof("v4-valid-na-claims", ev, rels, claims, priv),
		true, 1, 3, 2,
		[]verifycore.V4ClaimResult{
			{ID: "claim.build", Type: "build_passed", Statement: "Build passed", Status: "pass", SupportedBy: []string{"git"}, Valid: true},
			{ID: "claim.na", Type: "security_scan", Statement: "Not applicable", Status: "not_applicable", SupportedBy: []string{"git"}, Valid: true},
		})
}

func v4ValidSingleEvidenceMultiClaims() CaseV4 {
	ev := []model.Evidence{
		{ID: "git", Type: "git", Source: "git", Payload: `{"commit":"abc123"}`, Digest: ""},
	}
	ev[0].Digest = model.EvidenceDigest(ev[0].ID, ev[0].Payload)
	rels := []model.Relation{
		{ID: "r1", From: "exec-001", To: "git", Kind: model.RelProduces},
		{ID: "r2", From: "git", To: "c1", Kind: model.RelSupports},
		{ID: "r3", From: "git", To: "c2", Kind: model.RelSupports},
		{ID: "r4", From: "git", To: "c3", Kind: model.RelSupports},
	}
	claims := []model.V4Claim{
		{ID: "c1", Type: "build_passed", Subject: "execution:exec-001", Statement: "Build passed", Status: model.ClaimPass, SupportedBy: []string{"git"}},
		{ID: "c2", Type: "execution_bound", Subject: "execution:exec-001", Statement: "Bound to commit", Status: model.ClaimPass, SupportedBy: []string{"git"}},
		{ID: "c3", Type: "provenance", Subject: "execution:exec-001", Statement: "Provenance recorded", Status: model.ClaimPass, SupportedBy: []string{"git"}},
	}
	_, priv, _ := generateDeterministicKey()
	return v4MakeCase("v4-valid-single-ev-multi-claims", "v0.4 valid with 1 evidence supporting 3 claims",
		v4MakeProof("v4-valid-single-ev-multi-claims", ev, rels, claims, priv),
		true, 1, 4, 3,
		[]verifycore.V4ClaimResult{
			{ID: "c1", Type: "build_passed", Statement: "Build passed", Status: "pass", SupportedBy: []string{"git"}, Valid: true},
			{ID: "c2", Type: "execution_bound", Statement: "Bound to commit", Status: "pass", SupportedBy: []string{"git"}, Valid: true},
			{ID: "c3", Type: "provenance", Statement: "Provenance recorded", Status: "pass", SupportedBy: []string{"git"}, Valid: true},
		})
}

func v4ValidChainRelations() CaseV4 {
	ev := []model.Evidence{
		{ID: "src", Type: "git", Source: "git", Payload: `{"commit":"abc123"}`, Digest: ""},
		{ID: "build", Type: "build", Source: "go", Payload: `{"binary":"sha256:deadbeef"}`, Digest: ""},
		{ID: "test", Type: "tests", Source: "go test", Payload: `{"passed":10}`, Digest: ""},
	}
	for i := range ev {
		ev[i].Digest = model.EvidenceDigest(ev[i].ID, ev[i].Payload)
	}
	rels := []model.Relation{
		{ID: "r1", From: "exec-001", To: "src", Kind: model.RelProduces},
		{ID: "r2", From: "exec-001", To: "build", Kind: model.RelProduces},
		{ID: "r3", From: "exec-001", To: "test", Kind: model.RelProduces},
		{ID: "r4", From: "src", To: "build", Kind: model.RelDependsOn},
		{ID: "r5", From: "build", To: "test", Kind: model.RelDependsOn},
		{ID: "r6", From: "src", To: "c1", Kind: model.RelSupports},
		{ID: "r7", From: "build", To: "c2", Kind: model.RelSupports},
		{ID: "r8", From: "test", To: "c3", Kind: model.RelSupports},
	}
	claims := []model.V4Claim{
		{ID: "c1", Type: "build_passed", Subject: "execution:exec-001", Statement: "Source committed", Status: model.ClaimPass, SupportedBy: []string{"src"}},
		{ID: "c2", Type: "build_passed", Subject: "execution:exec-001", Statement: "Build artifact produced", Status: model.ClaimPass, SupportedBy: []string{"build"}},
		{ID: "c3", Type: "tests_passed", Subject: "execution:exec-001", Statement: "Tests passed", Status: model.ClaimPass, SupportedBy: []string{"test"}},
	}
	_, priv, _ := generateDeterministicKey()
	return v4MakeCase("v4-valid-chain-relations", "v0.4 valid with chained dependsOn relations",
		v4MakeProof("v4-valid-chain-relations", ev, rels, claims, priv),
		true, 3, 8, 3,
		[]verifycore.V4ClaimResult{
			{ID: "c1", Type: "build_passed", Statement: "Source committed", Status: "pass", SupportedBy: []string{"src"}, Valid: true},
			{ID: "c2", Type: "build_passed", Statement: "Build artifact produced", Status: "pass", SupportedBy: []string{"build"}, Valid: true},
			{ID: "c3", Type: "tests_passed", Statement: "Tests passed", Status: "pass", SupportedBy: []string{"test"}, Valid: true},
		})
}

func v4ValidWithRevokedClaim() CaseV4 {
	ev := []model.Evidence{
		{ID: "git", Type: "git", Source: "git", Payload: `{"commit":"abc123"}`, Digest: ""},
	}
	ev[0].Digest = model.EvidenceDigest(ev[0].ID, ev[0].Payload)
	rels := []model.Relation{
		{ID: "r1", From: "exec-001", To: "git", Kind: model.RelProduces},
		{ID: "r2", From: "git", To: "c1", Kind: model.RelSupports},
		{ID: "r3", From: "git", To: "c2", Kind: model.RelSupports},
	}
	claims := []model.V4Claim{
		{ID: "c1", Type: "build_passed", Subject: "execution:exec-001", Statement: "Build passed", Status: model.ClaimPass, SupportedBy: []string{"git"}},
		{ID: "c2", Type: "security_scan", Subject: "execution:exec-001", Statement: "Scan failed", Status: model.ClaimFail, SupportedBy: []string{"git"}},
	}
	_, priv, _ := generateDeterministicKey()
	return v4MakeCase("v4-valid-fail-claim", "v0.4 valid with failed claim status (signed, not tampered)",
		v4MakeProof("v4-valid-fail-claim", ev, rels, claims, priv),
		true, 1, 3, 2,
		[]verifycore.V4ClaimResult{
			{ID: "c1", Type: "build_passed", Statement: "Build passed", Status: "pass", SupportedBy: []string{"git"}, Valid: true},
			{ID: "c2", Type: "security_scan", Statement: "Scan failed", Status: "fail", SupportedBy: []string{"git"}, Valid: true},
		})
}

func v4ValidNotApplicableMixed() CaseV4 {
	ev := []model.Evidence{
		{ID: "git", Type: "git", Source: "git", Payload: `{"commit":"abc123"}`, Digest: ""},
	}
	ev[0].Digest = model.EvidenceDigest(ev[0].ID, ev[0].Payload)
	rels := []model.Relation{
		{ID: "r1", From: "exec-001", To: "git", Kind: model.RelProduces},
		{ID: "r2", From: "git", To: "c1", Kind: model.RelSupports},
		{ID: "r3", From: "git", To: "c2", Kind: model.RelSupports},
		{ID: "r4", From: "git", To: "c3", Kind: model.RelSupports},
	}
	claims := []model.V4Claim{
		{ID: "c1", Type: "build_passed", Subject: "execution:exec-001", Statement: "Build passed", Status: model.ClaimPass, SupportedBy: []string{"git"}},
		{ID: "c2", Type: "tests_passed", Subject: "execution:exec-001", Statement: "Skipped", Status: model.ClaimNotApplicable, SupportedBy: []string{"git"}},
		{ID: "c3", Type: "security_scan", Subject: "execution:exec-001", Statement: "Pending review", Status: model.ClaimPending, SupportedBy: []string{"git"}},
	}
	_, priv, _ := generateDeterministicKey()
	return v4MakeCase("v4-valid-na-mixed", "v0.4 valid with pass/not_applicable/pending mix",
		v4MakeProof("v4-valid-na-mixed", ev, rels, claims, priv),
		true, 1, 4, 3,
		[]verifycore.V4ClaimResult{
			{ID: "c1", Type: "build_passed", Statement: "Build passed", Status: "pass", SupportedBy: []string{"git"}, Valid: true},
			{ID: "c2", Type: "tests_passed", Statement: "Skipped", Status: "not_applicable", SupportedBy: []string{"git"}, Valid: true},
			{ID: "c3", Type: "security_scan", Statement: "Pending review", Status: "pending", SupportedBy: []string{"git"}, Valid: true},
		})
}

// ============================================================================
// v0.4 invalid cases (expanded)
// ============================================================================

func v4InvalidEvidenceDigestMismatch() CaseV4 {
	ev := []model.Evidence{
		{ID: "git", Type: "git", Source: "git", Payload: `{"commit":"abc123"}`, Digest: "0000000000000000000000000000000000000000000000000000000000000000"},
	}
	rels := []model.Relation{
		{ID: "r1", From: "exec-001", To: "git", Kind: model.RelProduces},
	}
	claims := []model.V4Claim{
		{ID: "c1", Type: "build_passed", Subject: "execution:exec-001", Statement: "Build passed", Status: model.ClaimPass, SupportedBy: []string{"git"}},
	}
	_, priv, _ := generateDeterministicKey()
	p := v4MakeProof("v4-invalid-ev-digest", ev, rels, claims, priv)
	return v4MakeCase("v4-invalid-ev-digest", "v0.4 invalid: evidence digest does not match sha256(id:payload)",
		p, false, 1, 0, 0,
		nil)
}

func v4InvalidEvidencePayloadTamper() CaseV4 {
	ev := []model.Evidence{
		{ID: "git", Type: "git", Source: "git", Payload: `{"commit":"abc123"}`, Digest: ""},
	}
	ev[0].Digest = model.EvidenceDigest(ev[0].ID, ev[0].Payload)
	rels := []model.Relation{
		{ID: "r1", From: "exec-001", To: "git", Kind: model.RelProduces},
	}
	claims := []model.V4Claim{
		{ID: "c1", Type: "build_passed", Subject: "execution:exec-001", Statement: "Build passed", Status: model.ClaimPass, SupportedBy: []string{"git"}},
	}
	_, priv, _ := generateDeterministicKey()
	p := v4MakeProof("v4-invalid-ev-tamper", ev, rels, claims, priv)
	p.Evidence[0].Payload = `{"commit":"TAMPERED"}`
	return v4MakeCase("v4-invalid-ev-tamper", "v0.4 invalid: evidence payload tampered after digest computed",
		p, false, 1, 0, 0,
		nil)
}

func v4InvalidRelationFromTamper() CaseV4 {
	ev := []model.Evidence{
		{ID: "git", Type: "git", Source: "git", Payload: `{"commit":"abc123"}`, Digest: ""},
	}
	ev[0].Digest = model.EvidenceDigest(ev[0].ID, ev[0].Payload)
	rels := []model.Relation{
		{ID: "r1", From: "exec-001", To: "git", Kind: model.RelProduces},
	}
	claims := []model.V4Claim{
		{ID: "c1", Type: "build_passed", Subject: "execution:exec-001", Statement: "Build passed", Status: model.ClaimPass, SupportedBy: []string{"git"}},
	}
	_, priv, _ := generateDeterministicKey()
	p := v4MakeProof("v4-invalid-rel-from-tamper", ev, rels, claims, priv)
	p.Relations[0].From = "exec-EVIL"
	return v4MakeCase("v4-invalid-rel-from-tamper", "v0.4 invalid: relation From field tampered",
		p, false, 1, 0, 0,
		nil)
}

func v4InvalidRelationToTamper() CaseV4 {
	ev := []model.Evidence{
		{ID: "git", Type: "git", Source: "git", Payload: `{"commit":"abc123"}`, Digest: ""},
	}
	ev[0].Digest = model.EvidenceDigest(ev[0].ID, ev[0].Payload)
	rels := []model.Relation{
		{ID: "r1", From: "exec-001", To: "git", Kind: model.RelProduces},
	}
	claims := []model.V4Claim{
		{ID: "c1", Type: "build_passed", Subject: "execution:exec-001", Statement: "Build passed", Status: model.ClaimPass, SupportedBy: []string{"git"}},
	}
	_, priv, _ := generateDeterministicKey()
	p := v4MakeProof("v4-invalid-rel-to-tamper", ev, rels, claims, priv)
	p.Relations[0].To = "git-EVIL"
	return v4MakeCase("v4-invalid-rel-to-tamper", "v0.4 invalid: relation To field tampered",
		p, false, 1, 0, 0,
		nil)
}

func v4InvalidClaimSupportedByMissing() CaseV4 {
	ev := []model.Evidence{
		{ID: "git", Type: "git", Source: "git", Payload: `{"commit":"abc123"}`, Digest: ""},
	}
	ev[0].Digest = model.EvidenceDigest(ev[0].ID, ev[0].Payload)
	rels := []model.Relation{
		{ID: "r1", From: "exec-001", To: "git", Kind: model.RelProduces},
		{ID: "r2", From: "git", To: "c1", Kind: model.RelSupports},
	}
	claims := []model.V4Claim{
		{ID: "c1", Type: "build_passed", Subject: "execution:exec-001", Statement: "Build passed", Status: model.ClaimPass, SupportedBy: []string{"missing-evidence"}},
	}
	_, priv, _ := generateDeterministicKey()
	p := v4MakeProof("v4-invalid-claim-noref", ev, rels, claims, priv)
	return v4MakeCase("v4-invalid-claim-noref", "v0.4 invalid: claim SupportedBy references non-existent evidence",
		p, false, 1, 0, 0,
		nil)
}

func v4InvalidClaimStatusTamper() CaseV4 {
	ev := []model.Evidence{
		{ID: "git", Type: "git", Source: "git", Payload: `{"commit":"abc123"}`, Digest: ""},
	}
	ev[0].Digest = model.EvidenceDigest(ev[0].ID, ev[0].Payload)
	rels := []model.Relation{
		{ID: "r1", From: "exec-001", To: "git", Kind: model.RelProduces},
		{ID: "r2", From: "git", To: "c1", Kind: model.RelSupports},
	}
	claims := []model.V4Claim{
		{ID: "c1", Type: "build_passed", Subject: "execution:exec-001", Statement: "Build passed", Status: model.ClaimPass, SupportedBy: []string{"git"}},
	}
	_, priv, _ := generateDeterministicKey()
	p := v4MakeProof("v4-invalid-claim-status", ev, rels, claims, priv)
	p.Claims[0].Status = model.ClaimFail
	return v4MakeCase("v4-invalid-claim-status", "v0.4 invalid: claim status tampered from pass to fail",
		p, false, 1, 0, 0,
		nil)
}

func v4InvalidClaimTypeTamper() CaseV4 {
	ev := []model.Evidence{
		{ID: "git", Type: "git", Source: "git", Payload: `{"commit":"abc123"}`, Digest: ""},
	}
	ev[0].Digest = model.EvidenceDigest(ev[0].ID, ev[0].Payload)
	rels := []model.Relation{
		{ID: "r1", From: "exec-001", To: "git", Kind: model.RelProduces},
		{ID: "r2", From: "git", To: "c1", Kind: model.RelSupports},
	}
	claims := []model.V4Claim{
		{ID: "c1", Type: "build_passed", Subject: "execution:exec-001", Statement: "Build passed", Status: model.ClaimPass, SupportedBy: []string{"git"}},
	}
	_, priv, _ := generateDeterministicKey()
	p := v4MakeProof("v4-invalid-claim-type", ev, rels, claims, priv)
	p.Claims[0].Type = "evil_type"
	return v4MakeCase("v4-invalid-claim-type", "v0.4 invalid: claim type tampered",
		p, false, 1, 0, 0,
		nil)
}

func v4InvalidBindingAlgorithm() CaseV4 {
	ev := []model.Evidence{
		{ID: "git", Type: "git", Source: "git", Payload: `{"commit":"abc123"}`, Digest: ""},
	}
	ev[0].Digest = model.EvidenceDigest(ev[0].ID, ev[0].Payload)
	rels := []model.Relation{
		{ID: "r1", From: "exec-001", To: "git", Kind: model.RelProduces},
		{ID: "r2", From: "git", To: "c1", Kind: model.RelSupports},
	}
	claims := []model.V4Claim{
		{ID: "c1", Type: "build_passed", Subject: "execution:exec-001", Statement: "Build passed", Status: model.ClaimPass, SupportedBy: []string{"git"}},
	}
	_, priv, _ := generateDeterministicKey()
	p := v4MakeProof("v4-invalid-binding-algo", ev, rels, claims, priv)
	p.Binding.Algorithm = "md5"
	return v4MakeCase("v4-invalid-binding-algo", "v0.4 invalid: binding algorithm changed from sha256 to md5",
		p, false, 1, 0, 0,
		nil)
}

func v4InvalidSignatureAlgorithm() CaseV4 {
	ev := []model.Evidence{
		{ID: "git", Type: "git", Source: "git", Payload: `{"commit":"abc123"}`, Digest: ""},
	}
	ev[0].Digest = model.EvidenceDigest(ev[0].ID, ev[0].Payload)
	rels := []model.Relation{
		{ID: "r1", From: "exec-001", To: "git", Kind: model.RelProduces},
		{ID: "r2", From: "git", To: "c1", Kind: model.RelSupports},
	}
	claims := []model.V4Claim{
		{ID: "c1", Type: "build_passed", Subject: "execution:exec-001", Statement: "Build passed", Status: model.ClaimPass, SupportedBy: []string{"git"}},
	}
	_, priv, _ := generateDeterministicKey()
	p := v4MakeProof("v4-invalid-sig-algo", ev, rels, claims, priv)
	p.Signature.Algorithm = "sha256"
	return v4MakeCase("v4-invalid-sig-algo", "v0.4 invalid: signature algorithm changed to sha256",
		p, false, 1, 0, 0,
		nil)
}

func v4InvalidProjectNameTamper() CaseV4 {
	ev := []model.Evidence{
		{ID: "git", Type: "git", Source: "git", Payload: `{"commit":"abc123"}`, Digest: ""},
	}
	ev[0].Digest = model.EvidenceDigest(ev[0].ID, ev[0].Payload)
	rels := []model.Relation{
		{ID: "r1", From: "exec-001", To: "git", Kind: model.RelProduces},
		{ID: "r2", From: "git", To: "c1", Kind: model.RelSupports},
	}
	claims := []model.V4Claim{
		{ID: "c1", Type: "build_passed", Subject: "execution:exec-001", Statement: "Build passed", Status: model.ClaimPass, SupportedBy: []string{"git"}},
	}
	_, priv, _ := generateDeterministicKey()
	p := v4MakeProof("v4-invalid-proj-tamper", ev, rels, claims, priv)
	p.Project.Name = "EVIL_PROJECT"
	return v4MakeCase("v4-invalid-proj-tamper", "v0.4 invalid: project name tampered after signing",
		p, false, 1, 0, 0,
		nil)
}

func v4InvalidSubjectCommitTamper() CaseV4 {
	ev := []model.Evidence{
		{ID: "git", Type: "git", Source: "git", Payload: `{"commit":"abc123"}`, Digest: ""},
	}
	ev[0].Digest = model.EvidenceDigest(ev[0].ID, ev[0].Payload)
	rels := []model.Relation{
		{ID: "r1", From: "exec-001", To: "git", Kind: model.RelProduces},
		{ID: "r2", From: "git", To: "c1", Kind: model.RelSupports},
	}
	claims := []model.V4Claim{
		{ID: "c1", Type: "build_passed", Subject: "execution:exec-001", Statement: "Build passed", Status: model.ClaimPass, SupportedBy: []string{"git"}},
	}
	_, priv, _ := generateDeterministicKey()
	p := v4MakeProof("v4-invalid-commit-tamper", ev, rels, claims, priv)
	p.Subject.Commit = "deadbeef00000000"
	return v4MakeCase("v4-invalid-commit-tamper", "v0.4 invalid: subject commit tampered after signing",
		p, false, 1, 0, 0,
		nil)
}

func v4InvalidSubjectBranchTamper() CaseV4 {
	ev := []model.Evidence{
		{ID: "git", Type: "git", Source: "git", Payload: `{"commit":"abc123"}`, Digest: ""},
	}
	ev[0].Digest = model.EvidenceDigest(ev[0].ID, ev[0].Payload)
	rels := []model.Relation{
		{ID: "r1", From: "exec-001", To: "git", Kind: model.RelProduces},
		{ID: "r2", From: "git", To: "c1", Kind: model.RelSupports},
	}
	claims := []model.V4Claim{
		{ID: "c1", Type: "build_passed", Subject: "execution:exec-001", Statement: "Build passed", Status: model.ClaimPass, SupportedBy: []string{"git"}},
	}
	_, priv, _ := generateDeterministicKey()
	p := v4MakeProof("v4-invalid-branch-tamper", ev, rels, claims, priv)
	p.Subject.Branch = "evil-branch"
	return v4MakeCase("v4-invalid-branch-tamper", "v0.4 invalid: subject branch tampered after signing",
		p, false, 1, 0, 0,
		nil)
}

func v4InvalidEmptyEvidenceArray() CaseV4 {
	_, priv, _ := generateDeterministicKey()
	p := &model.V4Proof{
		ProofVersion: model.ProofVersionV2,
		ID:           "v4-invalid-empty-ev",
		Project:      model.Project{Name: "test", Repository: "https://example.com/test"},
		Subject:      model.Subject{Commit: "abc123", Branch: "main", Repository: "https://example.com/test"},
		Execution:    model.Execution{ID: "exec-001", Type: model.ExecCIWorkflow, StartedAt: "2026-08-21T02:00:00Z", CompletedAt: "2026-08-21T02:05:00Z"},
		Evidence:     []model.Evidence{},
		Relations:    []model.Relation{},
		Claims:       []model.V4Claim{{ID: "c1", Type: "build_passed", Subject: "execution:exec-001", Statement: "No evidence!", Status: model.ClaimPass, SupportedBy: []string{}}},
		Coverage:     model.V4Coverage{Evidence: model.CoverageDim{Total: 0, Verified: 0}, Relations: model.CoverageDim{Total: 0, Verified: 0}, Claims: model.CoverageDim{Total: 1, Verified: 1}, Score: 100},
		CreatedAt:    "2026-08-21T02:05:00Z",
		Builder:      model.Builder{Name: "proofx", Version: "0.4.0"},
	}
	entries := model.V4BindingEntries(p)
	p.Binding = model.Binding{Algorithm: "sha256", Root: model.V4Root(entries), Entries: entries}
	sigPayload := model.V4SigningPayload(p)
	sig, _ := proof.SignBytes(sigPayload, priv)
	pub := proof.PublicKeyOf(priv)
	p.Signature = model.Signature{Algorithm: "ed25519", PublicKey: proof.EncodePublicKey(pub), Value: sig}
	return v4MakeCase("v4-invalid-empty-ev", "v0.4 invalid: claim with no evidence support",
		p, false, 0, 0, 0,
		nil)
}

func v4InvalidWrongBindingRoot() CaseV4 {
	ev := []model.Evidence{
		{ID: "git", Type: "git", Source: "git", Payload: `{"commit":"abc123"}`, Digest: ""},
	}
	ev[0].Digest = model.EvidenceDigest(ev[0].ID, ev[0].Payload)
	rels := []model.Relation{
		{ID: "r1", From: "exec-001", To: "git", Kind: model.RelProduces},
		{ID: "r2", From: "git", To: "c1", Kind: model.RelSupports},
	}
	claims := []model.V4Claim{
		{ID: "c1", Type: "build_passed", Subject: "execution:exec-001", Statement: "Build passed", Status: model.ClaimPass, SupportedBy: []string{"git"}},
	}
	_, priv, _ := generateDeterministicKey()
	p := v4MakeProof("v4-invalid-wrong-root", ev, rels, claims, priv)
	p.Binding.Root = "0000000000000000000000000000000000000000000000000000000000000000"
	return v4MakeCase("v4-invalid-wrong-root", "v0.4 invalid: binding root tampered to zero hash",
		p, false, 1, 0, 0,
		nil)
}

// ============================================================================
// Helper to reduce boilerplate
// ============================================================================

func v4MakeCase(name, desc string, p *model.V4Proof, valid bool, evTotal, relTotal, claimTotal int, claimResults []verifycore.V4ClaimResult) CaseV4 {
	evVerified := 0
	relVerified := 0
	claimVerified := 0
	if valid {
		evVerified = evTotal
		relVerified = relTotal
		claimVerified = claimTotal
	}

	checks := []verifycore.Check{
		{Name: "version", Status: verifycore.StatusOK},
	}
	if evTotal > 0 {
		if valid {
			checks = append(checks, verifycore.Check{Name: "evidence", Status: verifycore.StatusOK})
		} else {
			checks = append(checks, verifycore.Check{Name: "evidence", Status: verifycore.StatusOK})
		}
	}
	if valid {
		checks = append(checks,
			verifycore.Check{Name: "binding", Status: verifycore.StatusOK},
			verifycore.Check{Name: "commitment", Status: verifycore.StatusOK},
			verifycore.Check{Name: "signature", Status: verifycore.StatusOK},
			verifycore.Check{Name: "claims", Status: verifycore.StatusOK},
		)
	} else {
		if evTotal > 0 {
			checks = append(checks,
				verifycore.Check{Name: "binding", Status: verifycore.StatusOK},
				verifycore.Check{Name: "commitment", Status: verifycore.StatusOK},
				verifycore.Check{Name: "signature", Status: verifycore.StatusOK},
			)
		}
	}

	return CaseV4{
		Name:        name,
		Description: desc,
		Proof:       p,
		Expect: verifycore.V4VerifyResult{
			ProofID: name,
			Valid:   valid,
			Checks:  checks,
			Coverage: model.V4Coverage{
				Evidence:  model.CoverageDim{Total: evTotal, Verified: evVerified},
				Relations: model.CoverageDim{Total: relTotal, Verified: relVerified},
				Claims:    model.CoverageDim{Total: claimTotal, Verified: claimVerified},
				Score:     boolToInt(valid) * 100,
			},
			Claims: claimResults,
		},
	}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
