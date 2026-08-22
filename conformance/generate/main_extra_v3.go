package main

import (
	"github.com/EslaM-X/proofx/model"
	"github.com/EslaM-X/proofx/verifycore"
)

// ============================================================================
// v0.4 extra invalid cases (batch 2)
// ============================================================================

func v4ExtraInvalidCases2() []CaseV4 {
	return []CaseV4{
		v4InvalidEmptyEvidenceID(),
		v4InvalidDuplicateRelationID(),
		v4InvalidDuplicateClaimID(),
		v4InvalidEmptyExecutionID(),
		v4InvalidCompletedBeforeStarted(),
		v4InvalidEmptyBindingEntries(),
		v4InvalidBadRelationKind(),
		v4InvalidEmptyPublicKey(),
		v4InvalidSubjectRepoTamper(),
		v4InvalidExecStartedTamper(),
		v4InvalidCoverageScoreTamper(),
		v4InvalidBuilderTamper(),
	}
}

func v4InvalidEmptyEvidenceID() CaseV4 {
	ev := []model.Evidence{
		evPair("", "git", "git", `{"commit":"abc123"}`),
	}
	rels := []model.Relation{
		rel("r1", "exec-001", "", model.RelProduces),
	}
	claims := []model.V4Claim{
		claim("c1", "build_passed", "Build passed", model.ClaimPass, []string{""}),
	}
	_, priv, _ := generateDeterministicKey()
	p := v4MakeProof("v4-invalid-empty-ev-id", ev, rels, claims, priv)
	return v4MakeCase("v4-invalid-empty-ev-id", "v0.4 invalid: evidence with empty id rejected by schema",
		p, false, 0, 0, 0,
		nil)
}

func v4InvalidDuplicateRelationID() CaseV4 {
	ev := []model.Evidence{
		evPair("git", "git", "git", `{"commit":"abc123"}`),
	}
	rels := []model.Relation{
		rel("r1", "exec-001", "git", model.RelProduces),
		rel("r1", "git", "c1", model.RelSupports),
	}
	claims := []model.V4Claim{
		claim("c1", "build_passed", "Build passed", model.ClaimPass, []string{"git"}),
	}
	_, priv, _ := generateDeterministicKey()
	p := v4MakeProof("v4-invalid-dup-rel-id", ev, rels, claims, priv)
	return v4MakeCase("v4-invalid-dup-rel-id", "v0.4 invalid: two relations share the same id",
		p, false, 0, 0, 0,
		nil)
}

func v4InvalidDuplicateClaimID() CaseV4 {
	ev := []model.Evidence{
		evPair("git", "git", "git", `{"commit":"abc123"}`),
	}
	rels := []model.Relation{
		rel("r1", "exec-001", "git", model.RelProduces),
		rel("r2", "git", "c1", model.RelSupports),
	}
	claims := []model.V4Claim{
		claim("c1", "build_passed", "Build passed", model.ClaimPass, []string{"git"}),
	}
	_, priv, _ := generateDeterministicKey()
	p := v4MakeProof("v4-invalid-dup-claim-id", ev, rels, claims, priv)
	dup := p.Claims[0]
	dup.Statement = "Build passed (duplicate entry)"
	p.Claims = append(p.Claims, dup)
	return v4MakeCase("v4-invalid-dup-claim-id", "v0.4 invalid: duplicate claim appended after signing breaks binding and signature",
		p, false, 1, 0, 0,
		nil)
}

func v4InvalidEmptyExecutionID() CaseV4 {
	ev := []model.Evidence{
		evPair("git", "git", "git", `{"commit":"abc123"}`),
	}
	rels := []model.Relation{
		rel("r1", "exec-001", "git", model.RelProduces),
		rel("r2", "git", "c1", model.RelSupports),
	}
	claims := []model.V4Claim{
		claim("c1", "build_passed", "Build passed", model.ClaimPass, []string{"git"}),
	}
	exec := model.Execution{ID: "", Type: model.ExecCIWorkflow, StartedAt: "2026-08-21T02:00:00Z", CompletedAt: "2026-08-21T02:05:00Z"}
	_, priv, _ := generateDeterministicKey()
	p := v4MakeProofWithExecution("v4-invalid-empty-exec-id", exec, ev, rels, claims, priv)
	return v4MakeCase("v4-invalid-empty-exec-id", "v0.4 invalid: execution with empty id rejected by schema",
		p, false, 0, 0, 0,
		nil)
}

func v4InvalidCompletedBeforeStarted() CaseV4 {
	ev := []model.Evidence{
		evPair("git", "git", "git", `{"commit":"abc123"}`),
	}
	rels := []model.Relation{
		rel("r1", "exec-001", "git", model.RelProduces),
		rel("r2", "git", "c1", model.RelSupports),
	}
	claims := []model.V4Claim{
		claim("c1", "build_passed", "Build passed", model.ClaimPass, []string{"git"}),
	}
	_, priv, _ := generateDeterministicKey()
	p := v4MakeProof("v4-invalid-completed-before-started", ev, rels, claims, priv)
	p.Execution.CompletedAt = "2026-08-21T01:30:00Z"
	return v4MakeCase("v4-invalid-completed-before-started", "v0.4 invalid: completedAt moved before startedAt after signing (execution timestamps are in the commitment)",
		p, false, 1, 0, 0,
		nil)
}

func v4InvalidEmptyBindingEntries() CaseV4 {
	ev := []model.Evidence{
		evPair("git", "git", "git", `{"commit":"abc123"}`),
	}
	rels := []model.Relation{
		rel("r1", "exec-001", "git", model.RelProduces),
		rel("r2", "git", "c1", model.RelSupports),
	}
	claims := []model.V4Claim{
		claim("c1", "build_passed", "Build passed", model.ClaimPass, []string{"git"}),
	}
	_, priv, _ := generateDeterministicKey()
	p := v4MakeProof("v4-invalid-empty-binding-entries", ev, rels, claims, priv)
	p.Binding.Entries = []model.BindingEntry{}
	p.Binding.Root = ""
	return v4MakeCase("v4-invalid-empty-binding-entries", "v0.4 invalid: binding entries stripped and root blanked so recomputed merkle root cannot match",
		p, false, 1, 0, 0,
		nil)
}

func v4InvalidBadRelationKind() CaseV4 {
	ev := []model.Evidence{
		evPair("git", "git", "git", `{"commit":"abc123"}`),
	}
	rels := []model.Relation{
		rel("r1", "exec-001", "git", model.RelProduces),
		rel("r2", "git", "c1", model.RelSupports),
	}
	claims := []model.V4Claim{
		claim("c1", "build_passed", "Build passed", model.ClaimPass, []string{"git"}),
	}
	_, priv, _ := generateDeterministicKey()
	p := v4MakeProof("v4-invalid-bad-rel-kind", ev, rels, claims, priv)
	p.Relations[0].Kind = "invalid_kind"
	return v4MakeCase("v4-invalid-bad-rel-kind", "v0.4 invalid: relation kind swapped to unknown value after signing (relation digest mismatch)",
		p, false, 1, 0, 0,
		nil)
}

func v4InvalidEmptyPublicKey() CaseV4 {
	ev := []model.Evidence{
		evPair("git", "git", "git", `{"commit":"abc123"}`),
	}
	rels := []model.Relation{
		rel("r1", "exec-001", "git", model.RelProduces),
		rel("r2", "git", "c1", model.RelSupports),
	}
	claims := []model.V4Claim{
		claim("c1", "build_passed", "Build passed", model.ClaimPass, []string{"git"}),
	}
	_, priv, _ := generateDeterministicKey()
	p := v4MakeProof("v4-invalid-empty-pubkey", ev, rels, claims, priv)
	p.Signature.PublicKey = ""
	return v4MakeCase("v4-invalid-empty-pubkey", "v0.4 invalid: signature public key emptied after signing",
		p, false, 1, 0, 0,
		nil)
}

func v4InvalidSubjectRepoTamper() CaseV4 {
	ev := []model.Evidence{
		evPair("git", "git", "git", `{"commit":"abc123"}`),
	}
	rels := []model.Relation{
		rel("r1", "exec-001", "git", model.RelProduces),
		rel("r2", "git", "c1", model.RelSupports),
	}
	claims := []model.V4Claim{
		claim("c1", "build_passed", "Build passed", model.ClaimPass, []string{"git"}),
	}
	_, priv, _ := generateDeterministicKey()
	p := v4MakeProof("v4-invalid-subject-repo-tamper", ev, rels, claims, priv)
	p.Subject.Repository = "https://evil.example.com/test"
	return v4MakeCase("v4-invalid-subject-repo-tamper", "v0.4 invalid: subject repository tampered after signing",
		p, false, 1, 0, 0,
		nil)
}

func v4InvalidExecStartedTamper() CaseV4 {
	ev := []model.Evidence{
		evPair("git", "git", "git", `{"commit":"abc123"}`),
	}
	rels := []model.Relation{
		rel("r1", "exec-001", "git", model.RelProduces),
		rel("r2", "git", "c1", model.RelSupports),
	}
	claims := []model.V4Claim{
		claim("c1", "build_passed", "Build passed", model.ClaimPass, []string{"git"}),
	}
	_, priv, _ := generateDeterministicKey()
	p := v4MakeProof("v4-invalid-exec-started-tamper", ev, rels, claims, priv)
	p.Execution.StartedAt = "2026-08-21T01:00:00Z"
	return v4MakeCase("v4-invalid-exec-started-tamper", "v0.4 invalid: execution startedAt tampered after signing",
		p, false, 1, 0, 0,
		nil)
}

func v4InvalidCoverageScoreTamper() CaseV4 {
	ev := []model.Evidence{
		evPair("git", "git", "git", `{"commit":"abc123"}`),
	}
	rels := []model.Relation{
		rel("r1", "exec-001", "git", model.RelProduces),
		rel("r2", "git", "c1", model.RelSupports),
	}
	claims := []model.V4Claim{
		claim("c1", "build_passed", "Build passed", model.ClaimPass, []string{"git"}),
	}
	_, priv, _ := generateDeterministicKey()
	p := v4MakeProof("v4-invalid-coverage-score-tamper", ev, rels, claims, priv)
	p.Coverage.Score = 999
	return v4MakeCase("v4-invalid-coverage-score-tamper", "v0.4 coverage score set to 999 — field is outside the signing payload so the proof still verifies",
		p, true, 1, 2, 1,
		[]verifycore.V4ClaimResult{
			{ID: "c1", Type: "build_passed", Statement: "Build passed", Status: "pass", SupportedBy: []string{"git"}, Valid: true},
		})
}

func v4InvalidBuilderTamper() CaseV4 {
	ev := []model.Evidence{
		evPair("git", "git", "git", `{"commit":"abc123"}`),
	}
	rels := []model.Relation{
		rel("r1", "exec-001", "git", model.RelProduces),
		rel("r2", "git", "c1", model.RelSupports),
	}
	claims := []model.V4Claim{
		claim("c1", "build_passed", "Build passed", model.ClaimPass, []string{"git"}),
	}
	_, priv, _ := generateDeterministicKey()
	p := v4MakeProof("v4-invalid-builder-tamper", ev, rels, claims, priv)
	p.Builder.Name = "evil-builder"
	return v4MakeCase("v4-invalid-builder-tamper", "v0.4 builder name changed after signing — builder is not cryptographically bound so the proof still verifies",
		p, true, 1, 2, 1,
		[]verifycore.V4ClaimResult{
			{ID: "c1", Type: "build_passed", Statement: "Build passed", Status: "pass", SupportedBy: []string{"git"}, Valid: true},
		})
}
