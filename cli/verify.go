package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/EslaM-X/proofx/config"
	"github.com/EslaM-X/proofx/evidence"
	"github.com/EslaM-X/proofx/model"
	"github.com/EslaM-X/proofx/proof"
)

// Check is one line of a verification report.
type Check struct {
	Name    string `json:"name"`
	Status  string `json:"status"` // ok | fail | skipped
	Detail  string `json:"detail,omitempty"`
}

// VerifyResult is the machine-readable outcome of `proofx verify`.
type VerifyResult struct {
	ProofID     string  `json:"proofId"`
	Verified    bool    `json:"verified"`
	Checks      []Check `json:"checks"`
	Coverage    model.Coverage `json:"coverage"`
}

// cmdVerify re-verifies a proof document against the current repository.
func (c *CLI) cmdVerify(args []string) int {
	if len(args) < 1 {
		fmt.Fprintf(c.Stderr, "proofx: verify: usage: proofx verify <proof.json> [dir]\n")
		return 2
	}
	proofFile := args[0]
	dir := "."
	if len(args) > 1 {
		dir = args[1]
	}
	b, err := os.ReadFile(proofFile)
	if err != nil {
		fmt.Fprintf(c.Stderr, "proofx: verify: %v\n", err)
		return 1
	}
	p, err := proof.ParseProof(b)
	if err != nil {
		fmt.Fprintf(c.Stderr, "proofx: verify: %v\n", err)
		return 1
	}
	res := verifyAgainst(p, dir, time.Now())
	printVerify(c.Stdout, res)
	if res.Verified {
		return 0
	}
	return 1
}

// verifyAgainst re-collects current evidence and compares every digest.
func verifyAgainst(p *model.Proof, dir string, now time.Time) VerifyResult {
	res := VerifyResult{ProofID: p.ID, Checks: []Check{}}

	// 1. structure
	okStruct := checkBinding(p)
	res.Checks = append(res.Checks, okStruct)

	// 2. re-collect current evidence
	cfg, _ := config.Load(dir)
	col := &evidence.Collectors{
		Git:       evidence.GitCollector(dir),
		Artifacts: evidence.ArtifactsCollector(dir, cfgArtifacts(cfg)),
		Depends:   evidence.LockfilesCollector(dir, cfgLockfiles(cfg)),
		Tests:     evidence.TestsCollector(dir, testsSummaryFile(dir)),
		Env:       evidence.EnvCollector(dir),
	}
	current := evidence.Collect(col, now)

	// 3. compare per evidence node
	index := map[string]model.Evidence{}
	for _, r := range current {
		if r.Err == nil {
			index[r.Evidence.ID] = r.Evidence
		}
	}
	verified := 0
	for _, e := range p.Evidence {
		cur, ok := index[e.ID]
		if !ok {
			res.Checks = append(res.Checks, Check{Name: e.ID, Status: "skipped", Detail: "evidence source not present in current repo"})
			continue
		}
		if cur.Digest == e.Digest {
			verified++
			res.Checks = append(res.Checks, Check{Name: e.ID, Status: "ok", Detail: shortDigest(e.Digest)})
		} else {
			res.Checks = append(res.Checks, Check{Name: e.ID, Status: "fail", Detail: fmt.Sprintf("expected %s got %s", shortDigest(e.Digest), shortDigest(cur.Digest))})
		}
	}

	// 4. signature
	res.Checks = append(res.Checks, Check{Name: "signature", Status: statusOf(proof.VerifySignature(p)), Detail: "ed25519 over binding root"})

	// 5. coverage
	total := len(p.Evidence)
	score := 0
	if total > 0 {
		score = int(float64(verified) / float64(total) * 100)
	}
	res.Coverage = model.Coverage{Total: total, Verified: verified, Score: score}

	allOK := okStruct.Status == "ok"
	for _, ch := range res.Checks {
		if ch.Status == "fail" {
			allOK = false
		}
	}
	res.Verified = allOK
	return res
}

func checkBinding(p *model.Proof) Check {
	if err := proof.VerifyBinding(p); err != nil {
		return Check{Name: "binding", Status: "fail", Detail: err.Error()}
	}
	return Check{Name: "binding", Status: "ok", Detail: "merkle root matches evidence digests"}
}

func statusOf(err error) string {
	if err == nil {
		return "ok"
	}
	return "fail"
}

func shortDigest(d string) string {
	if len(d) <= 12 {
		return d
	}
	return d[:12]
}

func cfgArtifacts(c *config.Config) []string {
	if c == nil {
		return nil
	}
	return c.Artifacts
}

func cfgLockfiles(c *config.Config) []string {
	if c == nil {
		return nil
	}
	return c.Lockfiles
}

// printVerify renders the human-readable verification report.
func printVerify(w interface{ Write([]byte) (int, error) }, res VerifyResult) {
	fmt.Fprintf(w, "ProofX Verification — %s\n", res.ProofID)
	fmt.Fprintln(w, strings.Repeat("─", 48))
	for _, ch := range res.Checks {
		mark := "  "
		switch ch.Status {
		case "ok":
			mark = "✓ "
		case "fail":
			mark = "✗ "
		case "skipped":
			mark = "· "
		}
		detail := ""
		if ch.Detail != "" {
			detail = "  (" + ch.Detail + ")"
		}
		fmt.Fprintf(w, "%s %s%s\n", mark, ch.Name, detail)
	}
	fmt.Fprintln(w, strings.Repeat("─", 48))
	if res.Verified {
		fmt.Fprintf(w, "✓ VERIFIED — %d/%d evidence nodes match current repo\n", res.Coverage.Verified, res.Coverage.Total)
	} else {
		fmt.Fprintf(w, "✗ NOT VERIFIED — %d/%d evidence nodes match current repo\n", res.Coverage.Verified, res.Coverage.Total)
	}
	fmt.Fprintf(w, "Verification coverage: %d/100\n", res.Coverage.Score)
}
