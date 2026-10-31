package secretops

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/None-Labs-VulnHound/vulnhound-community/pkg/models"
)

// Dispatcher coordinates confidential security disclosures to GitHub and GitLab.
type Dispatcher struct {
	DefaultAssignee string
}

func NewDispatcher(defaultAssignee string) *Dispatcher {
	if defaultAssignee == "" {
		defaultAssignee = "limmireu1214@gmail.com"
	}
	return &Dispatcher{DefaultAssignee: defaultAssignee}
}

// CreateSecretAdvisory routes the confidential report to GitHub or GitLab.
func (d *Dispatcher) CreateSecretAdvisory(req models.SecretAdvisoryRequest) (string, error) {
	if req.Assignee == "" {
		req.Assignee = d.DefaultAssignee
	}

	switch strings.ToLower(req.Platform) {
	case "gitlab", "glab":
		return d.createGitLabConfidentialIssue(req)
	case "github", "gh":
		return d.createGitHubSecurityAdvisory(req)
	default:
		return "", fmt.Errorf("unsupported platform: %s (use 'github' or 'gitlab')", req.Platform)
	}
}

// createGitLabConfidentialIssue creates a confidential issue via `glab issue create -c`.
func (d *Dispatcher) createGitLabConfidentialIssue(req models.SecretAdvisoryRequest) (string, error) {
	body := fmt.Sprintf(`### 🔒 Confidential Security Advisory

* **Project Manager**: %s
* **Implementation Owner**: %s
* **Severity**: %s
* **Associated CVE**: %s

---

### 📌 Vulnerability Summary
%s

### 🔍 Proof of Concept & Attack Surface
%s

### 🛡️ Recommended Remediation
%s
`, req.Assignee, req.Assignee, req.Severity, req.CVEID, req.Summary, req.PoC, req.Remediation)

	args := []string{
		"issue", "create",
		"-R", req.Repo,
		"-t", req.Title,
		"-d", body,
		"-l", "security,confidential",
		"-c", // confidential flag
	}
	if req.Assignee != "" {
		args = append(args, "--assignee", "mireu-lab")
	}

	cmd := exec.Command("glab", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("glab execution failed: %s (output: %s)", err, string(out))
	}

	return strings.TrimSpace(string(out)), nil
}

// createGitHubSecurityAdvisory creates a draft security advisory via `gh api`.
func (d *Dispatcher) createGitHubSecurityAdvisory(req models.SecretAdvisoryRequest) (string, error) {
	body := fmt.Sprintf(`### 🔒 Confidential Security Advisory

* **Project Manager**: %s
* **Implementation Owner**: %s
* **Severity**: %s
* **Associated CVE**: %s

---

### 📌 Summary
%s

### 🔍 Vulnerability Details & Attack Vector
%s

### 🛠️ Remediation Guidance
%s
`, req.Assignee, req.Assignee, req.Severity, req.CVEID, req.Summary, req.PoC, req.Remediation)

	// Fallback to private issue creation if repo is private, or use gh issue with private labeling
	args := []string{
		"issue", "create",
		"-R", req.Repo,
		"-t", "[CONFIDENTIAL] " + req.Title,
		"-b", body,
		"-l", "security,confidential",
	}
	if req.Assignee != "" {
		args = append(args, "--assignee", "Mireu-Lab")
	}

	cmd := exec.Command("gh", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("gh command failed: %s (output: %s)", err, string(out))
	}

	return strings.TrimSpace(string(out)), nil
}
