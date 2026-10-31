package cwe

import (
	"strings"

	"github.com/None-Labs-VulnHound/vulnhound-community/pkg/models"
)

// DefaultCatalog contains standard MITRE CWE Top 25 and major weakness classes.
var DefaultCatalog = map[string]models.Weakness{
	"CWE-89": {
		ID:          "CWE-89",
		Name:        "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
		Abstraction: "Base",
		Description: "The product constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command.",
		Mitigations: []string{
			"Use parameterized queries, prepared statements, or stored procedures instead of string concatenation.",
			"Apply strict allow-list input validation on all user-supplied data.",
			"Enforce the principle of least privilege on database accounts.",
		},
		RelatedCWEs: []string{"CWE-707", "CWE-943"},
	},
	"CWE-79": {
		ID:          "CWE-79",
		Name:        "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
		Abstraction: "Base",
		Description: "The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
		Mitigations: []string{
			"Contextually encode all user-supplied output before rendering into HTML, JavaScript, CSS, or URLs.",
			"Implement a Content Security Policy (CSP) with strict nonce/hash rules.",
			"Use modern frameworks that perform automatic contextual escaping (e.g., React, Go html/template).",
		},
		RelatedCWEs: []string{"CWE-707", "CWE-74"},
	},
	"CWE-22": {
		ID:          "CWE-22",
		Name:        "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
		Abstraction: "Base",
		Description: "The product uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the product does not properly neutralize special elements such as '..' sequences that can resolve to a location that is outside of the restricted directory.",
		Mitigations: []string{
			"Validate user input using allow-lists of permitted characters or file extensions.",
			"Resolve canonical paths with filepath.Clean and verify that the target starts with the base directory prefix.",
			"Store files under indirect randomized UUID identifiers instead of user-supplied names.",
		},
		RelatedCWEs: []string{"CWE-707", "CWE-23"},
	},
	"CWE-78": {
		ID:          "CWE-78",
		Name:        "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
		Abstraction: "Base",
		Description: "The product constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command when it is sent to a downstream component.",
		Mitigations: []string{
			"Avoid executing system shell commands. Use structured native APIs (e.g. exec.Command without shell expansion).",
			"If external command execution is unavoidable, pass arguments as discrete array parameters rather than concatenated strings.",
			"Execute processes in restricted sandboxes or containers with minimal system capabilities (drop CAP_SYS_ADMIN).",
		},
		RelatedCWEs: []string{"CWE-77", "CWE-707"},
	},
	"CWE-502": {
		ID:          "CWE-502",
		Name:        "Deserialization of Untrusted Data",
		Abstraction: "Class",
		Description: "The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid.",
		Mitigations: []string{
			"Avoid binary or object serialization formats. Use safer data interchange formats such as JSON, Protocol Buffers, or MessagePack.",
			"Digitally sign serialized data with HMAC before transmission and verify signature before deserialization.",
			"Run deserialization routines in isolated sandboxes with strict execution controls.",
		},
		RelatedCWEs: []string{"CWE-20"},
	},
	"CWE-287": {
		ID:          "CWE-287",
		Name:        "Improper Authentication",
		Abstraction: "Class",
		Description: "When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.",
		Mitigations: []string{
			"Enforce multi-factor authentication (MFA) and secure credential handling.",
			"Use robust cryptographic algorithms with salt (e.g. Argon2id, bcrypt) for password storage.",
			"Implement rate-limiting and account lockout mechanisms against brute-force attacks.",
		},
		RelatedCWEs: []string{"CWE-284"},
	},
	"CWE-798": {
		ID:          "CWE-798",
		Name:        "Use of Hard-coded Credentials",
		Abstraction: "Base",
		Description: "The product contains hard-coded credentials, such as a password or cryptographic key, which it uses for inbound authentication, outbound communication, or encryption.",
		Mitigations: []string{
			"Store credentials in secure secret management systems (e.g., HashiCorp Vault, Google Secret Manager).",
			"Integrate secret scanners (e.g. gitleaks, trivy) into pre-commit hooks and CI/CD pipelines.",
			"Implement automated credential rotation policies.",
		},
		RelatedCWEs: []string{"CWE-255", "CWE-522"},
	},
	"CWE-434": {
		ID:          "CWE-434",
		Name:        "Unrestricted Upload of File with Dangerous Type",
		Abstraction: "Base",
		Description: "The product allows the attacker to upload or transfer files of dangerous types that can be directly processed or executed within the environment.",
		Mitigations: []string{
			"Inspect magic bytes and MIME types, not solely file extensions.",
			"Store uploaded files on an isolated domain, GCS bucket, or CDN with no script execution privileges.",
			"Rename uploaded files to random non-predictable UUIDs.",
		},
		RelatedCWEs: []string{"CWE-20"},
	},
}

// GetCWE returns the weakness specification by ID.
func GetCWE(cweID string) (*models.Weakness, bool) {
	cweID = strings.ToUpper(strings.TrimSpace(cweID))
	if !strings.HasPrefix(cweID, "CWE-") {
		cweID = "CWE-" + cweID
	}
	w, ok := DefaultCatalog[cweID]
	if !ok {
		return nil, false
	}
	return &w, true
}
