package models

import "time"

// Vulnerability represents a normalized CVE record.
type Vulnerability struct {
	ID              string    `json:"id"`                         // e.g. "CVE-2024-1234"
	Source          string    `json:"source"`                     // "NVD", "MITRE", "GHSA"
	PublishedAt     time.Time `json:"published_at"`               // Disclosure timestamp
	ModifiedAt      time.Time `json:"modified_at"`                // Last update timestamp
	Description     string    `json:"description"`                // Vulnerability description
	CWEIDs          []string  `json:"cwe_ids,omitempty"`          // Associated CWE IDs (e.g. ["CWE-89", "CWE-79"])
	CVSSv3Score     float64   `json:"cvss_v3_score"`              // CVSS base score (0.0 - 10.0)
	Severity        string    `json:"severity"`                   // "LOW", "MEDIUM", "HIGH", "CRITICAL"
	Vector          string    `json:"cvss_vector,omitempty"`      // CVSS metric vector string
	References      []string  `json:"references,omitempty"`       // Advisory links and patch references
	Remediation     string    `json:"remediation,omitempty"`      // Suggested mitigation or patch guidance
	VectorEmbedding []float32 `json:"vector_embedding,omitempty"` // Pre-calculated embedding vector
}

// Weakness represents a normalized MITRE CWE record.
type Weakness struct {
	ID          string   `json:"id"`                     // e.g. "CWE-89"
	Name        string   `json:"name"`                   // e.g. "SQL Injection"
	Abstraction string   `json:"abstraction,omitempty"`  // "Class", "Base", "Variant"
	Description string   `json:"description"`            // High-level explanation
	Mitigations []string `json:"mitigations,omitempty"`  // Standard mitigation strategies
	RelatedCWEs []string `json:"related_cwes,omitempty"` // Parent/child weakness relations
}

// SearchQuery represents a RAG query request.
type SearchQuery struct {
	Text     string  `json:"text"`               // Natural language search query or code snippet
	CVEID    string  `json:"cve_id,omitempty"`   // Direct lookup by CVE ID
	CWEID    string  `json:"cwe_id,omitempty"`   // Direct lookup by CWE ID
	Severity string  `json:"severity,omitempty"` // Filter by severity
	MinCVSS  float64 `json:"min_cvss,omitempty"` // Minimum CVSS threshold
	Limit    int     `json:"limit,omitempty"`    // Max results to return
}

// SearchResult holds ranked RAG search results with relevance scores.
type SearchResult struct {
	Vulnerability Vulnerability `json:"vulnerability"`
	CWEInfo       *Weakness     `json:"cwe_info,omitempty"`
	Score         float64       `json:"relevance_score"`
	Matches       []string      `json:"matching_reasons,omitempty"`
}

// SecretAdvisoryRequest holds metadata for creating a private advisory or confidential issue.
type SecretAdvisoryRequest struct {
	Platform    string `json:"platform"`              // "github" or "gitlab"
	Repo        string `json:"repo"`                  // "owner/repo" or "group/repo"
	Title       string `json:"title"`                 // Advisory / Issue title
	Summary     string `json:"summary"`               // Vulnerability summary
	CVEID       string `json:"cve_id,omitempty"`      // Associated CVE ID
	Severity    string `json:"severity"`              // "LOW", "MEDIUM", "HIGH", "CRITICAL"
	PoC         string `json:"poc_details,omitempty"` // Confidential Proof of Concept
	Remediation string `json:"remediation"`           // Defense recommendations
	Assignee    string `json:"assignee"`              // Primary owner (default: limmireu1214@gmail.com)
}
