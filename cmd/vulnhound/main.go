package main

import (
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/None-Labs-VulnHound/vulnhound-community/pkg/ai"
	"github.com/None-Labs-VulnHound/vulnhound-community/pkg/cwe"
	"github.com/None-Labs-VulnHound/vulnhound-community/pkg/mcp"
	"github.com/None-Labs-VulnHound/vulnhound-community/pkg/models"
	"github.com/None-Labs-VulnHound/vulnhound-community/pkg/nvd"
	"github.com/None-Labs-VulnHound/vulnhound-community/pkg/rag"
	"github.com/None-Labs-VulnHound/vulnhound-community/pkg/secretops"
)

//go:embed data/seed_cves.json
var embeddedSeedData []byte

var (
	engine       *rag.Engine
	dispatcher   *secretops.Dispatcher
	gemmaAdvisor *ai.GemmaAdvisor
)

func init() {
	var vulns []models.Vulnerability
	_ = json.Unmarshal(embeddedSeedData, &vulns)

	// Try loading additional external database if exists
	localPaths := []string{
		"data/cve_database.json",
		"/data/cve_database.json",
		"/etc/vulnhound/cve_database.json",
	}
	for _, p := range localPaths {
		if extra, err := nvd.LoadLocalDatabase(p); err == nil && len(extra) > 0 {
			vulns = append(vulns, extra...)
			break
		}
	}

	engine = rag.NewEngine(vulns)
	dispatcher = secretops.NewDispatcher("limmireu1214@gmail.com")
	gemmaAdvisor = ai.NewGemmaAdvisor("", os.Getenv("GEMMA_API_KEY"))
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "query", "search":
			runQueryCLI(os.Args[2:])
			return
		case "cwe":
			runCWECLI(os.Args[2:])
			return
		case "mcp", "server":
			runMCPServer()
			return
		case "advisory", "secret-ops":
			runAdvisoryCLI(os.Args[2:])
			return
		case "version", "-v":
			fmt.Println("NoneLabs VulnHound Community v1.0.0 (Zero-Cloud Edition)")
			return
		case "help", "-h", "--help":
			printHelp()
			return
		}
	}

	printHelp()
}

func runMCPServer() {
	server := mcp.NewServer(os.Stdin, os.Stdout, engine)
	if err := server.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "VulnHound MCP error: %v\n", err)
		os.Exit(1)
	}
}

func runQueryCLI(args []string) {
	fs := flag.NewFlagSet("query", flag.ExitOnError)
	cveID := fs.String("cve", "", "Target CVE ID (e.g. CVE-2024-3094)")
	cweID := fs.String("cwe", "", "Target CWE ID (e.g. CWE-89)")
	severity := fs.String("severity", "", "Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)")
	limit := fs.Int("limit", 5, "Number of results to return")
	_ = fs.Parse(args)

	queryText := strings.Join(fs.Args(), " ")
	results := engine.Search(models.SearchQuery{
		Text:     queryText,
		CVEID:    *cveID,
		CWEID:    *cweID,
		Severity: *severity,
		Limit:    *limit,
	})

	printJSON(map[string]interface{}{
		"query":       queryText,
		"cve_filter":  *cveID,
		"cwe_filter":  *cweID,
		"total_count": len(results),
		"results":     results,
	})
}

func runCWECLI(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: vulnhound cwe <CWE-ID> (e.g. CWE-89, CWE-79)")
		return
	}
	target := args[0]
	weakness, ok := cwe.GetCWE(target)
	if !ok {
		fmt.Printf("CWE ID '%s' not found in standard catalog.\n", target)
		return
	}
	printJSON(weakness)
}

func runAdvisoryCLI(args []string) {
	fs := flag.NewFlagSet("advisory", flag.ExitOnError)
	platform := fs.String("platform", "github", "'github' or 'gitlab'")
	repo := fs.String("repo", "", "Target repo (e.g. owner/repo)")
	title := fs.String("title", "", "Advisory title")
	cveID := fs.String("cve", "", "Associated CVE ID")
	lang := fs.String("lang", "en", "Target language for Gemma 4 (en, ko, ja)")
	severity := fs.String("severity", "HIGH", "Severity (CRITICAL, HIGH, MEDIUM)")
	summary := fs.String("summary", "", "Vulnerability summary (optional if CVE is provided)")
	poc := fs.String("poc", "", "Confidential PoC description")
	remediation := fs.String("remediation", "", "Mitigation advice")
	_ = fs.Parse(args)

	if *repo == "" || (*title == "" && *cveID == "") {
		fmt.Println("Error: --repo and either --title or --cve are required.")
		fs.Usage()
		return
	}

	if *title == "" {
		*title = fmt.Sprintf("Security Vulnerability Advisory: %s", *cveID)
	}

	// Enrich with RAG data & Gemma 4 if CVE ID is given
	if *cveID != "" {
		res := engine.Search(models.SearchQuery{CVEID: *cveID})
		if len(res) > 0 {
			targetVuln := res[0].Vulnerability
			targetCWE := res[0].CWEInfo
			if *summary == "" {
				*summary = targetVuln.Description
			}
			if *remediation == "" {
				*remediation = targetVuln.Remediation
			}

			// Generate multilingual structured advisory with Gemma 4
			gemmaAdvisory, err := gemmaAdvisor.RequestAdvisory(targetVuln, targetCWE, *lang)
			if err == nil && gemmaAdvisory != "" {
				*summary = gemmaAdvisory
			}
		}
	}

	req := models.SecretAdvisoryRequest{
		Platform:    *platform,
		Repo:        *repo,
		Title:       *title,
		Summary:     *summary,
		CVEID:       *cveID,
		Severity:    *severity,
		PoC:         *poc,
		Remediation: *remediation,
		Assignee:    "limmireu1214@gmail.com",
	}

	res, err := dispatcher.CreateSecretAdvisory(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create confidential advisory: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✅ Confidential advisory created successfully:\n%s\n", res)
}

func printJSON(v interface{}) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Printf("JSON format error: %v\n", err)
		return
	}
	fmt.Println(string(data))
}

func printHelp() {
	fmt.Print(`NoneLabs VulnHound Community Edition (v1.0.0)
Zero-Cloud, Self-Contained Vulnerability Intelligence & Secret Ops Engine

Usage:
  vulnhound [command] [flags]

Commands:
  query       Search CVE vulnerabilities by keyword or natural language
  cwe         Inspect MITRE CWE specification and mitigations
  mcp         Run as Model Context Protocol (MCP) server over Stdio
  advisory    Create confidential security advisory (GitHub / GitLab)
  version     Display current version

Examples:
  vulnhound query "buffer overflow in curl"
  vulnhound query -cve CVE-2024-3094
  vulnhound query -cwe CWE-89 -severity CRITICAL
  vulnhound cwe CWE-79
  vulnhound advisory -platform github -repo None-Labs/core -title "SQLi in Auth API" -cve CVE-2024-1234
  vulnhound mcp
`)
}
