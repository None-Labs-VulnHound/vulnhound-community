package nvd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/None-Labs-VulnHound/vulnhound-community/pkg/models"
)

// NVDFeedResponse represents a standard NVD API 2.0 response schema subset.
type NVDFeedResponse struct {
	ResultsPerPage  int    `json:"resultsPerPage"`
	StartIndex      int    `json:"startIndex"`
	TotalResults    int    `json:"totalResults"`
	Format          string `json:"format"`
	Version         string `json:"version"`
	Timestamp       string `json:"timestamp"`
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			LastModified string `json:"lastModified"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CvssMetricV31 []struct {
					CvssData struct {
						Version      string  `json:"version"`
						VectorString string  `json:"vectorString"`
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
			} `json:"metrics"`
			Weaknesses []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			} `json:"weaknesses"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// ParseFeed parses an NVD JSON stream into normalized Vulnerability structs.
func ParseFeed(r io.Reader) ([]models.Vulnerability, error) {
	var resp NVDFeedResponse
	if err := json.NewDecoder(r).Decode(&resp); err != nil {
		return nil, fmt.Errorf("failed to decode NVD feed: %w", err)
	}

	var results []models.Vulnerability
	for _, item := range resp.Vulnerabilities {
		cve := item.CVE
		var desc string
		for _, d := range cve.Descriptions {
			if d.Lang == "en" {
				desc = d.Value
				break
			}
		}

		var cvssScore float64
		var severity string
		var cvssVector string
		if len(cve.Metrics.CvssMetricV31) > 0 {
			m := cve.Metrics.CvssMetricV31[0].CvssData
			cvssScore = m.BaseScore
			severity = strings.ToUpper(m.BaseSeverity)
			cvssVector = m.VectorString
		}

		var cwes []string
		for _, w := range cve.Weaknesses {
			for _, d := range w.Description {
				if strings.HasPrefix(strings.ToUpper(d.Value), "CWE-") {
					cwes = append(cwes, strings.ToUpper(d.Value))
				}
			}
		}

		var refs []string
		for _, ref := range cve.References {
			refs = append(refs, ref.URL)
		}

		pubTime, _ := time.Parse(time.RFC3339, cve.Published)
		modTime, _ := time.Parse(time.RFC3339, cve.LastModified)

		results = append(results, models.Vulnerability{
			ID:          cve.ID,
			Source:      "NVD",
			PublishedAt: pubTime,
			ModifiedAt:  modTime,
			Description: desc,
			CWEIDs:      cwes,
			CVSSv3Score: cvssScore,
			Severity:    severity,
			Vector:      cvssVector,
			References:  refs,
		})
	}

	return results, nil
}

// LoadLocalDatabase loads a saved Vulnerabilities JSON array from disk.
func LoadLocalDatabase(path string) ([]models.Vulnerability, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var vulns []models.Vulnerability
	if err := json.Unmarshal(data, &vulns); err != nil {
		return nil, err
	}
	return vulns, nil
}

// SaveLocalDatabase saves vulnerabilities array to disk.
func SaveLocalDatabase(path string, vulns []models.Vulnerability) error {
	data, err := json.MarshalIndent(vulns, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// FetchRecentFeed downloads latest CVEs from the NVD API (with graceful fallback).
func FetchRecentFeed(apiKey string, limit int) ([]models.Vulnerability, error) {
	if limit <= 0 {
		limit = 100
	}
	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=%d", limit)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	if apiKey != "" {
		req.Header.Set("apiKey", apiKey)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("nvd api returned status: %d", resp.StatusCode)
	}

	return ParseFeed(resp.Body)
}
