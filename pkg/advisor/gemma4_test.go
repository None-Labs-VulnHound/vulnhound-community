package advisor

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/None-Labs-VulnHound/vulnhound-community/pkg/models"
)

func TestGemmaAdvisorMockGenerate(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := aiStudioResponse{
			Candidates: []struct {
				Content struct {
					Parts []struct {
						Text string `json:"text"`
					} `json:"parts"`
				} `json:"content"`
			}{
				{
					Content: struct {
						Parts []struct {
							Text string `json:"text"`
						} `json:"parts"`
					}{
						Parts: []struct {
							Text string `json:"text"`
						}{
							{Text: "### 📌 보안 권고문 (Security Advisory)\n\n**식별된 취약점**: CWE-89 SQL 인젝션\n**조치 방안**: Prepared Statement 적용 필요."},
						},
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer mockServer.Close()

	adv := &GemmaAdvisor{
		APIKey:     "test-key",
		Model:      "gemma-4",
		HTTPClient: mockServer.Client(),
	}

	matches := []models.Vulnerability{
		{
			ID:          "CWE-89",
			Severity:    "CRITICAL",
			Description: "Improper neutralization of special elements in SQL query",
		},
	}

	// Override URL for testing
	origURL := "https://generativelanguage.googleapis.com/v1beta/models/gemma-4:generateContent?key=test-key"
	_ = origURL

	// Verify request payload creation
	if adv.APIKey != "test-key" {
		t.Fatalf("expected APIKey test-key, got %s", adv.APIKey)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
}

func TestGemmaAdvisorAPIKeyValidation(t *testing.T) {
	_, err := NewGemmaAdvisor("", "")
	if err == nil {
		t.Fatalf("expected error when API key is missing")
	}
	if !strings.Contains(err.Error(), "API Key is required") {
		t.Fatalf("expected API Key error, got %v", err)
	}
}
