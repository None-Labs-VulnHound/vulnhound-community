package advisor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/None-Labs-VulnHound/vulnhound-community/pkg/models"
)

// Hardcoded official Gemma 4 model targets to prevent arbitrary or paid model invocations.
const (
	DefaultGemmaModel = "gemma-4-31b-it"
)

// AllowedGemmaModels defines the strict whitelist of authorized Gemma 4 models.
var AllowedGemmaModels = map[string]bool{
	"gemma-4-31b-it": true,
	"gemma-4-27b-it": true,
	"gemma-4-9b-it":  true,
}

// GemmaAdvisor connects to Google AI Studio to synthesize multilingual security advisories.
type GemmaAdvisor struct {
	APIKey     string
	Model      string
	HTTPClient *http.Client
}

// NewGemmaAdvisor initializes a Google AI Studio client with BYOK and strict Gemma 4 model enforcement.
func NewGemmaAdvisor(apiKey string, model string) (*GemmaAdvisor, error) {
	if apiKey == "" {
		apiKey = os.Getenv("GEMINI_API_KEY")
		if apiKey == "" {
			apiKey = os.Getenv("GOOGLE_API_KEY")
		}
	}
	if apiKey == "" {
		return nil, fmt.Errorf("Google AI Studio API Key is required (set GEMINI_API_KEY or use --api-key)")
	}

	// Strictly hardcode and enforce Gemma 4 model target
	if model == "" {
		model = DefaultGemmaModel
	}
	if !AllowedGemmaModels[model] {
		return nil, fmt.Errorf("unauthorized model target %q: VulnHound strictly enforces official Gemma 4 models (e.g. %s)", model, DefaultGemmaModel)
	}

	return &GemmaAdvisor{
		APIKey: apiKey,
		Model:  model,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

type aiStudioRequest struct {
	Contents          []content `json:"contents"`
	SystemInstruction *content  `json:"systemInstruction,omitempty"`
}

type content struct {
	Role  string `json:"role"`
	Parts []part `json:"parts"`
}

type part struct {
	Text string `json:"text"`
}

type aiStudioResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Status  string `json:"status"`
	} `json:"error,omitempty"`
}

// GenerateSecurityAdvisory produces an AppSec report in the requested language (ko, en, ja).
func (g *GemmaAdvisor) GenerateSecurityAdvisory(codeSnippet string, matches []models.Vulnerability, lang string) (string, error) {
	if lang == "" {
		lang = "ko"
	}

	var matchContext strings.Builder
	for i, m := range matches {
		matchContext.WriteString(fmt.Sprintf("[%d] ID: %s | Severity: %s | Score: %.1f\n    Desc: %s\n\n",
			i+1, m.ID, m.Severity, m.CVSSv3Score, m.Description))
	}

	systemPrompt := `You are an elite Application Security Auditor (AppSec Expert) powered by NoneLabs VulnHound.
Your task is to analyze user-provided source code together with matched RAG vulnerability intelligence (CVE/CWE) and produce a professional, actionable Security Advisory Report.

Requirements:
1. Output language MUST strictly be in: ` + lang + ` (Korean for 'ko', English for 'en', Japanese for 'ja').
2. Structure:
   - 📌 Executive Summary (개요 및 위험도)
   - 🔍 Detailed Vulnerability Breakdown (식별된 취약점 상세 분석 & 위험 라인)
   - 🛠️ Remediation / Secure Code Patch (조치 방안 및 안전한 수정 코드)
   - 📚 Referenced Standards (연계된 CVE/CWE 레퍼런스)
3. Maintain zero hallucinations by strictly anchoring your findings to the provided RAG context.`

	userPrompt := fmt.Sprintf("Source Code Under Audit:\n```\n%s\n```\n\nMatched RAG Vulnerability Intelligence:\n%s\n\nPlease generate the comprehensive Security Advisory Report now.",
		codeSnippet, matchContext.String())

	reqPayload := aiStudioRequest{
		SystemInstruction: &content{
			Role:  "system",
			Parts: []part{{Text: systemPrompt}},
		},
		Contents: []content{
			{
				Role:  "user",
				Parts: []part{{Text: userPrompt}},
			},
		},
	}

	rawJSON, err := json.Marshal(reqPayload)
	if err != nil {
		return "", fmt.Errorf("failed to encode request: %w", err)
	}

	apiURL := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", g.Model, g.APIKey)

	req, err := http.NewRequest(http.MethodPost, apiURL, bytes.NewBuffer(rawJSON))
	if err != nil {
		return "", fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("AI Studio API request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	var aiResp aiStudioResponse
	if err := json.Unmarshal(bodyBytes, &aiResp); err != nil {
		return "", fmt.Errorf("failed to decode response JSON: %w (raw: %s)", err, string(bodyBytes))
	}

	if aiResp.Error != nil {
		return "", fmt.Errorf("Google AI Studio Error %d (%s): %s", aiResp.Error.Code, aiResp.Error.Status, aiResp.Error.Message)
	}

	if len(aiResp.Candidates) == 0 || len(aiResp.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("AI Studio returned empty response candidates")
	}

	return aiResp.Candidates[0].Content.Parts[0].Text, nil
}
