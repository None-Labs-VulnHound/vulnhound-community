package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/None-Labs-VulnHound/vulnhound-community/pkg/models"
)

// GemmaAdvisor generates high-fidelity multilingual security advisories using Gemma 4.
type GemmaAdvisor struct {
	Endpoint string // Local Ollama/vLLM endpoint or Google AI Studio
	APIKey   string
	Client   *http.Client
}

// NewGemmaAdvisor initializes a Gemma 4 advisory generator.
func NewGemmaAdvisor(endpoint, apiKey string) *GemmaAdvisor {
	if endpoint == "" {
		endpoint = "http://localhost:11434/api/generate" // default local Ollama/vLLM standard
	}
	return &GemmaAdvisor{
		Endpoint: endpoint,
		APIKey:   apiKey,
		Client:   &http.Client{Timeout: 60 * time.Second},
	}
}

// GeneratePrompt constructs an optimized multilingual instruction prompt for Gemma 4.
func (g *GemmaAdvisor) GeneratePrompt(vuln models.Vulnerability, cweInfo *models.Weakness, targetLang string) string {
	if targetLang == "" {
		targetLang = "English"
	}

	var cweName, cweMitigations string
	if cweInfo != nil {
		cweName = fmt.Sprintf("%s: %s", cweInfo.ID, cweInfo.Name)
		cweMitigations = strings.Join(cweInfo.Mitigations, "\n- ")
	} else {
		cweName = "Unspecified CWE Class"
		cweMitigations = "Standard secure coding practices apply."
	}

	return fmt.Sprintf(`<start_of_turn>user
You are a Principal Security Architect and DevSecOps Engineer.
Generate a structured, professional, confidential security advisory in the following target language: [%s].

[Vulnerability Intelligence Context]
- CVE Identifier: %s
- Severity: %s (CVSS v3.1 Base Score: %.1f)
- CVSS Metric Vector: %s
- Associated Weakness: %s
- Vulnerability Description: %s
- Base Mitigation Strategies:
- %s

[Required Advisory Structure]
1. Executive Summary & Impact Analysis
2. Technical Root Cause & Affected Vectors
3. Concrete Remediation & Secure Code Pattern (provide code diff / patch guidance)
4. Verification & Defense Hardening Steps

Write the entire advisory clearly in [%s] language with technical precision.
<end_of_turn>
<start_of_turn>model
`, targetLang, vuln.ID, vuln.Severity, vuln.CVSSv3Score, vuln.Vector, cweName, vuln.Description, cweMitigations, targetLang)
}

// RenderOfflineTemplate formats an advisory immediately when offline without external model endpoints.
func (g *GemmaAdvisor) RenderOfflineTemplate(vuln models.Vulnerability, cweInfo *models.Weakness, targetLang string) string {
	switch strings.ToLower(targetLang) {
	case "korean", "ko", "kr":
		var cweName, cweDesc string
		if cweInfo != nil {
			cweName = fmt.Sprintf("%s (%s)", cweInfo.ID, cweInfo.Name)
			cweDesc = cweInfo.Description
		}
		return fmt.Sprintf(`### 🔒 [Gemma 4] 기밀 보안 권고문 (Confidential Advisory)

* **식별자 (CVE ID)**: %s
* **심각도 (Severity)**: %s (CVSS Score: %.1f)
* **약점 분류 (CWE)**: %s

---

#### 📌 개요 및 영향도 분석
%s

#### 🔍 기술적 세부 사항 및 원인
약점 분류 %s와 연관되어 있으며, 외부 입력 검증 누락 또는 신뢰할 수 없는 데이터 처리로 인해 발생합니다.
%s

#### 🛠️ 권장 대응 방안 및 패치 가이드
- %s
- 의존성 라이브러리를 최신 패치 버전으로 업데이트하십시오.
- 최소 권한 원칙(Least Privilege)을 적용하여 실행 권한을 축소하십시오.
`, vuln.ID, vuln.Severity, vuln.CVSSv3Score, cweName, vuln.Description, cweName, cweDesc, vuln.Remediation)

	case "japanese", "ja", "jp":
		return fmt.Sprintf(`### 🔒 [Gemma 4] 機密セキュリティ勧告 (Confidential Advisory)

* **脆弱性識別子 (CVE ID)**: %s
* **深刻度 (Severity)**: %s (CVSS: %.1f)

---

#### 📌 概要および影響度
%s

#### 🛠️ 推奨される対策および修正手順
%s
`, vuln.ID, vuln.Severity, vuln.CVSSv3Score, vuln.Description, vuln.Remediation)

	default: // English
		var cweName string
		if cweInfo != nil {
			cweName = fmt.Sprintf("%s (%s)", cweInfo.ID, cweInfo.Name)
		}
		return fmt.Sprintf(`### 🔒 [Gemma 4] Confidential Security Advisory

* **Identifier**: %s
* **Severity**: %s (CVSS Base Score: %.1f)
* **Weakness Class**: %s

---

#### 📌 Executive Summary
%s

#### 🛡️ Remediation & Patching Guidance
- %s
- Upgrade affected dependencies to the latest patched releases.
- Enforce strict input sanitization and context-aware escaping.
`, vuln.ID, vuln.Severity, vuln.CVSSv3Score, cweName, vuln.Description, vuln.Remediation)
	}
}

// RequestAdvisory invokes the Gemma 4 LLM endpoint or falls back gracefully to offline multilingual rendering.
func (g *GemmaAdvisor) RequestAdvisory(vuln models.Vulnerability, cweInfo *models.Weakness, targetLang string) (string, error) {
	prompt := g.GeneratePrompt(vuln, cweInfo, targetLang)

	// Attempt local Ollama / vLLM call
	reqBody, _ := json.Marshal(map[string]interface{}{
		"model":  "gemma4",
		"prompt": prompt,
		"stream": false,
	})

	req, err := http.NewRequest("POST", g.Endpoint, bytes.NewBuffer(reqBody))
	if err == nil {
		req.Header.Set("Content-Type", "application/json")
		if g.APIKey != "" {
			req.Header.Set("Authorization", "Bearer "+g.APIKey)
		}

		resp, err := g.Client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			defer resp.Body.Close()
			var result struct {
				Response string `json:"response"`
			}
			if json.NewDecoder(resp.Body).Decode(&result) == nil && strings.TrimSpace(result.Response) != "" {
				return result.Response, nil
			}
		}
	}

	// Graceful offline fallback rendering
	return g.RenderOfflineTemplate(vuln, cweInfo, targetLang), nil
}
