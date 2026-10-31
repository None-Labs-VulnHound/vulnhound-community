package rag

import (
	"math"
	"sort"
	"strings"
	"sync"

	"github.com/None-Labs-VulnHound/vulnhound-community/pkg/cwe"
	"github.com/None-Labs-VulnHound/vulnhound-community/pkg/models"
)

// Engine is an in-memory high-speed hybrid keyword & vector RAG engine.
type Engine struct {
	mu          sync.RWMutex
	vulns       []models.Vulnerability
	byID        map[string]models.Vulnerability
	byCWE       map[string][]models.Vulnerability
	vectorStore *VectorStore
}

// NewEngine creates an initialized RAG Engine with vulnerability items.
func NewEngine(initialVulns []models.Vulnerability) *Engine {
	e := &Engine{
		byID:        make(map[string]models.Vulnerability),
		byCWE:       make(map[string][]models.Vulnerability),
		vectorStore: NewVectorStore(),
	}
	e.Index(initialVulns)
	return e
}

// Index bulk adds or updates vulnerabilities in the engine.
func (e *Engine) Index(items []models.Vulnerability) {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, v := range items {
		upperID := strings.ToUpper(v.ID)
		e.byID[upperID] = v
		for _, c := range v.CWEIDs {
			cweUpper := strings.ToUpper(c)
			e.byCWE[cweUpper] = append(e.byCWE[cweUpper], v)
		}
		e.vulns = append(e.vulns, v)

		// Register pre-computed embedding
		if len(v.VectorEmbedding) > 0 {
			e.vectorStore.Add(upperID, v.VectorEmbedding)
		} else {
			synVec := GenerateSyntheticEmbedding(v.ID+" "+v.Description, 384)
			e.vectorStore.Add(upperID, synVec)
		}
	}
}

// Search performs hybrid lexical and semantic similarity matching over indexed vulnerabilities.
func (e *Engine) Search(q models.SearchQuery) []models.SearchResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	limit := q.Limit
	if limit <= 0 {
		limit = 10
	}

	// 1. Direct CVE ID lookup
	if q.CVEID != "" {
		targetID := strings.ToUpper(strings.TrimSpace(q.CVEID))
		if v, ok := e.byID[targetID]; ok {
			var cweInfo *models.Weakness
			if len(v.CWEIDs) > 0 {
				cweInfo, _ = cwe.GetCWE(v.CWEIDs[0])
			}
			return []models.SearchResult{
				{
					Vulnerability: v,
					CWEInfo:       cweInfo,
					Score:         1.0,
					Matches:       []string{"Exact CVE ID match"},
				},
			}
		}
	}

	// 2. Direct CWE ID filter lookup
	if q.CWEID != "" {
		cweTarget := strings.ToUpper(strings.TrimSpace(q.CWEID))
		if !strings.HasPrefix(cweTarget, "CWE-") {
			cweTarget = "CWE-" + cweTarget
		}
		matchedVulns := e.byCWE[cweTarget]
		cweInfo, _ := cwe.GetCWE(cweTarget)

		var results []models.SearchResult
		for _, v := range matchedVulns {
			if q.Severity != "" && !strings.EqualFold(v.Severity, q.Severity) {
				continue
			}
			if q.MinCVSS > 0 && v.CVSSv3Score < q.MinCVSS {
				continue
			}
			results = append(results, models.SearchResult{
				Vulnerability: v,
				CWEInfo:       cweInfo,
				Score:         0.95,
				Matches:       []string{"Exact CWE classification match"},
			})
			if len(results) >= limit {
				break
			}
		}
		return results
	}

	// 3. Keyword / Bag-of-words relevance scoring
	tokens := tokenize(q.Text)
	if len(tokens) == 0 && q.Severity == "" && q.MinCVSS == 0 {
		return nil
	}

	type scoredItem struct {
		res   models.SearchResult
		score float64
	}
	var scored []scoredItem

	for _, v := range e.vulns {
		if q.Severity != "" && !strings.EqualFold(v.Severity, q.Severity) {
			continue
		}
		if q.MinCVSS > 0 && v.CVSSv3Score < q.MinCVSS {
			continue
		}

		score, matchReasons := calculateRelevance(v, tokens)
		if score > 0 {
			var cweInfo *models.Weakness
			if len(v.CWEIDs) > 0 {
				cweInfo, _ = cwe.GetCWE(v.CWEIDs[0])
			}
			scored = append(scored, scoredItem{
				res: models.SearchResult{
					Vulnerability: v,
					CWEInfo:       cweInfo,
					Score:         math.Round(score*100) / 100,
					Matches:       matchReasons,
				},
				score: score,
			})
		}
	}

	sort.Slice(scored, func(i, j int) bool {
		return scored[i].score > scored[j].score
	})

	var out []models.SearchResult
	for i := 0; i < len(scored) && i < limit; i++ {
		out = append(out, scored[i].res)
	}

	return out
}

func tokenize(text string) []string {
	text = strings.ToLower(text)
	var tokens []string
	fields := strings.FieldsFunc(text, func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_')
	})
	for _, f := range fields {
		if len(f) >= 2 {
			tokens = append(tokens, f)
		}
	}
	return tokens
}

func calculateRelevance(v models.Vulnerability, tokens []string) (float64, []string) {
	if len(tokens) == 0 {
		return 0.5, []string{"Filter match"}
	}

	descLower := strings.ToLower(v.Description)
	idLower := strings.ToLower(v.ID)

	var score float64
	var reasons []string

	for _, tok := range tokens {
		if strings.Contains(idLower, tok) {
			score += 2.0
			reasons = append(reasons, "Matched CVE Identifier: "+tok)
		}
		if strings.Contains(descLower, tok) {
			score += 0.5
			reasons = append(reasons, "Matched description keyword: "+tok)
		}
		for _, c := range v.CWEIDs {
			if strings.EqualFold(c, tok) || strings.EqualFold(c, "cwe-"+tok) {
				score += 1.5
				reasons = append(reasons, "Matched CWE ID: "+c)
			}
		}
	}

	// CVSS Severity weight
	if v.CVSSv3Score > 7.0 {
		score += 0.1 * (v.CVSSv3Score - 7.0)
	}

	return score, reasons
}
