package rag

import (
	"encoding/json"
	"math"
	"os"
	"sort"
	"strings"
)

// PreEmbeddedIndex represents a pre-computed vector index bundle ready for zero-dependency distribution.
type PreEmbeddedIndex struct {
	Version    string              `json:"version"`     // e.g. "2026.10.31-pre-embedded"
	ModelName  string              `json:"model_name"`  // e.g. "bge-small-en-v1.5" or "all-MiniLM-L6-v2"
	Dimension  int                 `json:"dimension"`   // e.g. 384 or 768
	TotalCount int                 `json:"total_count"` // Total indexed records
	Vectors    []PreEmbeddedRecord `json:"vectors"`     // Serialized pre-computed vectors
}

// PreEmbeddedRecord holds a single CVE's pre-computed embedding and key metadata.
type PreEmbeddedRecord struct {
	ID        string    `json:"id"`
	Vector    []float32 `json:"vector"`
	Magnitude float32   `json:"magnitude"` // Pre-calculated L2 norm for fast dot product
}

// CosineSimilarity calculates the cosine similarity between two float32 vectors.
func CosineSimilarity(a, b []float32) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0.0
	}

	var dot, magA, magB float64
	for i := 0; i < len(a); i++ {
		valA := float64(a[i])
		valB := float64(b[i])
		dot += valA * valB
		magA += valA * valA
		magB += valB * valB
	}

	if magA == 0 || magB == 0 {
		return 0.0
	}

	return dot / (math.Sqrt(magA) * math.Sqrt(magB))
}

// FastCosineWithNorm calculates similarity when vector A is normalized and B has pre-computed magnitude.
func FastCosineWithNorm(query []float32, target []float32, targetMag float32) float64 {
	if len(query) != len(target) || len(query) == 0 {
		return 0.0
	}

	var dot, queryMag float64
	for i := 0; i < len(query); i++ {
		q := float64(query[i])
		dot += q * float64(target[i])
		queryMag += q * q
	}

	if queryMag == 0 || targetMag == 0 {
		return 0.0
	}

	return dot / (math.Sqrt(queryMag) * float64(targetMag))
}

// VectorStore holds pre-computed vectors in-memory for instant nearest neighbor search.
type VectorStore struct {
	records []PreEmbeddedRecord
	byID    map[string]PreEmbeddedRecord
}

// NewVectorStore initializes an in-memory vector store.
func NewVectorStore() *VectorStore {
	return &VectorStore{
		byID: make(map[string]PreEmbeddedRecord),
	}
}

// LoadPreEmbeddedFile loads pre-embedded vectors from a bundled JSON file.
func (vs *VectorStore) LoadPreEmbeddedFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var idx PreEmbeddedIndex
	if err := json.Unmarshal(data, &idx); err != nil {
		return err
	}

	for _, rec := range idx.Vectors {
		vs.Add(rec.ID, rec.Vector)
	}
	return nil
}

// Add inserts a pre-computed vector and computes its magnitude if not present.
func (vs *VectorStore) Add(id string, vec []float32) {
	if len(vec) == 0 {
		return
	}

	var sumSq float64
	for _, val := range vec {
		sumSq += float64(val) * float64(val)
	}
	mag := float32(math.Sqrt(sumSq))

	rec := PreEmbeddedRecord{
		ID:        strings.ToUpper(id),
		Vector:    vec,
		Magnitude: mag,
	}
	vs.records = append(vs.records, rec)
	vs.byID[rec.ID] = rec
}

// SearchNearest returns top K items matching the query vector.
func (vs *VectorStore) SearchNearest(queryVec []float32, topK int) []struct {
	ID    string
	Score float64
} {
	if len(queryVec) == 0 || len(vs.records) == 0 {
		return nil
	}

	type match struct {
		id    string
		score float64
	}
	var scored []match

	for _, rec := range vs.records {
		sim := FastCosineWithNorm(queryVec, rec.Vector, rec.Magnitude)
		if sim > 0.01 {
			scored = append(scored, match{
				id:    rec.ID,
				score: math.Round(sim*1000) / 1000,
			})
		}
	}

	sort.Slice(scored, func(i, j int) bool {
		return scored[i].score > scored[j].score
	})

	limit := topK
	if limit > len(scored) {
		limit = len(scored)
	}

	var results []struct {
		ID    string
		Score float64
	}
	for i := 0; i < limit; i++ {
		results = append(results, struct {
			ID    string
			Score float64
		}{
			ID:    scored[i].id,
			Score: scored[i].score,
		})
	}

	return results
}

// GenerateSyntheticEmbedding generates a deterministic hashed dense vector for offline testing.
func GenerateSyntheticEmbedding(text string, dim int) []float32 {
	if dim <= 0 {
		dim = 384
	}
	vec := make([]float32, dim)
	text = strings.ToLower(text)
	words := strings.Fields(text)

	for _, w := range words {
		var h uint32 = 2166136261
		for i := 0; i < len(w); i++ {
			h ^= uint32(w[i])
			h *= 16777619
		}
		idx := int(h % uint32(dim))
		vec[idx] += 1.0
	}

	// Normalize
	var mag float64
	for _, v := range vec {
		mag += float64(v) * float64(v)
	}
	if mag > 0 {
		norm := float32(math.Sqrt(mag))
		for i := range vec {
			vec[i] /= norm
		}
	}

	return vec
}
