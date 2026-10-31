package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"

	"github.com/None-Labs-VulnHound/vulnhound-community/pkg/cwe"
	"github.com/None-Labs-VulnHound/vulnhound-community/pkg/models"
	"github.com/None-Labs-VulnHound/vulnhound-community/pkg/rag"
	"github.com/None-Labs-VulnHound/vulnhound-community/pkg/secretops"
)

type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type JSONRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id,omitempty"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
}

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type Server struct {
	reader     *bufio.Reader
	writer     io.Writer
	ragEngine  *rag.Engine
	dispatcher *secretops.Dispatcher
}

func NewServer(r io.Reader, w io.Writer, engine *rag.Engine) *Server {
	return &Server{
		reader:     bufio.NewReader(r),
		writer:     w,
		ragEngine:  engine,
		dispatcher: secretops.NewDispatcher("limmireu1214@gmail.com"),
	}
}

func (s *Server) Start() error {
	for {
		line, err := s.reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if len(line) == 0 {
			continue
		}

		var req JSONRPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			s.sendError(nil, -32700, "Parse error")
			continue
		}
		s.handleRequest(&req)
	}
}

func (s *Server) handleRequest(req *JSONRPCRequest) {
	switch req.Method {
	case "initialize":
		s.sendResult(req.ID, map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
			"serverInfo": map[string]interface{}{
				"name":    "nonelabs-vulnhound",
				"version": "1.0.0",
			},
		})
	case "notifications/initialized":
	case "ping":
		s.sendResult(req.ID, map[string]interface{}{})
	case "tools/list":
		s.handleToolsList(req.ID)
	case "tools/call":
		s.handleToolCall(req.ID, req.Params)
	default:
		if req.ID != nil {
			s.sendError(req.ID, -32601, fmt.Sprintf("Method not found: %s", req.Method))
		}
	}
}

func (s *Server) handleToolsList(id interface{}) {
	tools := []map[string]interface{}{
		{
			"name":        "vulnhound_search_cve",
			"description": "Search CVE vulnerabilities by keyword, natural language query, or CVE ID using the offline RAG engine.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"query":    map[string]interface{}{"type": "string", "description": "Search keyword or CVE description snippet"},
					"cve_id":   map[string]interface{}{"type": "string", "description": "Direct CVE ID (e.g., CVE-2024-3094)"},
					"cwe_id":   map[string]interface{}{"type": "string", "description": "Associated CWE ID (e.g., CWE-89)"},
					"severity": map[string]interface{}{"type": "string", "description": "Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)"},
					"limit":    map[string]interface{}{"type": "number", "default": 5},
				},
			},
		},
		{
			"name":        "vulnhound_lookup_cwe",
			"description": "Look up MITRE CWE specification, attack explanations, and defensive mitigation strategies.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"cwe_id": map[string]interface{}{"type": "string", "description": "CWE ID (e.g. CWE-89, CWE-79, CWE-22)"},
				},
				"required": []string{"cwe_id"},
			},
		},
		{
			"name":        "vulnhound_create_secret_advisory",
			"description": "Create a confidential security advisory or private issue in GitHub or GitLab to prevent zero-day leakages.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"platform":    map[string]interface{}{"type": "string", "description": "'github' or 'gitlab'"},
					"repo":        map[string]interface{}{"type": "string", "description": "Target repository (e.g., owner/repo)"},
					"title":       map[string]interface{}{"type": "string", "description": "Advisory title"},
					"summary":     map[string]interface{}{"type": "string", "description": "High-level vulnerability overview"},
					"cve_id":      map[string]interface{}{"type": "string", "description": "CVE ID if identified"},
					"severity":    map[string]interface{}{"type": "string", "default": "HIGH", "description": "CRITICAL, HIGH, MEDIUM, LOW"},
					"poc_details": map[string]interface{}{"type": "string", "description": "Confidential proof-of-concept steps"},
					"remediation": map[string]interface{}{"type": "string", "description": "Suggested patch or defensive steps"},
				},
				"required": []string{"platform", "repo", "title", "summary", "remediation"},
			},
		},
	}

	s.sendResult(id, map[string]interface{}{"tools": tools})
}

func (s *Server) handleToolCall(id interface{}, paramsRaw json.RawMessage) {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(paramsRaw, &params); err != nil {
		s.sendError(id, -32602, "Invalid params")
		return
	}

	var outputText string

	switch params.Name {
	case "vulnhound_search_cve":
		var args struct {
			Query    string `json:"query"`
			CVEID    string `json:"cve_id"`
			CWEID    string `json:"cwe_id"`
			Severity string `json:"severity"`
			Limit    int    `json:"limit"`
		}
		_ = json.Unmarshal(params.Arguments, &args)
		res := s.ragEngine.Search(models.SearchQuery{
			Text:     args.Query,
			CVEID:    args.CVEID,
			CWEID:    args.CWEID,
			Severity: args.Severity,
			Limit:    args.Limit,
		})
		bytes, _ := json.MarshalIndent(res, "", "  ")
		outputText = string(bytes)

	case "vulnhound_lookup_cwe":
		var args struct {
			CWEID string `json:"cwe_id"`
		}
		_ = json.Unmarshal(params.Arguments, &args)
		w, ok := cwe.GetCWE(args.CWEID)
		if !ok {
			outputText = fmt.Sprintf("CWE ID '%s' not found in standard catalog.", args.CWEID)
		} else {
			bytes, _ := json.MarshalIndent(w, "", "  ")
			outputText = string(bytes)
		}

	case "vulnhound_create_secret_advisory":
		var req models.SecretAdvisoryRequest
		if err := json.Unmarshal(params.Arguments, &req); err != nil {
			s.sendError(id, -32602, "Invalid advisory arguments")
			return
		}
		res, err := s.dispatcher.CreateSecretAdvisory(req)
		if err != nil {
			s.sendError(id, -32000, fmt.Sprintf("Failed to create confidential advisory: %v", err))
			return
		}
		outputText = fmt.Sprintf("Confidential advisory successfully dispatched: %s", res)

	default:
		s.sendError(id, -32601, fmt.Sprintf("Tool not found: %s", params.Name))
		return
	}

	s.sendResult(id, map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": outputText,
			},
		},
	})
}

func (s *Server) sendResult(id interface{}, result interface{}) {
	s.sendResponse(JSONRPCResponse{JSONRPC: "2.0", ID: id, Result: result})
}

func (s *Server) sendError(id interface{}, code int, message string) {
	s.sendResponse(JSONRPCResponse{JSONRPC: "2.0", ID: id, Error: &RPCError{Code: code, Message: message}})
}

func (s *Server) sendResponse(resp JSONRPCResponse) {
	data, _ := json.Marshal(resp)
	_, _ = s.writer.Write(append(data, '\n'))
}
