# NoneLabs VulnHound Community Edition

<div align="center">

```
 __      __     _         _    _                       _ 
 \ \    / /    | |       | |  | |                     | |
  \ \  / /_   _| |_ __   | |__| | ___  _   _ _ __   __| |
   \ \/ /| | | | | '_ \  |  __  |/ _ \| | | | '_ \ / _` |
    \  / | |_| | | | | | | |  | | (_) | |_| | | | | (_| |
     \/   \__,_|_|_| |_| |_|  |_|\___/ \__,_|_| |_|\__,_|
                                                          
           Zero-Cloud • Self-Contained • Secret Ops
```

[![Go Reference](https://pkg.go.dev/badge/github.com/None-Labs-VulnHound/vulnhound-community.svg)](https://pkg.go.dev/github.com/None-Labs-VulnHound/vulnhound-community)
[![License: LGPL v3](https://img.shields.io/badge/License-LGPL_v3-blue.svg)](https://www.gnu.org/licenses/lgpl-3.0)
[![CI & OCI Build](https://github.com/None-Labs-VulnHound/vulnhound-community/actions/workflows/ci.yml/badge.svg)](https://github.com/None-Labs-VulnHound/vulnhound-community/actions)
[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8?logo=go)](https://go.dev/)

</div>

---

## 📌 Project Overview

**NoneLabs VulnHound** is a next-generation **self-contained vulnerability intelligence & confidential security operations (Secret Ops) engine** architected around the core philosophy of **"Zero-Cloud, Zero-Cost, Zero-Exposure"**.

Eliminating costly cloud vector databases and 24/7 server infrastructure, it packages 300,000+ NVD (National Vulnerability Database) CVE records and full MITRE CWE threat intelligence into an embedded, lightweight hybrid vector RAG engine delivered as a single Go binary and OCI container.

Furthermore, to prevent accidental zero-day exposure during discovery, it natively integrates a confidential stealth workflow that delivers isolated security disclosures and private patches directly through **GitHub Security Advisories** and **GitLab Confidential Issues/MRs**.

---

## 🏛️ Architecture & System Design

```text
[NVD / MITRE Vulnerability Feeds]
                 │
                 ▼ (Scheduled Automated Ingestion & Quantization)
┌─────────────────────────────────────────────────────────────┐
│                 NoneLabs VulnHound Engine                   │
│                                                             │
│   ┌────────────────────┐       ┌────────────────────────┐   │
│   │  pkg/nvd & pkg/cwe │       │  pkg/rag Hybrid Engine │   │
│   │ (CVE 300k+ / CWE)  │ ────> │ (Lexical & Vector RAG) │   │
│   └────────────────────┘       └───────────┬────────────┘   │
│                                            │                │
│   ┌────────────────────┐       ┌───────────▼────────────┐   │
│   │   pkg/secretops    │ <──── │      pkg/mcp Server    │   │
│   │ (Advisories/glab)  │       │ (AI Agent RPC Stdio)   │   │
│   └────────────────────┘       └────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                 │
                 ▼ (Portable Single Distroless Container: ~300MB)
┌─────────────────────────────────────────────────────────────┐
│                   Ops & Agent Integration                   │
│                                                             │
│  [GitOps CI/CD Runner]   [Local AI Coding Agent]  [K8s Pod] │
│  - PR/MR Vulnerability   - Claude / Antigravity   - Sidecar │
│  - One-line Exit ($0)    - Native Tool Calling    - Daemon  │
└─────────────────────────────────────────────────────────────┘
```

---

## ⚖️ Dual-Edition Strategy: Community vs Enterprise

NoneLabs VulnHound operates a 2-Track strategy, strictly delineating community defensive knowledge sharing from commercial offensive exploitation validation:

| Dimension | Community Edition (Free / Open-Source) ⭐ | Enterprise Edition (Commercial) 💼 |
| :--- | :--- | :--- |
| **Philosophy** | **Zero-Cloud, Zero-Cost, Self-Contained** | **Continuous Threat Exposure & Active Pentest** |
| **Infra Cost** | **$0 Maintenance Overhead** | Subscription License / Private Cloud Deployment |
| **Security Agent** | 🛡️ **Blue Team (`agent-secops`)**: Defense, Audit, RAG | ⚔️ **Red Team (`agent-pentest`) + Integrated Blue Team** |
| **Offensive Tooling** | ❌ **Excluded** (Zero legal liability, safe static analysis) | ✅ **Live Pentest & Exploit Validation Toolchains**<br>(Nuclei, Metasploit API, PoC sandbox execution) |
| **RAG Dataset** | Embedded offline scheduled bundle (~300MB OCI) | Real-time NVD streaming, CISA KEV, dark web threat intel |
| **Secrets & Patching** | GitHub Security Advisory, GitLab Confidential integration | Automated secure fix PR generation (Auto-Remediation) |
| **Packaging** | Static Go binary, Docker container, MCP server | SaaS dashboard, multi-tenant fleet Kubernetes deployment |

---

## ✨ Key Features (Community Edition)

* 📦 **Zero-Cloud & Zero-Cost ($0)**:
  * Fully standalone single OCI container (`ghcr.io/none-labs-vulnhound/vulnhound-community`) with zero database or API subscription costs.
* ⚡ **Ultra-Fast Hybrid RAG (Lexical & Semantic)**:
  * Sub-50ms offline query resolution fusing keywords, CVSS metrics, CWE classifications, and dense vector similarity.
* 🛡️ **Built-in MITRE CWE Mitigation Intelligence**:
  * Actionable design- and code-level defense guidelines for CWE Top 25 vulnerability classes.
* 🌐 **Gemma 4 Multilingual Security Advisory AI**:
  * Adopts Google's state-of-the-art open model **Gemma 4** as the dedicated advisory generation engine.
  * Synthesizes professional, zero-hallucination AppSec advisory reports grounded in RAG findings across global languages.
* 🔒 **Confidential Secret Ops (Zero-Day Leak Prevention)**:
  * Automatically routes detected vulnerabilities directly into confidential **GitHub Security Advisories** and **GitLab Confidential Issues / MRs (`-c`)**.
* 🔌 **Model Context Protocol (MCP) Standard Compliance**:
  * Out-of-the-box stdio integration for LLM coding agents (Claude Desktop, Cursor, Antigravity) with 3 dedicated tools:
    * `vulnhound_search_cve`: CVE vulnerability RAG search
    * `vulnhound_lookup_cwe`: CWE specification and mitigation strategy lookup
    * `vulnhound_create_secret_advisory`: Confidential security advisory dispatch

---

## 🚀 Quick Start

### 1. Build from Source

```bash
git clone https://github.com/None-Labs-VulnHound/vulnhound-community.git
cd vulnhound-community
go build -o vulnhound cmd/vulnhound/main.go
```

### 2. CLI Command Examples

```bash
# 1. Search vulnerabilities via natural language or keywords
./vulnhound query "buffer overflow in curl"

# 2. Inspect specific CVE ID details and recommended mitigations
./vulnhound query -cve CVE-2024-3094

# 3. Search by CWE classification and severity
./vulnhound query -cwe CWE-89 -severity CRITICAL

# 4. Lookup MITRE CWE defensive mitigation guide
./vulnhound cwe CWE-79

# 5. Automatically publish a confidential security advisory
./vulnhound advisory \
  -platform github \
  -repo None-Labs/core \
  -title "Critical SQL Injection in User Login" \
  -cve CVE-2024-XXXX \
  -severity CRITICAL \
  -remediation "Use prepared parameterized statements."
```

### 3. Docker / OCI Execution (Zero Dependency)

```bash
# Execute ephemeral audit in GitOps CI pipeline
docker run --rm ghcr.io/none-labs-vulnhound/vulnhound-community:latest query -cve CVE-2024-3094

# Launch MCP server for AI coding agent integration
docker run -i --rm ghcr.io/none-labs-vulnhound/vulnhound-community:latest mcp
```

### 4. MCP Agent Configuration

Add to `mcp_config.json` or `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "vulnhound": {
      "command": "vulnhound",
      "args": ["mcp"]
    }
  }
}
```

---

## 📄 License

This project is licensed under the [GNU Lesser General Public License v3.0 (LGPL-3.0)](LICENSE).
