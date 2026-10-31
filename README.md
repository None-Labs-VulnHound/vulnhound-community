# NoneLabs VulnHound Community Edition

[![Go Reference](https://pkg.go.dev/badge/github.com/None-Labs-VulnHound/vulnhound-community.svg)](https://pkg.go.dev/github.com/None-Labs-VulnHound/vulnhound-community)
[![License: LGPL v3](https://img.shields.io/badge/License-LGPL_v3-blue.svg)](https://www.gnu.org/licenses/lgpl-3.0)
[![CI & OCI Build](https://github.com/None-Labs-VulnHound/vulnhound-community/actions/workflows/ci.yml/badge.svg)](https://github.com/None-Labs-VulnHound/vulnhound-community/actions)
[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8?logo=go)](https://go.dev/)

> **NoneLabs VulnHound Community** is a **Zero-Cloud, Self-Contained Vulnerability Intelligence Engine & Secret Ops Tool** written in Go.
> It embeds NVD CVE databases and MITRE CWE catalogs into a lightweight, offline-capable RAG vector engine and integrates directly with **GitHub Security Advisories** and **GitLab Confidential Issues/MRs** for confidential vulnerability disclosures without zero-day leakages.

---

## ✨ Features (Community Edition)

* 📦 **Zero-Cloud & Self-Contained ($0 Cost)**:
  * Complete CVE/CWE data and embedded search engine packaged into a minimal single OCI container (~300MB). Zero external cloud dependencies.
* ⚡ **High-Speed Lexical & Semantic RAG Engine**:
  * Hybrid keyword and vector search over CVE records with sub-millisecond query responses in air-gapped CI environments.
* 🛡️ **Defensive CWE Knowledge Base**:
  * Built-in MITRE CWE Top 25 descriptions, architectural weaknesses, and actionable code mitigation strategies.
* 🔒 **Confidential Secret Ops (Zero-Day Protection)**:
  * Programmatically dispatch private vulnerability reports directly into **GitHub Security Advisories** (`gh`) or **GitLab Confidential Issues / MRs** (`glab -c`).
* 🔌 **Model Context Protocol (MCP) Server**:
  * Native JSON-RPC 2.0 stdio MCP server for direct pairing with AI coding agents (Antigravity, Cursor, Claude).

---

## 🚀 Quick Start

### 1. Installation

```bash
git clone https://github.com/None-Labs-VulnHound/vulnhound-community.git
cd vulnhound-community
go build -o vulnhound cmd/vulnhound/main.go
```

### 2. CLI Usage Examples

```bash
# 1. Search CVE by keyword or natural language
./vulnhound query "buffer overflow in curl"

# 2. Look up specific CVE with mitigation details
./vulnhound query -cve CVE-2024-3094

# 3. Query vulnerabilities matching CWE and severity
./vulnhound query -cwe CWE-89 -severity CRITICAL

# 4. Inspect MITRE CWE mitigation specification
./vulnhound cwe CWE-79

# 5. Dispatch confidential security advisory (GitHub / GitLab)
./vulnhound advisory \
  -platform github \
  -repo None-Labs/core \
  -title "Critical SQL Injection in User Login" \
  -cve CVE-2024-XXXX \
  -severity CRITICAL \
  -remediation "Use prepared parameterized statements."
```

### 3. Docker / OCI Container Execution

```bash
# Run one-off search in CI/CD pipeline
docker run --rm ghcr.io/none-labs-vulnhound/vulnhound-community:latest query -cve CVE-2024-3094

# Run as an MCP Server over Stdio
docker run -i --rm ghcr.io/none-labs-vulnhound/vulnhound-community:latest mcp
```

### 4. MCP Server Configuration (Antigravity / Claude Desktop / Cursor)

Add the following to your `mcp_config.json`:

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

## 🗺️ Editions & Roadmap

| Feature | Community (Free / Open-Source) | Enterprise (Commercial / B2B) |
| :--- | :--- | :--- |
| **Philosophy** | **Zero-Cloud & Self-Contained** | **Continuous Threat Exposure Management** |
| **Cost** | **100% Free ($0)** | Subscription / Custom License |
| **Agent Focus** | **Blue Team (`agent-secops`)** | **Red Team (`agent-pentest`) + Blue Team** |
| **RAG Knowledge Base** | Embedded Offline CVE & CWE (~300MB) | Real-time NVD/KEV Streaming + Threat Feeds |
| **Active Penetration Tools** | ❌ (Passive diagnostics only) | ✅ **Active Exploit PoC Testing (Nuclei, Metasploit API)** |
| **Attack Surface Management** | ❌ | ✅ Continuous External Attack Surface Scanner |
| **Compliance Export** | Markdown / JSON | Automated PDF/Excel Reports (SOC2, ISO 27001) |

---

## 📄 License

This project is licensed under the [GNU Lesser General Public License v3.0 (LGPL-3.0)](LICENSE).
