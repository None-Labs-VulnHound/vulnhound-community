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

## 📌 Project Overview (프로젝트 소개)

**NoneLabs VulnHound**는 **"Zero-Cloud, Zero-Cost, Zero-Exposure"** 철학을 바탕으로 설계된 차세대 **자립형 취약점 인텔리전스 & 비밀 보안 운영(Secret Ops) 엔진**입니다.

대규모 클라우드 벡터 DB나 상시 구동 서버 비용을 일체 배제하고, NVD(National Vulnerability Database) CVE 30만 건과 MITRE CWE 전체 위협 지식을 **경량 임베디드 벡터 RAG 엔진**으로 패키징하여 단일 Go 바이너리 및 OCI 컨테이너로 제공합니다.

또한, 취약점 발견 시 외부에 제로데이가 무단 노출되지 않도록 **GitHub Security Advisories** 및 **GitLab Confidential Issues/MRs**를 통해 비공개 상태로 패치까지 완결할 수 있는 완전 비밀 파이프라인(Stealth Ops)을 기본 내장하고 있습니다.

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

NoneLabs VulnHound는 오픈소스 커뮤니티의 방어 중심 지식 확산과 기업용 고도화 침투 실증을 위해 **무료(Community)** 및 **상용(Enterprise)**의 2-Track 전략으로 운영됩니다.

| 구분 | Community Edition (무료 / Open-Source) ⭐ | Enterprise Edition (상용 / Commercial) 💼 |
| :--- | :--- | :--- |
| **운영 철학** | **Zero-Cloud, Zero-Cost, Self-Contained** | **Continuous Threat Exposure & Active Pentest** |
| **인프라 비용** | **완전 무료 ($0 유지비)** | 구독형 라이선스 / 프라이빗 클라우드 배포 |
| **보안 에이전트** | 🛡️ **Blue Team (`agent-secops`)**: 방어, 진단, 지식 RAG | ⚔️ **Red Team (`agent-pentest`) + Blue Team 통합** |
| **능동 해킹 도구** | ❌ **비포함** (법적 리스크 방지 및 안전한 정적 진단) | ✅ **실제 모의침투 & Exploit 실증 툴체인 내장**<br>(Nuclei, Metasploit API, PoC 샌드박스 검증) |
| **RAG 데이터셋** | 내장된 오프라인 정기 패키지 (~300MB OCI) | 실시간 NVD 스트리밍, CISA KEV, 다크웹 위협 인텔 |
| **시크릿 & 패치** | GitHub Security Advisory, GitLab Confidential 연동 | 취약 코드 자동 픽스 PR 발송 (Auto-Remediation) |
| **배포 형태** | 정적 Go 바이너리, Docker 컨테이너, MCP 서버 | SaaS 대시보드, Multi-tenant Fleet K8s 배포 |

---

## ✨ Key Features (Community Edition)

* 📦 **Zero-Cloud & Zero-Cost ($0)**:
  * 클라우드 데이터베이스, API 호출 비용 없이 완전 독립 실행 가능한 단일 OCI 컨테이너(`ghcr.io/none-labs-vulnhound/vulnhound-community`).
* ⚡ **초고속 하이브리드 RAG (Hybrid Lexical & Semantic)**:
  * 키워드, CVSS 메트릭, CWE ID, 자연어 벡터 유사도를 결합하여 오프라인 환경에서도 50ms 이내에 최적의 보안 완화책 도출.
* 🛡️ **MITRE CWE 대응 가이드 기본 내장**:
  * CWE Top 25 주요 취약점 클래스에 대해 설계 및 코드 레벨의 구체적인 방어 지침(Mitigations) 제공.
* 🌐 **Gemma 4 다국어 보안 권고문 생성 (Multilingual Advisory AI)**:
  * Google의 차세대 경량 고성능 다국어 파운데이션 모델인 **Gemma 4**를 전담 Advisory Generation Engine으로 채택.
  * CVE/CWE RAG 검색 결과를 바탕으로 한국어, 영어, 일본어 등 글로벌 표준 보안 권고문을 자동 생성 및 번역 렌더링.
* 🔒 **Confidential Secret Ops (제로데이 노출 방지)**:
  * 취약점 발견 시 일반 공개 Issue에 노출하지 않고, 비공개 상태인 **GitHub Security Advisories** 및 **GitLab Confidential Issues / MRs (`-c`)**로 안전하게 보고서 발송.
* 🔌 **Model Context Protocol (MCP) 표준 호환**:
  * Claude Desktop, Cursor, Antigravity 등 LLM 에이전트와 Stdio 기반으로 즉시 연동되는 3종의 전용 보안 도구 제공:
    * `vulnhound_search_cve`: CVE 취약점 RAG 검색
    * `vulnhound_lookup_cwe`: CWE 규격 및 완화 전략 조회
    * `vulnhound_create_secret_advisory`: 비밀 보안 권고문 발행

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
# 1. 자연어 또는 키워드로 취약점 검색
./vulnhound query "buffer overflow in curl"

# 2. 특정 CVE ID 상세 및 권장 완화책 조회
./vulnhound query -cve CVE-2024-3094

# 3. CWE 및 심각도(Severity) 기반 검색
./vulnhound query -cwe CWE-89 -severity CRITICAL

# 4. MITRE CWE 방어 완화 가이드 조회
./vulnhound cwe CWE-79

# 5. 비밀 보안 권고문(Confidential Advisory) 자동 발행
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
# GitOps CI 파이프라인에서 1회성 검사 실행
docker run --rm ghcr.io/none-labs-vulnhound/vulnhound-community:latest query -cve CVE-2024-3094

# AI 에이전트 연동용 MCP 서버 실행
docker run -i --rm ghcr.io/none-labs-vulnhound/vulnhound-community:latest mcp
```

### 4. MCP Agent Configuration

`mcp_config.json` 또는 `claude_desktop_config.json`에 추가:

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
