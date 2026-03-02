# agenticqa-scan-action

<div align="center">

### The first GitHub Action that maps every integration point in your AI codebase — 13 CWE categories, attack surface score, test coverage gaps — in one step.

[![GitHub Marketplace](https://img.shields.io/badge/GitHub%20Marketplace-agenticqa--scan--action-blue?logo=github&logoColor=white&style=for-the-badge)](https://github.com/marketplace/actions/agenticqa-architecture-scan)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)
[![SARIF](https://img.shields.io/badge/Output-SARIF%202.1.0-orange?style=for-the-badge)](https://sarifweb.azurewebsites.net/)
[![No API Key](https://img.shields.io/badge/API%20Key-Not%20Required-brightgreen?style=for-the-badge)](#no-api-key-required)

**Before you ship code, know exactly where attackers will look.**

</div>

---

## Why This Exists

AI systems are architecturally different from traditional software. They call LLM APIs, orchestrate autonomous agents, expose MCP tools, and pass external data through serialization chains — all of which are attack surfaces that standard SAST tools were not designed to detect.

Most teams discover their AI system's attack surface in a post-incident review. This action catches it at every pull request.

`agenticqa-scan-action` walks your entire codebase — Python, TypeScript, JavaScript, Go, Java, Swift, YAML — and maps every integration point across 13 CWE categories. It scores your attack surface, identifies untested areas, and uploads findings as SARIF to GitHub's Security tab.

---

## Quickstart — One Line

```yaml
- uses: nhomyk/agenticqa-scan-action@v1
```

Add it to any job that checks out your code.

---

## Full Workflow

```yaml
name: Architecture Security Scan

on: [push, pull_request]

jobs:
  architecture-scan:
    name: AgenticQA Architecture Scan
    runs-on: ubuntu-latest
    permissions:
      security-events: write   # upload findings to GitHub Security tab
      contents: read

    steps:
      - uses: actions/checkout@v4

      - uses: nhomyk/agenticqa-scan-action@v1
        id: scan
        with:
          fail-on-critical: 'true'   # block deploys if RCE-class areas found

      - name: Show attack surface score
        run: |
          echo "Attack surface: ${{ steps.scan.outputs.attack-surface-score }}/100"
          echo "Critical areas: ${{ steps.scan.outputs.critical-count }}"
          echo "Untested areas: ${{ steps.scan.outputs.untested-count }}"
```

Findings appear under **Security → Code scanning alerts.**

---

## What It Detects

### 13 Integration Categories

| Category | CWE | Severity | What It Flags |
|----------|-----|----------|---------------|
| `SHELL_EXEC` | CWE-78 | 🔴 critical | `subprocess.run`, `os.system`, `exec.Command` — RCE risk |
| `EXTERNAL_HTTP` | CWE-918 | 🟠 high | `requests.get`, `fetch()`, `http.Get` — SSRF risk |
| `DATABASE` | CWE-89 | 🟠 high | SQLite, PostgreSQL, MongoDB, SQLAlchemy connections |
| `ENV_SECRETS` | CWE-798 | 🟠 high | `os.getenv`, `process.env`, `System.getenv` — credential leakage |
| `SERIALIZATION` | CWE-502 | 🟠 high | `pickle.loads`, `yaml.load`, `ObjectInputStream` — unsafe deserialization |
| `NETWORK_SOCKET` | CWE-601 | 🟠 high | Raw TCP/Unix socket creation |
| `AGENT_FRAMEWORK` | CWE-693 | 🟠 high | LangChain, LangGraph, CrewAI, AutoGen, OpenAI, Anthropic SDK |
| `CLOUD_SERVICE` | CWE-306 | 🟡 medium | `boto3`, `google.cloud`, Azure SDK calls |
| `AUTH_BOUNDARY` | CWE-306 | 🟡 medium | JWT decode, `@login_required`, `verify_token` |
| `MIDDLEWARE` | CWE-284 | 🟡 medium | FastAPI, Flask, Express routes and middleware |
| `MCP_TOOL` | CWE-284 | 🟡 medium | `@mcp.tool` registrations — AI agent attack surface |
| `FILE_SYSTEM` | CWE-73 | 🟡 medium | File write operations — path traversal risk |
| `EVENT_BUS` | CWE-400 | 🔵 low | Celery, Redis, Kafka, RabbitMQ pub/sub |

### 6 Languages

Python · TypeScript · JavaScript · Go · Java · Swift

### Plus YAML/JSON

GitHub Actions workflows, Kubernetes configs, CI/CD pipelines.

---

## Output — GitHub Security Tab

Every integration area becomes a Code Scanning alert:

```
┌─────────────────────────────────────────────────────────────────────┐
│  Security  /  Code scanning alerts                                   │
│                                                                      │
│  ● ARCH_SHELL_EXEC     Error    subprocess.run at src/runner.py:42  │
│  ● ARCH_AGENT_FRAMEWORK Warning  Anthropic SDK at src/agents.py:15  │
│  ● ARCH_EXTERNAL_HTTP  Warning  requests.post at src/client.py:88   │
│  ● ARCH_SERIALIZATION  Warning  pickle.loads at src/ingest.py:31    │
│                                                                      │
│  47 open alerts  ·  Powered by AgenticQA Architecture Scanner        │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Step Summary

After every run, a full breakdown appears in your workflow's Summary tab:

```
🟡 AgenticQA Architecture Scan — Score 42/100

Integration areas found: 47  |  Critical: 3  |  Untested: 12
Attack surface score: 42/100  |  Test coverage confidence: 68%

⚠️ 3 critical area(s) detected — SHELL_EXEC requires immediate review

| Category         | Count | CWE     | Severity   |
|------------------|-------|---------|------------|
| SHELL_EXEC       | 3     | CWE-78  | 🔴 critical |
| EXTERNAL_HTTP    | 12    | CWE-918 | 🟠 high    |
| AGENT_FRAMEWORK  | 8     | CWE-693 | 🟠 high    |
| DATABASE         | 6     | CWE-89  | 🟠 high    |
| ENV_SECRETS      | 5     | CWE-798 | 🟠 high    |
| AUTH_BOUNDARY    | 4     | CWE-306 | 🟡 medium  |
| MIDDLEWARE       | 4     | CWE-284 | 🟡 medium  |
| FILE_SYSTEM      | 3     | CWE-73  | 🟡 medium  |
| EVENT_BUS        | 2     | CWE-400 | 🔵 low     |

Top untested high-risk areas (12 total):
- src/workers/runner.py:42 — SHELL_EXEC
- src/agents/executor.py:88 — AGENT_FRAMEWORK
- src/ingest/pipeline.py:31 — SERIALIZATION
```

---

## Attack Surface Score

The score (0–100) is density-normalized across your codebase:

```
Score = Σ(severity_weight × unique_files_affected / total_files) × coverage_factor
```

Where:
- `critical` weight = 80, `high` = 50, `medium` = 25, `low` = 10
- `coverage_factor` = 1.0 (fully tested) → 2.0 (no tests at all)
- Score capped at 100 — large well-tested repos won't be unfairly penalized

**Interpretation:**
| Score | Meaning |
|-------|---------|
| 0–24 | 🟢 Low exposure — well-tested, bounded integration surface |
| 25–49 | 🟡 Moderate — standard for an actively developed service |
| 50–74 | 🟠 High — multiple untested high-risk areas, requires prioritization |
| 75–100 | 🔴 Critical — significant attack surface, many untested entry points |

---

## Use Outputs in Downstream Steps

```yaml
- uses: nhomyk/agenticqa-scan-action@v1
  id: scan

# Block deployment if attack surface score is too high
- name: Enforce score gate
  if: steps.scan.outputs.attack-surface-score >= 75
  run: |
    echo "❌ Attack surface score ${{ steps.scan.outputs.attack-surface-score }}/100 exceeds threshold"
    exit 1

# Or use the built-in threshold input
- uses: nhomyk/agenticqa-scan-action@v1
  with:
    fail-on-score: '75'        # fail if score >= 75
    fail-on-critical: 'true'   # also fail on any RCE-class area
```

---

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `repo-path` | `.` | Path to the repository root to scan |
| `fail-on-critical` | `false` | Exit code 1 if any critical (SHELL_EXEC) areas are found |
| `fail-on-score` | `0` | Exit code 1 if attack surface score ≥ this value (0 = disabled) |
| `sarif-output` | `agenticqa-scan-results.sarif` | SARIF output filename |
| `upload-sarif` | `true` | Upload to GitHub Code Scanning (`security-events: write` required) |
| `category` | `agenticqa-architecture` | SARIF category — useful when running multiple scans |

## Outputs

| Output | Values | Description |
|--------|--------|-------------|
| `findings-count` | integer | Total integration areas across all 13 categories |
| `critical-count` | integer | Critical-severity areas (SHELL_EXEC, command injection vectors) |
| `attack-surface-score` | 0–100 | Density-normalized attack surface score |
| `test-coverage` | 0–100 | Test coverage confidence for detected integration areas |
| `untested-count` | integer | Integration areas with no test coverage |
| `sarif-file` | path | Location of the generated SARIF file |

---

## Real Scan Results — AgenticQA Scanned on Itself

Running `agenticqa-scan-action` on the AgenticQA platform itself:

```
Files scanned:          247
Integration areas:      785
Critical areas:         12     (subprocess calls in SRE agent's auto-fix loop)
Attack surface score:   38/100
Test coverage:          76%
Untested areas:         89

Categories detected:
• MIDDLEWARE       (CWE-284): 198  — FastAPI routes + middleware layers
• AGENT_FRAMEWORK (CWE-693): 124  — Anthropic SDK + multi-agent orchestration
• ENV_SECRETS      (CWE-798): 110  — Configuration reads (not credentials)
• EXTERNAL_HTTP    (CWE-918): 89   — Weaviate, Qdrant, Neo4j client calls
• DATABASE         (CWE-89):  72   — SQLite + asyncpg connections
• FILE_SYSTEM      (CWE-73):  68   — Artifact store, SARIF output, config writes
• AUTH_BOUNDARY    (CWE-306): 45   — JWT middleware, bearer token verification
• SHELL_EXEC       (CWE-78):  12   — subprocess in SRE self-healing CI loop
• MCP_TOOL         (CWE-284): 8    — MCP server tool registrations
• SERIALIZATION    (CWE-502): 24   — JSON/YAML config parsing
• CLOUD_SERVICE    (CWE-306): 18   — GitHub API, S3 (optional)
• NETWORK_SOCKET   (CWE-601): 5    — Qdrant binary protocol
• EVENT_BUS        (CWE-400): 12   — Redis Celery task queue
```

---

## No API Key Required

All scanning is **pure static analysis.** The action:

- Never calls an LLM
- Never sends your code to an external service
- Produces results deterministically — same code, same findings, every run
- Works entirely within your GitHub Actions runner

---

## How It Works

```
Your repo
    │
    ├── Language detection     → .py / .ts / .js / .go / .java / .swift / .yaml
    │
    ├── Pattern matching       → pre-compiled regex for each of 13 categories
    │   (per-language)           applied to every source file in the repo
    │
    ├── Test cross-reference   → each finding linked to matching test files
    │   (coverage mapping)       untested areas flagged for prioritization
    │
    ├── Attack surface score   → density × coverage factor, capped at 100
    │
    └── SARIF export           → one finding per integration area
                                          │
                                          ▼
                               GitHub Security → Code scanning alerts
```

---

## Related Actions

| Action | What It Does |
|--------|-------------|
| **[MCP Security Scan](https://github.com/marketplace/actions/mcp-security-scan)** | Deep scan of MCP servers: tool poisoning, SSRF, prompt injection, DataFlow taint |
| **[EU AI Act Compliance Check](https://github.com/marketplace/actions/eu-ai-act-compliance-check)** | Annex III risk classification + Art.9/13/14/22 conformity |
| **AgenticQA Architecture Scan** *(this action)* | Full codebase architecture map — all 13 CWE categories |

Use all three together for complete AI system security and compliance coverage:

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: nhomyk/agenticqa-scan-action@v1       # architecture map
  - uses: nhomyk/mcp-scan-action@v1             # MCP/AI-specific threats
  - uses: nhomyk/eu-ai-act-check-action@v1      # EU AI Act compliance
```

---

## Powered by AgenticQA

This action wraps the architecture scanner from **[AgenticQA](https://github.com/nhomyk/AgenticQA)** — an open-source autonomous CI/CD platform for AI-native teams.

AgenticQA adds to your pipeline:
- **Architecture scanning** (this action) — 13 integration categories, attack surface score
- **MCP security** — [mcp-scan-action](https://github.com/marketplace/actions/mcp-security-scan)
- **EU AI Act compliance** — [eu-ai-act-check-action](https://github.com/marketplace/actions/eu-ai-act-compliance-check)
- **HIPAA PHI detection** — 5 PHI taint categories across your codebase
- **Self-healing CI** — SRE agent auto-fixes lint errors and test failures
- **Red Team hardening** — 20 bypass techniques + constitutional gate

[Explore AgenticQA →](https://github.com/nhomyk/AgenticQA)

---

## License

MIT © [nhomyk](https://github.com/nhomyk)
