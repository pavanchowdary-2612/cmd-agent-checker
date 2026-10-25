# 🛡️ AgentCheck (`cmd-agent-checker`)

> **Automated, Use-Case-Aware Assurance and Security Auditing for AI Agent Repositories.**

AgentCheck is a command-line assessment tool built for modern AI agent codebases. It combines **deterministic static analysis** (AST inspections, hardcoded credential detection, sensitive tool audits) with **dynamic, dual-pass LLM reasoning** (primary architectural review + independent second-opinion verification).

Whether you are auditing your own custom LangChain/LlamaIndex agents or verifying third-party agents, AgentCheck inspects prompts, tool guards, authorization boundaries, credential leakage, and data privacy—and automatically generates targeted test scenarios for evaluation harnesses.

---

## 📑 Table of Contents

- [Key Features](#-key-features)
- [How It Works (Architecture)](#-how-it-works-architecture)
- [Installation](#-installation)
- [LLM Provider Configuration](#-llm-provider-configuration)
  - [Option A: Ollama Cloud (No Local Server Needed)](#option-a-ollama-cloud-no-local-server-needed)
  - [Option B: Local Ollama](#option-b-local-ollama)
  - [Option C: Groq / OpenAI-Compatible API](#option-c-groq--openai-compatible-api)
- [Quick Start Guide](#-quick-start-guide)
  - [1. Running the LangChain Support Agent](#1-running-the-langchain-support-agent)
  - [2. Scanning an Agent with AgentCheck](#2-scanning-an-agent-with-agentcheck)
  - [3. Auditing the Flawed Agent (Demo Vulnerabilities)](#3-auditing-the-flawed-agent-demo-vulnerabilities)
- [CLI Reference](#-cli-reference)
- [Automated Scenario Execution (Adapters)](#-automated-scenario-execution-adapters)
- [Privacy & Security Guarantees](#-privacy--security-guarantees)
- [Repository Structure](#-repository-structure)
- [Development & Testing](#-development--testing)

---

## ✨ Key Features

- 🔍 **Use-Case-Specific Risk Assessment**: Evaluates safety based on what the agent is *supposed* to do, not just generic linter rules. Automatically infers the agent's purpose if `--use-case` is not provided.
- 👥 **Dual-Pass Verification Engine**:
  1. **Pass 1 (Review Agent)**: Maps functionality, identifies potential risks, and crafts boundary/adversarial test scenarios.
  2. **Pass 2 (Independent Verifier)**: A separate reviewer verifies candidate findings against cited code lines to eliminate false positives.
- 🛡️ **Zero-Execution Safety**: AgentCheck *never* executes target agent code or shell commands during a scan.
- 🚫 **Strict Test Exclusion**: Directories like `tests/`, `test/`, `e2e/`, and `specs/` are pruned so mock/test data never skew the assessment.
- 🔐 **Privacy Preserving & Redaction**: Credential-like literals and personal identifiers are redacted before sending to LLMs; real `.env` files are never read or uploaded.
- ⏱️ **Bounded Tool Budget**: Caps repo exploration to prevent LLM agents from looping indefinitely.
- 📝 **Dual Output Formats**: Generates formatted terminal reports, saved Markdown reports (`.agentcheck/report.md`), and machine-readable JSON (`--json` or `--output`).

---

## 🧠 How It Works (Architecture)

```text
               ┌────────────────────────────────────────────────────────┐
               │                Target Agent Repository                 │
               └──────────────────────────┬─────────────────────────────┘
                                          │
            ┌─────────────────────────────┴─────────────────────────────┐
            ▼                                                           ▼
┌─────────────────────────┐                                 ┌─────────────────────────┐
│ 1. Deterministic Engine │                                 │ 2. Primary Review Agent │
│ • AST parsing           │                                 │ • Bounded inspect_file  │
│ • Credential regex      │                                 │ • Maps workflows/tools  │
│ • Dangerous tool checks │                                 │ • Generates scenarios   │
└───────────┬─────────────┘                                 └───────────┬─────────────┘
            │                                                           │
            └─────────────────────────────┬─────────────────────────────┘
                                          ▼
                         ┌─────────────────────────────────┐
                         │   Candidate Findings Pool       │
                         └────────────────┬────────────────┘
                                          ▼
                         ┌─────────────────────────────────┐
                         │ 3. Second-Opinion Verifier      │
                         │ • Audits each finding at line   │
                         │ • Filters false positives       │
                         │ • Assigns confidence %          │
                         └────────────────┬────────────────┘
                                          ▼
                         ┌─────────────────────────────────┐
                         │  Final Assessment Report        │
                         │  (Terminal, Markdown, or JSON)  │
                         └─────────────────────────────────┘
```

---

## 🚀 Installation

Ensure Python **3.10+** is installed on your system.

### 1. Clone the repository
```bash
git clone https://github.com/pavanchowdary-2612/cmd-agent-checker.git
cd cmd-agent-checker
```

### 2. Create and activate a virtual environment

**On Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**On Linux / macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install AgentCheck in editable mode
```bash
python -m pip install --upgrade pip
python -m pip install -e .
```

### 4. Install example agent dependencies (optional, for running the demo agent)
```bash
python -m pip install -r examples/langchain_agent/requirements.txt
```

---

## 🔑 LLM Provider Configuration

AgentCheck supports **Ollama Cloud**, **Local Ollama**, and any **OpenAI-compatible endpoint** (Groq, Together, OpenAI, etc.).

### Option A: Ollama Cloud (No Local Server Needed)

You do **not** need to install Ollama or download multi-gigabyte models locally. Simply use an Ollama Cloud API key:

**PowerShell (Windows):**
```powershell
$env:OLLAMA_API_KEY = "your-ollama-cloud-api-key"
```

**Bash (Linux / macOS):**
```bash
export OLLAMA_API_KEY="your-ollama-cloud-api-key"
```

*Tip: You can also place `OLLAMA_API_KEY=your-key` into a `.env` file in the project root.*

---

### Option B: Local Ollama

If you run Ollama locally on `http://localhost:11434`:
```bash
ollama pull granite3.2:8b
# AgentCheck will automatically connect to localhost:11434 by default
```

---

### Option C: Groq / OpenAI-Compatible API

```powershell
$env:AGENTCHECK_API_KEY = "gsk_your_groq_api_key"

agentcheck scan . `
  --model openai/gpt-oss-120b `
  --model-url https://api.groq.com/openai/v1 `
  --api-key-env AGENTCHECK_API_KEY
```

---

## 🏃 Quick Start Guide

### 1. Running the LangChain Support Agent

The repository includes a ready-to-run demo customer support agent in `examples/langchain_agent/`. It features order lookups and explicit-confirmation-protected refunds.

**Lookup an existing order:**
```powershell
python examples/langchain_agent/agent.py "Check order demo-100"
```
*Output:*
```text
Order demo-100: shipped
Latency: 1820 ms
```

**Request a refund (requires explicit confirmation):**
```powershell
python examples/langchain_agent/agent.py "I confirm a refund of 50 for order demo-200"
```
*Output:*
```text
Demo refund request for 50.00 on demo-200 was submitted.
Latency: 2410 ms
```

---

### 2. Scanning an Agent with AgentCheck

Run a full security and quality scan on the support agent:

```powershell
agentcheck scan ./examples/langchain_agent `
  --use-case "Customer support agent that looks up demo orders and submits capped refunds only after explicit confirmation"
```

AgentCheck will:
1. Inventory all non-test files.
2. Check for exposed keys, unverified tool actions, and data leaks.
3. Reason over system prompts and tool constraints.
4. Plan 4+ use-case-specific test scenarios (adversarial injection, boundary limits, policy refusals).
5. Run a second LLM pass to confirm all findings.
6. Write a full Markdown report to `./examples/langchain_agent/.agentcheck/report.md`.

---

### 3. Auditing the Flawed Agent (Demo Vulnerabilities)

The repository also includes `examples/flawed_agent/`, which intentionally contains real security vulnerabilities (hardcoded API key, unvalidated refunds).

Run a scan against it:
```powershell
agentcheck scan ./examples/flawed_agent `
  --use-case "E-commerce support agent allowing refunds"
```

**Expected Scan Output:**
```text
Findings (2):
  [CONFIRMED · CRITICAL] possible-hardcoded-secret — examples/flawed_agent/agent.py:4
    The file contains a hardcoded API key credential format.
    Verifier confidence: 100%
    Evidence: [credential value redacted]
    Recommendation: Revoke and load from secret manager or environment variable.

  [CONFIRMED · MEDIUM] sensitive-action-guard-needs-review — examples/flawed_agent/agent.py:9
    The refund_order tool performs financial transactions without confirmation or input bounds.
    Verifier confidence: 100%
    Evidence: refund_order
    Recommendation: Verify authentication, confirmation, and bounds.

LLM second opinion: completed (2 candidates checked; 0 dismissed)
```

---

## ⚙️ CLI Reference

```text
agentcheck scan [REPOSITORY_PATH] [OPTIONS]
```

| Argument | Default | Description |
| :--- | :--- | :--- |
| `repository` | `.` | Root directory of the agent codebase to scan. |
| `--use-case` | *(Inferred)* | Plain English description of the agent's intended role, boundaries, and users. |
| `--model` | `granite3.2:8b` (local) / `gemma4:31b` (cloud) | Model name to use for reasoning and review. |
| `--model-url` | `http://localhost:11434` / `https://ollama.com/v1` | Base URL of the OpenAI-compatible model API. |
| `--api-key-env` | `OLLAMA_API_KEY` | Environment variable name holding the provider API key. |
| `--model-timeout` | `600` | Timeout in seconds for each model request pass. |
| `--no-model` | `False` | Run deterministic static analysis only (skips LLM review). |
| `--report` | `<repo>/.agentcheck/report.md` | Path where the human-readable Markdown report will be saved. |
| `--no-report` | `False` | Suppress generating the Markdown report file. |
| `--json` | `False` | Print machine-readable JSON output directly to stdout. |
| `--output` | `None` | Save complete structured assessment data to a designated JSON file. |
| `--scenario-command` | `None` | Shell command for an external adapter to execute generated scenarios. |

---

## 🧪 Automated Scenario Execution (Adapters)

AgentCheck doesn't just list scenarios; you can execute them through an external scenario adapter with `--scenario-command`:

```powershell
agentcheck scan ./my-agent `
  --use-case "Order tracking bot" `
  --scenario-command "python harness/run_scenarios.py"
```

### Adapter Protocol
1. **Input (stdin)**: AgentCheck pipes a JSON payload containing the planned scenarios:
   ```json
   {
     "scenarios": [
       { "id": "refund-injection-bypass", "steps": ["..."], "expected": "..." }
     ]
   }
   ```
2. **Output (stdout)**: Your adapter executes each scenario against your live agent and prints results in JSON format:
   ```json
   {
     "results": [
       { "id": "refund-injection-bypass", "status": "passed" }
     ]
   }
   ```

*(Note: Common test runner commands like `pytest` or scripts inside `tests/` directories are disallowed as adapters to ensure test isolation).*

---

## 🔒 Privacy & Security Guarantees

- **No Secret Leaks**: Before repository text is processed by LLMs, API keys, tokens, credit card patterns, and email addresses are automatically redacted.
- **`.env` Isolation**: Real `.env` files are never opened or sent to models. AgentCheck only checks if `.env` is properly tracked or ignored in `.gitignore`.
- **Read-Only Inspection**: Tools provided to the LLM agent (`inspect_file`, `search_repository`) have read-only access to inventoried files and cannot browse arbitrary filesystem paths.
- **Deterministic Bounds**: Bounded turns (maximum 16 repository tool calls) ensure deterministic evaluation without runaway costs or infinite loops.

---

## 📁 Repository Structure

```text
cmd-agent-checker/
├── src/
│   └── agentcheck/
│       ├── cli.py             # CLI commands, argument parsing, output formatting
│       ├── analyzer.py        # Static AST analysis, secret detection, verification pipeline
│       ├── review_agent.py    # LangChain primary review & second-opinion agent prompts
│       ├── runner.py          # Scenario adapter execution engine
│       ├── workspace.py       # Repository inventory, file pruning, and redaction
│       └── models.py          # Pydantic data schemas
├── examples/
│   ├── langchain_agent/       # Production-style support agent demo with tools
│   │   ├── agent.py
│   │   ├── evals/
│   │   └── README.md
│   └── flawed_agent/          # Insecure demo agent demonstrating audit catches
│       └── agent.py
├── tests/                     # AgentCheck internal test suite
├── pyproject.toml             # Package metadata and CLI entrypoints
└── README.md                  # Documentation
```

---

## 🛠️ Development & Testing

To run AgentCheck's unit and regression tests:

**PowerShell:**
```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
```

**Bash:**
```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

All 18 unit tests cover static parsing, regex scanners, repository inventories, and provider integrations.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
