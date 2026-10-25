# AgentCheck

AgentCheck is a terminal-based assessment agent for code repositories that contain AI agents. It combines deterministic repository checks with optional model-assisted review tailored to the use case you provide. It inventories source, prompts, documentation, configs, and evaluation harness files; identifies sensitivity and authorization concerns; and proposes use-case-specific scenarios. Target repository test directories are excluded completely and are never run.

AgentCheck does not promise to check literally every possible defect. Findings are evidence-backed leads for review. Scenario results only count as executed when a test runner or adapter actually ran and returned results.

## Requirements

- Python 3.10+
- LangChain and the model-provider integrations (installed with AgentCheck)
- For use-case reasoning and scenario generation: Ollama locally, Ollama Cloud, or another OpenAI-compatible endpoint

## Install and run

```bash
python -m pip install -e .
agentcheck scan ./some-agent-repo --use-case "An assistant that answers product questions and can place an order after user confirmation"
```

By default, AgentCheck uses local Ollama at `http://localhost:11434` with `granite3.2:8b`. If `OLLAMA_API_KEY` is set and no explicit model endpoint is configured, it automatically selects Ollama Cloud at `https://ollama.com/v1` with `gemma4:31b`; no local Ollama installation is needed. You can also configure an endpoint explicitly:

```bash
agentcheck scan ./some-agent-repo \
  --use-case "Your agent's purpose and boundaries" \
  --model llama3.1:8b \
  --model-url http://localhost:11434
```

For an OpenAI-compatible endpoint, set `AGENTCHECK_MODEL_URL` to its `/v1` base URL, set the model name, and put the API key in `AGENTCHECK_API_KEY` (or choose another environment variable with `--api-key-env`). Model review can be skipped with `--no-model`; this performs deterministic checks only and cannot produce meaningful use-case-specific analysis.

### Ollama Cloud (no local Ollama installation)

AgentCheck can call Ollama Cloud directly. You do not need the Ollama desktop app, a local Ollama server, or a model downloaded to your computer. Create an Ollama Cloud API key and keep it in the `OLLAMA_API_KEY` environment variable. When that variable is set, AgentCheck selects the cloud endpoint automatically. In PowerShell, this prompts for the key without echoing it:

```powershell
$secure = Read-Host "Ollama Cloud API key" -AsSecureString
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try {
  $env:OLLAMA_API_KEY = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
} finally {
  [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
}

agentcheck scan . `
  --use-case "Describe this agent's task, users, and safety boundaries" `
  --model gemma4:31b `
  --model-url https://ollama.com/v1 `
  --api-key-env OLLAMA_API_KEY
```

Use a model ID currently available to your Ollama Cloud account. The key is read from the environment and is not written into the repository. AgentCheck sends included repository text to the configured hosted provider; review your data-handling requirements first.

Every scan writes a human-readable Markdown report to `<scanned-repo>/.agentcheck/report.md` by default. This directory is excluded from future scans. Use `--report path/to/report.md` to choose another path, `--no-report` to disable the Markdown file, `--json` for terminal JSON output, or `--output report.json` to save the full structured JSON report.

Each model request has a 600-second default timeout to accommodate slower local models and large repositories. Set `--model-timeout 900` for slower hardware, or configure `AGENTCHECK_MODEL_TIMEOUT` for your user environment. A scan can make two model requests: initial review and second-opinion verification.

## What happens in a scan

1. AgentCheck inventories supported readable text files across the repository, skipping generated, dependency, VCS, and test directories. It records skipped large and unreadable files in the JSON report.
2. Deterministic checks look for credential literals, possible email/phone/card data, sensitive action functions, Python parse errors, and harness/evaluation structure.
3. Unless `--no-model` is set, AgentCheck starts a LangChain review agent with a use-case-specific assurance prompt and two bounded, read-only tools: `inspect_file` and `search_repository`. These can access only already-inventoried, redacted file contents; they cannot read arbitrary paths or run target code. The agent first builds an evidence-backed functional map of the target (purpose, users, workflows, tools/actions, data, external services, and safeguards), then traces relevant behavior across files to assess risks and propose scenarios grounded in those workflows. Repository inspection is capped at 16 tool calls per model pass; after that, repository tools are hidden so the model must finish its structured report instead of looping indefinitely. It should not treat names or keyword matches alone as proof. A separate LangChain verifier inspects static and first-pass model findings against their cited evidence and searches for missed issues. New second-pass findings must cite an inventoried file and valid line and are marked uncertain pending human review. Confirmed and uncertain findings remain visible; high-confidence false positives are separated into a dismissed section with the verifier's reason. If verification is unavailable, findings remain visible as unverified. A configured hosted model receives included repository text; do not point private code at a hosted endpoint unless your policy permits it.
4. A project-specific scenario adapter runs only when `--scenario-command` is supplied. It must be outside excluded test directories, receives the model-generated scenario list as JSON on stdin, and prints JSON with a `results` array on stdout. Each result should include the scenario `id`, a `status` (`passed`, `failed`, or `blocked`), and optional `actual` output. AgentCheck rejects common test-runner commands and adapter paths inside excluded test directories.

Directories named `test`, `tests`, `__tests__`, `unit_tests`, `integration_tests`, `e2e`, `spec`, or `specs` are pruned before traversal. Their files are not opened, included in model context, or run. This applies to the target repository; AgentCheck's own development tests are maintained and run separately by its developers.

Source comments and fenced code examples in Markdown are excluded from static checks and model context so illustrative values are not treated as live behavior. Markdown prose and supported text/config files remain in scope. The report states the analysis scope and whether the independent second opinion completed.

Example:

```bash
agentcheck scan ./some-agent-repo \
  --use-case "Customer support agent; may issue refunds only after explicit confirmation" \
  --scenario-command "python harness/agentcheck_adapter.py"
```

The adapter should invoke a dedicated scenario harness located outside excluded test directories, using safe fixtures and returning observed outcomes. A model-generated scenario is a test plan until an adapter actually executes it. AgentCheck does not execute generated scenarios by guessing how to invoke arbitrary agent code.

## Scope and limits

The initial deterministic analyzers are strongest for common text formats and Python AST. Model review can reason about other supported source languages, prompt files, and harness layouts, subject to model quality and context limits. The report says when some files were too large or excluded. Binary assets are not interpreted. Static analysis cannot prove runtime safety, complete policy compliance, or future reliability. Review results before relying on an agent for consequential actions.

Real `.env` files are never opened: AgentCheck records their paths and checks Git tracking/ignore status without reading their contents or sending them to a model. A tracked `.env` is reported as critical; an unignored one is reported as a commit risk. Before model review, AgentCheck also redacts credential-like literals, private-key blocks, and likely email, phone, and card values from supported text files. A hosted model endpoint still receives the remaining repository text, including source code and documentation; confirm this complies with your data-handling policy.

## Developing

```bash
$env:PYTHONPATH = "src"  # PowerShell
python -m unittest discover -s tests -v
```

These are AgentCheck's own development tests. When scanning a target repository, AgentCheck excludes its test directories and never invokes its test runner.

## Groq setup

The CLI accepts Groq's OpenAI-compatible Chat Completions API. Keep the API key in an environment variable; never commit it or paste it into source code.

PowerShell:

```powershell
$env:AGENTCHECK_API_KEY = "your-new-key"
agentcheck scan ./some-agent-repo `
  --use-case "Describe the agent's task and boundaries" `
  --model openai/gpt-oss-120b `
  --model-url https://api.groq.com/openai/v1
```

If Groq returns HTTP 403, AgentCheck now includes the provider's error code and message when available. Groq documents 403 responses for models blocked by organization or project model permissions. Check those settings in the [Groq console](https://console.groq.com/docs/model-permissions), or select a model permitted for your project.

### Use-case inference

`--use-case` is optional. If omitted, AgentCheck asks the model to infer the agent's purpose from its prompts, tool definitions, documentation, and configuration, then tailor findings and scenarios to that inferred purpose. Test directories are excluded from this inference. The report records the inferred use case, confidence, and supporting repository paths when the model returns them. If the repo does not make its purpose clear, provide `--use-case` to avoid assessing against a guess. An explicit `--use-case` always overrides inference.
#   c m d - a g e n t - c h e c k e r  
 