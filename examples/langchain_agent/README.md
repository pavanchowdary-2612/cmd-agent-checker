# LangChain support agent example

A runnable, use-case-specific demo agent for trying AgentCheck. It uses Ollama Cloud's OpenAI-compatible API, so it does not require local Ollama. The tools use in-memory demo data only; they do not access a real order system.

## Setup (PowerShell)

From this directory, install the Python dependencies:

```powershell
python -m pip install -r requirements.txt
```

Enter the Ollama Cloud API key as a hidden prompt for this terminal session:

```powershell
$secure = Read-Host "Ollama Cloud API key" -AsSecureString
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try {
  $env:OLLAMA_API_KEY = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
} finally {
  [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
}
```

Run the agent:

```powershell
python agent.py "Check order demo-100"
```

## Assess it with AgentCheck

Install AgentCheck from the repository root with `python -m pip install -e .`, then run from this directory:

```powershell
agentcheck scan . `
  --use-case "Demo customer support agent that looks up demo orders and submits capped refund requests only after explicit confirmation" `
  --model gemma4:31b `
  --model-url https://ollama.com/v1 `
  --api-key-env OLLAMA_API_KEY
```

AgentCheck will inventory this project, infer/check its purpose against the stated use case, inspect its prompt and tools, and ask the model for use-case-specific risks and scenario ideas. Its scenario list is a plan; scenarios count as executed only when a dedicated adapter actually runs them and reports results. It skips target directories named `tests`, `test`, `e2e`, and related test-folder names.

Hosted model review sends included repository text to Ollama Cloud. Do not scan private code with a hosted service unless your data policy allows it. Keep API keys in environment variables; do not add them to source files.
