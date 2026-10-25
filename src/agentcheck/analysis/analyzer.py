"""Deterministic sensitivity checks and optional model-assisted repo review."""

import ast
import json
from pathlib import Path
import re
from typing import Any

# Updated imports: point to the new sub-package locations
from ..core.models import Finding
from ..agents.review_agent import invoke_review_agent, invoke_verification_agent, model_error_message
from ..workspace_pkg.workspace import Inventory, analysis_text, model_context_files

# -----------------------------------------------------------------------------
# Regular Expressions for Deterministic Static Checks
# -----------------------------------------------------------------------------

# Detects common secret and key variable/identifier names
SECRET_NAME_RE = re.compile(r"(?i)(?:api[_-]?key|secret|token|password|private[_-]?key|access[_-]?key|client[_-]?secret)")

# Matches literal assignment patterns like 'api_key = "..."' or 'token: "..."'
SECRET_LITERAL_RE = re.compile(r"(?i)([A-Za-z0-9_.-]*(?:api[_-]?key|secret|token|password|private[_-]?key|access[_-]?key|client[_-]?secret)[A-Za-z0-9_.-]*)\s*[:=]\s*(['\"])([^'\"]{16,})\2")

# Recognizes known vendor API token prefixes (Groq, OpenAI, GitHub, AWS Access Keys)
KNOWN_TOKEN_RE = re.compile(r"(?i)\b(?:gsk_[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})\b")

# Matches cryptographic private key header blocks
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")

# Matches email address formats
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)

# Matches payment card digit sequences
CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")

# Matches international and domestic phone number patterns
PHONE_RE = re.compile(r"(?<!\w)(?:\+\d{1,3}[ .-]?)?(?:\(?\d{2,4}\)?[ .-]?)?\d{3,4}[ .-]?\d{3,4}(?!\w)")

# Matches AWS Amazon Resource Names (ARNs) to prevent false-positive phone number matches
AWS_ARN_RE = re.compile(r"\barn:aws:[^\s\"']+")


# -----------------------------------------------------------------------------
# Static Analysis Pass: Deterministic AST & Regex Auditing
# -----------------------------------------------------------------------------

def static_findings(inventory: Inventory) -> list[Finding]:
    """Run fast deterministic checks against files, AST trees, and git metadata."""
    findings: list[Finding] = []
    
    # Check .env git tracking and gitignore compliance
    for env_file in inventory.environment_files:
        path = str(env_file["path"])
        if env_file.get("git_tracked") is True:
            findings.append(Finding(
                "tracked-environment-file", "critical",
                "A real .env file is tracked by Git; it may contain credentials. Its contents were not opened.",
                path, evidence="[contents not read]",
                recommendation="Revoke any credentials in this file, remove it from Git history, and keep local environment files ignored."
            ))
        elif env_file.get("git_ignored") is False:
            findings.append(Finding(
                "environment-file-not-ignored", "medium",
                "A real .env file is not ignored by Git and could be committed accidentally. Its contents were not opened.",
                path, evidence="[contents not read]",
                recommendation="Add this environment file pattern to .gitignore and verify it is not tracked."
            ))
            
    # Audit each source file line by line
    for item in inventory.files:
        lines = analysis_text(item.path, item.content).splitlines()
        
        # Check 1: Private key blocks in code or config
        for line_no, line in enumerate(lines, 1):
            if PRIVATE_KEY_RE.search(line):
                findings.append(Finding(
                    "possible-private-key", "critical",
                    "Private key material marker found in repository text.",
                    item.path, line_no, "[private key material redacted]",
                    "Remove the key, revoke or rotate it, and inspect repository history and deployment use."
                ))
                break
                
        # Check 2: Vendor API key patterns, personal PII, and payment cards
        for line_no, line in enumerate(lines, 1):
            known_token = KNOWN_TOKEN_RE.search(line)
            if known_token and not _looks_like_placeholder(known_token.group(0)):
                findings.append(Finding(
                    "possible-hardcoded-secret", "critical",
                    "Recognized credential format appears directly in repository text.",
                    item.path, line_no, "[credential value redacted]",
                    "Treat this credential as exposed: revoke or rotate it, then load the replacement from a secret manager or environment variable."
                ))
                
            # Scan non-python files for literal key-value secret assignments
            if not item.path.endswith(".py"):
                secret_literal = SECRET_LITERAL_RE.search(line)
                if secret_literal and _looks_like_secret_literal(secret_literal.group(3)):
                    findings.append(Finding(
                        "possible-hardcoded-secret", "critical",
                        f"A credential-like string is assigned directly to '{secret_literal.group(1)}'; this is a literal, not an environment/config lookup.",
                        item.path, line_no, "[credential value redacted]",
                        "Treat this credential as exposed: revoke or rotate it, then load the replacement from a secret manager or environment variable."
                    ))
                    
            # Scan for non-mock personal email addresses
            if EMAIL_RE.search(line) and not any(marker in line.lower() for marker in ("example.com", "example.org", "example.net", "@test", "@pytest")):
                findings.append(Finding(
                    "possible-personal-data", "high",
                    "Possible hard-coded email address.",
                    item.path, line_no, "[redacted email]",
                    "Confirm this is synthetic; remove or anonymize real personal data and review repository history."
                ))
                
            # Scan for numbers satisfying the Luhn checksum algorithm
            for match in CARD_RE.finditer(line):
                digits = re.sub(r"\D", "", match.group(0))
                if 13 <= len(digits) <= 19 and _luhn(digits):
                    findings.append(Finding(
                        "possible-payment-card", "critical",
                        "Number passes a payment-card checksum and may be real card data.",
                        item.path, line_no, "[redacted card-like value]",
                        "Remove the value, rotate or invalidate it if real, and inspect commit history."
                    ))
                    
            # Scan for unredacted phone numbers outside AWS ARNs
            if not CARD_RE.search(line):
                phone_scan_line = AWS_ARN_RE.sub("", line)
                phone = PHONE_RE.search(phone_scan_line)
                if phone and len(re.sub(r"\D", "", phone.group(0))) >= 10:
                    findings.append(Finding(
                        "possible-personal-data", "high",
                        "Possible hard-coded phone number.",
                        item.path, line_no, "[redacted phone number]",
                        "Confirm this is synthetic; remove or anonymize real personal data and review repository history."
                    ))

        # Check 3: Python AST Parsing for unconfirmed destructive tools and hardcoded assignments
        if item.path.endswith(".py"):
            try:
                tree = ast.parse(item.content, filename=item.path)
            except SyntaxError as exc:
                findings.append(Finding("python-parse-error", "medium", f"Static Python parsing failed: {exc.msg}.", item.path, exc.lineno))
                continue
                
            for node in ast.walk(tree):
                # Detect assignment of literal strings to secret-named variables
                if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                    value = node.value
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    target_names = [name for target in targets for name in _target_names(target)]
                    if any(SECRET_NAME_RE.search(name) for name in target_names) and isinstance(value, ast.Constant) and isinstance(value.value, str):
                        literal = value.value.strip()
                        if _looks_like_secret_literal(literal):
                            findings.append(Finding(
                                "possible-hardcoded-secret", "critical",
                                f"A credential-like string is assigned directly to '{target_names[0]}'; this is a literal, not an environment/config lookup.",
                                item.path, node.lineno, "[credential value redacted]",
                                "Treat this credential as exposed: revoke or rotate it, then load the replacement from a secret manager or environment variable."
                            ))
                            
                # Detect sensitive action functions lacking explicit confirmation checks
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _is_sensitive_action(node.name):
                    names = " ".join(child.id if isinstance(child, ast.Name) else child.attr for child in ast.walk(node) if isinstance(child, (ast.Name, ast.Attribute)))
                    if not re.search(r"approval|confirm|authorize|approved", names, re.I):
                        findings.append(Finding(
                            "sensitive-action-guard-needs-review", "medium",
                            f"The name '{node.name}' suggests a destructive operation, but this function body has no obvious authorization/confirmation reference. This heuristic cannot verify guards in callers or shared helpers.",
                            item.path, node.lineno, node.name,
                            "Trace callers and shared authorization helpers, then verify authentication, authorization, confirmation, input bounds, and idempotency."
                        ))
                        
    # Deduplicate findings by rule, file path, and line number
    unique: dict[tuple[str, str, int | None], Finding] = {}
    for finding in findings:
        unique.setdefault((finding.rule, finding.path, finding.line), finding)
    return list(unique.values())


# -----------------------------------------------------------------------------
# AST and Token Validation Helpers
# -----------------------------------------------------------------------------

def _target_names(node: ast.AST) -> list[str]:
    """Extract identifier names from an AST assignment target node."""
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        return [name for element in node.elts for name in _target_names(element)]
    if isinstance(node, ast.Attribute):
        return [node.attr]
    return []


def _looks_like_placeholder(value: str) -> bool:
    """Heuristic check to determine if a string is a template placeholder or dummy value."""
    lowered = value.casefold()
    return value.startswith(("$", "${", "%")) or any(marker in lowered for marker in ("example", "placeholder", "changeme", "your_", "xxxx", "dummy", "fake", "redacted"))


def _looks_like_secret_literal(value: str) -> bool:
    """Determine if a string possesses characteristics of an active credential."""
    if len(value) < 16 or _looks_like_placeholder(value):
        return False
    if KNOWN_TOKEN_RE.search(value):
        return True
    # Verify the token contains multiple character classes (lowercase, uppercase, digits, punctuation)
    classes = sum((any(char.islower() for char in value), any(char.isupper() for char in value), any(char.isdigit() for char in value), any(not char.isalnum() for char in value)))
    return classes >= 2 and not any(char.isspace() for char in value)


def _luhn(value: str) -> bool:
    """Compute the Luhn checksum algorithm used to validate payment card numbers."""
    digits = [int(char) for char in value]
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _is_sensitive_action(name: str) -> bool:
    """Check if a function name indicates a high-impact or destructive operation."""
    return bool(re.search(r"delete|remove|refund|transfer|purchase|charge|send_money|create_user|grant_access", name, re.I))


# -----------------------------------------------------------------------------
# Finding Verification (Pass 2: Second Opinion Engine)
# -----------------------------------------------------------------------------

def verify_findings(
    inventory: Inventory,
    use_case: str,
    model: str,
    base_url: str,
    api_key: str | None,
    findings: list[Finding],
    timeout_seconds: int = 180,
    review_context: list[str] | None = None
) -> tuple[list[Finding], list[Finding], str | None]:
    """Ask the configured model to independently validate candidate findings against redacted repo context."""
    safe_files, _ = model_context_files(inventory)
    candidates = []
    
    # Format candidate findings into JSON payload for the verification agent
    for index, finding in enumerate(findings):
        candidates.append({
            "id": f"finding-{index}", "rule": finding.rule, "severity": finding.severity,
            "message": finding.message, "path": finding.path, "line": finding.line,
            "recommendation": finding.recommendation,
        })
        
    try:
        content = invoke_verification_agent(model, base_url, api_key, timeout_seconds, safe_files, use_case, candidates, review_context or [])
        verdict_data = _extract_json(content)
        verdicts = verdict_data.get("verdicts")
        if not isinstance(verdicts, list):
            raise ValueError("verifier response is missing a verdicts array")
            
        by_id = {str(item.get("id")): item for item in verdicts if isinstance(item, dict)}
        active: list[Finding] = []
        dismissed: list[Finding] = []
        
        # Process verification verdict for each candidate
        for index, finding in enumerate(findings):
            verdict = by_id.get(f"finding-{index}", {})
            status = verdict.get("status")
            if status not in {"confirmed", "uncertain", "false_positive"}:
                status = "uncertain"
                
            reason = str(verdict.get("reason", "Verifier returned no explanation; human review is needed."))[:1000]
            confidence = verdict.get("confidence")
            confidence = max(0.0, min(1.0, float(confidence))) if isinstance(confidence, (int, float)) else None
            
            # Dismiss as false positive only when verifier confidence is at least 80%
            if status == "false_positive" and (confidence is None or confidence < 0.8):
                status = "uncertain"
                reason = "Verifier suspected a false positive but did not provide high enough confidence to dismiss it. " + reason
                
            finding.verification_status = status
            finding.verification_reason = reason
            finding.verification_confidence = confidence
            
            if status == "false_positive":
                dismissed.append(finding)
            else:
                if reason:
                    finding.message = reason
                active.append(finding)
                
        # Ingest any distinct additional findings discovered by the second-opinion auditor
        known_paths = {item.path: item for item in inventory.files}
        existing = {(finding.rule, finding.path, finding.line) for finding in findings}
        
        for entry in verdict_data.get("additional_findings", [])[:50]:
            if not isinstance(entry, dict):
                continue
            path = str(entry.get("path", "")).replace("\\", "/")
            line = entry.get("line")
            if path not in known_paths or not isinstance(line, int) or line < 1 or line > len(known_paths[path].content.splitlines()):
                continue
            rule = str(entry.get("rule", "second-opinion-review"))[:100]
            if (rule, path, line) in existing:
                continue
            severity = str(entry.get("severity", "medium")).lower()
            if severity not in {"critical", "high", "medium", "low"}:
                severity = "medium"
            candidate = Finding(
                rule, severity, str(entry.get("message", "Potential issue found in independent second-pass review."))[:2000],
                path, line, str(entry.get("evidence", ""))[:500] or None,
                str(entry.get("recommendation", ""))[:1000] or None,
                "uncertain", "Found during independent second-pass review; corroborate the cited behavior before treating it as confirmed.", None,
            )
            active.append(candidate)
            existing.add((rule, path, line))
            
        return active, dismissed, None
        
    except Exception as exc:
        # Fallback gracefully if verification agent times out or errors
        for finding in findings:
            finding.verification_status = "unverified"
            finding.verification_reason = "Independent model verification was unavailable; this candidate has not been confirmed."
        detail = model_error_message(exc, api_key, timeout_seconds, base_url)
        return findings, [], f"Finding verification unavailable: {detail}"


# -----------------------------------------------------------------------------
# Robust JSON Extraction from Model Responses
# -----------------------------------------------------------------------------

def _extract_json(content: str) -> dict[str, Any]:
    """Robustly parse JSON objects from model output, handling preamble/postamble prose."""
    decoder = json.JSONDecoder()
    candidates: list[dict[str, Any]] = []
    covered_until = -1
    
    # Iterate through content and attempt decoding from each opening brace
    for index, character in enumerate(content):
        if character != "{" or index < covered_until:
            continue
        try:
            value, end = decoder.raw_decode(content, index)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            candidates.append(value)
            covered_until = end
            
    if not candidates:
        raise ValueError("model response did not contain a valid JSON object")
        
    # Return the last valid decoded JSON object
    return candidates[-1]


# -----------------------------------------------------------------------------
# Primary Model Review (Pass 1 Engine)
# -----------------------------------------------------------------------------

def model_review(
    inventory: Inventory,
    use_case: str,
    model: str,
    base_url: str,
    api_key: str | None = None,
    timeout_seconds: int = 180
) -> tuple[list[Finding], list[dict[str, Any]], list[str], str | None, float | None, str | None, dict[str, Any]]:
    """Execute primary LLM review agent, parse structured findings, and build use-case scenarios."""
    safe_files, omitted = model_context_files(inventory)
    known_paths = {item.path: item for item in inventory.files}
    
    try:
        content = invoke_review_agent(
            model, base_url, api_key, timeout_seconds, safe_files, use_case, inventory.harness_files,
        )
        data = _extract_json(content)
        findings = []
        
        # Validate each model-reported finding against actual repository paths and lines
        for entry in data.get("findings", []):
            if not isinstance(entry, dict):
                continue
            path = str(entry.get("path", "")).replace("\\", "/")
            line = entry.get("line")
            # Enforce that findings reference valid, included relative files and line numbers
            if Path(path).is_absolute() or path not in known_paths or not isinstance(line, int) or line < 1:
                continue
            if line > len(known_paths[path].content.splitlines()):
                continue
            severity = str(entry.get("severity", "medium")).lower()
            if severity not in {"critical", "high", "medium", "low"}:
                severity = "medium"
            findings.append(Finding(
                str(entry.get("rule", "model-review")), severity,
                str(entry.get("message", "Potential issue identified by model review."))[:2000],
                path, line, str(entry.get("evidence", ""))[:500] or None,
                str(entry.get("recommendation", ""))[:1000] or None
            ))
            
        # Parse and format generated test scenarios
        scenarios = []
        seen_ids: set[str] = set()
        for index, entry in enumerate(data.get("scenarios", [])[:100], 1):
            if not isinstance(entry, dict):
                continue
            scenario_id = str(entry.get("id") or f"scenario-{index:03d}")[:100]
            if scenario_id in seen_ids:
                scenario_id = f"{scenario_id}-{index}"
            seen_ids.add(scenario_id)
            steps = entry.get("steps", [])
            if isinstance(steps, str):
                steps = [steps]
            if not isinstance(steps, list):
                steps = []
            scenarios.append({
                "id": scenario_id,
                "title": str(entry.get("title", f"Scenario {index}"))[:500],
                "category": str(entry.get("category", "use_case"))[:100],
                "steps": [str(step)[:1000] for step in steps[:30]],
                "expected": str(entry.get("expected", ""))[:2000],
            })
            
        # Compile assessment summary, limitations, and redaction notes
        limitations = [str(item) for item in data.get("limitations", [])]
        summary = str(data.get("summary", ""))
        notes = ([f"Model review summary: {summary}"] if summary else []) + limitations
        notes.append("Credential-like literals, private-key blocks, and likely personal identifiers were redacted from model context; local deterministic checks still inspect original text.")
        if omitted:
            notes.append(f"Model context limit excluded {len(omitted)} files: {', '.join(omitted[:20])}.")
            
        # Extract inferred use case and confidence when provided
        inferred_use_case = str(data.get("inferred_use_case", "")).strip()
        confidence = data.get("use_case_confidence")
        confidence = max(0.0, min(1.0, float(confidence))) if isinstance(confidence, (int, float)) else None
        evidence_paths = [str(path).replace("\\", "/") for path in data.get("use_case_evidence", []) if str(path).replace("\\", "/") in known_paths]
        
        # Build functional agent profile
        raw_profile = data.get("agent_profile", {})
        profile: dict[str, Any] = {}
        if isinstance(raw_profile, dict):
            for key in ("purpose",):
                if raw_profile.get(key):
                    profile[key] = str(raw_profile[key])[:2000]
            for key in ("intended_users", "workflows", "tools_and_actions", "data_and_sensitivity", "external_services", "safeguards"):
                values = raw_profile.get(key, [])
                if isinstance(values, list):
                    profile[key] = [str(value)[:1000] for value in values[:40]]
            raw_paths = raw_profile.get("source_paths", [])
            if isinstance(raw_paths, list):
                profile["source_paths"] = [
                    str(path).replace("\\", "/") for path in raw_paths
                    if str(path).replace("\\", "/") in known_paths
                ][:40]
                
        if inferred_use_case:
            supporting_paths = evidence_paths or profile.get("source_paths", [])
            notes.append("Use-case inference evidence: " + (", ".join(supporting_paths) if supporting_paths else "model reasoning from repository context; no valid evidence file paths returned"))
            
        return findings, scenarios, notes, inferred_use_case, confidence, None, profile
        
    except Exception as exc:
        detail = model_error_message(exc, api_key, timeout_seconds, base_url)
        return [], [], [], None, None, f"Model review unavailable: {detail}", {}
