"""AgentCheck command line."""

import argparse
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

from . import __version__
from .analyzer import model_review, static_findings, verify_findings
from .models import ScanResult
from .runner import run_scenarios, scenario_command_is_excluded
from .workspace import EXCLUDED_TEST_DIRS, inventory_repository


def _load_agentcheck_env() -> None:
    """Load supported settings from AgentCheck's own .env file.

    Resolve the file from this installed package's project root, never from
    the repository being scanned. Existing process variables always win.
    """
    config_path = Path(__file__).resolve().parents[2] / ".env"
    if not config_path.is_file():
        return
    try:
        lines = config_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("export "):
            stripped = stripped[7:].lstrip()
        name, separator, value = stripped.partition("=")
        name = name.strip()
        if not separator or not name or not (name.startswith("AGENTCHECK_") or name == "OLLAMA_API_KEY"):
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        os.environ.setdefault(name, value)


def _render(result: ScanResult) -> str:
    lines = [
        "AgentCheck assessment",
        f"Repository: {result.root}",
        f"Use case: {result.use_case}",
        f"Readable text files inventoried: {result.inventory.get('text_files', 0)}",
        f"Model review: {result.model_used or 'not available'}",
        "",
    ]
    if result.findings:
        lines.append(f"Findings ({len(result.findings)}):")
        for finding in result.findings:
            location = f"{finding.path}:{finding.line}" if finding.path and finding.line else finding.path or "repository level"
            verification = f"{finding.verification_status.upper()} · " if finding.verification_status else ""
            lines.append(f"  [{verification}{finding.severity.upper()}] {finding.rule} — {location}")
            lines.append(f"    {finding.message}")
            if finding.verification_confidence is not None:
                lines.append(f"    Verifier confidence: {finding.verification_confidence:.0%}")
            if finding.evidence:
                lines.append(f"    Evidence: {finding.evidence}")
            if finding.recommendation:
                lines.append(f"    Recommendation: {finding.recommendation}")
    else:
        lines.append("No findings were returned. This is not proof the agent is safe or correct.")
    if result.dismissed_findings:
        lines.extend(["", f"Dismissed by second opinion ({len(result.dismissed_findings)}):"])
        for finding in result.dismissed_findings:
            location = f"{finding.path}:{finding.line}" if finding.path and finding.line else finding.path or "repository level"
            lines.append(f"  [FALSE POSITIVE] {finding.rule} — {location}")
            lines.append(f"    Reason: {finding.verification_reason or 'Verifier found insufficient evidence.'}")
    lines.extend(["", f"Use-case scenarios planned ({len(result.scenarios)}):"])
    for scenario in result.scenarios:
        steps = "; ".join(str(step) for step in scenario.get("steps", []))
        lines.append(f"  - {scenario.get('id', '?')} [{scenario.get('category', 'scenario')}]: {scenario.get('title', 'Untitled')}")
        if steps:
            lines.append(f"    Steps: {steps}")
        if scenario.get("expected"):
            lines.append(f"    Expected: {scenario['expected']}")
    if result.inventory:
        lines.extend(["", f"Harness/eval files discovered: {result.inventory.get('harness_file_count', 0)}"])
        opinion = result.inventory.get("second_opinion", {})
        if opinion:
            lines.append(f"LLM second opinion: {opinion.get('status', 'unknown')} ({opinion.get('checked_findings', 0)} candidates checked; {opinion.get('additional_findings', 0)} new candidates; {opinion.get('dismissed_findings', 0)} dismissed)")
        lines.append("Analysis scope: comments and fenced Markdown code examples excluded; Markdown prose and supported text/config files included.")
        execution = result.inventory.get("scenario_execution")
        if execution:
            lines.extend(["", f"Scenario adapter: {execution.get('status')}"])
            for row in execution.get("results", []):
                lines.append(f"  - {row.get('id', 'unknown')}: {row.get('status', 'unspecified')} — {row.get('actual', '')}")
            if execution.get("error"):
                lines.append(f"  Adapter detail: {execution['error']}")
            if execution.get("output"):
                lines.append(f"  Adapter output: {execution['output'][-2000:]}")
    if result.notes:
        lines.extend(["", "Limitations and notes:"])
        lines.extend(f"  - {note}" for note in result.notes)
    lines.extend(["", "Target test directories were excluded and never read or run. Model and static findings require human review."])
    return "\n".join(lines)


def _render_markdown(result: ScanResult) -> str:
    """Render a user-facing report with the inferred functionality and evidence."""
    lines = [
        "# AgentCheck assessment",
        "",
        f"- **Repository:** `{result.root}`",
        f"- **Use case:** {result.use_case}",
        f"- **Use-case source:** {result.use_case_source}",
        f"- **Model:** {result.model_used or 'unavailable'}",
        f"- **Readable files inventoried:** {result.inventory.get('text_files', 0)}",
        f"- **Harness/evaluation files:** {result.inventory.get('harness_file_count', 0)}",
        "",
        "## What this agent does",
    ]
    profile = result.agent_profile
    if profile:
        if profile.get("purpose"):
            lines.extend(["", f"**Purpose:** {profile['purpose']}"])
        for field, title in (
            ("intended_users", "Intended users"), ("workflows", "Main workflows"),
            ("tools_and_actions", "Tools and actions"), ("data_and_sensitivity", "Data and sensitivity"),
            ("external_services", "External services"), ("safeguards", "Safeguards found"),
        ):
            values = profile.get(field, [])
            if values:
                lines.extend(["", f"### {title}", ""])
                lines.extend(f"- {value}" for value in values)
        if profile.get("source_paths"):
            lines.extend(["", "**Profile evidence:** " + ", ".join(f"`{path}`" for path in profile["source_paths"])])
    else:
        lines.extend(["", "The model did not return a functional map. Review the limitations below; this assessment may not be use-case-aware."])
    lines.extend(["", "## Assessment summary", ""])
    summaries = [note.removeprefix("Model review summary: ") for note in result.notes if note.startswith("Model review summary:")]
    lines.extend(summaries or ["No model summary was available."])
    lines.extend(["", f"## Findings ({len(result.findings)})", ""])
    if result.findings:
        for finding in result.findings:
            location = f"{finding.path}:{finding.line}" if finding.path and finding.line else finding.path or "repository level"
            status = f" · {finding.verification_status}" if finding.verification_status else ""
            lines.extend([
                f"### {finding.severity.upper()}{status}: {finding.rule}",
                "",
                f"**Location:** `{location}`",
                "",
                finding.message,
            ])
            if finding.evidence:
                lines.extend(["", f"**Evidence:** `{finding.evidence}`"])
            if finding.recommendation:
                lines.extend(["", f"**Recommended action:** {finding.recommendation}"])
            if finding.verification_reason:
                lines.extend(["", f"**Second opinion:** {finding.verification_reason}"])
            lines.append("")
    else:
        lines.append("No actionable findings were returned in this run. This is not proof the agent is safe or correct.")
    if result.dismissed_findings:
        lines.extend(["", f"## Findings dismissed by second opinion ({len(result.dismissed_findings)})", ""])
        for finding in result.dismissed_findings:
            location = f"{finding.path}:{finding.line}" if finding.path and finding.line else finding.path or "repository level"
            lines.extend([f"- **{finding.rule}** at `{location}` — {finding.verification_reason or 'Insufficient evidence.'}"])
    lines.extend(["", f"## Use-case scenarios proposed ({len(result.scenarios)})", ""])
    for scenario in result.scenarios:
        lines.extend([f"### {scenario.get('title', scenario.get('id', 'Scenario'))}", "", f"Category: {scenario.get('category', 'scenario')}", ""])
        lines.extend(f"- {step}" for step in scenario.get("steps", []))
        if scenario.get("expected"):
            lines.extend(["", f"**Expected:** {scenario['expected']}"])
        lines.append("")
    lines.extend(["## Scope and limitations", ""])
    if result.notes:
        lines.extend(f"- {note}" for note in result.notes)
    lines.extend([
        "- Target test directories were excluded and never read or run.",
        "- Proposed scenarios are plans; they were not executed unless an adapter result is explicitly shown.",
        "- Findings and model conclusions require human review.",
        "",
    ])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    _load_agentcheck_env()
    parser = argparse.ArgumentParser(prog="agentcheck", description="Review an agent repository and test plan against its use case.")
    parser.add_argument("--version", action="version", version=f"agentcheck {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="assess an agent repository")
    scan.add_argument("repository", type=Path)
    scan.add_argument("--use-case", help="override the use case inferred from the repository")
    cloud_key_configured = bool(os.getenv("OLLAMA_API_KEY"))
    default_model = "gemma4:31b" if cloud_key_configured else "granite3.2:8b"
    default_model_url = "https://ollama.com/v1" if cloud_key_configured else "http://localhost:11434"
    default_api_key_env = "OLLAMA_API_KEY" if cloud_key_configured else "AGENTCHECK_API_KEY"
    scan.add_argument("--model", default=os.getenv("AGENTCHECK_MODEL", default_model), help="Ollama or OpenAI-compatible model name")
    scan.add_argument("--model-url", default=os.getenv("AGENTCHECK_MODEL_URL", default_model_url), help="model API base URL; uses Ollama Cloud when OLLAMA_API_KEY is set, otherwise local Ollama")
    scan.add_argument("--api-key-env", default=os.getenv("AGENTCHECK_API_KEY_ENV", default_api_key_env), help="environment variable holding an API key for compatible hosted endpoints")
    scan.add_argument("--model-timeout", type=int, default=int(os.getenv("AGENTCHECK_MODEL_TIMEOUT", "600")), help="timeout in seconds for each model review request (default: 600)")
    scan.add_argument("--no-model", action="store_true", help="run repository checks without model-assisted use-case review")
    scan.add_argument("--scenario-command", help="opt in to a scenario adapter outside excluded test directories; receives scenario JSON on stdin and returns {results:[{id,status,actual}]} on stdout")
    scan.add_argument("--scenario-timeout", type=int, default=300, help="scenario harness timeout in seconds")
    scan.add_argument("--json", action="store_true", help="print the complete JSON report")
    scan.add_argument("--output", type=Path, help="also save the JSON report to this path")
    scan.add_argument("--report", type=Path, default=Path(".agentcheck/report.md"), help="Markdown report path (relative paths are inside the scanned repository; default: .agentcheck/report.md)")
    scan.add_argument("--no-report", action="store_true", help="do not write the default Markdown report")
    args = parser.parse_args(argv)

    if not args.repository.is_dir():
        parser.error(f"repository path is not a directory: {args.repository}")
    if args.scenario_timeout <= 0 or args.model_timeout <= 0:
        parser.error("timeouts must be greater than zero")
    if args.scenario_command and args.no_model:
        parser.error("--scenario-command requires model-generated scenarios; remove --no-model")
    if args.scenario_command and scenario_command_is_excluded(args.scenario_command):
        parser.error("scenario command points to a test directory or test runner; put a dedicated AgentCheck adapter outside excluded test directories")

    inventory = inventory_repository(args.repository)
    supplied_use_case = (args.use_case or "").strip()
    result = ScanResult(inventory.root, supplied_use_case or "Use case will be inferred from the repository", inventory.is_agent_candidate, files_scanned=len(inventory.files))
    result.use_case_source = "user" if supplied_use_case else "pending_inference"
    result.inventory = {
        "text_files": len(inventory.files),
        "harness_file_count": len(inventory.harness_files),
        "harness_files": inventory.harness_files,
        "skipped_large_files": inventory.skipped_large,
        "unreadable_files": inventory.unreadable,
        "agent_repo_candidate": inventory.is_agent_candidate,
        "environment_files": inventory.environment_files,
        "excluded_test_directories": sorted(EXCLUDED_TEST_DIRS),
        "analysis_scope": {"comments": "excluded", "markdown_fenced_code_examples": "excluded", "markdown_prose": "included"},
    }
    result.findings.extend(static_findings(inventory))
    if not inventory.is_agent_candidate:
        result.notes.append("Agent-repository detection is heuristic and did not confirm both a supported model-library import and a tool/agent definition.")
    if inventory.environment_files:
        env_paths = ", ".join(str(item["path"]) for item in inventory.environment_files)
        result.notes.append(f"Found real environment file(s): {env_paths}. Their contents were not read or sent to the model; only paths and Git tracking/ignore status were checked.")
    model_scenarios_generated = False
    review_context: list[str] = []

    model_available = False
    if not args.no_model:
        api_key = os.getenv(args.api_key_env)
        findings, scenarios, notes, inferred_use_case, confidence, error, profile = model_review(inventory, supplied_use_case, args.model, args.model_url, api_key, args.model_timeout)
        result.findings.extend(findings)
        result.scenarios.extend(scenarios)
        model_scenarios_generated = bool(scenarios)
        result.notes.extend(notes)
        result.agent_profile = profile
        review_context = [*notes, "Agent functional map: " + json.dumps(profile, ensure_ascii=False)]
        result.model_used = args.model if not error else None
        model_available = not bool(error)
        if not supplied_use_case and inferred_use_case:
            result.use_case = inferred_use_case
            result.use_case_source = "inferred_from_repository"
            result.use_case_confidence = confidence
        elif not supplied_use_case and not inferred_use_case:
            result.use_case = "Could not infer; provide --use-case"
            result.use_case_source = "inference_unavailable"
        if error:
            result.notes.append(error)
            result.notes.append("Model review is the use-case reasoning engine; install/start Ollama or configure an OpenAI-compatible endpoint for scenario-driven assessment.")
        parsed_endpoint = urlparse(args.model_url)
        if parsed_endpoint.hostname not in {"localhost", "127.0.0.1", "::1"}:
            result.notes.append("Repository source and prompt text were sent to a non-local model endpoint. Confirm this complies with your data-handling policy.")
    else:
        result.notes.append("Model review was disabled; use-case-specific scenario generation and semantic code review were not performed.")
        if not supplied_use_case:
            result.use_case = "Not provided; use-case inference needs model review"
            result.use_case_source = "inference_unavailable"

    if not result.scenarios:
        result.scenarios = [{"id": "generic-001", "title": f"Typical use-case request: {result.use_case}", "category": "happy_path", "steps": [], "expected": "Complete the request within the stated policy and use case."}]
        result.notes.append("Fallback scenario is a placeholder, not a generated or executed evaluation.")

    if args.scenario_command and result.scenarios:
        if model_scenarios_generated:
            scenario_result = run_scenarios(inventory.root, args.scenario_command, result.scenarios, args.scenario_timeout)
            result.inventory["scenario_execution"] = scenario_result
        else:
            result.inventory["scenario_execution"] = {"status": "not_run", "reason": "No model-generated scenarios were available."}

    if model_available:
        initial_count = len(result.findings)
        result.findings, result.dismissed_findings, verification_error = verify_findings(
            inventory, result.use_case, args.model, args.model_url, os.getenv(args.api_key_env), result.findings, args.model_timeout, review_context,
        )
        result.inventory["second_opinion"] = {
            "status": "unavailable" if verification_error else "completed",
            "checked_findings": initial_count,
            "additional_findings": max(0, len(result.findings) + len(result.dismissed_findings) - initial_count),
            "dismissed_findings": len(result.dismissed_findings),
        }
        if verification_error:
            result.notes.append(verification_error)
    elif result.findings:
        result.inventory["second_opinion"] = {"status": "not_requested" if args.no_model else "unavailable", "checked_findings": 0, "additional_findings": 0, "dismissed_findings": 0}
        for finding in result.findings:
            finding.verification_status = "not_requested" if args.no_model else "unverified"
        if args.no_model:
            result.notes.append("Second-opinion verification was skipped with --no-model; findings are candidates for human review.")
    else:
        result.inventory["second_opinion"] = {"status": "not_requested" if args.no_model else "unavailable", "checked_findings": 0, "additional_findings": 0, "dismissed_findings": 0}

    result.findings.sort(key=lambda finding: ({"critical": 0, "high": 1, "medium": 2, "low": 3}.get(finding.severity, 4), finding.path, finding.line or 0))
    report_path = None
    if not args.no_report:
        report_path = args.report if args.report.is_absolute() else inventory.root / args.report
        report_path = report_path.resolve()
        result.inventory["report_path"] = str(report_path)
    output = json.dumps(result.to_dict(), indent=2, ensure_ascii=False)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output + "\n", encoding="utf-8")
    if report_path is not None:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(_render_markdown(result), encoding="utf-8")
    print(output if args.json else _render(result))
    if report_path is not None and not args.json:
        print(f"\nMarkdown report saved to: {report_path}")
    scenario_failed = False
    execution = result.inventory.get("scenario_execution")
    if execution:
        scenario_failed = execution.get("status") != "completed" or any(row.get("status") != "passed" for row in execution.get("results", []))
    return int(scenario_failed)


if __name__ == "__main__":
    sys.exit(main())
