"""Shared data models for scans, findings, and assessment reports."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


# -----------------------------------------------------------------------------
# Finding Model: Represents an actionable security or safety observation
# -----------------------------------------------------------------------------

@dataclass
class Finding:
    """A single security, privacy, or safety finding identified during an assessment."""

    # Stable identifier of the rule or check (e.g. 'possible-hardcoded-secret')
    rule: str

    # Severity ranking: 'critical', 'high', 'medium', or 'low'
    severity: str

    # Human-readable message detailing cause and concrete use-case impact
    message: str

    # Relative repository path where the issue occurs
    path: str

    # 1-based line number in the source file, or None if repository-wide
    line: int | None = None

    # Redacted code snippet or evidence extracted from the target file
    evidence: str | None = None

    # Actionable remediation advice tailored to the finding
    recommendation: str | None = None

    # Status from second-opinion verifier: 'confirmed', 'uncertain', or 'false_positive'
    verification_status: str | None = None

    # Explanation from the independent verifier justifying the status
    verification_reason: str | None = None

    # Verifier confidence score between 0.0 and 1.0
    verification_confidence: float | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert finding instance into a serializable dictionary."""
        return asdict(self)


# -----------------------------------------------------------------------------
# ScanResult Model: Aggregates complete assessment metadata and findings
# -----------------------------------------------------------------------------

@dataclass
class ScanResult:
    """Comprehensive outcome of a repository scan including inventory, findings, and scenarios."""

    # Absolute path to the scanned repository root
    root: Path

    # Stated or inferred intended use case of the target agent
    use_case: str

    # Boolean indicating if the repository appears to contain AI agent implementations
    is_agent_repo: bool

    # Total number of readable non-test text files inspected
    files_scanned: int = 0

    # List of active confirmed and uncertain findings
    findings: list[Finding] = field(default_factory=list)

    # Findings dismissed as false positives by the second-opinion verifier
    dismissed_findings: list[Finding] = field(default_factory=list)

    # Generated test scenarios proposed for execution harnesses
    scenarios: list[dict[str, Any]] = field(default_factory=list)

    # Explanatory assessment notes, data policy notices, and scope boundaries
    notes: list[str] = field(default_factory=list)

    # Detailed repository inventory metadata (file counts, harness paths, exclusions)
    inventory: dict[str, Any] = field(default_factory=dict)

    # Name of the LLM model used for review (e.g. 'gemma4:31b'), or None
    model_used: str | None = None

    # Source of the use-case string: 'user', 'inferred_from_repository', or 'inference_unavailable'
    use_case_source: str = "user"

    # Confidence score of use-case inference (0.0 to 1.0)
    use_case_confidence: float | None = None

    # Functional profile mapping purpose, workflows, tools, and safeguards
    agent_profile: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert complete scan result into a JSON-serializable dictionary."""
        return {
            "root": str(self.root),
            "use_case": self.use_case,
            "is_agent_repo": self.is_agent_repo,
            "files_scanned": self.files_scanned,
            "findings": [item.to_dict() for item in self.findings],
            "dismissed_findings": [item.to_dict() for item in self.dismissed_findings],
            "scenarios": self.scenarios,
            "notes": self.notes,
            "inventory": self.inventory,
            "model_used": self.model_used,
            "use_case_source": self.use_case_source,
            "use_case_confidence": self.use_case_confidence,
            "agent_profile": self.agent_profile,
        }
