"""Shared data models for scans and findings."""

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Finding:
    rule: str
    severity: str
    message: str
    path: str
    line: int | None = None
    evidence: str | None = None
    recommendation: str | None = None
    verification_status: str | None = None
    verification_reason: str | None = None
    verification_confidence: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    root: Path
    use_case: str
    is_agent_repo: bool
    files_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    dismissed_findings: list[Finding] = field(default_factory=list)
    scenarios: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    inventory: dict[str, Any] = field(default_factory=dict)
    model_used: str | None = None
    use_case_source: str = "user"
    use_case_confidence: float | None = None
    agent_profile: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
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
