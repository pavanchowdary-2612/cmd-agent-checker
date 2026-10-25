"""Static and model-assisted analysis sub-package for AgentCheck.

Provides deterministic static findings, model-driven review, and
second-opinion verification at the `agentcheck.analysis` namespace.
"""

# Re-export public analysis functions for convenient access
from .analyzer import model_review, static_findings, verify_findings

__all__ = ["model_review", "static_findings", "verify_findings"]
