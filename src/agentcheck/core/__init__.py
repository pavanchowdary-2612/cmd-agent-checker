"""Core data models sub-package for AgentCheck.

Exposes Finding and ScanResult at the `agentcheck.core` namespace so that
internal sub-packages and external consumers can import from a single location.
"""

# Re-export core models for convenient top-level access
from .models import Finding, ScanResult

__all__ = ["Finding", "ScanResult"]
