"""CLI sub-package for AgentCheck.

Exposes the main CLI entrypoint and report rendering functions at the
`agentcheck.cli_pkg` namespace.
"""

# Re-export the main CLI entry point for use as a script target
from .cli import main

__all__ = ["main"]
