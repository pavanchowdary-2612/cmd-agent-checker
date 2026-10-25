"""Workspace inventory sub-package for AgentCheck.

Provides repository traversal, file classification, redaction helpers,
and model context preparation at the `agentcheck.workspace_pkg` namespace.
"""

# Re-export all public workspace symbols for convenient access
from .workspace import (
    EXCLUDED_TEST_DIRS,
    Inventory,
    SourceFile,
    analysis_text,
    inventory_repository,
    model_context,
    model_context_files,
)

__all__ = [
    "EXCLUDED_TEST_DIRS",
    "Inventory",
    "SourceFile",
    "analysis_text",
    "inventory_repository",
    "model_context",
    "model_context_files",
]
