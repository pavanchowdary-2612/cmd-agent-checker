"""Scenario execution sub-package for AgentCheck.

Exposes safe subprocess-based scenario runner and command validation helper
at the `agentcheck.execution` namespace.
"""

# Re-export scenario runner functions for convenient access
from .runner import run_scenarios, scenario_command_is_excluded

__all__ = ["run_scenarios", "scenario_command_is_excluded"]
