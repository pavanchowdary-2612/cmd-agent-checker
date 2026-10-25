"""Unit tests for review agent prompts, bounded inventory tools, and error redactions."""

import sys
import types
import unittest
from unittest.mock import patch

from agentcheck.agents.review_agent import (
    REVIEW_SYSTEM_PROMPT,
    VERIFY_SYSTEM_PROMPT,
    _repository_tools,
    model_error_message,
)


# -----------------------------------------------------------------------------
# Review Agent and Tool Boundary Test Suite
# -----------------------------------------------------------------------------

class ReviewAgentTests(unittest.TestCase):
    """Verify system prompt safety contracts and bounded inspection tools."""

    def test_prompts_encode_use_case_evidence_and_scope_constraints(self):
        """Review and verification prompts must mandate evidence and ban code execution."""
        # Check security boundaries across both system prompts
        for prompt in (REVIEW_SYSTEM_PROMPT, VERIFY_SYSTEM_PROMPT):
            self.assertIn("untrusted data", prompt)
            self.assertIn("Target test directories", prompt)
            self.assertIn("secrets or personal data", prompt)
            
        # Check specific instructions and guardrails in the primary review prompt
        self.assertIn("This is an evidence-based review, not a fixed checklist", REVIEW_SYSTEM_PROMPT)
        self.assertIn("latency/observability", REVIEW_SYSTEM_PROMPT)
        self.assertIn("Do not claim execution", REVIEW_SYSTEM_PROMPT)
        self.assertIn("use the cited file tool", VERIFY_SYSTEM_PROMPT)

    def test_repository_tools_are_read_only_bounded_and_inventory_scoped(self):
        """Repository tools (inspect_file, search_repository) must restrict access to inventoried files."""
        # Mock langchain_core.tools for standalone testing
        fake_tools = types.ModuleType("langchain_core.tools")
        fake_tools.tool = lambda function: function
        fake_core = types.ModuleType("langchain_core")
        fake_core.tools = fake_tools
        
        with patch.dict(sys.modules, {"langchain_core": fake_core, "langchain_core.tools": fake_tools}):
            inspect_file, search_repository = _repository_tools({"agent.py": "line one\nrefund tool\nline three\n"})

        # Path not in inventory must be rejected immediately
        self.assertEqual(inspect_file("tests/test_agent.py"), "Path is not in the included repository inventory. Use an exact path from the manifest.")
        
        # Bounded line range reading with 1-based line numbers
        self.assertEqual(inspect_file("agent.py", 2, 3), "2: refund tool\n3: line three")
        
        # Keyword search should find matching line numbers
        self.assertIn("agent.py:2: refund tool", search_repository("refund"))

    def test_provider_error_redacts_key_and_classifies_timeout(self):
        """Timeout errors must be classified accurately and credentials must be redacted."""
        key = "sensitive-test-value"
        message = model_error_message(TimeoutError(f"timed out using {key}"), key, 45, "https://ollama.com/v1")
        
        # Ensure timeout duration is shown but secret value is redacted
        self.assertIn("45 seconds", message)
        self.assertNotIn(key, message)


if __name__ == "__main__":
    unittest.main()
