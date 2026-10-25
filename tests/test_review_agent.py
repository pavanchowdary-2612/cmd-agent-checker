import sys
import types
import unittest
from unittest.mock import patch

from agentcheck.review_agent import (
    REVIEW_SYSTEM_PROMPT,
    VERIFY_SYSTEM_PROMPT,
    _repository_tools,
    model_error_message,
)


class ReviewAgentTests(unittest.TestCase):
    def test_prompts_encode_use_case_evidence_and_scope_constraints(self):
        for prompt in (REVIEW_SYSTEM_PROMPT, VERIFY_SYSTEM_PROMPT):
            self.assertIn("untrusted data", prompt)
            self.assertIn("Target test directories", prompt)
            self.assertIn("secrets or personal data", prompt)
        self.assertIn("This is an evidence-based review, not a fixed checklist", REVIEW_SYSTEM_PROMPT)
        self.assertIn("latency/observability", REVIEW_SYSTEM_PROMPT)
        self.assertIn("Do not claim execution", REVIEW_SYSTEM_PROMPT)
        self.assertIn("use the cited file tool", VERIFY_SYSTEM_PROMPT)

    def test_repository_tools_are_read_only_bounded_and_inventory_scoped(self):
        fake_tools = types.ModuleType("langchain_core.tools")
        fake_tools.tool = lambda function: function
        fake_core = types.ModuleType("langchain_core")
        fake_core.tools = fake_tools
        with patch.dict(sys.modules, {"langchain_core": fake_core, "langchain_core.tools": fake_tools}):
            inspect_file, search_repository = _repository_tools({"agent.py": "line one\nrefund tool\nline three\n"})

        self.assertEqual(inspect_file("tests/test_agent.py"), "Path is not in the included repository inventory. Use an exact path from the manifest.")
        self.assertEqual(inspect_file("agent.py", 2, 3), "2: refund tool\n3: line three")
        self.assertIn("agent.py:2: refund tool", search_repository("refund"))

    def test_provider_error_redacts_key_and_classifies_timeout(self):
        key = "sensitive-test-value"
        message = model_error_message(TimeoutError(f"timed out using {key}"), key, 45, "https://ollama.com/v1")
        self.assertIn("45 seconds", message)
        self.assertNotIn(key, message)


if __name__ == "__main__":
    unittest.main()
