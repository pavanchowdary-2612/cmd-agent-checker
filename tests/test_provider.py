import io
import json
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

from agentcheck.analyzer import model_review, verify_findings
from agentcheck.models import Finding
from agentcheck.workspace import Inventory, SourceFile


class ProviderDiagnosticsTests(unittest.TestCase):
    def test_second_opinion_dismisses_only_high_confidence_false_positive(self):
        inventory = Inventory(Path("."), [], [], [], [], False)
        response_body = json.dumps({"verdicts": [
            {"id": "finding-0", "status": "false_positive", "reason": "The line reads the key from an environment variable; no literal credential is present.", "confidence": 0.96}
        ]})
        candidates = [Finding("possible-hardcoded-secret", "critical", "Possible key", "agent.py", 4)]
        with patch("agentcheck.analyzer.invoke_verification_agent", return_value=response_body):
            active, dismissed, error = verify_findings(inventory, "support agent", "model", "http://localhost:11434", None, candidates)
        self.assertIsNone(error)
        self.assertEqual(active, [])
        self.assertEqual(dismissed[0].verification_status, "false_positive")
        self.assertIn("environment variable", dismissed[0].verification_reason)

    def test_second_opinion_keeps_low_confidence_rejection_as_uncertain(self):
        inventory = Inventory(Path("."), [], [], [], [], False)
        response_body = json.dumps({"verdicts": [
            {"id": "finding-0", "status": "false_positive", "reason": "Might be a false alarm.", "confidence": 0.51}
        ]})
        candidates = [Finding("possible-hardcoded-secret", "critical", "Possible key", "agent.py", 4)]
        with patch("agentcheck.analyzer.invoke_verification_agent", return_value=response_body):
            active, dismissed, _ = verify_findings(inventory, "support agent", "model", "http://localhost:11434", None, candidates)
        self.assertEqual(len(active), 1)
        self.assertEqual(dismissed, [])
        self.assertEqual(active[0].verification_status, "uncertain")

    def test_second_opinion_only_adds_findings_with_valid_inventory_locations(self):
        inventory = Inventory(Path("."), [SourceFile("agent.py", "def run():\n    pass\n", 20)], [], [], [], False)
        response_body = json.dumps({"verdicts": [], "additional_findings": [
            {"rule": "missing-boundary", "severity": "high", "message": "Concrete issue", "path": "agent.py", "line": 2, "evidence": "pass", "recommendation": "Add a guard"},
            {"rule": "hallucinated", "severity": "critical", "message": "Not in inventory", "path": "tests/test_fake.py", "line": 1},
        ]})
        with patch("agentcheck.analyzer.invoke_verification_agent", return_value=response_body):
            active, dismissed, error = verify_findings(inventory, "support agent", "model", "http://localhost:11434", None, [])
        self.assertIsNone(error)
        self.assertEqual(dismissed, [])
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0].path, "agent.py")
        self.assertEqual(active[0].verification_status, "uncertain")

    def test_groq_model_permission_error_is_actionable_and_redacted(self):
        key = "test-secret-key-value"
        body = json.dumps({"error": {
            "message": "Model blocked for key test-secret-key-value",
            "code": "model_permission_blocked_org",
        }}).encode()
        error = HTTPError("https://api.groq.com/openai/v1/chat/completions", 403, "Forbidden", {}, io.BytesIO(body))
        inventory = Inventory(Path("."), [], [], [], [], False)
        with patch("agentcheck.analyzer.invoke_review_agent", side_effect=error):
            findings, scenarios, notes, inferred, confidence, issue, profile = model_review(
                inventory, "connectivity check", "openai/gpt-oss-120b",
                "https://api.groq.com/openai/v1", key,
            )
        self.assertEqual(findings, [])
        self.assertEqual(scenarios, [])
        self.assertIn("model_permission_blocked_org", issue)
        self.assertIn("organization model permissions", issue)
        self.assertNotIn(key, issue)

    def test_use_case_can_be_inferred_from_model_review(self):
        inventory = Inventory(Path("."), [], [], [], [], False)
        content = json.dumps({
            "agent_profile": {"purpose": "Customer support with order lookup and confirmed refunds", "workflows": ["Look up an order"]},
            "inferred_use_case": "A customer support agent that looks up orders and refunds them after confirmation.",
            "use_case_confidence": 0.91,
            "use_case_evidence": [],
            "findings": [],
            "scenarios": [{"title": "Confirmation required", "category": "safety", "steps": ["request refund"], "expected": "ask before refund"}],
        })
        with patch("agentcheck.analyzer.invoke_review_agent", return_value=content):
            findings, scenarios, notes, inferred, confidence, error, profile = model_review(
                inventory, "", "gemma4:31b", "http://localhost:11434",
            )
        self.assertEqual(findings, [])
        self.assertEqual(error, None)
        self.assertEqual(confidence, 0.91)
        self.assertIn("customer support agent", inferred)
        self.assertTrue(scenarios[0]["id"].startswith("scenario-"))
        self.assertIn("Look up an order", profile["workflows"])


if __name__ == "__main__":
    unittest.main()
