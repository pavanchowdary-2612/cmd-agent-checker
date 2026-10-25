"""Unit tests for provider diagnostics, error redaction, and second-opinion verdicts."""

import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from agentcheck.analysis.analyzer import model_review, verify_findings
from agentcheck.core.models import Finding
from agentcheck.workspace_pkg.workspace import Inventory, SourceFile


# -----------------------------------------------------------------------------
# Provider Diagnostics & Verification Test Suite
# -----------------------------------------------------------------------------

class ProviderDiagnosticsTests(unittest.TestCase):
    """Verify provider error handling, key redaction, and verdict filtering."""

    def test_second_opinion_dismisses_only_high_confidence_false_positive(self):
        """High-confidence (>= 0.8) false positive verdicts should be moved to dismissed."""
        inventory = Inventory(Path("."), [], [], [], [], False)
        response_body = json.dumps({"verdicts": [
            {"id": "finding-0", "status": "false_positive", "reason": "The line reads the key from an environment variable; no literal credential is present.", "confidence": 0.96}
        ]})
        candidates = [Finding("possible-hardcoded-secret", "critical", "Possible key", "agent.py", 4)]
        
        # Mock verification agent response
        with patch("agentcheck.analysis.analyzer.invoke_verification_agent", return_value=response_body):
            active, dismissed, error = verify_findings(inventory, "support agent", "model", "http://localhost:11434", None, candidates)
            
        # Verify dismissal of candidate finding
        self.assertIsNone(error)
        self.assertEqual(active, [])
        self.assertEqual(dismissed[0].verification_status, "false_positive")
        self.assertIn("environment variable", dismissed[0].verification_reason)

    def test_second_opinion_keeps_low_confidence_rejection_as_uncertain(self):
        """Low-confidence (< 0.8) false positive rejections must be retained as uncertain."""
        inventory = Inventory(Path("."), [], [], [], [], False)
        response_body = json.dumps({"verdicts": [
            {"id": "finding-0", "status": "false_positive", "reason": "Might be a false alarm.", "confidence": 0.51}
        ]})
        candidates = [Finding("possible-hardcoded-secret", "critical", "Possible key", "agent.py", 4)]
        
        # Mock verification agent returning low confidence score
        with patch("agentcheck.analysis.analyzer.invoke_verification_agent", return_value=response_body):
            active, dismissed, _ = verify_findings(inventory, "support agent", "model", "http://localhost:11434", None, candidates)
            
        # Verify finding was kept in active pool marked as uncertain
        self.assertEqual(len(active), 1)
        self.assertEqual(dismissed, [])
        self.assertEqual(active[0].verification_status, "uncertain")

    def test_second_opinion_only_adds_findings_with_valid_inventory_locations(self):
        """Additional findings must reference actual inventoried files and valid line numbers."""
        inventory = Inventory(Path("."), [SourceFile("agent.py", "def run():\n    pass\n", 20)], [], [], [], False)
        response_body = json.dumps({"verdicts": [], "additional_findings": [
            {"rule": "missing-boundary", "severity": "high", "message": "Concrete issue", "path": "agent.py", "line": 2, "evidence": "pass", "recommendation": "Add a guard"},
            {"rule": "hallucinated", "severity": "critical", "message": "Not in inventory", "path": "tests/test_fake.py", "line": 1},
        ]})
        
        # Mock verifier proposing real vs hallucinated findings
        with patch("agentcheck.analysis.analyzer.invoke_verification_agent", return_value=response_body):
            active, dismissed, error = verify_findings(inventory, "support agent", "model", "http://localhost:11434", None, [])
            
        # Only the finding matching an inventoried file should be accepted
        self.assertIsNone(error)
        self.assertEqual(dismissed, [])
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0].path, "agent.py")
        self.assertEqual(active[0].verification_status, "uncertain")

    def test_groq_model_permission_error_is_actionable_and_redacted(self):
        """Groq permission errors (HTTP 403) must be sanitized to protect secret API keys."""
        key = "test-secret-key-value"
        body = json.dumps({"error": {
            "message": "Model blocked for key test-secret-key-value",
            "code": "model_permission_blocked_org",
        }}).encode()
        error = HTTPError("https://api.groq.com/openai/v1/chat/completions", 403, "Forbidden", {}, io.BytesIO(body))
        inventory = Inventory(Path("."), [], [], [], [], False)
        
        # Trigger review agent exception with mock HTTPError
        with patch("agentcheck.analysis.analyzer.invoke_review_agent", side_effect=error):
            findings, scenarios, notes, inferred, confidence, issue, profile = model_review(
                inventory, "connectivity check", "openai/gpt-oss-120b",
                "https://api.groq.com/openai/v1", key,
            )
            
        # Verify secret key was redacted from the resulting error message
        self.assertEqual(findings, [])
        self.assertEqual(scenarios, [])
        self.assertIn("model_permission_blocked_org", issue)
        self.assertIn("organization model permissions", issue)
        self.assertNotIn(key, issue)

    def test_use_case_can_be_inferred_from_model_review(self):
        """Model review should infer the agent's purpose, confidence, and functional profile."""
        inventory = Inventory(Path("."), [], [], [], [], False)
        content = json.dumps({
            "agent_profile": {"purpose": "Customer support with order lookup and confirmed refunds", "workflows": ["Look up an order"]},
            "inferred_use_case": "A customer support agent that looks up orders and refunds them after confirmation.",
            "use_case_confidence": 0.91,
            "use_case_evidence": [],
            "findings": [],
            "scenarios": [{"title": "Confirmation required", "category": "safety", "steps": ["request refund"], "expected": "ask before refund"}],
        })
        
        # Mock review agent returning inferred use case and functional profile
        with patch("agentcheck.analysis.analyzer.invoke_review_agent", return_value=content):
            findings, scenarios, notes, inferred, confidence, error, profile = model_review(
                inventory, "", "gemma4:31b", "http://localhost:11434",
            )
            
        # Verify inferred metadata was correctly parsed
        self.assertEqual(findings, [])
        self.assertEqual(error, None)
        self.assertEqual(confidence, 0.91)
        self.assertIn("customer support agent", inferred)
        self.assertTrue(scenarios[0]["id"].startswith("scenario-"))
        self.assertIn("Look up an order", profile["workflows"])


if __name__ == "__main__":
    unittest.main()
