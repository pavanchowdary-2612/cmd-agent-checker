import tempfile
import unittest
from pathlib import Path

from agentcheck.analyzer import _luhn, static_findings
from agentcheck.workspace import Inventory
from agentcheck.runner import run_scenarios, scenario_command_is_excluded
from agentcheck.workspace import inventory_repository, model_context


class WorkflowTests(unittest.TestCase):
    def test_inventory_excludes_test_directories_but_includes_harness(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as directory:
            root = Path(directory)
            (root / "pyproject.toml").write_text("[project]\nname = 'sample-agent'\n", encoding="utf-8")
            (root / "agent.py").write_text("from langchain.tools import tool\n@tool\ndef delete_user(): pass\n", encoding="utf-8")
            (root / "tests").mkdir()
            (root / "tests" / "test_agent.py").write_text("THIS FILE MUST NOT BE READ person@example.invalid\n", encoding="utf-8")
            (root / "nested").mkdir()
            (root / "nested" / "Test").mkdir()
            (root / "nested" / "Test" / "secret.py").write_text("PRIVATE TEST CONTENT", encoding="utf-8")
            (root / "eval_harness.py").write_text("# eval cases", encoding="utf-8")
            env_secret = "example-secret-value-123456"
            (root / ".env").write_text(f"OPENAI_API_KEY={env_secret}", encoding="utf-8")
            inventory = inventory_repository(root)
            self.assertEqual(len(inventory.files), 3)
            self.assertTrue(inventory.is_agent_candidate)
            self.assertFalse(any("tests" in item.path.casefold().split("/") or "test" in item.path.casefold().split("/") for item in inventory.files))
            self.assertIn("eval_harness.py", inventory.harness_files)
            context, omitted = model_context(inventory)
            self.assertNotIn("THIS FILE MUST NOT BE READ", context)
            self.assertNotIn("PRIVATE TEST CONTENT", context)
            self.assertNotIn(env_secret, context)
            self.assertNotIn(".env", omitted)
            self.assertEqual(inventory.environment_files[0]["path"], ".env")
            self.assertNotIn(env_secret, str(inventory.environment_files))

    def test_sensitive_literals_and_actions_are_reported_without_echoing_card(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as directory:
            root = Path(directory)
            (root / "agent.py").write_text(
                "API_KEY = 'abcdefghijklmnop12345'\n"
                "OWNER = 'person@acme.invalid'\n"
                "CARD = '4111 1111 1111 1111'\n"
                "def refund_order(order_id):\n    return order_id\n",
                encoding="utf-8",
            )
            findings = static_findings(inventory_repository(root))
            rules = {finding.rule for finding in findings}
            context, _ = model_context(inventory_repository(root))
            self.assertIn("possible-hardcoded-secret", rules)
            self.assertIn("possible-personal-data", rules)
            self.assertIn("possible-payment-card", rules)
            self.assertIn("sensitive-action-guard-needs-review", rules)
            action_finding = next(item for item in findings if item.rule == "sensitive-action-guard-needs-review")
            self.assertEqual(action_finding.severity, "medium")
            self.assertNotIn("4111 1111 1111 1111", str([finding.to_dict() for finding in findings]))
            self.assertNotIn("abcdefghijklmnop12345", context)
            self.assertNotIn("person@acme.invalid", context)

    def test_aws_arn_account_id_is_not_reported_as_phone_number(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as directory:
            root = Path(directory)
            (root / "sts.py").write_text(
                '"""Example role: arn:aws:iam::123456789012:role/RoleName."""\n',
                encoding="utf-8",
            )
            findings = static_findings(inventory_repository(root))
            self.assertNotIn("possible-personal-data", {item.rule for item in findings})

    def test_secret_rule_ignores_api_key_variable_and_env_lookup(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as directory:
            root = Path(directory)
            (root / "agent.py").write_text(
                "api_key = os.getenv('GROQ_API_KEY')\n"
                "client_secret = settings.client_secret\n",
                encoding="utf-8",
            )
            findings = static_findings(inventory_repository(root))
            self.assertNotIn("possible-hardcoded-secret", {finding.rule for finding in findings})
            context, _ = model_context(inventory_repository(root))
            self.assertIn("os.getenv('GROQ_API_KEY')", context)

    def test_secret_finding_explains_literal_cause_without_revealing_value(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as directory:
            root = Path(directory)
            (root / "agent.py").write_text("api_key = 'abcdefghijklmnop12345'\n", encoding="utf-8")
            findings = static_findings(inventory_repository(root))
            secret = next(item for item in findings if item.rule == "possible-hardcoded-secret")
            self.assertIn("assigned directly", secret.message)
            self.assertEqual(secret.evidence, "[credential value redacted]")

    def test_secret_literal_check_covers_non_python_config_without_flagging_lookup(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as directory:
            root = Path(directory)
            (root / "settings.yaml").write_text(
                "api_key: 'abcdefghijklmnop12345'\n"
                "client_secret: '${CLIENT_SECRET}'\n",
                encoding="utf-8",
            )
            findings = static_findings(inventory_repository(root))
            secrets = [item for item in findings if item.rule == "possible-hardcoded-secret"]
            self.assertEqual(len(secrets), 1)
            self.assertEqual(secrets[0].line, 1)
            self.assertIn("assigned directly", secrets[0].message)

    def test_comments_and_markdown_code_examples_are_ignored_but_markdown_prose_is_scanned(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as directory:
            root = Path(directory)
            (root / "agent.py").write_text(
                "# api_key = 'abcdefghijklmnop12345'\n"
                "api_key = os.getenv('AGENT_API_KEY')  # gsk_1234567890123456789012345\n",
                encoding="utf-8",
            )
            (root / "README.md").write_text(
                "Contact real.person@company.invalid for help.\n\n"
                "```python\napi_key = 'abcdefghijklmnop12345'\n```\n\n"
                "<!-- support person hidden@example.invalid -->\n",
                encoding="utf-8",
            )
            inventory = inventory_repository(root)
            findings = static_findings(inventory)
            self.assertNotIn("possible-hardcoded-secret", {item.rule for item in findings})
            email_findings = [item for item in findings if item.rule == "possible-personal-data"]
            self.assertEqual(len(email_findings), 1)
            self.assertEqual(email_findings[0].path, "README.md")
            context, _ = model_context(inventory)
            self.assertNotIn("abcdefghijklmnop12345", context)
            self.assertNotIn("hidden@example.invalid", context)

    def test_luhn_and_scenario_adapter_protocol(self):
        self.assertTrue(_luhn("4111111111111111"))
        self.assertFalse(_luhn("4111111111111112"))
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as directory:
            root = Path(directory)
            adapter = root / "adapter.py"
            adapter.write_text("import json,sys\ndata=json.load(sys.stdin)\nprint(json.dumps({'results':[{'id':s['id'],'status':'passed'} for s in data['scenarios']]}))\n", encoding="utf-8")
            result = run_scenarios(root, f'python "{adapter}"', [{"id": "case-1", "title": "example"}])
            self.assertEqual(result["status"], "completed")
            self.assertEqual(result["results"][0]["status"], "passed")

    def test_scenario_adapter_cannot_point_to_test_directory_or_runner(self):
        self.assertTrue(scenario_command_is_excluded("python tests/adapter.py"))
        self.assertTrue(scenario_command_is_excluded("python -m pytest"))
        self.assertTrue(scenario_command_is_excluded("npm test"))
        self.assertFalse(scenario_command_is_excluded("python harness/agentcheck_adapter.py"))

    def test_tracked_env_is_reported_without_exposing_contents(self):
        inventory = Inventory(
            Path("."), [], [], [], [], False,
            [{"path": "backend/.env", "git_tracked": True, "git_ignored": False}],
        )
        findings = static_findings(inventory)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "tracked-environment-file")
        self.assertNotIn("SECRET_VALUE", str(findings[0].to_dict()))


if __name__ == "__main__":
    unittest.main()
