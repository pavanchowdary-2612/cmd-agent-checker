"""Opt-in execution of explicitly configured scenario adapters."""

import shlex
import subprocess
import json
from pathlib import Path


def scenario_command_is_excluded(command: str) -> bool:
    """Reject adapters in test directories and common test-runner commands."""
    tokens = [token.casefold().replace("\\", "/") for token in shlex.split(command)]
    forbidden_runners = {"pytest", "unittest", "jest", "vitest", "playwright", "mocha", "ava"}
    excluded_dirs = {"test", "tests", "__tests__", "unit_tests", "integration_tests", "e2e", "spec", "specs"}
    for token in tokens:
        parts = token.split("/")
        if any(part in excluded_dirs for part in parts) or token in forbidden_runners:
            return True
        if token == "-m" and tokens.index(token) + 1 < len(tokens) and tokens[tokens.index(token) + 1] in {"pytest", "unittest"}:
            return True
        if token == "test" and len(tokens) > 1:
            return True
    return False


def run_scenarios(root: Path, command: str, scenarios: list[dict], timeout: int = 300) -> dict:
    import time

    argv = shlex.split(command)
    started = time.monotonic()
    try:
        completed = subprocess.run(argv, cwd=root, input=json.dumps({"scenarios": scenarios}), capture_output=True, text=True, timeout=timeout, check=False, shell=False)
        if completed.returncode:
            return {"status": "failed", "command": argv, "return_code": completed.returncode, "output": (completed.stderr or completed.stdout)[-10_000:], "duration_seconds": time.monotonic() - started}
        try:
            payload = json.loads(completed.stdout)
            rows = payload["results"]
            if not isinstance(rows, list):
                raise ValueError("results must be an array")
            expected_ids = {str(item.get("id", "")) for item in scenarios}
            received_ids = set()
            allowed_statuses = {"passed", "failed", "blocked"}
            for row in rows:
                if not isinstance(row, dict) or str(row.get("id", "")) not in expected_ids:
                    raise ValueError("each result must reference a submitted scenario id")
                if row["id"] in received_ids:
                    raise ValueError(f"duplicate scenario result: {row['id']}")
                if row.get("status") not in allowed_statuses:
                    raise ValueError(f"scenario {row['id']} status must be passed, failed, or blocked")
                received_ids.add(row["id"])
            missing = expected_ids - received_ids
            if missing:
                raise ValueError(f"adapter omitted scenario results: {', '.join(sorted(missing))}")
            return {"status": "completed", "command": argv, "results": rows, "duration_seconds": time.monotonic() - started}
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            return {"status": "invalid_adapter_output", "command": argv, "error": str(exc), "output": completed.stdout[-10_000:], "duration_seconds": time.monotonic() - started}
    except subprocess.TimeoutExpired as exc:
        return {"status": "timed_out", "command": argv, "output": str(exc)[:10_000], "duration_seconds": time.monotonic() - started}
    except OSError as exc:
        return {"status": "could_not_start", "command": argv, "error": str(exc), "duration_seconds": time.monotonic() - started}
