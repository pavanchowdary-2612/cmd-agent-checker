"""Opt-in execution of explicitly configured scenario adapters."""

import json
from pathlib import Path
import shlex
import subprocess
import time


# -----------------------------------------------------------------------------
# Command Safety Validation: Block Test Runners & Excluded Directories
# -----------------------------------------------------------------------------

def scenario_command_is_excluded(command: str) -> bool:
    """Reject adapters in test directories and common test-runner commands.
    
    Prevents AgentCheck from running existing unit tests, pytest suites,
    or test-directory files instead of a designated scenario adapter.
    """
    # Tokenize the input command string safely across operating systems
    tokens = [token.casefold().replace("\\", "/") for token in shlex.split(command)]
    
    # List of prohibited test runners to ensure isolation from project test suites
    forbidden_runners = {"pytest", "unittest", "jest", "vitest", "playwright", "mocha", "ava"}
    
    # Directory names that are strictly excluded from execution
    excluded_dirs = {"test", "tests", "__tests__", "unit_tests", "integration_tests", "e2e", "spec", "specs"}
    
    # Check each token against excluded paths and banned runner binaries
    for token in tokens:
        parts = token.split("/")
        if any(part in excluded_dirs for part in parts) or token in forbidden_runners:
            return True
        
        # Guard against 'python -m pytest' or 'python -m unittest' invocations
        if token == "-m" and tokens.index(token) + 1 < len(tokens) and tokens[tokens.index(token) + 1] in {"pytest", "unittest"}:
            return True
        
        # Guard against commands like 'npm test' or 'cargo test'
        if token == "test" and len(tokens) > 1:
            return True
            
    return False


# -----------------------------------------------------------------------------
# Scenario Execution Engine: Spawns Adapter Subprocess and Validates JSON
# -----------------------------------------------------------------------------

def run_scenarios(root: Path, command: str, scenarios: list[dict], timeout: int = 300) -> dict:
    """Execute model-generated scenarios via an external adapter command.
    
    Pipes scenarios JSON to stdin and expects a structured JSON report on stdout.
    """
    # Parse the command arguments and initialize timing
    argv = shlex.split(command)
    started = time.monotonic()
    
    try:
        # Spawn the adapter process without shell expansion for security
        completed = subprocess.run(
            argv,
            cwd=root,
            input=json.dumps({"scenarios": scenarios}),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
        )
        
        # Capture non-zero exit codes from the adapter process
        if completed.returncode:
            return {
                "status": "failed",
                "command": argv,
                "return_code": completed.returncode,
                "output": (completed.stderr or completed.stdout)[-10_000:],
                "duration_seconds": time.monotonic() - started,
            }
            
        # Parse and validate the JSON output produced by the adapter
        try:
            payload = json.loads(completed.stdout)
            rows = payload["results"]
            if not isinstance(rows, list):
                raise ValueError("results must be an array")
                
            # Track scenario IDs to ensure full, non-duplicate coverage
            expected_ids = {str(item.get("id", "")) for item in scenarios}
            received_ids = set()
            allowed_statuses = {"passed", "failed", "blocked"}
            
            # Validate each scenario result row against the protocol
            for row in rows:
                if not isinstance(row, dict) or str(row.get("id", "")) not in expected_ids:
                    raise ValueError("each result must reference a submitted scenario id")
                if row["id"] in received_ids:
                    raise ValueError(f"duplicate scenario result: {row['id']}")
                if row.get("status") not in allowed_statuses:
                    raise ValueError(f"scenario {row['id']} status must be passed, failed, or blocked")
                received_ids.add(row["id"])
                
            # Verify no scenario results were omitted by the adapter
            missing = expected_ids - received_ids
            if missing:
                raise ValueError(f"adapter omitted scenario results: {', '.join(sorted(missing))}")
                
            return {
                "status": "completed",
                "command": argv,
                "results": rows,
                "duration_seconds": time.monotonic() - started,
            }
            
        # Catch and report JSON schema or parsing discrepancies
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            return {
                "status": "invalid_adapter_output",
                "command": argv,
                "error": str(exc),
                "output": completed.stdout[-10_000:],
                "duration_seconds": time.monotonic() - started,
            }
            
    # Handle timeout expiration when the adapter exceeds allotted seconds
    except subprocess.TimeoutExpired as exc:
        return {
            "status": "timed_out",
            "command": argv,
            "output": str(exc)[:10_000],
            "duration_seconds": time.monotonic() - started,
        }
        
    # Handle system-level OS errors (such as missing executables or file permissions)
    except OSError as exc:
        return {
            "status": "could_not_start",
            "command": argv,
            "error": str(exc),
            "duration_seconds": time.monotonic() - started,
        }
