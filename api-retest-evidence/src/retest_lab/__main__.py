"""Portable report generation: PYTHONPATH=src python3 -m retest_lab --verify."""

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import unittest

from .scenarios import build_corpus
from .verifier import RULES, assess


LIMITATIONS = [
    "All identities, expenses, conversations, API responses, and audit data are synthetic; no real network endpoint is contacted.",
    "Source labels represent assumed trusted adapters in this laboratory; they are not cryptographic provenance or independent production telemetry.",
    "The service is a single-process in-memory model. Real concurrency, transaction isolation, revocation propagation, and distributed audit completeness are not established.",
    "Logical ticks specify a deterministic authorization decision point, not a measured latency or real-world timing guarantee.",
    "Assistant text is fixed synthetic prose. No LLM or SLM is executed, trained, evaluated, or credited with these verdicts.",
    "PASS applies only to the scoped attempt and observed final interval; it is not a general security certification or proof about future effects.",
    "The corpus intentionally includes faulty services and corrupted evidence. FAIL counts measure fixture outcomes, not vulnerabilities discovered in any organization.",
    "This is a personal project developed with AI coding assistance in November 2026; it is not attributed to Telekom or any employer or client.",
]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("results"))
    parser.add_argument("--verify", action="store_true", help="Run the actual unittest regression suite and attach its output.")
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[2]
    output = args.output
    output.mkdir(parents=True, exist_ok=True)

    verification = {"executed": False, "tests_run": None, "passed": None}
    if args.verify:
        buffer = io.StringIO()
        suite = unittest.defaultTestLoader.discover(str(root / "tests"), pattern="test_*.py")
        test_result = unittest.TextTestRunner(stream=buffer, verbosity=2).run(suite)
        (output / "test-output.txt").write_text(buffer.getvalue(), encoding="utf-8")
        verification = {
            "executed": True,
            "tests_run": test_result.testsRun,
            "failures": len(test_result.failures),
            "errors": len(test_result.errors),
            "skipped": len(test_result.skipped),
            "passed": test_result.wasSuccessful(),
            "command": "PYTHONPATH=src python3 -m retest_lab --verify --output results",
            "stdout_file": "test-output.txt",
            "counting_note": "unittest test-method count; subtests are not counted as separate tests.",
        }
        audit_env = os.environ.copy()
        audit_env["PYTHONPATH"] = str(root / "src") + os.pathsep + audit_env.get("PYTHONPATH", "")
        audit_run = subprocess.run(
            [sys.executable, str(root / "tests" / "audit_invariants.py")],
            cwd=str(root), env=audit_env, capture_output=True, text=True, check=False,
        )
        audit_output = audit_run.stdout + audit_run.stderr
        (output / "audit-output.txt").write_text(audit_output, encoding="utf-8")
        counts = re.search(r"^(\d+) independent assertions; (\d+) passed; (\d+) failed$", audit_output, re.MULTILINE)
        audit_passed = audit_run.returncode == 0 and counts is not None and int(counts[3]) == 0
        verification["independent_audit"] = {
            "executed": True,
            "assertions_run": int(counts[1]) if counts else None,
            "assertions_passed": int(counts[2]) if counts else None,
            "assertions_failed": int(counts[3]) if counts else None,
            "passed": audit_passed,
            "command": "PYTHONPATH=src python3 tests/audit_invariants.py",
            "stdout_file": "audit-output.txt",
        }
        verification["passed"] = verification["passed"] and audit_passed

    corpus = build_corpus()
    assessments = [assess(case).to_dict() for case in corpus]
    summary = {"total": len(assessments)}
    summary.update({verdict: sum(row["verdict"] == verdict for row in assessments)
                    for verdict in ["PASS", "FAIL", "INCONCLUSIVE"]})
    sources = {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for folder in [root / "src", root / "tests"]
        for path in sorted(folder.rglob("*.py"))
    }
    report = {
        "project": {
            "title": "Delegated Expense Submission: Evidence-Based Authorization Retest",
            "date": "2026-11-18",
            "provenance": "Personal project created with AI coding assistance in November 2026. Synthetic fixtures; no Telekom/employer attribution.",
            "synthetic": True,
            "no_network": True,
            "no_slm": True,
            "no_llm_execution": True,
            "model_execution_scope": "These no-model flags apply only to this deterministic engine run, not to separately produced model-comparison artifacts.",
        },
        "run": {
            "host_clock_utc": datetime.now(timezone.utc).isoformat(),
            "python_version": platform.python_version(),
            "deterministic_fields": ["corpus", "summary", "results", "rules"],
        },
        "summary": summary,
        "verification": verification,
        "rules": RULES,
        "limitations": LIMITATIONS,
        "source_sha256": sources,
        "results": assessments,
    }
    for filename, payload in [("report.json", report), ("corpus.json", [case.to_dict() for case in corpus])]:
        (output / filename).write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    with (output / "verdicts.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=[
            "scenario_id", "title", "request_id", "expected_authorization", "expected_api",
            "observed_api", "before_status", "after_status", "verdict", "reasons",
        ])
        writer.writeheader()
        for row in assessments:
            writer.writerow({
                "scenario_id": row["scenario_id"], "title": row["title"],
                "request_id": row["command"]["request_id"],
                "expected_authorization": row["expected"]["authorization"],
                "expected_api": row["expected"]["api"],
                "observed_api": row["observed"]["api_status"],
                "before_status": (row["observed"]["business_before"] or {}).get("status"),
                "after_status": (row["observed"]["business_after"] or {}).get("status"),
                "verdict": row["verdict"], "reasons": " | ".join(row["reasons"]),
            })
    print(json.dumps({"summary": summary, "verification": verification, "output": str(output)}, indent=2))
    return 0 if not args.verify or verification["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
