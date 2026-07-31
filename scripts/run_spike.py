#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def main() -> int:
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    report = {
        "schema": "portable-binding-spike-result-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "local_contract": "PASS" if result.wasSuccessful() else "FAIL",
        "live_faramesh": "NOT_RUN",
        "live_github_safe_outputs": "NOT_RUN",
        "overall": "IN_PROGRESS" if result.wasSuccessful() else "FAIL",
        "blocker": (
            "Local contract passed; live credentialed Faramesh and GitHub "
            "Agentic Workflows executions remain."
            if result.wasSuccessful()
            else "Local contract or attack tests failed."
        ),
    }
    output_dir = ROOT / "reports"
    output_dir.mkdir(exist_ok=True)
    output_path = output_dir / "latest.json"
    output_path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"\nReport: {output_path}")
    print(f"Overall: {report['overall']}")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
