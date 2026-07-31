from __future__ import annotations

import unittest
from pathlib import Path


class WorkflowContractTestCase(unittest.TestCase):
    def test_invocation_is_known_before_dispatch(self) -> None:
        repository = Path(__file__).resolve().parents[1]
        workflow = (
            repository / ".github/workflows/portable-binding-demo.md"
        ).read_text()
        safe_output = (
            repository / ".github/workflows/shared/portable-binding.md"
        ).read_text()

        self.assertIn("invocation:", workflow)
        self.assertIn("${{ inputs.invocation }}", workflow)
        self.assertIn("invocation:", safe_output)
        self.assertIn('"invocation":"${{ inputs.invocation }}"', safe_output)
        self.assertNotIn("github.run_id", safe_output)


if __name__ == "__main__":
    unittest.main()
