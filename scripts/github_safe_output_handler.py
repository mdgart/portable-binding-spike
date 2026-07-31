#!/usr/bin/env python3
"""Trusted GitHub custom Safe Output job handler."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from portable_binding.adapters import GitHubSafeOutputsAdapter
from portable_binding.execution import GitHubIssueExecutor
from portable_binding.replay import SQLiteReplayLedger


def required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"missing required environment variable: {name}")
    return value


def main() -> int:
    if len(sys.argv) != 2:
        raise RuntimeError("usage: github_safe_output_handler.py AGENT_OUTPUT")
    agent_output = Path(sys.argv[1]).read_bytes()
    public_key = serialization.load_pem_public_key(
        required_env("PORTABLE_BINDING_PUBLIC_KEY").encode()
    )
    scope = json.loads(required_env("PORTABLE_BINDING_SCOPE"))
    adapter = GitHubSafeOutputsAdapter(
        public_key,
        SQLiteReplayLedger(
            os.environ.get("PORTABLE_BINDING_REPLAY_DB", "portable-binding-replay.db")
        ),
        scope,
    )
    result = adapter.execute(
        agent_output,
        GitHubIssueExecutor(required_env("GITHUB_TOKEN")),
    )
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

