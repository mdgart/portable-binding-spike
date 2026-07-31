#!/usr/bin/env python3
"""Trusted post-permit Faramesh tool handler."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from portable_binding.adapters import FarameshAdapter
from portable_binding.certificate import BindingCertificate
from portable_binding.execution import GitHubIssueExecutor
from portable_binding.replay import SQLiteReplayLedger


def required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"missing required environment variable: {name}")
    return value


def main() -> int:
    if len(sys.argv) != 2:
        raise RuntimeError("usage: faramesh_tool_handler.py CALL_ARGUMENTS")
    call_arguments = json.loads(Path(sys.argv[1]).read_text())
    public_key = serialization.load_pem_public_key(
        required_env("PORTABLE_BINDING_PUBLIC_KEY").encode()
    )
    scope = json.loads(required_env("PORTABLE_BINDING_SCOPE"))
    adapter = FarameshAdapter(
        public_key,
        SQLiteReplayLedger(
            os.environ.get("PORTABLE_BINDING_REPLAY_DB", "portable-binding-replay.db")
        ),
        scope,
    )
    result = adapter.execute(
        call_arguments,
        GitHubIssueExecutor(required_env("GITHUB_TOKEN")),
    )
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
