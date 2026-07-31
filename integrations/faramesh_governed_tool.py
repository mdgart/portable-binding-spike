"""Example Faramesh SDK-shim integration.

Faramesh evaluates the full action_json and certificate_json arguments before
calling bound_github_issue. The function then performs binding verification at
the final trusted boundary and executes only the verified bytes.
"""

from __future__ import annotations

import json
import os

from cryptography.hazmat.primitives import serialization
from faramesh import GovernedToolSet

from portable_binding.adapters import FarameshAdapter
from portable_binding.execution import GitHubIssueExecutor
from portable_binding.replay import SQLiteReplayLedger


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"missing required environment variable: {name}")
    return value


def bound_github_issue(action_json: str, certificate_json: str) -> str:
    """Execute one certificate-bound GitHub issue creation."""

    public_key = serialization.load_pem_public_key(
        _required_env("PORTABLE_BINDING_PUBLIC_KEY").encode()
    )
    adapter = FarameshAdapter(
        public_key,
        SQLiteReplayLedger(
            os.environ.get("PORTABLE_BINDING_REPLAY_DB", "portable-binding-replay.db")
        ),
        json.loads(_required_env("PORTABLE_BINDING_SCOPE")),
    )
    return adapter.execute(
        {
            "action_json": action_json,
            "certificate_json": certificate_json,
        },
        GitHubIssueExecutor(_required_env("GITHUB_TOKEN")),
    )


tools = GovernedToolSet(
    [bound_github_issue],
    agent_id=os.environ.get("FARAMESH_AGENT_ID", "portable-binding-agent"),
    fail_open=False,
)

