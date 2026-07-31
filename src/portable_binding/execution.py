"""Trusted execution boundary."""

from __future__ import annotations

import json
import re
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Protocol

from .certificate import VerifiedAction
from .contract import PortableAction, action_from_bytes, digest_bytes


class ActionExecutor(Protocol):
    def execute_verified(self, verified: VerifiedAction) -> str: ...


@dataclass
class RecordingExecutor:
    """Deterministic stand-in for protected external state."""

    records: list[dict[str, object]] = field(default_factory=list)

    def execute_verified(self, verified: VerifiedAction) -> str:
        action = action_from_bytes(verified.canonical_action)
        record = {
            "digest": digest_bytes(verified.canonical_action),
            "namespace": action.namespace,
            "operation": action.operation,
            "parameters": dict(action.parameters),
            "nonce": verified.certificate.nonce,
        }
        self.records.append(record)
        return str(record["digest"])


Transport = Callable[[str, bytes, str], tuple[int, bytes]]


def urllib_transport(url: str, body: bytes, token: str) -> tuple[int, bytes]:
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


@dataclass
class GitHubIssueExecutor:
    """Protected GitHub write accepting only verified canonical bytes."""

    token: str
    transport: Transport = urllib_transport

    def execute_verified(self, verified: VerifiedAction) -> str:
        action = action_from_bytes(verified.canonical_action)
        if action.namespace != "github" or action.operation != "create_issue":
            raise ValueError("executor only supports github/create_issue")
        parameters = dict(action.parameters)
        if set(parameters) != {"repository", "title", "body"}:
            raise ValueError("create_issue parameters must be repository, title, and body")
        repository = parameters["repository"]
        title = parameters["title"]
        body = parameters["body"]
        if (
            not isinstance(repository, str)
            or re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is None
        ):
            raise ValueError("invalid GitHub repository")
        if not isinstance(title, str) or not isinstance(body, str):
            raise ValueError("GitHub issue title and body must be strings")
        request_body = json.dumps(
            {"title": title, "body": body},
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        status, response = self.transport(
            f"https://api.github.com/repos/{repository}/issues",
            request_body,
            self.token,
        )
        if status < 200 or status >= 300:
            raise RuntimeError(f"GitHub issue creation failed with status {status}")
        try:
            result = json.loads(response)
        except json.JSONDecodeError as error:
            raise RuntimeError("GitHub returned invalid JSON") from error
        return str(result.get("html_url") or result.get("url") or "")


def assert_executed_identity(
    action: PortableAction,
    executor: RecordingExecutor,
) -> None:
    if not executor.records:
        raise AssertionError("no action was executed")
    if executor.records[-1]["digest"] != digest_bytes(action.to_bytes()):
        raise AssertionError("executed identity differs from proposed action")
