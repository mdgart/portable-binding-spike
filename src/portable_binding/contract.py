"""Platform-neutral action contract and deterministic encoding."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping

MAX_SAFE_INTEGER = 9_007_199_254_740_991


class ContractError(ValueError):
    """Raised when an action cannot be represented portably."""


def _validate_json_subset(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > MAX_SAFE_INTEGER:
            raise ContractError(f"{path}: integer exceeds portable safe range")
        return
    if isinstance(value, float):
        raise ContractError(f"{path}: floats are excluded from binding-v1")
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_subset(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise ContractError(f"{path}: object keys must be ASCII strings")
            _validate_json_subset(item, f"{path}.{key}")
        return
    raise ContractError(f"{path}: unsupported value type {type(value).__name__}")


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    """Encode the binding-v1 canonical JSON subset.

    The subset excludes floats and non-ASCII object keys to avoid runtime
    differences that are irrelevant to this spike. String values remain
    full Unicode.
    """

    material = dict(value)
    _validate_json_subset(material)
    return json.dumps(
        material,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


@dataclass(frozen=True)
class PortableAction:
    namespace: str
    operation: str
    parameters: Mapping[str, Any]

    def as_dict(self) -> dict[str, Any]:
        action = {
            "kind": "tool-call",
            "namespace": self.namespace,
            "operation": self.operation,
            "parameters": dict(self.parameters),
        }
        canonical_bytes(action)
        return action

    def to_bytes(self) -> bytes:
        return canonical_bytes(self.as_dict())


def digest_bytes(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def digest_action(action: PortableAction) -> str:
    return digest_bytes(action.to_bytes())


def action_from_bytes(payload: bytes) -> PortableAction:
    try:
        decoded = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ContractError("verified action bytes are not valid JSON") from error
    if not isinstance(decoded, dict):
        raise ContractError("verified action must be an object")
    if decoded.get("kind") != "tool-call":
        raise ContractError("unsupported action kind")
    expected = {"kind", "namespace", "operation", "parameters"}
    if set(decoded) != expected:
        raise ContractError("verified action has unexpected fields")
    if not isinstance(decoded["namespace"], str) or not decoded["namespace"]:
        raise ContractError("namespace must be a non-empty string")
    if not isinstance(decoded["operation"], str) or not decoded["operation"]:
        raise ContractError("operation must be a non-empty string")
    if not isinstance(decoded["parameters"], dict):
        raise ContractError("parameters must be an object")
    action = PortableAction(
        namespace=decoded["namespace"],
        operation=decoded["operation"],
        parameters=decoded["parameters"],
    )
    if action.to_bytes() != payload:
        raise ContractError("verified action bytes are not canonical")
    return action

