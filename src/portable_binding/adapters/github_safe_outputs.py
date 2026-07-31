"""Adapter for GitHub Agentic Workflows buffered Safe Outputs."""

from __future__ import annotations

import json
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..certificate import BindingCertificate, verify_certificate
from ..contract import ContractError, PortableAction
from ..execution import ActionExecutor
from ..replay import ReplayLedger


class GitHubSafeOutputsAdapter:
    """Consume the buffered agent_output.json in the permission-controlled job."""

    OUTPUT_TYPE = "portable_binding"

    def __init__(
        self,
        public_key: Ed25519PublicKey,
        ledger: ReplayLedger,
        expected_scope: Mapping[str, Any],
    ) -> None:
        self.public_key = public_key
        self.ledger = ledger
        self.expected_scope = dict(expected_scope)

    @classmethod
    def reconstruct(
        cls,
        agent_output: bytes,
    ) -> tuple[PortableAction, BindingCertificate]:
        try:
            document = json.loads(agent_output)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ContractError("Safe Outputs buffer is not valid JSON") from error
        if not isinstance(document, dict):
            raise ContractError("Safe Outputs buffer must be an object")
        if "items" not in document or not set(document).issubset(
            {"items", "errors"}
        ):
            raise ContractError("Safe Outputs buffer has unexpected fields")
        errors = document.get("errors", [])
        if not isinstance(errors, list):
            raise ContractError("Safe Outputs errors must be an array")
        if errors:
            raise ContractError("Safe Outputs buffer contains errors")
        items = document["items"]
        if not isinstance(items, list):
            raise ContractError("Safe Outputs items must be an array")
        matches = [
            item
            for item in items
            if isinstance(item, dict) and item.get("type") == cls.OUTPUT_TYPE
        ]
        if len(matches) != 1:
            raise ContractError("expected exactly one portable_binding output")
        item = matches[0]
        if set(item) != {
            "type",
            "invocation",
            "action_json",
            "certificate_json",
        }:
            raise ContractError("portable_binding output has unexpected fields")
        if not isinstance(item["invocation"], str):
            raise ContractError("Safe Outputs invocation must be a string")
        if not isinstance(item["action_json"], str):
            raise ContractError("Safe Outputs action_json must be a string")
        if not isinstance(item["certificate_json"], str):
            raise ContractError("Safe Outputs certificate_json must be a string")
        try:
            action_data = json.loads(item["action_json"])
            certificate_data = json.loads(item["certificate_json"])
        except json.JSONDecodeError as error:
            raise ContractError("Safe Outputs JSON input is invalid") from error
        if not isinstance(action_data, dict):
            raise ContractError("Safe Outputs action must be an object")
        if set(action_data) != {"namespace", "operation", "parameters"}:
            raise ContractError("Safe Outputs action has unexpected fields")
        if not isinstance(action_data["parameters"], dict):
            raise ContractError("Safe Outputs parameters must be an object")
        action = PortableAction(
            namespace=action_data["namespace"],
            operation=action_data["operation"],
            parameters=action_data["parameters"],
        )
        if not isinstance(certificate_data, dict):
            raise ContractError("Safe Outputs certificate must be an object")
        certificate = BindingCertificate.from_dict(certificate_data)
        if item["invocation"] != certificate.scope.get("invocation"):
            raise ContractError(
                "Safe Outputs invocation does not match signed certificate scope"
            )
        return action, certificate

    def execute(self, agent_output: bytes, executor: ActionExecutor) -> str:
        action, certificate = self.reconstruct(agent_output)
        verified = verify_certificate(
            action,
            certificate,
            self.expected_scope,
            self.public_key,
            self.ledger,
        )
        return executor.execute_verified(verified)
