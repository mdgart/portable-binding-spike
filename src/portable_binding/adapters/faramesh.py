"""Adapter called by a Faramesh-governed tool after a permit decision."""

from __future__ import annotations

import json
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..certificate import BindingCertificate, verify_certificate
from ..contract import ContractError, PortableAction
from ..execution import ActionExecutor
from ..replay import ReplayLedger


class FarameshAdapter:
    """Verify inside the governed callable, immediately before execution.

    Faramesh's SDK shim evaluates the callable and its full structured
    arguments before invoking it. This adapter consumes those unchanged
    arguments once the governed callable is entered.
    """

    def __init__(
        self,
        public_key: Ed25519PublicKey,
        ledger: ReplayLedger,
        expected_scope: Mapping[str, Any],
    ) -> None:
        self.public_key = public_key
        self.ledger = ledger
        self.expected_scope = dict(expected_scope)

    @staticmethod
    def reconstruct(
        call_arguments: Mapping[str, Any],
    ) -> tuple[PortableAction, BindingCertificate]:
        if set(call_arguments) != {"action_json", "certificate_json"}:
            raise ContractError("governed call has missing or unexpected arguments")
        if not isinstance(call_arguments["action_json"], str):
            raise ContractError("action_json must be a string")
        if not isinstance(call_arguments["certificate_json"], str):
            raise ContractError("certificate_json must be a string")
        try:
            action_data = json.loads(call_arguments["action_json"])
            certificate_data = json.loads(call_arguments["certificate_json"])
        except json.JSONDecodeError as error:
            raise ContractError("governed call JSON input is invalid") from error
        if not isinstance(action_data, dict):
            raise ContractError("governed action must be an object")
        if set(action_data) != {"namespace", "operation", "parameters"}:
            raise ContractError("governed action has unexpected fields")
        if not isinstance(action_data["parameters"], dict):
            raise ContractError("governed action parameters must be an object")
        if not isinstance(certificate_data, dict):
            raise ContractError("governed certificate must be an object")
        return (
            PortableAction(
                namespace=action_data["namespace"],
                operation=action_data["operation"],
                parameters=action_data["parameters"],
            ),
            BindingCertificate.from_dict(certificate_data),
        )

    def execute(
        self,
        call_arguments: Mapping[str, Any],
        executor: ActionExecutor,
    ) -> str:
        action, certificate = self.reconstruct(call_arguments)
        verified = verify_certificate(
            action,
            certificate,
            self.expected_scope,
            self.public_key,
            self.ledger,
        )
        return executor.execute_verified(verified)
