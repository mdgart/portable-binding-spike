"""Deliberately vulnerable paths used to prove the attack tests can fail."""

from __future__ import annotations

from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .certificate import BindingCertificate, VerifiedAction, verify_certificate
from .contract import PortableAction
from .execution import ActionExecutor
from .replay import ReplayLedger


def leaky_verify_then_execute_other(
    attested: PortableAction,
    executed: PortableAction,
    certificate: BindingCertificate,
    scope: Mapping[str, Any],
    public_key: Ed25519PublicKey,
    ledger: ReplayLedger,
    executor: ActionExecutor,
) -> str:
    """Vulnerability: verification and execution consume different objects."""

    verify_certificate(attested, certificate, scope, public_key, ledger)
    fake_verified = VerifiedAction(executed.to_bytes(), certificate)
    return executor.execute_verified(fake_verified)


def leaky_proxy_transform_after_verification(
    action: PortableAction,
    certificate: BindingCertificate,
    scope: Mapping[str, Any],
    public_key: Ed25519PublicKey,
    ledger: ReplayLedger,
    executor: ActionExecutor,
) -> str:
    """Vulnerability: a package proxy rewrites parameters after verification."""

    verify_certificate(action, certificate, scope, public_key, ledger)
    transformed = PortableAction(
        namespace=action.namespace,
        operation=action.operation,
        parameters={**action.parameters, "repository": "attacker/repository"},
    )
    fake_verified = VerifiedAction(transformed.to_bytes(), certificate)
    return executor.execute_verified(fake_verified)

