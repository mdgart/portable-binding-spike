"""Ed25519 certificate issuance and verification."""

from __future__ import annotations

import base64
import secrets
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .contract import PortableAction, canonical_bytes, digest_action
from .replay import ReplayLedger


class CertificateError(RuntimeError):
    """Raised when a certificate is invalid for the proposed action."""


def _time_text(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("certificate timestamps must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_time(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise CertificateError(f"invalid certificate timestamp: {value}") from error


@dataclass(frozen=True)
class BindingCertificate:
    version: str
    key_id: str
    artifact_digest: str
    scope: Mapping[str, Any]
    issued_at: str
    expires_at: str
    nonce: str
    signature: str

    def unsigned_dict(self) -> dict[str, Any]:
        material = asdict(self)
        material.pop("signature")
        return material

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "BindingCertificate":
        expected = {
            "version",
            "key_id",
            "artifact_digest",
            "scope",
            "issued_at",
            "expires_at",
            "nonce",
            "signature",
        }
        if set(value) != expected:
            raise CertificateError("certificate has missing or unexpected fields")
        if not isinstance(value["scope"], dict):
            raise CertificateError("certificate scope must be an object")
        return cls(**dict(value))


@dataclass(frozen=True)
class VerifiedAction:
    """Only this value may cross into an executor."""

    canonical_action: bytes
    certificate: BindingCertificate


def issue_certificate(
    action: PortableAction,
    scope: Mapping[str, Any],
    private_key: Ed25519PrivateKey,
    *,
    key_id: str = "spike-key-1",
    now: datetime | None = None,
    lifetime: timedelta = timedelta(minutes=5),
    nonce: str | None = None,
) -> BindingCertificate:
    now = now or datetime.now(timezone.utc)
    unsigned = {
        "version": "binding-v1",
        "key_id": key_id,
        "artifact_digest": digest_action(action),
        "scope": dict(scope),
        "issued_at": _time_text(now),
        "expires_at": _time_text(now + lifetime),
        "nonce": nonce or secrets.token_urlsafe(18),
    }
    signature = private_key.sign(canonical_bytes(unsigned))
    return BindingCertificate(
        **unsigned,
        signature=base64.urlsafe_b64encode(signature).decode("ascii"),
    )


def verify_certificate(
    action: PortableAction,
    certificate: BindingCertificate,
    expected_scope: Mapping[str, Any],
    public_key: Ed25519PublicKey,
    ledger: ReplayLedger,
    *,
    now: datetime | None = None,
) -> VerifiedAction:
    now = now or datetime.now(timezone.utc)
    if certificate.version != "binding-v1":
        raise CertificateError("unsupported certificate version")
    if canonical_bytes(dict(certificate.scope)) != canonical_bytes(dict(expected_scope)):
        raise CertificateError("certificate scope mismatch")
    if certificate.artifact_digest != digest_action(action):
        raise CertificateError("certificate does not bind proposed action")
    issued_at = _parse_time(certificate.issued_at)
    expires_at = _parse_time(certificate.expires_at)
    if now < issued_at:
        raise CertificateError("certificate is not valid yet")
    if now >= expires_at:
        raise CertificateError("certificate expired")
    try:
        signature = base64.urlsafe_b64decode(certificate.signature.encode("ascii"))
        public_key.verify(signature, canonical_bytes(certificate.unsigned_dict()))
    except (ValueError, InvalidSignature) as error:
        raise CertificateError("certificate signature invalid") from error
    ledger.reserve(certificate.nonce)
    return VerifiedAction(action.to_bytes(), certificate)

