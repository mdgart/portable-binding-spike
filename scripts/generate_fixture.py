#!/usr/bin/env python3
"""Generate one keypair, action, certificate, and both platform envelopes."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from portable_binding.certificate import issue_certificate
from portable_binding.contract import PortableAction


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--title", default="Portable binding live test")
    parser.add_argument("--body", default="Created by the portable-binding spike.")
    parser.add_argument("--invocation", required=True)
    parser.add_argument("--output", type=Path, default=Path("fixture"))
    args = parser.parse_args()

    action = PortableAction(
        namespace="github",
        operation="create_issue",
        parameters={
            "repository": args.repository,
            "title": args.title,
            "body": args.body,
        },
    )
    scope = {
        "audience": "protected-action-executor",
        "invocation": args.invocation,
        "target": f"github:{args.repository}",
    }
    private_key = Ed25519PrivateKey.generate()
    certificate = issue_certificate(action, scope, private_key)
    action_data = {
        "namespace": action.namespace,
        "operation": action.operation,
        "parameters": dict(action.parameters),
    }
    action_json = json.dumps(action_data, ensure_ascii=False, separators=(",", ":"))
    certificate_json = json.dumps(
        certificate.as_dict(),
        ensure_ascii=False,
        separators=(",", ":"),
    )

    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "private-key.pem").write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (args.output / "public-key.pem").write_bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    write_json(args.output / "action.json", action_data)
    write_json(args.output / "certificate.json", certificate.as_dict())
    write_json(args.output / "scope.json", scope)
    write_json(
        args.output / "faramesh-call.json",
        {"action_json": action_json, "certificate_json": certificate_json},
    )
    write_json(
        args.output / "agent_output.json",
        {
            "items": [
                {
                    "type": "portable_binding",
                    "action_json": action_json,
                    "certificate_json": certificate_json,
                }
            ]
        },
    )
    print(args.output.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

