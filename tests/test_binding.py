from __future__ import annotations

import copy
import json
import threading
import unittest
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from portable_binding.adapters import FarameshAdapter, GitHubSafeOutputsAdapter
from portable_binding.canaries import (
    leaky_proxy_transform_after_verification,
    leaky_verify_then_execute_other,
)
from portable_binding.certificate import (
    BindingCertificate,
    CertificateError,
    issue_certificate,
)
from portable_binding.contract import ContractError, PortableAction, digest_action
from portable_binding.execution import (
    GitHubIssueExecutor,
    RecordingExecutor,
    assert_executed_identity,
)
from portable_binding.replay import MemoryReplayLedger, ReplayError


class BindingTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.action = PortableAction(
            namespace="github",
            operation="create_issue",
            parameters={
                "repository": "example/project",
                "title": "Portable binding",
                "body": "The exact verified body.",
            },
        )
        self.scope = {
            "audience": "protected-action-executor",
            "invocation": "spike-run-001",
            "target": "github:example/project",
        }
        self.certificate = issue_certificate(
            self.action,
            self.scope,
            self.private_key,
            nonce="nonce-001",
        )

    def faramesh_call(
        self,
        action: PortableAction | None = None,
        certificate: BindingCertificate | None = None,
    ) -> dict:
        action = action or self.action
        certificate = certificate or self.certificate
        return {
            "action_json": json.dumps(
                {
                    "namespace": action.namespace,
                    "operation": action.operation,
                    "parameters": dict(action.parameters),
                }
            ),
            "certificate_json": json.dumps(certificate.as_dict()),
        }

    def safe_output(
        self,
        action: PortableAction | None = None,
        certificate: BindingCertificate | None = None,
    ) -> bytes:
        action = action or self.action
        certificate = certificate or self.certificate
        return json.dumps(
            {
                "items": [
                    {
                        "type": "portable_binding",
                        "action_json": json.dumps(
                            {
                                "namespace": action.namespace,
                                "operation": action.operation,
                                "parameters": dict(action.parameters),
                            }
                        ),
                        "certificate_json": json.dumps(certificate.as_dict()),
                    }
                ]
            }
        ).encode()

    def test_same_certificate_and_identity_work_in_both_adapters(self) -> None:
        faramesh_executor = RecordingExecutor()
        FarameshAdapter(
            self.public_key,
            MemoryReplayLedger(),
            self.scope,
        ).execute(
            self.faramesh_call(),
            faramesh_executor,
        )
        safe_outputs_executor = RecordingExecutor()
        GitHubSafeOutputsAdapter(
            self.public_key,
            MemoryReplayLedger(),
            self.scope,
        ).execute(
            self.safe_output(),
            safe_outputs_executor,
        )
        assert_executed_identity(self.action, faramesh_executor)
        assert_executed_identity(self.action, safe_outputs_executor)
        self.assertEqual(
            faramesh_executor.records[-1]["digest"],
            safe_outputs_executor.records[-1]["digest"],
        )
        self.assertEqual(
            self.certificate.artifact_digest,
            digest_action(self.action),
        )

    def test_mutation_is_rejected_by_both_adapters(self) -> None:
        mutated = PortableAction(
            namespace=self.action.namespace,
            operation=self.action.operation,
            parameters={**self.action.parameters, "body": "MUTATED"},
        )
        with self.assertRaises(CertificateError):
            FarameshAdapter(
                self.public_key,
                MemoryReplayLedger(),
                self.scope,
            ).execute(
                self.faramesh_call(mutated),
                RecordingExecutor(),
            )
        with self.assertRaises(CertificateError):
            GitHubSafeOutputsAdapter(
                self.public_key,
                MemoryReplayLedger(),
                self.scope,
            ).execute(
                self.safe_output(mutated),
                RecordingExecutor(),
            )

    def test_valid_certificate_cannot_be_substituted(self) -> None:
        other = PortableAction(
            namespace="github",
            operation="create_issue",
            parameters={
                "repository": "example/project",
                "title": "Different",
                "body": "Different action",
            },
        )
        other_certificate = issue_certificate(
            other,
            self.scope,
            self.private_key,
            nonce="nonce-other",
        )
        with self.assertRaises(CertificateError):
            GitHubSafeOutputsAdapter(
                self.public_key,
                MemoryReplayLedger(),
                self.scope,
            ).execute(
                self.safe_output(self.action, other_certificate),
                RecordingExecutor(),
            )

    def test_scope_substitution_is_rejected(self) -> None:
        wrong_scope = {**self.scope, "target": "github:attacker/project"}
        with self.assertRaises(CertificateError):
            FarameshAdapter(
                self.public_key,
                MemoryReplayLedger(),
                wrong_scope,
            ).execute(
                self.faramesh_call(),
                RecordingExecutor(),
            )

    def test_signature_tampering_is_rejected(self) -> None:
        document = self.certificate.as_dict()
        document["expires_at"] = "2099-01-01T00:00:00Z"
        tampered = BindingCertificate.from_dict(document)
        with self.assertRaises(CertificateError):
            FarameshAdapter(
                self.public_key,
                MemoryReplayLedger(),
                self.scope,
            ).execute(
                self.faramesh_call(certificate=tampered),
                RecordingExecutor(),
            )

    def test_expired_certificate_is_rejected(self) -> None:
        expired = issue_certificate(
            self.action,
            self.scope,
            self.private_key,
            now=datetime.now(timezone.utc) - timedelta(hours=1),
            lifetime=timedelta(minutes=1),
            nonce="expired",
        )
        with self.assertRaises(CertificateError):
            FarameshAdapter(
                self.public_key,
                MemoryReplayLedger(),
                self.scope,
            ).execute(
                self.faramesh_call(certificate=expired),
                RecordingExecutor(),
            )

    def test_replay_is_rejected(self) -> None:
        ledger = MemoryReplayLedger()
        adapter = FarameshAdapter(self.public_key, ledger, self.scope)
        adapter.execute(
            self.faramesh_call(),
            RecordingExecutor(),
        )
        with self.assertRaises(ReplayError):
            adapter.execute(
                self.faramesh_call(),
                RecordingExecutor(),
            )

    def test_concurrent_replay_has_one_winner(self) -> None:
        ledger = MemoryReplayLedger()
        successes: list[str] = []
        failures: list[Exception] = []
        barrier = threading.Barrier(2)

        def attempt() -> None:
            try:
                barrier.wait()
                FarameshAdapter(self.public_key, ledger, self.scope).execute(
                    self.faramesh_call(),
                    RecordingExecutor(),
                )
                successes.append("ok")
            except Exception as error:
                failures.append(error)

        threads = [threading.Thread(target=attempt) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], ReplayError)

    def test_faramesh_call_rejects_unexpected_arguments(self) -> None:
        call = self.faramesh_call()
        call["unbound"] = "must not be ignored"
        with self.assertRaises(ContractError):
            FarameshAdapter(
                self.public_key,
                MemoryReplayLedger(),
                self.scope,
            ).execute(call, RecordingExecutor())

    def test_ambiguous_safe_output_is_rejected(self) -> None:
        item = json.loads(self.safe_output())["items"][0]
        ambiguous = json.dumps({"items": [item, copy.deepcopy(item)]}).encode()
        with self.assertRaises(ContractError):
            GitHubSafeOutputsAdapter(
                self.public_key,
                MemoryReplayLedger(),
                self.scope,
            ).execute(ambiguous, RecordingExecutor())

    def test_toctou_mutation_of_original_envelope_cannot_change_execution(self) -> None:
        call = self.faramesh_call()

        class MutatingExecutor(RecordingExecutor):
            def execute_verified(inner_self, verified):
                call["action_json"] = json.dumps(
                    {
                        "namespace": "github",
                        "operation": "create_issue",
                        "parameters": {
                            **self.action.parameters,
                            "repository": "attacker/repository",
                        },
                    }
                )
                return super().execute_verified(verified)

        executor = MutatingExecutor()
        FarameshAdapter(
            self.public_key,
            MemoryReplayLedger(),
            self.scope,
        ).execute(call, executor)
        self.assertEqual(
            executor.records[-1]["parameters"]["repository"],
            "example/project",
        )

    def test_verified_bytes_are_the_github_request_body_source(self) -> None:
        captured: dict[str, object] = {}

        def transport(url: str, body: bytes, token: str) -> tuple[int, bytes]:
            captured.update(url=url, body=body, token=token)
            return 201, b'{"html_url":"https://github.test/issues/1"}'

        result = FarameshAdapter(
            self.public_key,
            MemoryReplayLedger(),
            self.scope,
        ).execute(
            self.faramesh_call(),
            GitHubIssueExecutor("test-token", transport),
        )
        self.assertEqual(result, "https://github.test/issues/1")
        self.assertEqual(
            captured["url"],
            "https://api.github.com/repos/example/project/issues",
        )
        self.assertEqual(
            json.loads(captured["body"]),
            {
                "title": "Portable binding",
                "body": "The exact verified body.",
            },
        )

    def test_safe_outputs_executes_the_same_github_request_body(self) -> None:
        captured: dict[str, object] = {}

        def transport(url: str, body: bytes, token: str) -> tuple[int, bytes]:
            captured.update(url=url, body=body, token=token)
            return 201, b'{"html_url":"https://github.test/issues/2"}'

        result = GitHubSafeOutputsAdapter(
            self.public_key,
            MemoryReplayLedger(),
            self.scope,
        ).execute(
            self.safe_output(),
            GitHubIssueExecutor("test-token", transport),
        )
        self.assertEqual(result, "https://github.test/issues/2")
        self.assertEqual(
            captured["url"],
            "https://api.github.com/repos/example/project/issues",
        )
        self.assertEqual(
            json.loads(captured["body"]),
            {
                "title": "Portable binding",
                "body": "The exact verified body.",
            },
        )

    def test_canary_detects_verify_execute_substitution(self) -> None:
        evil = PortableAction(
            namespace="github",
            operation="create_issue",
            parameters={**self.action.parameters, "body": "EVIL"},
        )
        executor = RecordingExecutor()
        leaky_verify_then_execute_other(
            self.action,
            evil,
            self.certificate,
            self.scope,
            self.public_key,
            MemoryReplayLedger(),
            executor,
        )
        self.assertEqual(executor.records[-1]["parameters"]["body"], "EVIL")
        self.assertNotEqual(
            executor.records[-1]["digest"],
            self.certificate.artifact_digest,
        )

    def test_canary_detects_package_proxy_rewrite(self) -> None:
        executor = RecordingExecutor()
        leaky_proxy_transform_after_verification(
            self.action,
            self.certificate,
            self.scope,
            self.public_key,
            MemoryReplayLedger(),
            executor,
        )
        self.assertEqual(
            executor.records[-1]["parameters"]["repository"],
            "attacker/repository",
        )
        self.assertNotEqual(
            executor.records[-1]["digest"],
            self.certificate.artifact_digest,
        )


if __name__ == "__main__":
    unittest.main()
