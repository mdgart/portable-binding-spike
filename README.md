# Portable Binding Spike

This repository tests one question:

> Can the same certificate bind the exact action executed through a
> Faramesh-governed tool path and a GitHub Agentic Workflows Safe Outputs path?

It is a compatibility spike, not a production gateway. It deliberately excludes
the proposed project-memory system and any shared event schema.

## Contract

Both adapters reconstruct the same platform-neutral action:

```json
{
  "kind": "tool-call",
  "namespace": "github",
  "operation": "create_issue",
  "parameters": {
    "body": "The issue body",
    "repository": "owner/repository",
    "title": "The issue title"
  }
}
```

The action is encoded with the repository's canonical JSON subset and hashed
with SHA-256. An Ed25519 certificate signs that digest, its platform-neutral
scope, validity window, and nonce.

The secure boundary:

1. reconstructs the canonical action from the platform envelope;
2. verifies its digest, signature, scope, validity, and nonce;
3. reserves the nonce;
4. passes only the verified canonical bytes to the executor.

The caller's mutable envelope is never used after verification.

## Run

Requires Python 3.11+ and `cryptography`.

```bash
python -m unittest discover -s tests -v
python scripts/run_spike.py
```

The runner writes a machine-readable report to `reports/latest.json`.

Generate equivalent inputs for both live paths:

```bash
python scripts/generate_fixture.py \
  --repository owner/repository \
  --invocation "$INVOCATION_ID" \
  --output fixture
```

The generated private key is test material. Do not commit or reuse it.

## Repository map

- `src/portable_binding/contract.py`: canonical action contract
- `src/portable_binding/certificate.py`: Ed25519 certificate creation and verification
- `src/portable_binding/replay.py`: atomic nonce reservation
- `src/portable_binding/adapters/`: Faramesh and Safe Outputs envelope adapters
- `src/portable_binding/execution.py`: verified-bytes-only execution boundary
- `src/portable_binding/canaries.py`: deliberately vulnerable reference paths
- `tests/`: positive, attack, TOCTOU, and canary tests
- `.github/workflows/shared/portable-binding.md`: Safe Outputs custom-job fixture
- `docs/SPIKE_CHARTER.md`: fixed timebox and pass/blocked criteria
- `docs/RESULT.md`: current evidence-based result

## Current limitation

The automated suite proves the portable contract and adapter behavior locally.
It does not claim a live end-to-end integration with a running Faramesh daemon
or a credentialed GitHub Agentic Workflow. Those checks remain explicit
external-validation items in `docs/RESULT.md`.
