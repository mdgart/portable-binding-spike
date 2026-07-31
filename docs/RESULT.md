# Spike Result

Current status: **PROVISIONAL PASS / FARAMESH LIVE VALIDATION PENDING**

## Local contract

`PYTHONPATH=src python -m unittest discover -s tests -v` passes 22 tests.

Demonstrated locally:

- The same Ed25519 certificate verifies through both adapters.
- Both adapters reconstruct the same canonical action digest.
- Both executors emit the same GitHub request URL and body.
- Mutation, certificate substitution, scope substitution, signature tampering,
  expiry, sequential replay, concurrent replay, ambiguous output, and TOCTOU
  mutation are rejected.
- Two deliberately vulnerable canaries successfully execute substituted and
  proxy-rewritten actions, proving the negative suite observes real leaks.
- Package installation and Python bytecode compilation succeed.

## Live integration

Public interface review found compatible hooks:

- Faramesh's SDK shim evaluates a callable's full structured arguments before
  invoking the underlying function. The verifier is inside that governed
  callable.
- GitHub custom Safe Output jobs receive the buffered `GH_AW_AGENT_OUTPUT` file
  in a separate permission-controlled job. The verifier and GitHub write are
  executed in one process in that job.

Compiled integration evidence (2026-07-31):

- `gh-aw` v0.83.4 accepted `.github/workflows/portable-binding-demo.md` with
  no validation errors.
- Compilation produced `portable-binding-demo.lock.yml`, including the imported
  `portable-binding` safe-output job, the restricted
  `PORTABLE_BINDING_PUBLIC_KEY` secret, and the final
  `github_safe_output_handler.py` invocation.
- The safe-update approval covers that one expected verification key; action
  and container dependencies are pinned in the generated manifest.
- Live-run preparation caught and removed a circular scope dependency:
  `github.run_id` is unavailable when the certificate is issued before
  dispatch. Both paths now receive the same attestor-chosen opaque invocation
  identifier, preserving the platform-neutral certificate meaning.
- A regression test asserts that the compiled source contract never derives
  invocation identity from `github.run_id`.
- Live adapter discovery established the exact `gh-aw` envelope: the top level
  contains `items` plus an empty `errors` array, and each custom item includes
  `invocation`. The adapter accepts only that strict shape, rejects non-empty
  errors and unknown fields, and requires the item invocation to equal the
  certificate's signed scope.

Credentialed GitHub evidence (2026-07-31):

- The OpenAI/Codex workflow, threat-detection stage, Safe Outputs processing,
  and permission-controlled `portable_binding` job all completed successfully
  in [Actions run 30645628467](https://github.com/mdgart/portable-binding-spike/actions/runs/30645628467).
- The protected job verified the Ed25519 certificate, signed invocation scope,
  and exact canonical action before issuing the GitHub request.
- GitHub Actions created [issue #3](https://github.com/mdgart/portable-binding-spike/issues/3)
  with the certificate-bound title `Portable binding live test (Codex verified)`
  and body `Created by the portable-binding spike through GitHub Agentic
  Workflows using Codex.`
- One intermediate run emitted a safe `noop` after the model misclassified the
  signed dispatch as prompt injection. A clean retry passed threat detection;
  no detection policy was disabled or weakened.

Not yet demonstrated live:

- A running Faramesh daemon permitting the fixture and invoking the governed
  callable.

The local suite may prove the portable binding contract and catch adapter
regressions, but it cannot by itself establish that the public platforms expose
the required production hook without modification.

## Current judgment

The GitHub leg passes without a certificate-semantic fork or gateway-specific
certificate rule. The result remains provisional until the credentialed
Faramesh run completes or the 2026-08-06 hard stop is reached.
