# Spike Result

Current status: **PROVISIONAL PASS / LIVE VALIDATION PENDING**

## Local contract

`python scripts/run_spike.py` passes 15 tests.

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

Not yet demonstrated live:

- A running Faramesh daemon permitting the fixture and invoking the governed
  callable.
- A credentialed GitHub Agentic Workflow creating the bound issue.

GitHub only dispatches a `workflow_dispatch` workflow after the compiled file
exists on the default branch. The credentialed run therefore begins after the
draft PR is reviewed and merged; the spike does not change the default branch
or bypass that platform boundary.

The local suite may prove the portable binding contract and catch adapter
regressions, but it cannot by itself establish that the public platforms expose
the required production hook without modification.

## Current judgment

The binding design has not failed. No certificate-semantic fork or
gateway-specific rule has been required. The result remains provisional until
the two credentialed platform runs complete or the 2026-08-06 hard stop is
reached.
