# Spike 1: Binding Portability

Start: 2026-07-30  
Hard stop: 2026-08-06  
Budget: Five focused engineering days; no extension without a new decision.

## Question

Can one portable certificate prove that the exact artifact attested is the
artifact acted upon through both Faramesh-governed tool execution and GitHub
Agentic Workflows Safe Outputs?

## Pass criteria

- One certificate format and artifact-identity rule work in both paths.
- Verification occurs after the untrusted agent boundary and immediately
  before the protected action.
- Verified identity equals executed identity.
- Mutation, substitution, replay, TOCTOU, and package/proxy attacks fail.
- Deliberately vulnerable canaries prove the attack suite detects real leaks.
- Neither adapter changes certificate meaning.

## Blocked criteria

Record `BLOCKED` at the hard stop if correctness requires a Faramesh or gh-aw
fork, gateway-specific certificate meaning, inaccessible action content, or
unavailable credentials/infrastructure for the live proof.

## Exclusions

No graph, AI distillation, project-memory ontology, shared future event schema,
production gateway, or generalized policy language.

