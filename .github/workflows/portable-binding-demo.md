---
on:
  workflow_dispatch:
    inputs:
      invocation:
        description: "Attestor-chosen invocation identifier"
        required: true
        type: string
      action_json:
        description: "Trusted-attestor action JSON"
        required: true
        type: string
      certificate_json:
        description: "Trusted-attestor binding-v1 certificate JSON"
        required: true
        type: string
permissions:
  contents: read
  actions: read
imports:
  - shared/portable-binding.md
---

# Portable Binding Demonstration

Call the `portable-binding` safe-output tool exactly once. Pass
`${{ inputs.invocation }}` as `invocation`,
`${{ inputs.action_json }}` as `action_json` and
`${{ inputs.certificate_json }}` as `certificate_json`. Do not rewrite,
summarize, or repair either value.
