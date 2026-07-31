---
safe-outputs:
  jobs:
    portable-binding:
      description: "Execute one certificate-bound GitHub issue creation"
      runs-on: ubuntu-latest
      output: "Certificate-bound GitHub issue created"
      permissions:
        issues: write
        contents: read
      inputs:
        action_json:
          description: "Platform-neutral action encoded as strict JSON"
          required: true
          type: string
        certificate_json:
          description: "binding-v1 certificate encoded as strict JSON"
          required: true
          type: string
      steps:
        - uses: actions/checkout@v7
        - uses: actions/setup-python@v7
          with:
            python-version: "3.12"
        - run: python -m pip install .
        - name: Verify and execute the exact buffered output
          env:
            GITHUB_TOKEN: "${{ secrets.GITHUB_TOKEN }}"
            PORTABLE_BINDING_PUBLIC_KEY: "${{ secrets.PORTABLE_BINDING_PUBLIC_KEY }}"
            PORTABLE_BINDING_SCOPE: >-
              {"audience":"protected-action-executor",
              "invocation":"${{ github.run_id }}",
              "target":"github:${{ github.repository }}"}
          run: python scripts/github_safe_output_handler.py "$GH_AW_AGENT_OUTPUT"
---

# Portable Binding

Use this custom safe output only when a trusted attestor has issued a
`binding-v1` certificate for the exact action.
