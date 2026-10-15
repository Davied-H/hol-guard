# Extension `x-hol.tests`

Status: registered (alpha). Owner: HOL Guard maintainers.

`x-hol.tests` stores example events with a policy document, together with the decision each event must produce. Editors and CI run them before a policy is applied. The extension follows the registration rules in [`compatibility.md`](../compatibility.md#extension-registration).

## 1. Key and location

- Key: `x-hol.tests`.
- Allowed location: the `spec` object only. A reader that finds the key anywhere else treats it as an ordinary unregistered extension.
- Value schema: [`x-hol.tests.schema.json`](x-hol.tests.schema.json). Up to 256 tests.

```yaml
spec:
  defaults:
    mode: enforce
  rules:
    - id: block-unknown-mcp
      enabled: true
      effect: block
      match:
        tools: [mcp]
      lifetime:
        mode: permanent
      provenance:
        source: builder
        createdAt: 2026-10-14T00:00:00Z
  x-hol.tests:
    - id: mcp-is-blocked
      name: MCP servers are blocked for every agent
      event:
        harness: codex
        tool: mcp
      expect:
        effect: block
        ruleId: block-unknown-mcp
```

## 2. Semantics

Each test describes one request and the expected outcome:

- `event.harness` is required. `event.artifact`, `event.tool`, `event.publisher` and `event.workspace` are optional and correspond to the `artifacts`, `tools`, `publishers` and `workspaces` matchers. `event.tool` uses the same family names the compiler accepts for `match.tools`; `shell` is an alias of `tool-action`.
- `event.at` sets the evaluation clock so that `lifetime.mode: until` rules can be tested. Without it, a runner uses the current time.
- `expect.effect` is `allow`, `block`, or `default`. `default` means that no rule in the document applies, so the outcome falls through to `spec.defaults` and the client's own local rows.
- `expect.ruleId`, when present, must equal the id of the rule that decided the request.

A runner evaluates the document alone. It compiles the rules with the normative compiler, applies the frozen precedence in [`semantics.md`](../semantics.md#current-runtime-precedence-frozen), and compares the result with `expect`. It does not consult local approvals, one-shot grants, or rows from other documents. A test therefore checks what this document says, not what one particular device will decide.

## 3. Failure behaviour

- An enforcing reader must ignore `x-hol.tests` for matching, effect, lifetime, authority and precedence. Two documents that differ only in `x-hol.tests` compile to identical rows.
- Like every extension, the value takes part in the canonical document digest and the bundle signature, and it must not be dropped before hashing or forwarding.
- A runner that finds a value that does not match the extension schema reports `x_hol_tests_invalid` with the JSON path, and it runs no tests from that document.
- A failing test does not make the document invalid. Publishing tools may refuse to publish while tests fail, but the enforcement path never consults them.

## 4. Security and privacy

Test events are written by the policy author and stored in the document. They must not contain secrets, credentials or raw command text. The schema accepts only bounded identifiers and selector strings, and has no free-form command or payload field. Any tool that builds a test from a recorded decision must copy only the selector fields listed above.

## 5. Fixtures and consumers

- Fixture: [`fixtures/valid/with-tests.yaml`](../fixtures/valid/with-tests.yaml).
- Conformance: `tests/test_policy_document_extension_tests.py` checks that the fixture's extension value matches the schema, and that removing the extension changes the digest but leaves the compiled rows unchanged.
- First consumer: the Guard Cloud policy editor, which runs these tests before publishing. A local `hol-guard policy test` command is planned.

## 6. Collisions and retirement

The `x-hol.` prefix is reserved for HOL Guard maintainers. If a later core API version adds a native tests field, that version will define how `x-hol.tests` is migrated. v1alpha1 readers keep accepting the extension for the whole deprecation window that [`compatibility.md`](../compatibility.md#version-boundary) requires.
