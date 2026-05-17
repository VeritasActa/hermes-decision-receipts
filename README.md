# hermes-decision-receipts

Ed25519-signed decision receipts for [NousResearch/hermes-agent](https://github.com/NousResearch/hermes-agent) tool calls. Companion to [aeoess/hermes-aps-delegation](https://github.com/aeoess/hermes-aps-delegation) on the delegation/identity side.

**Apache-2.0 · Python 3.10+ · JCS (RFC 8785) + Ed25519 (RFC 8032)**

```bash
# v0.1.0: install from source until PyPI publication
pip install git+https://github.com/ScopeBlind/hermes-decision-receipts.git
```

## What this is

A Python library that wraps Hermes tool calls with cryptographic decision receipts, producing evidence that verifies offline via `@veritasacta/verify` against the [IETF Internet-Draft](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/).

Each Hermes tool call produces a receipt covering:

- Which tool was invoked (`tool_name`)
- What the decision was (`decision`: allow / deny / require_approval)
- What policy evaluated the call (`policy_id`, `policy_hash`)
- When it happened (`issued_at`, UTC)
- What came before (`previousReceiptHash`, chained)
- Which agent and session (`agent_id`, `session_id`)
- The skill version that produced the call (`skill_version_hash`), for composition with `hermes-aps-delegation`

## Relationship to hermes-aps-delegation

This repo and [aeoess/hermes-aps-delegation](https://github.com/aeoess/hermes-aps-delegation) cover complementary layers of the same Hermes agent governance story:

| Layer | Repo | Owner |
|---|---|---|
| Delegation / identity / charter enforcement | [aeoess/hermes-aps-delegation](https://github.com/aeoess/hermes-aps-delegation) | @aeoess |
| Decision receipts / per-tool-call evidence | **this repo** | @tomjwxf |
| Joint audit walker (receipts + delegation chain) | [aeoess/hermes-audit-walker](https://github.com/aeoess/hermes-audit-walker) | @aeoess / joint interop |

A Hermes agent using both produces receipts that:

1. Are individually signed and offline-verifiable (this repo).
2. Reference the APS delegation chain that authorized the agent to act (`hermes-aps-delegation`).
3. Chain into a single walkable audit trace covering both the authority path and the decision log.

See `examples/02_chain_with_aps.py` for the composition pattern.

## Quick start

```python
from hermes_decision_receipts import ReceiptSigner

# Generate a keypair (in production, load from KMS / HSM)
signer = ReceiptSigner.generate()
signer.save_key("keys/operator.json")

# Wrap a tool call
receipt = signer.sign_tool_call(
    tool_name="web_search",
    tool_args={"query": "Nous Research Hermes 4"},
    decision="allow",
    policy_id="research-read-only-v1",
    skill_version_hash="sha256:...",  # from hermes-aps-delegation
)

print(receipt.to_json())
# Verify externally:
# npx @veritasacta/verify receipt.json --key <signer.public_key_hex>
```

## Why decision receipts?

Hermes supports self-improvement: agents can create or modify their own skills. That's useful and risky. Useful because task-specific skills outperform general reasoning; risky because an agent modifying its own behavior is the exact shape of things that need external audit.

Without signed evidence per tool call, an auditor has:

- Logs produced by the agent being audited (no integrity property).
- No way to distinguish "skill v3 ran this tool call" from "skill v7 ran this tool call."
- No way to prove a given policy was active when a decision was made.

With signed decision receipts:

- Each tool call produces an Ed25519-signed JSON receipt binding the action, the governing policy, and the skill version that produced it.
- An external verifier (auditor, regulator, counterparty) replays the decision offline without trusting the operator.
- Receipts chain via `previousReceiptHash`; tampering with one breaks the chain.
- The format is standardized at the IETF as `draft-farley-acta-signed-receipts`, not a ScopeBlind- or Nous-specific invention.

Combined with `hermes-aps-delegation`'s charter enforcement, the result is a two-axis evidence surface: "was this agent authorized to act?" (APS) and "what did this agent actually do?" (decision receipts).

## Receipt format

Receipts follow `draft-farley-acta-signed-receipts-01`:

```json
{
  "payload": {
    "type": "hermes:decision",
    "spec": "draft-farley-acta-signed-receipts-01",
    "predicateType": "https://veritasacta.com/attestation/decision-receipt/v0.1",
    "tool_name": "web_search",
    "tool_input_hash": "sha256:...",
    "decision": "allow",
    "policy_id": "research-read-only-v1",
    "policy_hash": "sha256:...",
    "skill_version_hash": "sha256:...",
    "agent_id": "hermes-research-01",
    "session_id": "sess_abc123",
    "sequence": 7,
    "previousReceiptHash": "sha256:...",
    "issued_at": "2026-04-19T08:00:00Z",
    "issuer_id": "hermes-decision-receipts"
  },
  "signature": {
    "alg": "EdDSA",
    "kid": "sb:hermes:7a3f...",
    "sig": "hex-encoded-ed25519-sig"
  }
}
```

Canonicalization: JCS (RFC 8785) with AIP-0001 adaptations (ASCII-only keys, whole-number floats collapse to ints).

## Verification

```bash
npx @veritasacta/verify receipt.json --key <public-key-hex>
# ✓ Signature valid (Ed25519, kid: sb:hermes:7a3f...)
```

No ScopeBlind or Nous servers are contacted. The verifier is Apache-2.0 and offline.

## Status

**v0.1.0**, May 2026. The real signer has been cross-tested against `aeoess/hermes-audit-walker`; basic receipt and APS composition paths pass against the published signer contract.

Not yet on PyPI. Install from source:

```bash
git clone https://github.com/ScopeBlind/hermes-decision-receipts
cd hermes-decision-receipts
pip install -e ".[dev]"
```

### Known limitations in v0.1.0

- Hermes-specific integration is against **stubbed tool-call interfaces**, since Hermes internals aren't public. The signing layer works; the wiring against an actual Hermes runtime depends on Nous publishing a stable plugin / hook surface.
- Key management is a local JSON file. Production deployments should use KMS, HSM, or VOPRF-based issuance (see [veritasacta.com](https://veritasacta.com)).
- Receipt storage is whatever you configure (filesystem, object store, Rekor anchoring). No built-in store yet.

## Related

- [aeoess/hermes-aps-delegation](https://github.com/aeoess/hermes-aps-delegation) — APS delegation companion (same composition story, different layer).
- [aeoess/hermes-audit-walker](https://github.com/aeoess/hermes-audit-walker) — Offline verifier for the APS + decision-receipt cross-link.
- [draft-farley-acta-signed-receipts](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/) — IETF Internet-Draft (receipt format).
- [in-toto/attestation#549](https://github.com/in-toto/attestation/pull/549) — in-toto Decision Receipt predicate (composes with SLSA pipeline).
- [@veritasacta/verify](https://www.npmjs.com/package/@veritasacta/verify) — Reference offline verifier (Apache-2.0).
- [VeritasActa/agt-integration-profile](https://github.com/VeritasActa/agt-integration-profile) — Conformance profile for AGT backends.
- [protect-mcp](https://www.npmjs.com/package/protect-mcp) — Claude Code hooks + MCP gateway, same receipt format.
- [protect-mcp-adk](https://pypi.org/project/protect-mcp-adk/) — Google ADK plugin, same receipt format. Closest sibling to this package.
- [NousResearch/hermes-agent#11692](https://github.com/NousResearch/hermes-agent/issues/11692) — Hermes tracking issue.

## License

Apache-2.0. See [LICENSE](./LICENSE).
