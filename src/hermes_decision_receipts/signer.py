"""Ed25519 receipt signing following draft-farley-acta-signed-receipts-01.

Produces Passport-envelope receipts: { payload: {...}, signature: {alg, kid, sig} }
Canonicalization: JCS (RFC 8785) with AIP-0001 adaptations (ASCII-only keys,
whole-number floats collapse to integers).
Verification: npx @veritasacta/verify receipt.json --key <public-key-hex>

This is the Hermes-specific signer. Pattern mirrors protect-mcp-adk
(same format, different tool-call shape). Extension over the generic case:
a `skill_version_hash` field composes with the APS charter-enforcement
side (hermes-aps-delegation) so an auditor can ask "which skill version
produced this call" from the receipt chain alone.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from nacl.signing import SigningKey, VerifyKey

# ─── JCS canonicalization (RFC 8785 + AIP-0001) ─────────────────────────


def _assert_ascii_keys(obj: Any) -> None:
    """AIP-0001: all object keys MUST be ASCII."""
    if isinstance(obj, dict):
        for k in obj:
            if not isinstance(k, str):
                raise ValueError(f"non-string key: {type(k).__name__}")
            try:
                k.encode("ascii")
            except UnicodeEncodeError as e:
                raise ValueError(f"non-ASCII key: {k!r}") from e
            _assert_ascii_keys(obj[k])
    elif isinstance(obj, list):
        for item in obj:
            _assert_ascii_keys(item)


def _normalize_numbers(obj: Any) -> Any:
    """Match ECMAScript JSON.stringify: whole-number floats collapse to ints."""
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, float) and obj.is_integer():
        return int(obj)
    if isinstance(obj, dict):
        return {k: _normalize_numbers(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_normalize_numbers(v) for v in obj]
    return obj


def _jcs_canonicalize(obj: Any) -> str:
    _assert_ascii_keys(obj)
    normalized = _normalize_numbers(obj)
    return json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


# ─── Receipt types ─────────────────────────────────────────────────────


@dataclass
class Receipt:
    """An Ed25519-signed receipt in IETF draft envelope format."""

    payload: dict[str, Any]
    signature: dict[str, str]
    receipt_id: str

    def to_dict(self) -> dict[str, Any]:
        return {"payload": self.payload, "signature": self.signature}

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def verify(self, public_key_hex: str) -> bool:
        """Verify signature against the given public key.

        Matches @veritasacta/verify: signs the raw JCS-canonicalized bytes.
        Ed25519 handles internal hashing per RFC 8032.
        """
        try:
            verify_key = VerifyKey(bytes.fromhex(public_key_hex))
            canonical = _jcs_canonicalize(self.payload)
            message = canonical.encode("utf-8")
            sig_bytes = bytes.fromhex(self.signature["sig"])
            verify_key.verify(message, sig_bytes)
            return True
        except Exception:
            return False


@dataclass
class ReceiptChain:
    """Append-only chain of receipts linked by hash."""

    receipts: list[Receipt] = field(default_factory=list)
    _sequence: int = 0

    @property
    def length(self) -> int:
        return len(self.receipts)

    @property
    def last_hash(self) -> str | None:
        if not self.receipts:
            return None
        canonical = _jcs_canonicalize(self.receipts[-1].payload)
        return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def append(self, receipt: Receipt) -> None:
        self.receipts.append(receipt)
        self._sequence += 1

    def to_jsonl(self) -> str:
        """Export the chain as JSONL (one receipt per line)."""
        return "\n".join(r.to_json(indent=0).replace("\n", "") for r in self.receipts) + "\n"


# ─── Signer ────────────────────────────────────────────────────────────


class ReceiptSigner:
    """Signs Hermes tool-call decision receipts using Ed25519.

    Usage:
        signer = ReceiptSigner.generate()
        receipt = signer.sign_tool_call(
            tool_name="web_search",
            tool_args={"query": "Nous Hermes 4"},
            decision="allow",
            policy_id="research-read-only-v1",
        )
    """

    def __init__(
        self,
        signing_key: SigningKey,
        kid: str,
        issuer: str = "hermes-decision-receipts",
        agent_id: str | None = None,
    ):
        self._signing_key = signing_key
        self._kid = kid
        self._issuer = issuer
        self._agent_id = agent_id or "hermes-agent"
        self._session_id = f"sess_{os.urandom(6).hex()}"
        self._chain = ReceiptChain()

    @classmethod
    def generate(
        cls,
        issuer: str = "hermes-decision-receipts",
        agent_id: str | None = None,
    ) -> ReceiptSigner:
        """Generate a new Ed25519 keypair (development/testing).

        For production, use ReceiptSigner.from_key_file() after loading
        from a KMS, HSM, or VOPRF-issued key material.
        """
        key = SigningKey.generate()
        pub_hex = key.verify_key.encode().hex()
        kid = f"sb:hermes:{pub_hex[:12]}"
        return cls(key, kid, issuer, agent_id)

    @classmethod
    def from_key_file(
        cls,
        path: str,
        issuer: str = "hermes-decision-receipts",
        agent_id: str | None = None,
    ) -> ReceiptSigner:
        """Load signer from a JSON key file (same format as protect-mcp-adk)."""
        data = json.loads(Path(path).read_text())
        key = SigningKey(bytes.fromhex(data["private_key"]))
        kid = data.get("kid", f"sb:hermes:{data['public_key'][:12]}")
        return cls(key, kid, issuer, agent_id)

    @property
    def public_key_hex(self) -> str:
        return self._signing_key.verify_key.encode().hex()

    @property
    def kid(self) -> str:
        return self._kid

    @property
    def chain(self) -> ReceiptChain:
        return self._chain

    def save_key(self, path: str) -> None:
        """Save keypair to JSON file. Development use only; production uses KMS/HSM."""
        data = {
            "kid": self._kid,
            "private_key": self._signing_key.encode().hex(),
            "public_key": self.public_key_hex,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, indent=2))

    def sign_tool_call(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        decision: str = "allow",
        policy_id: str | None = None,
        policy_hash: str | None = None,
        skill_version_hash: str | None = None,
        parent_skill_version_hash: str | None = None,
        delegation_chain_root: str | None = None,
        result: dict[str, Any] | None = None,
        deny_reason: str | None = None,
        invocation_id: str | None = None,
    ) -> Receipt:
        """Sign a Hermes tool call, producing a receipt.

        Fields matching protect-mcp-adk:
          tool_name, tool_input_hash, decision, issued_at, issuer_id,
          session_id, sequence, previousReceiptHash

        Hermes-specific additions (compose with hermes-aps-delegation):
          skill_version_hash: which skill produced this call
          parent_skill_version_hash: prior version in the skill's revision chain
          delegation_chain_root: APS delegation root (authority-chain mode)
        """
        if decision not in {"allow", "deny", "require_approval", "compensated"}:
            raise ValueError(f"invalid decision: {decision!r}")

        # Hash tool args (privacy-preserving: raw args not stored in receipt).
        args_str = json.dumps(tool_args, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        tool_input_hash = "sha256:" + hashlib.sha256(args_str.encode("utf-8")).hexdigest()

        # Hash result if provided.
        result_hash = None
        if result is not None:
            result_str = json.dumps(
                result, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            )
            result_hash = "sha256:" + hashlib.sha256(result_str.encode("utf-8")).hexdigest()

        payload: dict[str, Any] = {
            "type": "hermes:decision",
            "spec": "draft-farley-acta-signed-receipts-01",
            "tool_name": tool_name,
            "tool_input_hash": tool_input_hash,
            "decision": decision,
            "issued_at": datetime.now(timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "issuer_id": self._issuer,
            "agent_id": self._agent_id,
            "session_id": self._session_id,
            "sequence": self._chain._sequence + 1,
            "previousReceiptHash": self._chain.last_hash,
        }

        # Optional fields.
        if policy_id is not None:
            payload["policy_id"] = policy_id
        if policy_hash is not None:
            payload["policy_hash"] = policy_hash
        if skill_version_hash is not None:
            payload["skill_version_hash"] = skill_version_hash
        if parent_skill_version_hash is not None:
            payload["parent_skill_version_hash"] = parent_skill_version_hash
        if delegation_chain_root is not None:
            payload["delegation_chain_root"] = delegation_chain_root
        if deny_reason is not None:
            payload["deny_reason"] = deny_reason
        if result_hash is not None:
            payload["output_hash"] = result_hash
        if invocation_id is not None:
            payload["invocation_id"] = invocation_id

        # Sign: JCS canonicalize -> Ed25519. RFC 8032 handles internal hashing.
        canonical = _jcs_canonicalize(payload)
        message = canonical.encode("utf-8")
        sig = self._signing_key.sign(message).signature
        receipt_id = "sha256:" + hashlib.sha256(message).hexdigest()

        receipt = Receipt(
            payload=payload,
            signature={
                "alg": "EdDSA",
                "kid": self._kid,
                "sig": sig.hex(),
            },
            receipt_id=receipt_id,
        )
        self._chain.append(receipt)
        return receipt
