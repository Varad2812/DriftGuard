"""Graded response: watch, ask a human, shrink the token, or isolate the agent."""
from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field

from .contracts import ContractRegistry
from .world import IAM_EXTRA_DATA, IAM_EXTRA_TOOLS


@dataclass
class Token:
    agent_id: str
    role: str
    value: str
    tools: set
    data: set
    revoked: bool = False
    events: list = field(default_factory=list)


class TokenBroker:
    """Issues agent tokens with the (over-broad) IAM grants and shrinks or revokes them on drift."""

    def __init__(self, registry: ContractRegistry):
        self.contracts = registry
        self.tokens: dict[str, Token] = {}

    def issue(self, agent_id: str, role: str) -> Token:
        c = self.contracts.get(role)
        tok = Token(agent_id, role, "dg_" + secrets.token_hex(12),
                    set(c.tools | IAM_EXTRA_TOOLS), set(c.data | IAM_EXTRA_DATA))
        self.tokens[agent_id] = tok
        return tok

    def downscope(self, agent_id: str) -> list[str]:
        """Cut the token back to exactly what the role contract allows."""
        tok = self.tokens[agent_id]
        c = self.contracts.get(tok.role, approved=True)
        removed = sorted((tok.tools - c.tools) | (tok.data - c.data))
        tok.tools &= set(c.tools)
        tok.data &= set(c.data)
        tok.events.append((time.time(), "downscoped", removed))
        return removed

    def revoke(self, agent_id: str):
        tok = self.tokens[agent_id]
        tok.revoked = True
        tok.events.append((time.time(), "revoked", []))

    def permits(self, agent_id: str, tool: str, data: str) -> bool:
        tok = self.tokens[agent_id]
        return not tok.revoked and tool in tok.tools and data in tok.data


def respond(broker: TokenBroker, agent_id: str, verdict, action: dict) -> dict:
    """Turn a verdict into an enforcement decision for this one action."""
    t = verdict.tier
    if t == "isolate":
        broker.revoke(agent_id)
        return {"decision": "block", "effect": "agent isolated, token revoked"}
    if t == "downscope":
        removed = broker.downscope(agent_id)
        allowed = broker.permits(agent_id, action["tool"], action["data"])
        return {"decision": "allow" if allowed else "block",
                "effect": f"token downscoped (removed: {', '.join(removed) or 'nothing'})"}
    if t == "ask_human":
        return {"decision": "allow", "effect": "flagged for human review"}
    return {"decision": "allow", "effect": None}
