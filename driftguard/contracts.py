"""Role contracts: the declared job of each agent, versioned and human-approved."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

DEFAULT_DIR = Path(__file__).resolve().parent.parent / "contracts"


@dataclass(frozen=True)
class RoleContract:
    role: str
    description: str
    owner: str
    version: int
    tools: frozenset
    data: frozenset
    egress: frozenset
    rate_per_min: int
    may_call: frozenset
    delegate: dict = field(default_factory=dict)  # callee role -> data classes the caller may receive
    tasks: dict = field(default_factory=dict)     # task name -> tools that serve it

    def allows_data_from(self, callee_role: str) -> frozenset:
        """Data classes this role may hold when it delegates to `callee_role`."""
        return self.data | frozenset(self.delegate.get(callee_role, ()))


class ContractRegistry:
    """Loads role contracts and their approved changes.

    `get(role)` returns the base contract; `get(role, approved=True)` returns the
    contract with every human-approved change applied. Undeclared changes never
    enter a contract, so they score as drift.
    """

    def __init__(self, directory: str | Path = DEFAULT_DIR):
        self._base: dict[str, RoleContract] = {}
        self._approved: dict[str, RoleContract] = {}
        self.changes: dict[str, list] = {}
        for path in sorted(Path(directory).glob("*.yaml")):
            raw = yaml.safe_load(path.read_text())
            base = self._build(raw, raw.get("version", 1), ())
            extra_tools = []
            for ch in raw.get("approved_changes", []) or []:
                extra_tools += ch.get("add_tools", [])
            last = max([raw.get("version", 1)] + [c["version"] for c in raw.get("approved_changes", []) or []])
            self._base[base.role] = base
            self._approved[base.role] = self._build(raw, last, extra_tools)
            self.changes[base.role] = raw.get("approved_changes", []) or []

    @staticmethod
    def _build(raw: dict, version: int, extra_tools) -> RoleContract:
        return RoleContract(
            role=raw["role"], description=raw.get("description", ""), owner=raw.get("owner", ""),
            version=version, tools=frozenset(raw["tools"]) | frozenset(extra_tools),
            data=frozenset(raw["data"]), egress=frozenset(raw["egress"]),
            rate_per_min=int(raw.get("rate_per_min", 60)), may_call=frozenset(raw.get("may_call", []) or []),
            delegate={k: list(v) for k, v in (raw.get("delegate") or {}).items()},
            tasks={k: list(v) for k, v in (raw.get("tasks") or {}).items()},
        )

    def get(self, role: str, approved: bool = False) -> RoleContract:
        return (self._approved if approved else self._base)[role]

    @property
    def roles(self) -> list[str]:
        return list(self._base)

    def __contains__(self, role: str) -> bool:
        return role in self._base
