"""Baselines DriftGuard is compared against."""
from __future__ import annotations

from .contracts import ContractRegistry
from .world import IAM_EXTRA_DATA, IAM_EXTRA_TOOLS, KNOWN_HOSTS, TOOL_DATA


class IAMOnly:
    """Classic access control: is this identity permitted? (Permissions are over-provisioned.)"""

    def __init__(self, registry: ContractRegistry | None = None):
        reg = registry or ContractRegistry()
        self.grants = {r: (reg.get(r).tools | IAM_EXTRA_TOOLS, reg.get(r).data | IAM_EXTRA_DATA) for r in reg.roles}

    def run(self, trace):
        out = []
        for x in trace["actions"]:
            tools, data = self.grants[x["role"]]
            out.append(100 if (x["tool"] not in tools or x["data"] not in data) else 0)
        return out


class AnomalyOnly:
    """UEBA-style anomaly detection: Isolation Forest on per-action features. No role, no provenance."""

    DATA = ["public", "supplier", "internal", "hr", "finance", "customer", "secret"]

    def __init__(self):
        try:
            from sklearn.ensemble import IsolationForest  # optional dependency
        except ImportError as e:  # pragma: no cover
            raise ImportError("AnomalyOnly baseline needs scikit-learn: pip install scikit-learn") from e
        self._IF = IsolationForest
        self.tools = sorted(set(TOOL_DATA))

    def _f(self, x, win=()):
        return ([int(x["tool"] == t) for t in self.tools] + [int(x["data"] == d) for d in self.DATA] +
                [int(bool(x["dest"]) and x["dest"] not in KNOWN_HOSTS), sum(1 for y in win if y["tool"] == x["tool"])])

    def fit(self, traces):
        X = [self._f(x, t["actions"][max(0, i - 8):i]) for t in traces for i, x in enumerate(t["actions"])]
        self.m = self._IF(n_estimators=300, contamination=0.01, random_state=0).fit(X)
        return self

    def run(self, trace):
        X = [self._f(x, trace["actions"][max(0, i - 8):i]) for i, x in enumerate(trace["actions"])]
        return [100 if p == -1 else 0 for p in self.m.predict(X)]
