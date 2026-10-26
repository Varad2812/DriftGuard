"""DriftGuard detector: six independent signals, one explainable risk score.

Signals
  1. policy    - is the action inside the agent's Role Contract?
  2. behavior  - Markov surprise, CUSUM for slow drift, bursts, peer-role breadth
  3. task      - does the action serve the user's task? (rule stand-in for an LLM judge)
  4. taint     - did untrusted content precede sensitive access or egress?
  5. decoy     - did the agent touch a tripwire record no real job needs?
  6. chain     - does a delegated call exceed the caller's authority?

Risk = max(floor, round(100 * sum(w_i * s_i))). Hard evidence sets a floor
(decoy >= 95, tainted egress to an unknown host >= 85).
"""
from __future__ import annotations

import math
import statistics
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from .contracts import ContractRegistry
from .world import DECOYS, EGRESS_TOOLS, KNOWN_HOSTS, SENSITIVE

WEIGHTS = {"policy": 0.30, "behavior": 0.20, "task": 0.15, "taint": 0.20, "chain": 0.15}


def percentile(values, q):
    """Linear-interpolated percentile (same as numpy's default)."""
    v = sorted(values)
    if not v:
        return 0.0
    k = (len(v) - 1) * q / 100
    lo, hi = math.floor(k), math.ceil(k)
    return float(v[lo] + (v[hi] - v[lo]) * (k - lo))


def tier(risk: int) -> str:
    if risk >= 85:
        return "isolate"
    if risk >= 60:
        return "downscope"
    if risk >= 30:
        return "ask_human"
    return "allow"


@dataclass
class Verdict:
    risk: int
    tier: str
    reasons: list
    signals: dict
    floor: int
    ms: float

    def to_dict(self):
        return {"risk": self.risk, "tier": self.tier, "reasons": self.reasons,
                "signals": self.signals, "floor": self.floor, "ms": round(self.ms, 4)}


def normalize(action: dict, default_role: str) -> dict:
    from .world import TOOL_DATA, TOOL_DEST
    tool = action["tool"]
    return {
        "tool": tool,
        "role": action.get("role") or default_role,
        "data": action.get("data") or TOOL_DATA.get(tool, "internal"),
        "dest": action.get("dest") if action.get("dest") is not None else TOOL_DEST.get(tool),
        "resource": action.get("resource") or f"{tool}:?",
        "untrusted": bool(action.get("untrusted", False)),
        "caller": action.get("caller"),
    }


class DriftGuard:
    """Learns normal behaviour per role, then scores agent sessions action by action."""

    def __init__(self, registry: ContractRegistry | None = None):
        self.contracts = registry or ContractRegistry()
        self.fitted = False

    # ------------------------------------------------------------ learning
    def fit(self, traces):
        """Learn transition statistics and peer-role breadth from benign traces."""
        self.trans = defaultdict(Counter)
        for tr in traces:
            prev = "<s>"
            for x in tr["actions"]:
                self.trans[(x["role"], prev)][x["tool"]] += 1
                prev = x["tool"]
        breadth = defaultdict(list)
        for tr in traces:
            breadth[tr["role"]].append(len({x["resource"] for x in tr["actions"] if x["data"] in SENSITIVE}))
        self.breadth = {r: percentile(v, 99) + 2 for r, v in breadth.items()}
        surprises = [self._surprise(x["role"], p, x["tool"]) for tr in traces
                     for p, x in zip(["<s>"] + [y["tool"] for y in tr["actions"]], tr["actions"])]
        self.mu = statistics.mean(surprises)
        self.sd = statistics.pstdev(surprises) + 1e-6
        self.fitted = True
        return self

    def _surprise(self, role, prev, tool):
        c = self.trans[(role, prev)]
        n = sum(c.values())
        return -math.log((c[tool] + 0.5) / (n + 0.5 * 20))

    # ------------------------------------------------------------ scoring
    def session(self, role: str, task: str, approved_changes: bool = False) -> "Session":
        if not self.fitted:
            raise RuntimeError("call fit() with benign traces first")
        if role not in self.contracts:
            raise KeyError(f"no role contract for '{role}'")
        return Session(self, role, task, approved_changes)

    def run(self, trace: dict) -> list[Verdict]:
        """Score a whole recorded trace (used by the benchmark)."""
        s = self.session(trace["role"], trace["task"], trace.get("contract_v2", False))
        return [s.score(x) for x in trace["actions"]]


@dataclass
class Session:
    guard: DriftGuard
    role: str
    task: str
    approved: bool = False
    history: list = field(default_factory=list)
    tainted: bool = False
    cusum: float = 0.0
    prev: str = "<s>"
    sensitive: set = field(default_factory=set)

    def score(self, action: dict) -> Verdict:
        t0 = time.perf_counter()
        g = self.guard
        x = normalize(action, self.role)
        c = g.contracts.get(x["role"], approved=self.approved)
        reasons, s = [], {}

        # 1. role policy
        pol = 0.0
        if x["tool"] not in c.tools:
            pol += .6; reasons.append(f"tool '{x['tool']}' outside role")
        if x["data"] not in c.data:
            pol += .6; reasons.append(f"data class '{x['data']}' outside role")
        if x["dest"] and x["dest"] not in c.egress and x["tool"] in EGRESS_TOOLS:
            pol += .5; reasons.append(f"destination {x['dest']} not in contract")
        s["policy"] = min(pol, 1)

        # 2. behaviour drift: Markov surprise, CUSUM, bursts, peer-role breadth
        z = (g._surprise(x["role"], self.prev, x["tool"]) - g.mu) / g.sd
        self.cusum = max(0.0, self.cusum + z - 0.5)
        beh = max(0, min(1, z / 4)) + min(1, self.cusum / 12)
        same = sum(1 for y in self.history[-8:] if y["tool"] == x["tool"])
        if same >= 5:
            beh += .5; reasons.append(f"burst: {same + 1}x {x['tool']} in 9 actions")
        if x["data"] in SENSITIVE and x["role"] == self.role:
            self.sensitive.add(x["resource"])
        floor = 0
        limit = g.breadth.get(self.role, 10)
        if len(self.sensitive) > limit:
            beh = 1.0; floor = 65
            reasons.append(f"{len(self.sensitive)} sensitive records this session; "
                           f"peer agents of this role touch <= {int(limit)}")
        s["behavior"] = min(beh, 1)

        # 3. task alignment
        task_tools = set(g.contracts.get(self.role).tasks.get(self.task, []))
        s["task"] = 0.0 if (x["tool"] in task_tools or x["role"] != self.role) else 0.5
        if s["task"] and x["data"] in ("hr", "finance") and x["data"] not in c.data:
            s["task"] = 1.0; reasons.append("action does not serve the user's task")

        # 4. provenance taint
        if x["untrusted"]:
            self.tainted = True
        taint = 0.0
        if self.tainted and x["tool"] in EGRESS_TOOLS and x["dest"] not in KNOWN_HOSTS:
            taint = 1.0; floor = 85
            reasons.append(f"tainted context -> egress to unknown host {x['dest']}")
        elif self.tainted and x["data"] not in c.data:
            taint = .7; reasons.append("untrusted content preceded off-role data access")
        if x["tool"] in EGRESS_TOOLS and x["dest"] not in KNOWN_HOSTS:
            floor = max(floor, 70); reasons.append(f"first-ever egress to {x['dest']}")
        s["taint"] = taint

        # 5. decoy tripwire
        if x["resource"] in DECOYS:
            floor = 95; reasons.append(f"DECOY touched: {x['resource']}")

        # 6. chain authority: a callee may not exceed its caller's authority
        ch = 0.0
        if x["caller"]:
            cc = g.contracts.get(x["caller"])
            if x["data"] not in cc.allows_data_from(x["role"]):
                ch = 1.0; floor = max(floor, 75)
                reasons.append(f"{x['caller']} -> {x['role']}: callee used '{x['data']}' "
                               f"data the caller may not hold")
        s["chain"] = ch

        risk = min(100, max(floor, round(100 * sum(WEIGHTS[k] * v for k, v in s.items()))))
        self.prev = x["tool"]
        self.history.append(x)
        return Verdict(risk, tier(risk), reasons, {k: round(v, 2) for k, v in s.items()},
                       floor, (time.perf_counter() - t0) * 1000)
