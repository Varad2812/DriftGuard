"""Attack simulator: benign agent sessions plus six attack families.

Every attack keeps the agent's credentials valid, which is the point of the
problem: IAM sees nothing wrong.
"""
from __future__ import annotations

import random

from .contracts import ContractRegistry
from .world import DECOYS, TOOL_DATA, TOOL_DEST

ATTACKS = ["injection", "stolen_token", "poisoned_tool", "slow_drift", "mimicry", "chain"]
ATTACK_ROLE = {"injection": "procurement", "stolen_token": "finance", "poisoned_tool": "support",
               "slow_drift": "hr_assistant", "mimicry": "procurement", "chain": "support"}


def act(tool, role, untrusted=False, data=None, dest=None, resource=None, caller=None, malicious=False):
    return dict(tool=tool, data=data or TOOL_DATA.get(tool, "internal"), dest=dest or TOOL_DEST.get(tool),
                untrusted=untrusted, resource=resource or f"{tool}:{random.randint(1, 400)}", caller=caller,
                malicious=malicious, role=role)


class Simulator:
    def __init__(self, registry: ContractRegistry | None = None):
        self.contracts = registry or ContractRegistry()

    def benign(self, role, rng, contract_change=False):
        c = self.contracts.get(role)
        task = rng.choice(list(c.tasks))
        seq = []
        for _ in range(rng.randint(2, 4)):
            for t in c.tasks[task]:
                if rng.random() < 0.85:
                    untrusted = t in ("read_doc", "search_suppliers", "read_ticket") and rng.random() < 0.6
                    seq.append(act(t, role, untrusted=untrusted))
            if rng.random() < 0.2:  # legitimate in-role exploration outside the current task
                seq.append(act(rng.choice(sorted(c.tools)), role))
        if contract_change:  # approved v2 contract adds read_file; the agent starts using it
            seq.append(act("read_file", role, data="internal", resource="shared/approved_template.docx"))
        if role == "support" and rng.random() < 0.3:  # declared delegation: refund lookup via finance
            seq.append(act("read_ledger", "finance", caller="support", data="finance"))
        return dict(role=role, task=task, actions=seq, attack=None, contract_v2=contract_change)

    def attack(self, kind, rng):
        role = ATTACK_ROLE[kind]
        base = self.benign(role, rng)
        a = base["actions"][: rng.randint(3, 6)]
        if kind == "injection":  # hidden instruction in a supplier PDF
            a += [act("read_doc", role, untrusted=True, resource="supplier_quote.pdf"),
                  act("read_file", role, data="hr", resource="hr/payroll_2026.xlsx", malicious=True),
                  act("http_post", role, data="hr", dest="x91-collect.net", malicious=True)]
        elif kind == "stolen_token":  # attacker tooling: bursty bulk reads, then egress, no taint
            a += [act("read_ledger", role, malicious=True) for _ in range(rng.randint(6, 12))]
            a += [act("http_post", role, data="finance", dest="paste-drop.io", malicious=True)]
        elif kind == "poisoned_tool":  # the tool's output carries the instruction
            a += [act("search_kb", role, untrusted=True, resource="kb/plugin_v2_result"),
                  act("lookup_customer", role, malicious=True),
                  act("reply_ticket", role, data="customer", dest="ext-support-helper.com", malicious=True)]
        elif kind == "slow_drift":  # in-role tool, slowly widening to records it never needs
            for i in range(rng.randint(8, 14)):
                a.append(act("lookup_employee", role, resource=f"emp:{1000 + i * 37}", malicious=True))
                if rng.random() < 0.5:
                    a.append(act("read_policy", role))
            a.append(act("send_email", role, data="hr", dest="mail.internal", malicious=True))
        elif kind == "mimicry":  # copies normal tool frequencies, touches one real-looking record
            a += [act(t, role) for t in rng.sample(self.contracts.get(role).tasks["compare_prices"] * 2, 4)]
            target = rng.choice(sorted(DECOYS)) if rng.random() < 0.7 else "finance/vendor_bank_details.csv"
            a += [act("read_doc", role, data="finance", resource=target, malicious=True),
                  act("send_email", role, data="finance", dest="mail.internal", malicious=True)]
        elif kind == "chain":  # confused deputy: support asks the finance agent for payroll
            a += [act("read_ticket", role, untrusted=True, resource="ticket:urgent-ceo"),
                  act("read_ledger", "finance", caller="support", data="hr", resource="payroll/ledger", malicious=True),
                  act("reply_ticket", role, data="hr", malicious=True)]
        return dict(role=role, task=base["task"], actions=a, attack=kind, contract_v2=False)

    def dataset(self, seed, train_per_role=150, benign_per_role=250, attacks_per_kind=100, change_rate=0.15):
        """Train set (benign only) and a test set (benign + every attack family)."""
        rng = random.Random(seed)
        random.seed(seed)
        roles = self.contracts.roles
        train = [self.benign(r, rng) for r in roles for _ in range(train_per_role)]
        test = [self.benign(r, rng, contract_change=(rng.random() < change_rate))
                for r in roles for _ in range(benign_per_role)]
        test += [self.attack(k, rng) for k in ATTACKS for _ in range(attacks_per_kind)]
        return train, test
