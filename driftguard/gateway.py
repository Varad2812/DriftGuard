"""DriftGuard gateway: a zero-dependency HTTP service every agent action passes through.

  POST /v1/sessions   {"agent_id", "role", "task"}              -> session id + agent token
  POST /v1/actions    {"session_id", "tool", ...}  (Bearer tok)  -> risk, reasons, decision
  GET  /v1/alerts     alerts raised so far
  GET  /v1/agents     agents, token state and latest risk
  GET  /v1/contracts/<role>
  GET  /healthz
  GET  /              the SOC console
"""
from __future__ import annotations

import json
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .contracts import ContractRegistry
from .detector import DriftGuard, normalize
from .response import TokenBroker, respond
from .simulator import Simulator

CONSOLE = Path(__file__).resolve().parent.parent / "console" / "index.html"


class Gateway:
    def __init__(self, registry: ContractRegistry | None = None, warm_start_seed: int = 7):
        self.contracts = registry or ContractRegistry()
        # Day-zero baseline: learn from simulated benign sessions of each declared role.
        train, _ = Simulator(self.contracts).dataset(warm_start_seed, benign_per_role=0, attacks_per_kind=0)
        self.guard = DriftGuard(self.contracts).fit(train)
        self.broker = TokenBroker(self.contracts)
        self.sessions, self.alerts, self.latest = {}, [], {}
        self.lock = threading.Lock()

    def open_session(self, agent_id, role, task, approved_changes=False):
        with self.lock:
            tok = self.broker.tokens.get(agent_id)
            if tok is None or tok.role != role:
                tok = self.broker.issue(agent_id, role)
            if tok.revoked:
                return 403, {"error": f"{agent_id} is isolated; a human must restore it"}
            sid = "s_" + uuid.uuid4().hex[:10]
            self.sessions[sid] = (agent_id, self.guard.session(role, task, approved_changes))
            return 200, {"session_id": sid, "token": tok.value, "contract_version": self.contracts.get(role, approved_changes).version}

    def act(self, sid, token, action):
        with self.lock:
            if sid not in self.sessions:
                return 404, {"error": "unknown session"}
            agent_id, session = self.sessions[sid]
            tok = self.broker.tokens[agent_id]
            if token != tok.value:
                return 401, {"error": "bad token"}
            if tok.revoked:
                return 403, {"decision": "block", "error": f"{agent_id} is isolated"}
            x = normalize(action, session.role)
            if not self.broker.permits(agent_id, x["tool"], x["data"]):
                if any(e[1] == "downscoped" for e in tok.events):
                    # Still reaching for scopes it just lost: treat as confirmed hijack.
                    self.broker.revoke(agent_id)
                    out = {"agent_id": agent_id, "decision": "block", "tier": "isolate",
                           "error": "out-of-scope retry after downscope: agent isolated, token revoked"}
                    self.alerts.append({"ts": time.time(), "action": x, **out})
                    self.latest[agent_id] = {"risk": 100, "tier": "isolate", "ts": time.time()}
                    return 403, out
                return 403, {"decision": "block", "error": "denied by token scopes"}
            v = session.score(x)
            out = {"agent_id": agent_id, "step": len(session.history), **v.to_dict(), **respond(self.broker, agent_id, v, x)}
            self.latest[agent_id] = {"risk": v.risk, "tier": v.tier, "ts": time.time()}
            if v.tier in ("downscope", "isolate"):
                self.alerts.append({"ts": time.time(), "action": x, **out})
            return 200, out

    def agents(self):
        return [{"agent_id": a, "role": t.role, "revoked": t.revoked, "tools": sorted(t.tools), "data": sorted(t.data),
                 **self.latest.get(a, {})} for a, t in self.broker.tokens.items()]


def make_handler(gw: Gateway):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):  # quiet
            pass

        def _send(self, code, body, ctype="application/json"):
            data = body if isinstance(body, bytes) else json.dumps(body, indent=1).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _json(self):
            n = int(self.headers.get("Content-Length", 0) or 0)
            return json.loads(self.rfile.read(n) or b"{}")

        def do_GET(self):
            p = self.path.split("?")[0]
            if p == "/healthz":
                return self._send(200, {"ok": True, "roles": gw.contracts.roles})
            if p == "/v1/alerts":
                return self._send(200, gw.alerts)
            if p == "/v1/agents":
                return self._send(200, gw.agents())
            if p.startswith("/v1/contracts/"):
                role = p.rsplit("/", 1)[-1]
                if role not in gw.contracts:
                    return self._send(404, {"error": "unknown role"})
                c = gw.contracts.get(role, approved=True)
                return self._send(200, {k: sorted(v) if isinstance(v, frozenset) else v for k, v in c.__dict__.items()})
            if p in ("/", "/console") and CONSOLE.exists():
                return self._send(200, CONSOLE.read_bytes(), "text/html; charset=utf-8")
            return self._send(404, {"error": "not found"})

        def do_POST(self):
            try:
                body = self._json()
            except json.JSONDecodeError:
                return self._send(400, {"error": "invalid JSON"})
            if self.path == "/v1/sessions":
                for k in ("agent_id", "role", "task"):
                    if k not in body:
                        return self._send(400, {"error": f"missing '{k}'"})
                if body["role"] not in gw.contracts:
                    return self._send(400, {"error": f"no role contract for '{body['role']}'"})
                return self._send(*gw.open_session(body["agent_id"], body["role"], body["task"],
                                                   bool(body.get("approved_changes"))))
            if self.path == "/v1/actions":
                tok = self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
                if "tool" not in body or "session_id" not in body:
                    return self._send(400, {"error": "need 'session_id' and 'tool'"})
                return self._send(*gw.act(body["session_id"], tok, body))
            return self._send(404, {"error": "not found"})

    return Handler


def serve(host="127.0.0.1", port=8080):
    gw = Gateway()
    srv = ThreadingHTTPServer((host, port), make_handler(gw))
    print(f"DriftGuard gateway on http://{host}:{port}  (roles: {', '.join(gw.contracts.roles)})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return srv
