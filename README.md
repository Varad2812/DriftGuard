# DriftGuard

**Catch AI agents that stop doing their job, even while their credentials are still valid.**

Built by **Team Akshaya** (VIT Pune) for **D3COY 1.0** · Problem statement: *Identity Drift Detection in Autonomous AI Agents*.

![DriftGuard console](docs/console.png)

## The problem

Companies give AI agents their own tokens and permissions. Security checks *who* the agent is, never *whether it is still doing the job it was created for*. A hidden instruction in a PDF, a poisoned tool or a stolen token changes what the agent does while every access check keeps passing.

## How DriftGuard works

Every agent action passes through the DriftGuard gateway and is judged against the agent's **Role Contract**, a short YAML file that declares what the agent is for.

```mermaid
flowchart LR
  A[AI agent] -->|tool call + token| G[DriftGuard gateway]
  G --> D{6 signals}
  D --> R[Risk 0-100 + reasons]
  R -->|0-29| W[allow]
  R -->|30-59| H[ask a human]
  R -->|60-84| S[downscope token]
  R -->|85+| I[isolate + revoke]
  G -->|allowed calls only| T[(tools, data, APIs)]
  C[Role contracts YAML] --> D
```

| # | Signal | How | Catches |
|---|---|---|---|
| 1 | Role policy | Action vs. the Role Contract | Out-of-role tool, data class or host |
| 2 | Behaviour drift | Markov surprise, CUSUM, bursts, peer-role breadth | Stolen tokens, slow drift |
| 3 | Task alignment | Action vs. the user's task (rule stand-in for an LLM judge) | Goal hijack with no rule broken |
| 4 | Provenance taint | Untrusted input followed by sensitive access or egress | Prompt injection, poisoned tools |
| 5 | Decoy tripwires | Honey records no real job touches | Mimicry |
| 6 | Chain authority | A callee may never exceed its caller's authority | Confused deputy across agents |

`Risk = max(floor, 100 × Σ wᵢ·sᵢ)`. Hard evidence sets a floor: decoy touched ≥ 95, tainted data sent to an unknown host ≥ 85.

## Quickstart

Python 3.10+ and PyYAML. scikit-learn is only needed for the anomaly baseline in the benchmark.

```bash
git clone https://github.com/Varad2812/driftguard.git && cd driftguard
pip install -r requirements.txt

python -m driftguard demo      # replay the Procurement-Agent hijack from the problem statement
python -m driftguard bench     # reproduce the benchmark below (about 3 minutes)
python -m driftguard serve     # gateway API + console on http://127.0.0.1:8080
python -m unittest discover -s tests -t .
```

### Demo output

```
 #  action                             risk                       decision
 7  read_doc supplier_quote.pdf          19  ###                  ALLOW
 8  read_file hr/payroll_2026.xlsx       79  ###############      BLOCK  token downscoped (removed: customer, finance, hr, http_post, secret)
 9  http_post x91-collect.net             -                       REJECTED  out-of-scope retry after downscope: agent isolated, token revoked
10  http_post x91-collect.net             -                       REJECTED  procurement-agent-07 is isolated
```

IAM would have allowed all of these actions: the token was valid the whole time.

![Real run: demo, tests and benchmark](docs/implementation.png)

## Results

`python -m driftguard bench`: 16,000 simulated agent sessions (6,000 attacks, 10,000 normal sessions including approved role changes and declared delegation), 4 roles, 10 random seeds. An alert means risk ≥ 60.

| Approach | Attacks caught | False alarms | Median actions to detect |
|---|---|---|---|
| IAM only | 0.0% | 0.0% | – |
| Anomaly only (UEBA-style Isolation Forest) | 20.1% | 5.8% | 4 |
| **DriftGuard** | **97.5%** (±0.4) | **0.0%** | **2** |

| Attack family | Caught |
|---|---|
| Prompt injection | 100% |
| Stolen token | 100% |
| Poisoned tool | 100% |
| Slow drift | 100% |
| Mimicry | 84.9% |
| Agent chain (confused deputy) | 100% |

Scoring costs under 0.02 ms per action (p99, detector only, one CPU core). Full numbers land in `results/benchmark.json`.

**Limitations.** The traces are synthetic and the task-alignment signal is rule-based. Mimicry that avoids every decoy is the weakest case. Next steps: run AgentDojo with live LLM agents, replace the task rules with a small LLM judge, and add masked re-execution to confirm hijacks before blocking.

## Gateway API

```http
POST /v1/sessions   {"agent_id": "procurement-agent-07", "role": "procurement", "task": "raise_pr"}
POST /v1/actions    {"session_id": "...", "tool": "read_file", "data": "hr", "resource": "hr/payroll_2026.xlsx"}
                    Authorization: Bearer <agent token>
GET  /v1/alerts     GET /v1/agents     GET /v1/contracts/<role>     GET /healthz
```

`examples/hijack_client.py` replays the hijack against a running gateway over HTTP.

## Project layout

```
contracts/            Role Contracts (YAML), versioned, with human-approved changes
driftguard/
  contracts.py        loads contracts, applies approved changes, declared delegation
  detector.py         the six signals and the explainable risk score (streaming, per session)
  response.py         graded response: token downscoping and revocation
  gateway.py          zero-dependency HTTP gateway + console
  simulator.py        benign sessions and six attack families
  baselines.py        IAM-only and anomaly-only baselines
  bench.py            benchmark harness
console/index.html    SOC console (3D agent graph, alert detail, action stream)
tests/                unit and end-to-end gateway tests
```

## Standards

Maps to OWASP Top 10 for Agentic Applications (ASI01 Agent Goal Hijack, ASI03 Identity & Privilege Abuse, ASI10 Rogue Agents) and the NIST NCCoE focus on agent identity, authorization and data-flow logging.

## License

MIT
