"""Benchmark: detection rate, false alarms and time-to-detect across seeds."""
from __future__ import annotations

import statistics
from collections import Counter

from .baselines import AnomalyOnly, IAMOnly
from .contracts import ContractRegistry
from .detector import DriftGuard, percentile
from .simulator import ATTACKS, Simulator

THRESHOLD = 60  # "downscope" tier or higher counts as an alert


def evaluate(score_fn, traces, thr=THRESHOLD):
    det, fp, ttd = Counter(), 0, []
    n_benign = sum(1 for t in traces if not t["attack"])
    for tr in traces:
        sc = score_fn(tr)
        if not tr["attack"]:
            fp += any(r >= thr for r in sc)
            continue
        first = next(i for i, x in enumerate(tr["actions"]) if x["malicious"])
        hit = next((i for i in range(first, len(sc)) if sc[i] >= thr), None)
        if hit is not None:  # alerts before the first malicious step do not count as detection
            det[tr["attack"]] += 1
            ttd.append(hit - first + 1)
    n_att = Counter(t["attack"] for t in traces if t["attack"])
    return {
        "detection": sum(det.values()) / sum(n_att.values()),
        "false_alarm_rate": fp / n_benign,
        "per_attack": {k: det[k] / n_att[k] for k in ATTACKS if k in n_att},
        "ttd_median": statistics.median(ttd) if ttd else None,
        "ttd_p95": percentile(ttd, 95) if ttd else None,
        "n_attack": sum(n_att.values()), "n_benign": n_benign,
    }


def run(seeds=range(100, 110), with_anomaly=True, log=print):
    reg = ContractRegistry()
    sim = Simulator(reg)
    rows = {"IAM only": [], "Anomaly only (UEBA)": [], "DriftGuard": []}
    latency = []
    for seed in seeds:
        train, test = sim.dataset(seed)
        dg = DriftGuard(reg).fit(train)

        def dg_scores(tr):
            v = dg.run(tr)
            latency.extend(x.ms for x in v)
            return [x.risk for x in v]

        rows["DriftGuard"].append(evaluate(dg_scores, test))
        rows["IAM only"].append(evaluate(IAMOnly(reg).run, test))
        if with_anomaly:
            try:
                rows["Anomaly only (UEBA)"].append(evaluate(AnomalyOnly().fit(train).run, test))
            except ImportError as e:
                log(f"skipping anomaly baseline: {e}")
                with_anomaly = False
        d = rows["DriftGuard"][-1]
        log(f"seed {seed}: DriftGuard caught {d['detection']:.1%}, false alarms {d['false_alarm_rate']:.1%}")
    summary = {}
    for name, rs in rows.items():
        if not rs:
            continue
        det = [r["detection"] for r in rs]
        far = [r["false_alarm_rate"] for r in rs]
        ttd = [r["ttd_median"] for r in rs if r["ttd_median"] is not None]
        summary[name] = {
            "detection_mean": statistics.mean(det), "detection_sd": statistics.pstdev(det),
            "false_alarm_mean": statistics.mean(far),
            "ttd_median": statistics.median(ttd) if ttd else None,
            "per_attack": {k: statistics.mean(r["per_attack"][k] for r in rs) for k in ATTACKS},
        }
    summary["DriftGuard"]["latency_ms_p99"] = percentile(latency, 99)
    summary["DriftGuard"]["actions_scored"] = len(latency)
    summary["config"] = {"seeds": list(seeds), "sessions": sum(r["n_attack"] + r["n_benign"] for r in rows["DriftGuard"]),
                         "attacks": sum(r["n_attack"] for r in rows["DriftGuard"]),
                         "benign": sum(r["n_benign"] for r in rows["DriftGuard"]), "alert_threshold": THRESHOLD}
    return summary
