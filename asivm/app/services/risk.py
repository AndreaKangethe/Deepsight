"""Contextual risk score 0-100 with every input recorded for audit."""
import copy

DEFAULT_POLICY = {
    "weights": {"cvss": 40, "kev": 25, "epss": 20, "criticality": 8, "exposure": 7},
    "exposure_factor": {"internal": 0.2, "dmz": 0.6, "internet": 1.0},
    "tiers": {"critical": 75, "high": 55, "medium": 35},
    "sla_days": {"critical": 7, "high": 30, "medium": 90, "low": 180},
    "unknown_cvss_assumed": 5.0,
}


def get_policy(org) -> dict:
    p = copy.deepcopy(DEFAULT_POLICY)
    for k, v in ((getattr(org, "settings", None) or {}).get("risk_policy") or {}).items():
        if isinstance(v, dict) and isinstance(p.get(k), dict):
            p[k].update(v)
        else:
            p[k] = v
    return p


def tier_for(score: float, policy: dict) -> str:
    t = policy["tiers"]
    return "critical" if score >= t["critical"] else "high" if score >= t["high"] else "medium" if score >= t["medium"] else "low"


def compute(vuln, asset, confidence: float, policy: dict):
    w = policy["weights"]
    cvss = vuln.cvss if vuln.cvss is not None else policy["unknown_cvss_assumed"]
    epss = vuln.epss or 0.0
    exp = policy["exposure_factor"].get(asset.exposure, 0.2)
    parts = {
        "cvss": round(cvss / 10 * w["cvss"], 2),
        "kev": float(w["kev"]) if vuln.kev else 0.0,
        "epss": round(epss * w["epss"], 2),
        "criticality": round((asset.criticality - 1) / 4 * w["criticality"], 2),
        "exposure": round(exp * w["exposure"], 2),
    }
    base = sum(parts.values())
    mult = round(0.7 + 0.3 * max(0.0, min(1.0, confidence)), 3)
    score = round(min(100.0, base * mult), 1)
    floor = None
    if vuln.kev and asset.exposure == "internet" and score < policy["tiers"]["high"]:
        score, floor = float(policy["tiers"]["high"]), "KEV on internet-exposed asset raised to 'high'"
    inputs = {"cvss": vuln.cvss, "cvss_assumed": vuln.cvss is None, "kev": bool(vuln.kev),
              "epss": vuln.epss, "asset_criticality": asset.criticality, "asset_exposure": asset.exposure,
              "match_confidence": confidence, "components": parts, "confidence_multiplier": mult,
              "floor_applied": floor}
    return score, tier_for(score, policy), inputs
