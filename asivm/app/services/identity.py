"""Identity-first asset correlation: many identifiers -> one persistent asset."""
import ipaddress
import re
from dataclasses import dataclass, field

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ..models import (Asset, AssetIdentifier, Finding, FindingEvent, ServiceObservation,
                      Software, utcnow)

WEIGHT = {"mac": 1.0, "cloud_id": 1.0, "serial": 1.0, "fqdn": 0.9, "artifact": 0.9,
          "hostname": 0.7, "ip": 0.4}
STRONG = {"mac", "cloud_id", "serial"}
NAME_TYPES = ("hostname", "fqdn", "artifact")


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def _norm(t: str, v) -> str | None:
    v = str(v).strip()
    if not v:
        return None
    if t == "mac":
        v = v.lower().replace("-", ":")
        return v if re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", v) else None
    if t == "ip":
        return str(ipaddress.ip_address(v)) if _is_ip(v) else None
    if t in ("hostname", "fqdn"):
        return v.lower().rstrip(".")
    return v if t in WEIGHT else None


def expand(identifiers: dict) -> list[tuple[str, str]]:
    out: set[tuple[str, str]] = set()
    for t, vals in identifiers.items():
        if vals is None:
            continue
        for raw in ([vals] if isinstance(vals, (str, int)) else vals):
            n = _norm(t, raw)
            if not n:
                continue
            if t in ("hostname", "fqdn"):
                if _is_ip(n):
                    continue
                if "." in n:
                    out.add(("fqdn", n))
                    out.add(("hostname", n.split(".")[0]))
                else:
                    out.add(("hostname", n))
            else:
                out.add((t, n))
    return sorted(out)


@dataclass
class Resolution:
    asset: Asset
    created: bool
    confidence: float
    reason: str
    merged: list[int] = field(default_factory=list)


def active_identifiers(db: Session, asset_id: int) -> dict[str, set[str]]:
    d: dict[str, set[str]] = {}
    for r in db.scalars(select(AssetIdentifier).where(AssetIdentifier.asset_id == asset_id,
                                                       AssetIdentifier.active == True)):  # noqa: E712
        d.setdefault(r.type, set()).add(r.value)
    return d


def resolve(db: Session, org_id: int, identifiers: dict, source: str = "manual",
            name: str | None = None, actor: str = "system") -> Resolution:
    ids = expand(identifiers)
    if not ids:
        raise ValueError("no usable identifiers supplied")
    inp: dict[str, set[str]] = {}
    for t, v in ids:
        inp.setdefault(t, set()).add(v)

    cands: dict[int, list[str]] = {}
    for t, v in ids:
        rows = db.scalars(
            select(AssetIdentifier.asset_id)
            .join(Asset, Asset.id == AssetIdentifier.asset_id)
            .where(AssetIdentifier.org_id == org_id, AssetIdentifier.type == t,
                   AssetIdentifier.value == v, AssetIdentifier.active == True,  # noqa: E712
                   Asset.status != "merged"))
        for aid in set(rows):
            cands.setdefault(aid, []).append(t)

    good = []
    for aid, matched in cands.items():
        cur = active_identifiers(db, aid)
        strong_match = any(t in STRONG for t in matched)
        if any(t in STRONG and t in cur and not (cur[t] & inp[t]) for t in inp):
            continue  # a strong identifier disagrees: it is a different machine
        if not strong_match and any(t in cur and not (cur[t] & inp[t]) for t in inp if t in NAME_TYPES):
            continue  # names disagree and nothing strong ties them: e.g. IP reassigned
        uniq = set(matched)
        score = min(1.0, max(WEIGHT[t] for t in uniq) + 0.05 * (len(uniq) - 1))
        good.append((score, aid, strong_match, sorted(uniq)))

    merged: list[int] = []
    if good:
        strongs = sorted([g for g in good if g[2]], key=lambda g: g[1])
        good.sort(key=lambda g: (-g[0], g[1]))
        if len(strongs) > 1:
            keep = db.get(Asset, strongs[0][1])
            for g in strongs[1:]:
                merge_assets(db, keep, db.get(Asset, g[1]), actor)
                merged.append(g[1])
            best = strongs[0]
        else:
            best = good[0]
        asset = db.get(Asset, best[1])
        res = Resolution(asset, False, best[0], f"matched on {', '.join(best[3])}", merged)
    else:
        nm = name or next((v for t in ("fqdn", "hostname", "artifact", "ip") for tt, v in ids if tt == t), ids[0][1])
        asset = Asset(org_id=org_id, name=nm, source=source)
        db.add(asset)
        db.flush()
        res = Resolution(asset, True, 1.0, "no existing asset matched; created new", [])

    now = utcnow()
    for t, v in ids:
        r = db.scalar(select(AssetIdentifier).where(AssetIdentifier.asset_id == asset.id,
                                                    AssetIdentifier.type == t, AssetIdentifier.value == v))
        if r:
            r.active, r.last_seen = True, now
        else:
            db.add(AssetIdentifier(org_id=org_id, asset_id=asset.id, type=t, value=v))
        if t == "ip":  # the address now belongs to this asset
            db.execute(update(AssetIdentifier).where(
                AssetIdentifier.org_id == org_id, AssetIdentifier.type == "ip",
                AssetIdentifier.value == v, AssetIdentifier.asset_id != asset.id).values(active=False))
    if asset.name and _is_ip(asset.name):
        better = next((v for t in ("fqdn", "hostname") for tt, v in ids if tt == t), None)
        if better:
            asset.name = better
    asset.last_seen = now
    db.flush()
    return res


def fingerprint(asset_id: int, fp_key: str) -> str:
    import hashlib
    return hashlib.sha256(f"{asset_id}|{fp_key}".encode()).hexdigest()


def merge_assets(db: Session, keep: Asset, drop: Asset, actor: str = "system"):
    if keep.id == drop.id:
        raise ValueError("cannot merge an asset into itself")
    have = {(r.type, r.value) for r in db.scalars(select(AssetIdentifier).where(AssetIdentifier.asset_id == keep.id))}
    for r in db.scalars(select(AssetIdentifier).where(AssetIdentifier.asset_id == drop.id)).all():
        if (r.type, r.value) in have:
            db.delete(r)
        else:
            r.asset_id = keep.id
    keep_svc = {(s.port, s.protocol) for s in db.scalars(select(ServiceObservation).where(ServiceObservation.asset_id == keep.id))}
    for s in db.scalars(select(ServiceObservation).where(ServiceObservation.asset_id == drop.id)).all():
        if (s.port, s.protocol) in keep_svc:
            db.delete(s)
        else:
            s.asset_id = keep.id
    for s in db.scalars(select(Software).where(Software.asset_id == drop.id)):
        s.asset_id = keep.id
    for f in db.scalars(select(Finding).where(Finding.asset_id == drop.id)).all():
        fp = fingerprint(keep.id, f.fp_key)
        dup = db.scalar(select(Finding).where(Finding.org_id == f.org_id, Finding.fingerprint == fp))
        if dup:
            for e in db.scalars(select(FindingEvent).where(FindingEvent.finding_id == f.id)):
                db.delete(e)
            db.delete(f)
        else:
            f.asset_id, f.fingerprint = keep.id, fp
            db.add(FindingEvent(finding_id=f.id, org_id=f.org_id, from_state=f.state, to_state=f.state,
                                actor=actor, note=f"asset #{drop.id} merged into #{keep.id}"))
    for attr in ("owner", "department", "asset_type", "os"):
        if not getattr(keep, attr) and getattr(drop, attr):
            setattr(keep, attr, getattr(drop, attr))
    keep.criticality = max(keep.criticality, drop.criticality)
    keep.first_seen = min(keep.first_seen, drop.first_seen)
    drop.status, drop.merged_into_id = "merged", keep.id
    db.flush()
