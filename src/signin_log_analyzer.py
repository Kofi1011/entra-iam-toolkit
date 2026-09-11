#!/usr/bin/env python3
"""
Entra ID Sign-in Log Analyzer
=============================================================================
Identity threat-detection for Microsoft Entra ID (Azure AD) sign-in logs.

Parses an Entra sign-in log export (CSV/JSON) and flags identity risks that
an IAM / SOC analyst would triage:

    * Password-spray / brute-force  (many failures across/against accounts)
    * Impossible travel             (two sign-ins too far apart, too fast)
    * New-country sign-ins          (first time a user logs in from a country)
    * Legacy authentication         (deprecated protocols that bypass MFA)
    * MFA not satisfied on success  (successful auth without strong MFA)

Output: a prioritized risk report (console + CSV) with HIGH/MEDIUM/LOW
severities, mapped to MITRE ATT&CK techniques for interview talking points.

Usage:
    python signin_log_analyzer.py --input signin_logs.csv --out risk_report.csv
    python signin_log_analyzer.py --input logs.csv --spray-threshold 5 --travel-kmh 900

Author: Kofi Williams
License: MIT
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable

# --------------------------------------------------------------------------- #
# Configuration defaults (all overridable via CLI)
# --------------------------------------------------------------------------- #
DEFAULT_SPRAY_THRESHOLD = 5        # failed sign-ins ...
DEFAULT_SPRAY_WINDOW_MIN = 10      # ... within this many minutes = spray/brute-force
DEFAULT_TRAVEL_KMH = 900           # faster than this between two logins = impossible travel
LEGACY_CLIENTS = {                 # Entra "clientAppUsed" values that bypass modern auth
    "Other clients",
    "IMAP4",
    "POP3",
    "SMTP",
    "MAPI",
    "Exchange ActiveSync",
    "Authenticated SMTP",
}

# MITRE ATT&CK mapping — useful to name-drop in interviews
MITRE = {
    "password_spray": "T1110.003 (Password Spraying)",
    "brute_force": "T1110.001 (Brute Force)",
    "impossible_travel": "T1078 (Valid Accounts) / anomalous access",
    "new_country": "T1078 (Valid Accounts)",
    "legacy_auth": "T1078.004 / MFA bypass",
    "mfa_not_satisfied": "T1621 (MFA Request Generation) / weak auth",
}

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class SignIn:
    """One normalized sign-in event."""
    user: str
    timestamp: datetime
    ip: str
    city: str
    country: str
    lat: float | None
    lon: float | None
    status: str          # "success" or "failure"
    client_app: str
    mfa_result: str      # e.g. "satisfied", "notApplied", "" 

    @property
    def is_failure(self) -> bool:
        return self.status.lower().startswith("fail")


@dataclass
class Finding:
    severity: str
    user: str
    category: str
    detail: str
    mitre: str
    timestamp: str = ""


# --------------------------------------------------------------------------- #
# Parsing / normalization
# --------------------------------------------------------------------------- #
def _parse_ts(raw: str) -> datetime:
    """Handle the ISO variants Entra exports (with/without Z, ms)."""
    raw = (raw or "").strip().replace("Z", "+00:00")
    for fmt in (None,):  # try fromisoformat first
        try:
            return datetime.fromisoformat(raw)
        except ValueError:
            break
    for fmt in ("%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(raw[:19], fmt)
        except ValueError:
            continue
    raise ValueError(f"Unrecognized timestamp: {raw!r}")


def _to_float(v) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _normalize(row: dict) -> SignIn | None:
    """Map flexible column names (Entra portal export vs Graph JSON) -> SignIn."""
    def pick(*keys, default=""):
        for k in keys:
            if k in row and row[k] not in (None, ""):
                return row[k]
        return default

    user = pick("userPrincipalName", "user", "User", "UserPrincipalName")
    if not user:
        return None
    try:
        ts = _parse_ts(pick("createdDateTime", "timestamp", "Date (UTC)", "Date"))
    except ValueError:
        return None

    return SignIn(
        user=user.lower(),
        timestamp=ts,
        ip=pick("ipAddress", "ip", "IP address"),
        city=pick("city", "City"),
        country=pick("countryOrRegion", "country", "Country"),
        lat=_to_float(pick("latitude", "lat")),
        lon=_to_float(pick("longitude", "lon")),
        status=pick("status", "Status", default="success"),
        client_app=pick("clientAppUsed", "client_app", "Client app"),
        mfa_result=pick("mfaResult", "authenticationRequirement", "mfa", default=""),
    )


def load_signins(path: Path) -> list[SignIn]:
    text = path.read_text(encoding="utf-8-sig")
    rows: Iterable[dict]
    if path.suffix.lower() == ".json":
        data = json.loads(text)
        rows = data.get("value", data) if isinstance(data, dict) else data
    else:
        rows = list(csv.DictReader(text.splitlines()))

    events = [e for e in (_normalize(r) for r in rows) if e]
    events.sort(key=lambda e: (e.user, e.timestamp))
    return events


# --------------------------------------------------------------------------- #
# Geo helper
# --------------------------------------------------------------------------- #
def haversine_km(lat1, lon1, lat2, lon2) -> float:
    """Great-circle distance between two lat/lon points in km."""
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlmb = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlmb / 2) ** 2
    return 2 * r * math.asin(min(1.0, math.sqrt(a)))


# --------------------------------------------------------------------------- #
# Detections
# --------------------------------------------------------------------------- #
def detect_spray_bruteforce(events, threshold, window_min) -> list[Finding]:
    """Flag >= threshold failed sign-ins for one user inside a rolling window."""
    findings = []
    by_user = defaultdict(list)
    for e in events:
        if e.is_failure:
            by_user[e.user].append(e)

    window = timedelta(minutes=window_min)
    for user, fails in by_user.items():
        fails.sort(key=lambda e: e.timestamp)
        start = 0
        for end in range(len(fails)):
            while fails[end].timestamp - fails[start].timestamp > window:
                start += 1
            count = end - start + 1
            if count >= threshold:
                findings.append(Finding(
                    severity="HIGH",
                    user=user,
                    category="Brute force / password spray",
                    detail=f"{count} failed sign-ins within {window_min} min "
                           f"(from {fails[start].ip})",
                    mitre=MITRE["brute_force"],
                    timestamp=fails[end].timestamp.isoformat(),
                ))
                break  # one finding per user is enough
    return findings


def detect_impossible_travel(events, max_kmh) -> list[Finding]:
    """Flag consecutive successful sign-ins requiring impossible travel speed."""
    findings = []
    by_user = defaultdict(list)
    for e in events:
        if not e.is_failure and e.lat is not None and e.lon is not None:
            by_user[e.user].append(e)

    for user, ev in by_user.items():
        ev.sort(key=lambda e: e.timestamp)
        for a, b in zip(ev, ev[1:]):
            dist = haversine_km(a.lat, a.lon, b.lat, b.lon)
            hours = (b.timestamp - a.timestamp).total_seconds() / 3600
            if dist < 500 or hours <= 0:
                continue
            speed = dist / hours
            if speed > max_kmh:
                findings.append(Finding(
                    severity="HIGH",
                    user=user,
                    category="Impossible travel",
                    detail=f"{a.city or a.country} -> {b.city or b.country}: "
                           f"{dist:.0f} km in {hours*60:.0f} min "
                           f"(~{speed:.0f} km/h)",
                    mitre=MITRE["impossible_travel"],
                    timestamp=b.timestamp.isoformat(),
                ))
    return findings


def detect_new_country(events) -> list[Finding]:
    """Flag the first successful sign-in from a country not seen before for a user."""
    findings = []
    seen = defaultdict(set)
    for e in sorted(events, key=lambda e: e.timestamp):
        if e.is_failure or not e.country:
            continue
        if seen[e.user] and e.country not in seen[e.user]:
            sev = "MEDIUM" if "satisf" in e.mfa_result.lower() else "HIGH"
            findings.append(Finding(
                severity=sev,
                user=e.user,
                category="New-country sign-in",
                detail=f"First sign-in from {e.country} ({e.city}); "
                       f"MFA: {e.mfa_result or 'unknown'}",
                mitre=MITRE["new_country"],
                timestamp=e.timestamp.isoformat(),
            ))
        seen[e.user].add(e.country)
    return findings


def detect_legacy_auth(events) -> list[Finding]:
    """Flag legacy/basic-auth protocols that bypass Conditional Access + MFA."""
    findings, flagged = [], set()
    for e in events:
        if e.client_app in LEGACY_CLIENTS and e.user not in flagged:
            findings.append(Finding(
                severity="MEDIUM",
                user=e.user,
                category="Legacy authentication",
                detail=f"Legacy protocol '{e.client_app}' used (bypasses MFA/CA)",
                mitre=MITRE["legacy_auth"],
                timestamp=e.timestamp.isoformat(),
            ))
            flagged.add(e.user)
    return findings


def detect_mfa_gap(events) -> list[Finding]:
    """Flag successful sign-ins where MFA was single-factor / not applied."""
    findings, flagged = [], set()
    for e in events:
        if e.is_failure or e.user in flagged:
            continue
        result = e.mfa_result.lower()
        if result in ("singlefactorauthentication", "notapplied", ""):
            findings.append(Finding(
                severity="LOW",
                user=e.user,
                category="Weak / no MFA on success",
                detail=f"Successful sign-in with MFA state '{e.mfa_result or 'none'}'",
                mitre=MITRE["mfa_not_satisfied"],
                timestamp=e.timestamp.isoformat(),
            ))
            flagged.add(e.user)
    return findings


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def run_all(events, args) -> list[Finding]:
    findings = []
    findings += detect_spray_bruteforce(events, args.spray_threshold, args.spray_window)
    findings += detect_impossible_travel(events, args.travel_kmh)
    findings += detect_new_country(events)
    findings += detect_legacy_auth(events)
    findings += detect_mfa_gap(events)
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.user))
    return findings


def print_report(events, findings):
    counts = defaultdict(int)
    for f in findings:
        counts[f.severity] += 1

    print("\n" + "=" * 66)
    print("        ENTRA ID SIGN-IN RISK REPORT")
    print("=" * 66)
    print(f"Events analyzed : {len(events)}")
    print(f"Unique users    : {len({e.user for e in events})}")
    print(f"Findings        : {len(findings)}  "
          f"(HIGH: {counts['HIGH']}  MEDIUM: {counts['MEDIUM']}  LOW: {counts['LOW']})")
    print("-" * 66)
    if not findings:
        print("No identity risks detected. ✅")
    for f in findings:
        print(f"[{f.severity:<6}] {f.user:<26} {f.category}")
        print(f"          {f.detail}")
        print(f"          ATT&CK: {f.mitre}")
    print("=" * 66 + "\n")


def write_csv(findings, out_path: Path):
    with out_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["severity", "user", "category", "detail", "mitre_attack", "timestamp"])
        for f in findings:
            w.writerow([f.severity, f.user, f.category, f.detail, f.mitre, f.timestamp])
    print(f"Report written to {out_path}")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Analyze Entra ID sign-in logs for identity risks."
    )
    p.add_argument("--input", "-i", required=True, help="Sign-in log CSV or JSON export")
    p.add_argument("--out", "-o", default="risk_report.csv", help="Output CSV path")
    p.add_argument("--spray-threshold", dest="spray_threshold", type=int,
                   default=DEFAULT_SPRAY_THRESHOLD, help="Failed sign-ins to flag spray")
    p.add_argument("--spray-window", dest="spray_window", type=int,
                   default=DEFAULT_SPRAY_WINDOW_MIN, help="Spray detection window (minutes)")
    p.add_argument("--travel-kmh", dest="travel_kmh", type=float,
                   default=DEFAULT_TRAVEL_KMH, help="Impossible-travel speed threshold")
    p.add_argument("--fail-on-high", action="store_true",
                   help="Exit non-zero if any HIGH finding (for CI/automation)")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    path = Path(args.input)
    if not path.exists():
        print(f"ERROR: input file not found: {path}", file=sys.stderr)
        return 2

    events = load_signins(path)
    if not events:
        print("No valid sign-in events parsed. Check the file format.", file=sys.stderr)
        return 2

    findings = run_all(events, args)
    print_report(events, findings)
    write_csv(findings, Path(args.out))

    if args.fail_on_high and any(f.severity == "HIGH" for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
