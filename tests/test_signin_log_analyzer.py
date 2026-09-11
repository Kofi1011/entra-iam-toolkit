"""
Unit tests for the Entra sign-in log analyzer.
Run with:  python -m pytest tests/ -v   (or: python tests/test_signin_log_analyzer.py)
"""
import sys
from datetime import datetime
from pathlib import Path

# Make src importable
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import signin_log_analyzer as sla  # noqa: E402


def _ev(user, ts, status="success", ip="1.1.1.1", city="Toronto",
        country="CA", lat=43.65, lon=-79.38, client="Browser", mfa="satisfied"):
    return sla.SignIn(
        user=user, timestamp=datetime.fromisoformat(ts), ip=ip, city=city,
        country=country, lat=lat, lon=lon, status=status,
        client_app=client, mfa_result=mfa,
    )


def test_haversine_known_distance():
    # Toronto -> Lagos is ~8900 km
    d = sla.haversine_km(43.6532, -79.3832, 6.5244, 3.3792)
    assert 8500 < d < 9300


def test_brute_force_detected():
    events = [_ev("u@x.com", f"2026-09-01T09:0{i}:00", status="failure")
              for i in range(6)]
    findings = sla.detect_spray_bruteforce(events, threshold=5, window_min=10)
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"


def test_brute_force_below_threshold():
    events = [_ev("u@x.com", f"2026-09-01T09:0{i}:00", status="failure")
              for i in range(3)]
    findings = sla.detect_spray_bruteforce(events, threshold=5, window_min=10)
    assert findings == []


def test_impossible_travel_detected():
    events = [
        _ev("u@x.com", "2026-09-01T08:00:00", city="Toronto", lat=43.65, lon=-79.38),
        _ev("u@x.com", "2026-09-01T08:40:00", city="Lagos", country="NG",
            lat=6.52, lon=3.37),
    ]
    findings = sla.detect_impossible_travel(events, max_kmh=900)
    assert len(findings) == 1
    assert "Impossible travel" in findings[0].category


def test_impossible_travel_ignores_reasonable_speed():
    events = [
        _ev("u@x.com", "2026-09-01T08:00:00", city="Toronto", lat=43.65, lon=-79.38),
        _ev("u@x.com", "2026-09-02T08:00:00", city="Lagos", country="NG",
            lat=6.52, lon=3.37),  # 24h apart -> fine
    ]
    assert sla.detect_impossible_travel(events, max_kmh=900) == []


def test_new_country_detected():
    events = [
        _ev("u@x.com", "2026-09-01T08:00:00", country="CA"),
        _ev("u@x.com", "2026-09-02T08:00:00", country="BR", mfa="notApplied"),
    ]
    findings = sla.detect_new_country(events)
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"  # MFA not satisfied -> HIGH


def test_legacy_auth_detected():
    events = [_ev("u@x.com", "2026-09-01T08:00:00", client="IMAP4")]
    findings = sla.detect_legacy_auth(events)
    assert len(findings) == 1
    assert findings[0].severity == "MEDIUM"


def test_end_to_end_sample_file():
    sample = Path(__file__).resolve().parents[1] / "samples" / "signin_logs_sample.csv"
    events = sla.load_signins(sample)
    assert len(events) > 0

    class Args:
        spray_threshold = 5
        spray_window = 10
        travel_kmh = 900
    findings = sla.run_all(events, Args())
    # We expect at least the three engineered HIGH findings
    highs = [f for f in findings if f.severity == "HIGH"]
    assert len(highs) >= 3


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS  {name}")
            except AssertionError as e:
                failed += 1
                print(f"FAIL  {name}: {e}")
    print(f"\n{'ALL TESTS PASSED' if not failed else f'{failed} TEST(S) FAILED'}")
    raise SystemExit(1 if failed else 0)
