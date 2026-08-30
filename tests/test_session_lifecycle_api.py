# -*- coding: utf-8 -*-
"""
Session lifecycle against a running API.

Requires the API on http://127.0.0.1:8000 (and therefore the database). Skips
cleanly when it isn't up, so it is safe in a unit-test run:

    python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000
    pytest tests/test_session_lifecycle_api.py -v

Covers two defects found by exercising the real API:

  1. A session created via POST was missing from the immediately-following GET.
     The write went through force_master(); the read was a separate request and
     RoutingSession sent it to a replica, which had not synced yet. Confirmed by
     execution -- the row was present in all three databases while the endpoint
     returned an empty list.

  2. There was no route to remove a session at all, and app.js never called one,
     so sessions could only accumulate. Removal is an ARCHIVE: findings,
     evidence, checkpoints and compliance scores all reference report_id, so a
     hard delete would tear a hole through the ledger.
"""
import random
import string

import pytest
import requests

BASE = "http://127.0.0.1:8000"
API = f"{BASE}/api"
PASSWORD = "PytestSess123!"


def _api_is_up():
    try:
        return requests.get(BASE, timeout=3).status_code == 200
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _api_is_up(), reason="API not running on :8000")


def _register_and_auth():
    """Register + login + OTP, returning (username, auth headers)."""
    import pyotp
    suf = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    user = f"pytest_{suf}@audit.com"
    r = requests.post(f"{API}/auth/register",
                      json={"username": user, "password": PASSWORD, "role": "auditor"}, timeout=30)
    r.raise_for_status()
    secret = r.json()["totp_secret"]
    requests.post(f"{API}/auth/login", json={"username": user, "password": PASSWORD}, timeout=30)
    r = requests.post(f"{API}/auth/verify-otp",
                      json={"username": user, "otp_code": pyotp.TOTP(secret).now()}, timeout=30)
    r.raise_for_status()
    return user, {"Authorization": f"Bearer {r.json()['token']}"}


# Auth is created ONCE per module, not per test.
#
# Registering a fresh auditor inside every test drove /auth/verify-otp into the
# login rate limiter -- 429 Too Many Requests -- which failed 8 of 10 tests
# against a containerised deployment. That limiter is a security control doing
# its job, not a defect; the tests were the thing behaving unreasonably. Sharing
# one authenticated identity also makes the suite several times faster.
@pytest.fixture(scope="module")
def owner():
    return _register_and_auth()


@pytest.fixture(scope="module")
def other_user():
    """A second identity, for the account-isolation check."""
    return _register_and_auth()


def _new_auditor():
    """Kept for tests that genuinely need a distinct identity."""
    return _register_and_auth()


def _create_session(headers, user, title="pytest session"):
    r = requests.post(f"{API}/audit/sessions",
                      data={"session_title": title, "framework": "ISO 27001", "username": user},
                      headers=headers, timeout=30)
    r.raise_for_status()
    return r.json()["session_id"]


def _list_ids(headers):
    r = requests.get(f"{API}/audit/sessions", headers=headers, timeout=30)
    r.raise_for_status()
    return [str(s.get("session_id")) for s in r.json().get("sessions", [])]


# ── Read-after-write ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("attempt", range(3))
def test_session_is_listed_immediately_after_creation(attempt, owner):
    """No sleep, no retry -- the read happens straight after the write, which is
    what a script or a fast click does. This returned an empty list before the
    sessions query was pinned to master."""
    user, headers = owner
    sid = _create_session(headers, user, f"read-after-write {attempt}")
    assert str(sid) in _list_ids(headers), "freshly created session missing from the list"


def test_multiple_sessions_all_appear(owner):
    user, headers = owner
    created = [_create_session(headers, user, f"multi {i}") for i in range(3)]
    listed = _list_ids(headers)
    missing = [s for s in created if str(s) not in listed]
    assert not missing, f"{len(missing)} of 3 sessions missing: {missing}"


# ── Archive / restore ────────────────────────────────────────────────────────

def test_archive_hides_session_but_keeps_the_record(owner):
    user, headers = owner
    keep = _create_session(headers, user, "keep me")
    drop = _create_session(headers, user, "archive me")

    r = requests.delete(f"{API}/audit/sessions/{drop}", headers=headers, timeout=30)
    assert r.status_code == 200, r.text[:200]

    listed = _list_ids(headers)
    assert str(drop) not in listed, "archived session still listed"
    assert str(keep) in listed, "archiving one session hid another"

    # The row must survive -- read from master, since a replica may lag.
    from src.db.database import SessionLocal, AuditReport, force_master
    db = SessionLocal()
    try:
        with force_master():
            row = db.query(AuditReport).filter(AuditReport.session_id == drop).first()
            assert row is not None, "archive deleted the ledger row"
            assert row.status == "Archived", f"unexpected status {row.status!r}"
            assert row.session_title, "session title lost"
    finally:
        db.close()


def test_archived_session_can_be_restored(owner):
    user, headers = owner
    sid = _create_session(headers, user, "restore me")
    requests.delete(f"{API}/audit/sessions/{sid}", headers=headers, timeout=30)
    assert str(sid) not in _list_ids(headers)

    r = requests.post(f"{API}/audit/sessions/{sid}/restore", headers=headers, timeout=30)
    assert r.status_code == 200, r.text[:200]
    assert str(sid) in _list_ids(headers), "restored session did not return to the list"


def test_archiving_twice_is_harmless(owner):
    user, headers = owner
    sid = _create_session(headers, user, "double archive")
    assert requests.delete(f"{API}/audit/sessions/{sid}", headers=headers, timeout=30).status_code == 200
    r = requests.delete(f"{API}/audit/sessions/{sid}", headers=headers, timeout=30)
    assert r.status_code == 200 and r.json().get("already_archived") is True


def test_archiving_an_unknown_session_is_404(owner):
    _user, headers = owner
    r = requests.delete(f"{API}/audit/sessions/does-not-exist-xyz", headers=headers, timeout=30)
    assert r.status_code == 404


def test_another_user_cannot_archive_your_session(owner, other_user):
    """Account isolation must hold on the new route."""
    owner_name, owner_h = owner
    sid = _create_session(owner_h, owner_name, "private")
    _other, other_h = other_user
    r = requests.delete(f"{API}/audit/sessions/{sid}", headers=other_h, timeout=30)
    assert r.status_code in (403, 404), f"another user archived it: {r.status_code}"
    assert str(sid) in _list_ids(owner_h), "session vanished from the owner's list"


def test_archive_requires_authentication(owner):
    user, headers = owner
    sid = _create_session(headers, user, "auth required")
    r = requests.delete(f"{API}/audit/sessions/{sid}", timeout=30)
    assert r.status_code == 401
