from src.auth.middleware import login, failed_attempts
from src.auth.tenant import Tenant


def test_successful_login():
    tenant = Tenant(is_enterprise=False)
    failed_attempts.clear()

    response = login(
        user_id="user-1",
        tenant=tenant,
        password_correct=True
    )

    assert response["status"] == 200
    assert response["body"] == {
        "message": "Login successful"
    }


def test_failed_login():
    tenant = Tenant(is_enterprise=False)
    failed_attempts.clear()

    response = login(
        user_id="user-1",
        tenant=tenant,
        password_correct=False
    )

    assert response["status"] == 401
    assert response["body"] == {
        "error": "Invalid credentials"
    }


def test_rate_limit_exceeded(monkeypatch):
    tenant = Tenant(is_enterprise=False)
    failed_attempts.clear()

    # Simulate 5 failed attempts
    fake_time = 1000.0
    for i in range(5):
        monkeypatch.setattr("time.time", lambda: fake_time + i * 0.1)
        response = login(
            user_id="user-rate-limit",
            tenant=tenant,
            password_correct=False
        )
        assert response["status"] == 401

    # 6th attempt should be rate limited
    monkeypatch.setattr("time.time", lambda: fake_time + 0.5)
    response = login(
        user_id="user-rate-limit",
        tenant=tenant,
        password_correct=False
    )
    assert response["status"] == 429
    assert response["body"] == {
        "error": "Too many failed login attempts"
    }


def test_enterprise_exempt(monkeypatch):
    tenant = Tenant(is_enterprise=True)
    failed_attempts.clear()

    fake_time = 1000.0
    monkeypatch.setattr("time.time", lambda: fake_time)

    # Simulate many failed attempts
    for i in range(10):
        monkeypatch.setattr("time.time", lambda t=fake_time + i * 0.1: t)
        response = login(
            user_id="enterprise-user",
            tenant=tenant,
            password_correct=False
        )
        # Enterprise tenants should not be rate limited
        assert response["status"] == 401
        assert response["body"] == {
            "error": "Invalid credentials"
        }


def test_success_clears(monkeypatch):
    tenant = Tenant(is_enterprise=False)
    failed_attempts.clear()

    fake_time = 1000.0
    monkeypatch.setattr("time.time", lambda: fake_time)

    # Make 3 failed attempts
    for i in range(3):
        monkeypatch.setattr("time.time", lambda t=fake_time + i * 0.1: t)
        response = login(
            user_id="user-clear",
            tenant=tenant,
            password_correct=False
        )
        assert response["status"] == 401

    # Successful login should clear the attempts
    monkeypatch.setattr("time.time", lambda: fake_time + 1.0)
    response = login(
        user_id="user-clear",
        tenant=tenant,
        password_correct=True
    )
    assert response["status"] == 200

    # After clearing, user should be able to make new attempts
    monkeypatch.setattr("time.time", lambda: fake_time + 2.0)
    response = login(
        user_id="user-clear",
        tenant=tenant,
        password_correct=False
    )
    assert response["status"] == 401
    assert "user-clear" not in failed_attempts or len(failed_attempts.get("user-clear", [])) == 1