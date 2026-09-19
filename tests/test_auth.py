from src.auth.middleware import login, _failed_attempts
from src.auth.tenant import Tenant


def test_successful_login():
    tenant = Tenant(is_enterprise=False)

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
    """Test that the 6th failed attempt within 60 seconds returns 429."""
    # Reset state
    _failed_attempts.clear()

    tenant = Tenant(is_enterprise=False)
    user_id = "user-ratelimit"
    fake_time = 1000.0

    # Mock time.time to control the sliding window
    monkeypatch.setattr("src.auth.middleware.time.time", lambda: fake_time)

    # Make 5 failed attempts
    for i in range(5):
        response = login(
            user_id=user_id,
            tenant=tenant,
            password_correct=False
        )
        assert response["status"] == 401
        assert response["body"] == {"error": "Invalid credentials"}

    # 6th attempt should be rate limited
    response = login(
        user_id=user_id,
        tenant=tenant,
        password_correct=False
    )
    assert response["status"] == 429
    assert response["body"] == {"error": "Too many failed login attempts"}


def test_enterprise_exempt(monkeypatch):
    """Test that enterprise tenants are exempt from rate limiting."""
    _failed_attempts.clear()

    tenant = Tenant(is_enterprise=True)
    user_id = "user-enterprise"
    fake_time = 1000.0

    monkeypatch.setattr("src.auth.middleware.time.time", lambda: fake_time)

    # Make 10 failed attempts with enterprise tenant
    for i in range(10):
        response = login(
            user_id=user_id,
            tenant=tenant,
            password_correct=False
        )
        # All should return 401, never 429
        assert response["status"] == 401
        assert response["body"] == {"error": "Invalid credentials"}


def test_success_clears(monkeypatch):
    """Test that a successful login clears the failed attempt count."""
    _failed_attempts.clear()

    tenant = Tenant(is_enterprise=False)
    user_id = "user-clear"
    fake_time = 1000.0

    monkeypatch.setattr("src.auth.middleware.time.time", lambda: fake_time)

    # Make 5 failed attempts
    for i in range(5):
        response = login(
            user_id=user_id,
            tenant=tenant,
            password_correct=False
        )
        assert response["status"] == 401

    # Successful login should clear the attempts
    response = login(
        user_id=user_id,
        tenant=tenant,
        password_correct=True
    )
    assert response["status"] == 200
    assert response["body"] == {"message": "Login successful"}

    # After successful login, we should be able to fail again
    # and not hit the rate limit until 5 more failures
    for i in range(5):
        response = login(
            user_id=user_id,
            tenant=tenant,
            password_correct=False
        )
        assert response["status"] == 401

    # 6th failure after success should be rate limited
    response = login(
        user_id=user_id,
        tenant=tenant,
        password_correct=False
    )
    assert response["status"] == 429