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


def test_rate_limiting_exceeded():
    # Clear state before test
    _failed_attempts.clear()

    tenant = Tenant(is_enterprise=False)

    # Make 5 failed attempts
    for i in range(5):
        response = login(
            user_id="user-2",
            tenant=tenant,
            password_correct=False
        )
        assert response["status"] == 401

    # 6th attempt should be rate limited
    response = login(
        user_id="user-2",
        tenant=tenant,
        password_correct=False
    )

    assert response["status"] == 429
    assert response["body"] == {
        "error": "Too many failed login attempts"
    }


def test_enterprise_exemption():
    # Clear state before test
    _failed_attempts.clear()

    tenant = Tenant(is_enterprise=True)

    # Make 10 failed attempts with enterprise tenant
    for i in range(10):
        response = login(
            user_id="user-3",
            tenant=tenant,
            password_correct=False
        )
        # Should always return 401, never 429
        assert response["status"] == 401
        assert response["body"] == {
            "error": "Invalid credentials"
        }


def test_success_clears_attempts():
    # Clear state before test
    _failed_attempts.clear()

    tenant = Tenant(is_enterprise=False)

    # Make 5 failed attempts
    for i in range(5):
        login(
            user_id="user-4",
            tenant=tenant,
            password_correct=False
        )

    # Successful login should clear attempts
    response = login(
        user_id="user-4",
        tenant=tenant,
        password_correct=True
    )

    assert response["status"] == 200

    # After successful login, should be able to fail again
    response = login(
        user_id="user-4",
        tenant=tenant,
        password_correct=False
    )

    assert response["status"] == 401