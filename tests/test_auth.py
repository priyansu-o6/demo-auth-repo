import pytest

from src.auth import middleware
from src.auth.middleware import login
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


FAILED_401 = {"status": 401, "body": {"error": "Invalid credentials"}}
SUCCESS_200 = {"status": 200, "body": {"message": "Login successful"}}
LIMITED_429 = {"status": 429, "body": {"error": "Too many failed login attempts"}}


@pytest.fixture(autouse=True)
def reset_state(monkeypatch):
    middleware._failed_attempts.clear()
    clock = {"now": 1000.0}
    monkeypatch.setattr(middleware.time, "monotonic", lambda: clock["now"])
    yield clock
    middleware._failed_attempts.clear()


def fail(user_id="user-1", enterprise=False):
    return login(user_id, Tenant(is_enterprise=enterprise), False)


def succeed(user_id="user-1", enterprise=False):
    return login(user_id, Tenant(is_enterprise=enterprise), True)


def test_five_failures_allowed_sixth_rate_limited():
    for _ in range(5):
        assert fail() == FAILED_401
    assert fail() == LIMITED_429


def test_rate_limit_is_per_user():
    for _ in range(5):
        fail("user-1")
    assert fail("user-1") == LIMITED_429
    assert fail("user-2") == FAILED_401


def test_enterprise_tenant_is_exempt():
    for _ in range(20):
        assert fail(enterprise=True) == FAILED_401
    assert succeed(enterprise=True) == SUCCESS_200


def test_sliding_window_expires_old_failures(reset_state):
    for _ in range(5):
        fail()
    assert fail() == LIMITED_429

    reset_state["now"] += 59
    assert fail() == LIMITED_429

    reset_state["now"] += 1  # original failures are now 60s old
    assert fail() == FAILED_401


def test_window_slides_rather_than_resets(reset_state):
    fail()  # t=1000
    reset_state["now"] += 30
    for _ in range(4):
        fail()  # t=1030
    assert fail() == LIMITED_429

    reset_state["now"] += 30  # t=1060: first failure expires, four remain
    assert fail() == FAILED_401
    assert fail() == LIMITED_429


def test_rate_limited_attempts_do_not_extend_the_window(reset_state):
    for _ in range(5):
        fail()
    reset_state["now"] += 30
    for _ in range(3):
        assert fail() == LIMITED_429
    reset_state["now"] += 30
    assert fail() == FAILED_401


def test_successful_login_clears_failed_attempts():
    for _ in range(4):
        fail()
    assert succeed() == SUCCESS_200
    for _ in range(5):
        assert fail() == FAILED_401
    assert fail() == LIMITED_429


def test_successful_login_not_blocked_after_threshold_and_resets():
    for _ in range(6):
        fail()
    assert fail() == LIMITED_429

    assert succeed() == SUCCESS_200
    assert fail() == FAILED_401


def test_success_does_not_clear_other_users():
    for _ in range(5):
        fail("user-1")
    assert succeed("user-2") == SUCCESS_200
    assert fail("user-1") == LIMITED_429
