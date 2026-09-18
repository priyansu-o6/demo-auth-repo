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