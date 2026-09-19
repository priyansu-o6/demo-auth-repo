import time

failed_attempts = {}
MAX_FAILED_ATTEMPTS = 5
WINDOW_SECONDS = 60


def login(user_id: str, tenant, password_correct: bool):
    # Skip rate limiting for enterprise tenants
    if not tenant.is_enterprise:
        current_time = time.time()

        # Prune timestamps older than 60 seconds
        if user_id in failed_attempts:
            failed_attempts[user_id] = [
                ts for ts in failed_attempts[user_id]
                if current_time - ts < WINDOW_SECONDS
            ]

    if password_correct:
        # Clear failed attempts on successful login
        if user_id in failed_attempts:
            del failed_attempts[user_id]

        return {
            "status": 200,
            "body": {
                "message": "Login successful"
            }
        }

    # Check rate limit for non-enterprise tenants on failed login
    if not tenant.is_enterprise:
        current_time = time.time()

        if user_id not in failed_attempts:
            failed_attempts[user_id] = []

        failed_attempts[user_id].append(current_time)

        if len(failed_attempts[user_id]) > MAX_FAILED_ATTEMPTS:
            return {
                "status": 429,
                "body": {
                    "error": "Too many failed login attempts"
                }
            }

    return {
        "status": 401,
        "body": {
            "error": "Invalid credentials"
        }
    }