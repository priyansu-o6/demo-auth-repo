import time

# Track failed login attempts per user with timestamps
_failed_attempts = {}


def login(user_id: str, tenant, password_correct: bool):
    # Check if rate limiting applies
    if not tenant.is_enterprise:
        # Prune attempts older than 60 seconds
        current_time = time.time()
        if user_id in _failed_attempts:
            _failed_attempts[user_id] = [
                timestamp for timestamp in _failed_attempts[user_id]
                if current_time - timestamp < 60
            ]

        # Check if rate limit exceeded (more than 5 failed attempts)
        if user_id in _failed_attempts and len(_failed_attempts[user_id]) >= 5 and not password_correct:
            return {
                "status": 429,
                "body": {
                    "error": "Too many failed login attempts"
                }
            }

    if password_correct:
        # Clear failed attempts on successful login
        if user_id in _failed_attempts:
            del _failed_attempts[user_id]

        return {
            "status": 200,
            "body": {
                "message": "Login successful"
            }
        }

    # Record failed attempt if not enterprise
    if not tenant.is_enterprise:
        if user_id not in _failed_attempts:
            _failed_attempts[user_id] = []
        _failed_attempts[user_id].append(time.time())

    return {
        "status": 401,
        "body": {
            "error": "Invalid credentials"
        }
    }