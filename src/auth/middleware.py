import time

# Global dict to track failed login attempts per user
# Maps user_id -> list of timestamps of failed attempts
_failed_attempts = {}


def login(user_id: str, tenant, password_correct: bool):
    if password_correct:
        # Clear failed attempts on successful login
        if user_id in _failed_attempts:
            _failed_attempts[user_id] = []

        return {
            "status": 200,
            "body": {
                "message": "Login successful"
            }
        }

    # Failed login - check rate limit (unless enterprise tenant)
    if not tenant.is_enterprise:
        current_time = time.time()

        if user_id not in _failed_attempts:
            _failed_attempts[user_id] = []

        # Prune attempts older than 60 seconds
        _failed_attempts[user_id] = [
            timestamp for timestamp in _failed_attempts[user_id]
            if current_time - timestamp < 60
        ]

        # If we already have 5 failed attempts within the window, reject on the 6th
        if len(_failed_attempts[user_id]) >= 5:
            return {
                "status": 429,
                "body": {
                    "error": "Too many failed login attempts"
                }
            }

        # Record this failed attempt
        _failed_attempts[user_id].append(current_time)

    return {
        "status": 401,
        "body": {
            "error": "Invalid credentials"
        }
    }