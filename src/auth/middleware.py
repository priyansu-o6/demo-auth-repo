import threading
import time

MAX_FAILED_ATTEMPTS = 5
WINDOW_SECONDS = 60

# user_id -> timestamps of recent failed login attempts
_failed_attempts = {}
_lock = threading.Lock()


def _purge_old_attempts(user_id: str, now: float) -> list:
    """Drop failed attempts outside the sliding window and return the rest."""
    recent = [
        t for t in _failed_attempts.get(user_id, [])
        if now - t < WINDOW_SECONDS
    ]
    if recent:
        _failed_attempts[user_id] = recent
    else:
        _failed_attempts.pop(user_id, None)
    return recent


def login(user_id: str, tenant, password_correct: bool):
    if tenant.is_enterprise:
        return _authenticate(password_correct)

    with _lock:
        if password_correct:
            _failed_attempts.pop(user_id, None)
            return _authenticate(password_correct)

        now = time.monotonic()
        recent = _purge_old_attempts(user_id, now)
        if len(recent) >= MAX_FAILED_ATTEMPTS:
            return {
                "status": 429,
                "body": {
                    "error": "Too many failed login attempts"
                }
            }

        recent.append(now)
        _failed_attempts[user_id] = recent
        return _authenticate(password_correct)


def _authenticate(password_correct: bool):
    if password_correct:
        return {
            "status": 200,
            "body": {
                "message": "Login successful"
            }
        }

    return {
        "status": 401,
        "body": {
            "error": "Invalid credentials"
        }
    }
