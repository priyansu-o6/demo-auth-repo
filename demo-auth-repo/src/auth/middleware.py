def login(user_id: str, tenant, password_correct: bool):
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