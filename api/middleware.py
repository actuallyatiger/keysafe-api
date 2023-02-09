from functools import wraps

from client import get_client
from flask import request
from jwtlib import JWT

client = get_client()
jwt = JWT()


def refresh_jwt(func):
    """
    Refresh the JWT if it has expired.
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        # Check the Authorization header
        token = request.headers.get("Authorization")
        if not token:
            return {"error": "Missing Authorization header"}, 401

        # Decode the JWT to get the user ID and session ID
        data = jwt.decode_token(token)
        if "error" in data:
            return {"error": "Invalid JWT"}, 401
        user_id = data["user_id"]
        session_id = data["sid"]

        # Check if the JWT has expired
        if jwt.check_expired(token):
            # If the JWT has expired, generate a new one
            if client.collection("sessions").document(session_id).get().exists:
                token = jwt.create_token(user_id, session_id)
            else:
                return {"error": "Invalid session"}, 401

        # Call the decorated function
        return func(token, *args, **kwargs)

    return wrapper
