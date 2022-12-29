from functools import wraps
from client import get_client
from jwtlib import JWT
from flask import request

client = get_client()
jwt = JWT()


def refresh_jwt(func):
    """
    Refresh the JWT if it has expired.
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        # Check the Authorization header
        authorization = request.headers.get("Authorization")
        if not authorization:
            return {"error": "Missing Authorization header"}, 401

        # Split the auth-scheme and the JWT
        auth_scheme, token = authorization.split()
        if auth_scheme.lower() != "bearer":
            return {"error": "Invalid auth-scheme"}, 401

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
                # Set the new JWT in the response header
            else:
                return {"error": "Invalid session"}, 401

        # Call the decorated function
        return func(token, *args, **kwargs)

    return wrapper
