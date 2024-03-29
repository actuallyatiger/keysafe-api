import os
from datetime import datetime, timedelta

import jwt


class JWT:
    """
    Generating and verifying JWT tokens.
    """

    def __init__(self, key=None):
        self.key = key if key is not None else os.environ.get("JWT_KEY")
        self.algorithm = "HS256"

    def create_token(self, user_id: str, session_id: str) -> str:
        """
        Generate a JWT token.
        """
        return jwt.encode(
            {
                "user_id": user_id,
                "sid": session_id,
                "exp": datetime.now() + timedelta(minutes=15),
            },
            self.key,
            algorithm=self.algorithm,
        )

    def decode_token(self, token: str) -> dict:
        """
        Decode a JWT token, without verification.
        """
        try:
            return jwt.decode(
                token,
                self.key,
                algorithms=[self.algorithm],
                options={"verify_signature": False},
            )
        except jwt.InvalidTokenError:
            return {"error": "Invalid token"}

    def check_expired(self, token: str) -> bool:
        """
        Check if a JWT token has expired.
        """
        try:
            jwt.decode(token, self.key, algorithms=[self.algorithm])
            return False
        except jwt.ExpiredSignatureError:
            return True
