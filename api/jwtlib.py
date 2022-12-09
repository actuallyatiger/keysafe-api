import os
from datetime import datetime, timedelta
import jwt


class JWT:
    """
    Generating and verifying JWT tokens.
    """

    def __init__(self):
        self.key = os.environ.get("JWT_KEY")
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

    def verify_token(self, token: str) -> bool:
        """
        Verify a JWT token.
        """
        try:
            jwt.decode(token, self.key, algorithms=[self.algorithm])
            return True
        except jwt.ExpiredSignatureError:
            return False
        except jwt.InvalidTokenError:
            return False
