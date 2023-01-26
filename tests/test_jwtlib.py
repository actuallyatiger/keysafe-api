import unittest
from base64 import b64decode
from ast import literal_eval

from api.jwtlib import JWT


class TestJWT(unittest.TestCase):
    """
    Test the JWT class.
    """

    def setUp(self):
        self.jwt = JWT(key="test_key")
        # pylint: disable=line-too-long
        self.predefined_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoidXNlcl9pZCIsInNpZCI6InNlc3Npb25faWQiLCJleHAiOjE2NzQ2NDgwMDB9.rXDIpGj5-RAHrWzdLY6PSDzxFgBHi2Oat_6KSNHXKO4"

    def test_create_token(self):
        """
        Test that the create_token function works as expected.
        """
        token = self.jwt.create_token("user_id", "session_id")
        self.assertTrue(token)
        components = token.split(".")
        header = literal_eval(b64decode(components[0]).decode())
        payload = literal_eval(b64decode(components[1]).decode())
        self.assertEqual(
            header,
            {"alg": "HS256", "typ": "JWT"},
        )
        self.assertEqual(payload["user_id"], "user_id")
        self.assertEqual(payload["sid"], "session_id")
        self.assertTrue(payload["exp"])

    def test_decode_token(self):
        """
        Test that the decode_token function works as expected.
        """
        decoded_token = self.jwt.decode_token(self.predefined_token)
        self.assertEqual(
            decoded_token,
            {"user_id": "user_id", "sid": "session_id", "exp": 1674648000},
        )

    def test_check_expired(self):
        """
        Test that the check_expired function works as expected.
        """
        self.assertTrue(self.jwt.check_expired(self.predefined_token))


if __name__ == "__main__":
    unittest.main()
