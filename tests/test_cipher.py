import unittest
from api.cipher import Hasher


class TestHasher(unittest.TestCase):
    """
    Test the Hasher class
    """

    def setUp(self):
        """
        Create an instance of the Hasher class
        """
        self.hasher = Hasher()

    def test_sha256_hash(self):
        """
        Test that the SHA256 hash function works as expected
        """
        password = "password"
        expected_hash = (
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
        )
        self.assertEqual(self.hasher.sha256_hash(password), expected_hash)

    def test_sha256_verify(self):
        """
        Test that the SHA256 verify function works as expected
        """
        password = "password"
        password_hash = (
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
        )
        self.assertTrue(self.hasher.sha256_verify(password, password_hash))
        self.assertFalse(self.hasher.sha256_verify(password, "invalidhash"))

    def test_argon_hash(self):
        """
        Test that the Argon2 hash function works as expected
        """
        password = "password"
        # Nonce means that the hash will be different every time,
        # so only check if a hash is returned
        self.assertTrue(self.hasher.argon_hash(password))

    def test_argon_verify(self):
        """
        Test that the Argon2 verify function works as expected
        """
        password = "password"
        password_hash = self.hasher.argon_hash(password)

        self.assertTrue(self.hasher.argon_verify(password_hash, password))
        self.assertFalse(self.hasher.argon_verify(password_hash, "invalidpassword"))


if __name__ == "__main__":
    unittest.main()
