from hmac import compare_digest
import hashlib
import argon2


class Hasher:
    """
    Class for handling hashing and verifying passwords.
    Methods: hash, verify
    """

    def __init__(self):
        """
        Settings: 2 parallellism, 192MB memory, 6 iterations,
        64 bytes hash length, 16 bytes salt length.
        """
        self.hasher = argon2.PasswordHasher(
            time_cost=6, memory_cost=192 * 1024, parallelism=2, hash_len=64, salt_len=16
        )

    def sha512_hash(self, password):
        """
        Hashes a password using SHA512
        :param password: The password to hash
        :return: The hashed password
        """
        return hashlib.sha512(password.encode()).hexdigest()

    def sha512_verify(self, password, password_hash):
        """
        Verifies a password against a SHA512 hash
        :param password: The password to verify
        :param hash: The hash to verify against
        :return: True if the password matches the hash, False otherwise
        """
        return compare_digest(self.sha512_hash(password), password_hash)

    def hash(self, password):
        """
        Hashes a password using Argon2
        :param password: The password to hash
        :return: The hashed password
        """

        return self.hasher.hash(password)

    def verify(self, password, password_hash):
        """
        Verifies a password against an Argon2 hash
        :param password: The password to verify
        :param hash: The hash to verify against
        :return: True if the password matches the hash, False otherwise
        """
        return self.hasher.verify(password_hash, password)
