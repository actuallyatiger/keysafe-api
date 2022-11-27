from hmac import compare_digest
from Crypto.Hash import SHA256
import argon2


class Hasher:
    """
    Class for handling hashing and verifying passwords.
    Methods: hash, verify
    """

    def __init__(self) -> None:
        """
        Settings: 2 parallellism, 192MB memory, 6 iterations,
        32 bytes hash length, 16 bytes salt length.
        """
        self.hasher = argon2.PasswordHasher(
            time_cost=6, memory_cost=192 * 1024, parallelism=2, hash_len=32, salt_len=16
        )

    def sha256_hash(self, password: str):
        """
        Hashes a password using SHA256
        :param password: The password to hash
        :return: The hashed password
        """
        return SHA256.new(password.encode()).hexdigest()

    def sha256_verify(self, password: str, password_hash: str) -> bool:
        """
        Verifies a password against a SHA256 hash
        :param password: The password to verify
        :param hash: The hash to verify against
        :return: True if the password matches the hash, False otherwise
        """
        return compare_digest(self.sha256_hash(password), password_hash)

    def argon_hash(self, password: str) -> str:
        """
        Hashes a password using Argon2
        :param password: The password to hash
        :return: The hashed password
        """

        return self.hasher.hash(password)

    def argon_verify(self, password: str, password_hash: str) -> bool:
        """
        Verifies a password against an Argon2 hash
        :param password: The password to verify
        :param hash: The hash to verify against
        :return: True if the password matches the hash, False otherwise
        """
        return self.hasher.verify(password_hash, password)
