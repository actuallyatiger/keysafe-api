from hmac import compare_digest
import hashlib
import argon2


class Encryptor:
    """
    Class for handling hashing and verifying passwords.
    Methods: hash, verify
    """

    def __init__(self):
        """
        Settings: 2 parallellism, 192MB memory, 6 iterations,
        32 bytes hash length, 16 bytes salt length.
        """
        self.hasher = argon2.PasswordHasher(
            time_cost=6, memory_cost=192 * 1024, parallelism=2, hash_len=32, salt_len=16
        )

    def sha256_hash(self, password):
        """
        Hashes a password using SHA256
        :param password: The password to hash
        :return: The hashed password
        """
        return hashlib.sha256(password.encode()).hexdigest()

    def sha256_verify(self, password, password_hash):
        """
        Verifies a password against a SHA256 hash
        :param password: The password to verify
        :param hash: The hash to verify against
        :return: True if the password matches the hash, False otherwise
        """
        return compare_digest(self.sha256_hash(password), password_hash)

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

    def encrypt(self, data):
        """
        Encrypts data using AES
        :param data: The data to encrypt
        :return: The encrypted data
        """
        pass

    def decrypt(self, data):
        """
        Decrypts data using AES
        :param data: The data to decrypt
        :return: The decrypted data
        """
        pass
