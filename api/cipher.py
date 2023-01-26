from hmac import compare_digest
import os
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
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

    def argon_verify(self, password_hash: str, password: str) -> bool:
        """
        Verifies a password against an Argon2 hash
        :param password: The password to verify
        :param hash: The hash to verify against
        :return: True if the password matches the hash, False otherwise
        """
        try:
            self.hasher.verify(password_hash, password)
            return True
        except argon2.exceptions.VerifyMismatchError:
            return False


class Encryptor:
    """
    Class for handling encryption and decryption.
    Algorithm: AES-256-GCM.
    Methods: encrypt, decrypt
    """

    def __init__(self, key=None) -> None:
        self.key = key if key is not None else bytes.fromhex(os.environ.get("AES_KEY"))

    def encrypt(self, plaintext: str) -> tuple[str, str, str]:
        """
        Encrypts data
        :param data: The data to encrypt
        :return ciphertext, nonce, hexdigest: The encrypted data
        """
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=os.urandom(12))
        ciphertext = cipher.encrypt(plaintext.encode())
        return ciphertext.hex(), cipher.nonce.hex(), cipher.hexdigest()

    def decrypt(self, ciphertext: str, nonce: str, hexdigest: str):
        """
        Decrypts data using AES
        :param data: The data to decrypt
        :return: The decrypted data as a hexdigest
        """
        try:
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=bytes.fromhex(nonce))
            plaintext = cipher.decrypt(bytes.fromhex(ciphertext))
            cipher.hexverify(hexdigest)
        except ValueError:
            return -1
        return plaintext.decode()
