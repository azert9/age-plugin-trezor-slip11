import abc
import hashlib
import secrets
from dataclasses import dataclass

_NONCE_SIZE = 16
_HASH_SIZE = 16


# Encryption process: AES_CBC(iv=0, H(N|M)|N|M)
# This should partially mitigate the lack of authentication, in simple settings
# where the adversary cannot control even partially any encrypted plaintext.


@dataclass
class Params:
    key: str
    ask_on_encrypt: bool = True
    ask_on_decrypt: bool = True


class Device(abc.ABC):
    def encrypt(self, params: Params, data: bytes) -> bytes:
        nonce = secrets.token_bytes(_NONCE_SIZE)

        padding_len = 16 - (_HASH_SIZE + _NONCE_SIZE + len(data)) % 16
        padding = bytes([padding_len] * padding_len)

        hasher = hashlib.sha256()
        hasher.update(nonce)
        hasher.update(data)
        hasher.update(padding)
        h = hasher.digest()[:_HASH_SIZE]

        return self._encrypt_raw(params, h + nonce + data + padding)

    def decrypt(self, params: Params, data: bytes) -> bytes:
        def _check_len(l: int) -> bool:
            return l % 16 == 0 and l >= _HASH_SIZE + _NONCE_SIZE + 1

        if not _check_len(len(data)):
            raise ValueError("bad ciphertext length")

        plaintext1 = self._decrypt_raw(params, data)

        if not _check_len(len(plaintext1)):
            raise ValueError("bad plaintext length")

        if hashlib.sha256(plaintext1[_HASH_SIZE:]).digest()[:_HASH_SIZE] != plaintext1[:_HASH_SIZE]:
            raise ValueError("message authentication failed")
        plaintext2 = plaintext1[_HASH_SIZE + _NONCE_SIZE:]

        padding_len = plaintext2[-1]
        if padding_len > len(plaintext2):
            raise ValueError("bad padding")

        return plaintext2[:-padding_len]

    @abc.abstractmethod
    def _encrypt_raw(self, params: Params, value: bytes) -> bytes:
        pass

    @abc.abstractmethod
    def _decrypt_raw(self, params: Params, value: bytes) -> bytes:
        pass
