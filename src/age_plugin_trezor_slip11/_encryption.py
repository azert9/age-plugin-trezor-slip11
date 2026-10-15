import abc
import hashlib
import secrets
import struct
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


class FakeDevice(Device):
    def _decrypt_raw(self, params: Params, value: bytes) -> bytes:
        if len(value) % 16 != 0:
            raise ValueError("ciphertext length is not a multiple of 16")

        # simple stream cipher just for testing

        hasher = hashlib.sha256()
        hasher.update(b"yes" if params.ask_on_decrypt else b"no")
        hasher.update(b"yes" if params.ask_on_encrypt else b"no")
        hasher.update(params.key.encode())
        key = hasher.digest()

        counter = 0
        keystream = bytes()
        while len(keystream) < len(value):
            counter += 1
            hasher = hashlib.sha256()
            hasher.update(struct.pack(">Q", counter))
            hasher.update(key)
            keystream += hasher.digest()
        keystream = keystream[:len(value)]

        return bytes([
            keystream[i] ^ value[i]
            for i in range(len(value))
        ])

    def _encrypt_raw(self, params: Params, value: bytes) -> bytes:
        if len(value) % 16 != 0:
            raise ValueError("plaintext length is not a multiple of 16")
        return self._decrypt_raw(params, value)
