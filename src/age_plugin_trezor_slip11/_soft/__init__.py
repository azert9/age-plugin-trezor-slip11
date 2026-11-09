import hashlib
import hmac

import Crypto.Cipher.AES
import shamir_mnemonic

from .. import _encryption, _constants
from . import _bip32


class SoftwareDevice(_encryption.Device):
    def __init__(self, mnemonic: str):
        # SLIP-0039: mnemonic to secret key
        self.__seed = shamir_mnemonic.combine_mnemonics([mnemonic])

    def _decrypt_raw(self, params: _encryption.Params, value: bytes) -> bytes:
        return self.__slip11_get_cipher(
            n=_constants.BIP_32_PATH,
            key=params.key,
            iv=_constants.IV,
            ask_on_encrypt=params.ask_on_encrypt,
            ask_on_decrypt=params.ask_on_decrypt,
        ).decrypt(value)

    def _encrypt_raw(self, params: _encryption.Params, value: bytes) -> bytes:
        return self.__slip11_get_cipher(
            n=_constants.BIP_32_PATH,
            key=params.key,
            iv=_constants.IV,
            ask_on_encrypt=params.ask_on_encrypt,
            ask_on_decrypt=params.ask_on_decrypt,
        ).encrypt(value)

    def __slip11_get_cipher(
            self,
            n: list[int],
            key: str,
            iv: bytes | None,
            ask_on_encrypt: bool,
            ask_on_decrypt: bool,
    ):
        bip32_node = _bip32.Node.root(self.__seed)
        for i in n:
            bip32_node = bip32_node.child(i)

        h = hmac.digest(
            bip32_node.key.private_key,
            key.encode() + (b"E1" if ask_on_encrypt else b"E0") + (b"D1" if ask_on_decrypt else b"D0"),
            hashlib.sha512,
        )

        key = h[:32]

        iv = iv or h[32:48]

        return Crypto.Cipher.AES.new(key=key, mode=Crypto.Cipher.AES.MODE_CBC, iv=iv)
