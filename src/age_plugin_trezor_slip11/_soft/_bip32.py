import hashlib
import hmac
import struct

import secp256k1


# https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki


class Node:
    def __init__(self, key: secp256k1.PrivateKey, chain_code: bytes):
        self.__key = key
        self.__chain_code = chain_code

    @staticmethod
    def root(seed: bytes) -> Node:
        h = hmac.digest(b"Bitcoin seed", seed, hashlib.sha512)
        return Node(secp256k1.PrivateKey(h[:32]), h[32:])

    @property
    def key(self) -> secp256k1.PrivateKey:
        return self.__key

    def child(self, index: int) -> Node:
        assert 0 <= index < 2 ** 32
        hardened = index >= 2 ** 31

        index_bytes = struct.pack(">I", index)
        if hardened:
            h = hmac.digest(self.__chain_code, b"\0" + self.__key.private_key + index_bytes, hashlib.sha512)
        else:
            h = hmac.digest(self.__chain_code, self.__key.pubkey.serialize() + index_bytes, hashlib.sha512)

        s = secp256k1.PrivateKey(h[:32]).tweak_add(self.__key.private_key)
        child_private_key = secp256k1.PrivateKey(s)

        return Node(child_private_key, h[32:])
