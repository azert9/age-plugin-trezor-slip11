import contextlib

import trezorlib.client
import trezorlib.misc

from . import _encryption
from ._encryption import Params

_APP_NAME = "age-plugin-trezor-slip11"
_BIP_32_PATH = [
    # random path: m/1468881396'/585060657'/255853328'/1959521498'
    3616365044, 2732544305, 2403336976, 4107005146
]


class LazyDevice(contextlib.AbstractContextManager, _encryption.Device):
    def __init__(self):
        self.__session = None

    def __exit__(self, exc_type, exc_value, traceback):
        if self.__session is not None:
            self.__session.close()
            self.__session = None

    def __get_session(self) -> trezorlib.client.Session:
        if self.__session is None:
            client = trezorlib.client.get_default_client(_APP_NAME)
            self.__session = trezorlib.client.get_default_session(client)
        return self.__session

    def _encrypt_raw(self, params: Params, value: bytes) -> bytes:
        return trezorlib.misc.encrypt_keyvalue(
            session=self.__get_session(),
            n=_BIP_32_PATH,
            key=params.key,
            value=value,
            iv=b"0" * 16,
            ask_on_encrypt=params.ask_on_encrypt,
            ask_on_decrypt=params.ask_on_decrypt,
        )

    def _decrypt_raw(self, params: Params, value: bytes) -> bytes:
        return trezorlib.misc.decrypt_keyvalue(
            session=self.__get_session(),
            n=_BIP_32_PATH,
            key=params.key,
            value=value,
            iv=b"0" * 16,
            ask_on_encrypt=params.ask_on_encrypt,
            ask_on_decrypt=params.ask_on_decrypt,
        )
