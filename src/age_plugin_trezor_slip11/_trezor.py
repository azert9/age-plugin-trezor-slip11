import contextlib

import trezorlib.client
import trezorlib.misc

from . import _encryption, _constants


class LazyDevice(contextlib.AbstractContextManager, _encryption.Device):
    """Represents a Trezor device, which we will only connect to when cryptographic operations are requested."""

    def __init__(self):
        self.__session = None

    def __exit__(self, exc_type, exc_value, traceback):
        if self.__session is not None:
            self.__session.close()
            self.__session = None

    def __get_session(self) -> trezorlib.client.Session:
        if self.__session is None:
            client = trezorlib.client.get_default_client(_constants.APP_NAME)
            self.__session = trezorlib.client.get_default_session(client)
        return self.__session

    def _encrypt_raw(self, params: _encryption.Params, value: bytes) -> bytes:
        return trezorlib.misc.encrypt_keyvalue(
            session=self.__get_session(),
            n=_constants.BIP_32_PATH,
            key=params.key,
            value=value,
            iv=_constants.IV,
            ask_on_encrypt=params.ask_on_encrypt,
            ask_on_decrypt=params.ask_on_decrypt,
        )

    def _decrypt_raw(self, params: Params, value: bytes) -> bytes:
        return trezorlib.misc.decrypt_keyvalue(
            session=self.__get_session(),
            n=_constants.BIP_32_PATH,
            key=params.key,
            value=value,
            iv=_constants.IV,
            ask_on_encrypt=params.ask_on_encrypt,
            ask_on_decrypt=params.ask_on_decrypt,
        )
