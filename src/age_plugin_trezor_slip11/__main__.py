import argparse
import base64
import dataclasses
import enum
import logging
import os
import re
import sys
import uuid
from dataclasses import dataclass

from . import _bech32
from . import _encryption
from . import _trezor

_AGE_RECIPIENT_STANZA = "jloc.fr/age-plugin-trezor-slip11"
_AGE_IDENTITY_HRP = "AGE-PLUGIN-TREZOR-SLIP11-"

_STANZA_ARG_LINE_REGEX = re.compile(r"^-> (\S+)(( \S+)*)\n$")
_STANZA_BODY_LINE_REGEX = re.compile(r"^([a-zA-Z0-9+/]{0,64})\n$")


def _b64_encode(data: bytes) -> str:
    return base64.standard_b64encode(data).rstrip(b"=").decode()


def _b64_decode(s: str) -> bytes:
    return base64.standard_b64decode(s + "=" * ((4 - len(s) % 4) % 4))


@dataclass
class _Stanza:
    arg0: str
    args: list[str] = dataclasses.field(default_factory=list)
    body: bytes = bytes()

    @staticmethod
    def receive() -> "_Stanza":
        m = _STANZA_ARG_LINE_REGEX.match(sys.stdin.readline())
        if m is None:
            raise ValueError("failed to parse stanza argument line")
        arg0 = m[1]
        args = [] if not m[2] else m[2][1:].split(" ")

        body = bytes()
        while True:
            line = sys.stdin.readline()
            m = _STANZA_BODY_LINE_REGEX.match(line)
            if m is None:
                raise ValueError("failed to parse stanza body line")
            line = m[1]
            if line:
                body += _b64_decode(line)
            if line is None or len(line) < 64:
                break

        return _Stanza(arg0=arg0, args=args, body=body)

    def send(self):
        print(f"-> {self.arg0}", end="")
        for arg in self.args:
            print(f" {arg}", end="")
        print()

        remaining = _b64_encode(self.body)
        body_ended = False
        while len(remaining) != 0:
            chunk_len = min(64, len(remaining))
            if chunk_len != 64:
                body_ended = True
            print(remaining[:chunk_len], flush=body_ended)
            remaining = remaining[chunk_len:]
        if not body_ended:
            print(flush=True)


@dataclass
class _TrezorIdentity:
    id: bytes
    encryption_params: _encryption.Params

    @staticmethod
    def generate(encryption_params: _encryption.Params) -> "_TrezorIdentity":
        return _TrezorIdentity(uuid.uuid4().bytes, encryption_params)

    def encode(self) -> str:
        return _bech32.encode(_AGE_IDENTITY_HRP, self.id + self.encryption_params.encode()).upper()

    @staticmethod
    def decode(identity: str) -> "_TrezorIdentity":
        (hrp, body) = _bech32.decode(identity)
        if hrp.upper() != _AGE_IDENTITY_HRP:
            raise ValueError(f"unsupported identity type {repr(hrp)}")

        if len(body) < 16:
            raise ValueError(f"identity body too short")

        return _TrezorIdentity(
            body[:16],
            _encryption.Params.decode(body[16:]),
        )


@dataclass
class _WrappedKey:
    identity_id: bytes
    encrypted_key: bytes

    @staticmethod
    def generate(device: _encryption.Device, identity: _TrezorIdentity, key: bytes) -> "_WrappedKey":
        encrypted_key = device.encrypt(identity.encryption_params, key)
        return _WrappedKey(identity_id=identity.id, encrypted_key=encrypted_key)

    def unwrap(self, device: _encryption.Device, encryption_params: _encryption.Params) -> bytes:
        return device.decrypt(encryption_params, self.encrypted_key)

    def encode(self) -> _Stanza:
        return _Stanza(
            arg0=_AGE_RECIPIENT_STANZA,
            args=[_b64_encode(self.identity_id)],
            body=self.encrypted_key,
        )

    @staticmethod
    def decode(stanza: _Stanza) -> "_WrappedKey":
        if stanza.arg0 != _AGE_RECIPIENT_STANZA:
            raise ValueError("wrapped key with wrong stanza name")
        if len(stanza.args) != 1:
            raise ValueError("wrapped key with wrong number of arguments")
        return _WrappedKey(identity_id=_b64_decode(stanza.args[0]), encrypted_key=stanza.body)


def _send_message(message: str):
    _Stanza(arg0="msg", body=message.encode()).send()
    if _Stanza.receive().arg0 != "ok":
        raise Exception("failed to send error")


def _send_internal_error(message: str):
    _Stanza(arg0="error", args=["internal"], body=message.encode()).send()
    if _Stanza.receive().arg0 != "ok":
        raise Exception("failed to send error")


def _send_recipient_error(identity_index: int, message: str):
    _Stanza(arg0="error", args=["recipient", str(identity_index)], body=message.encode()).send()
    if _Stanza.receive().arg0 != "ok":
        raise Exception("failed to send error")


def _send_identity_error(identity_index: int, message: str):
    _Stanza(arg0="error", args=["identity", str(identity_index)], body=message.encode()).send()
    if _Stanza.receive().arg0 != "ok":
        raise Exception("failed to send error")


class _AgePluginProtocol(enum.Enum):
    RECIPIENT_V1 = "recipient-v1"
    IDENTITY_V1 = "identity-v1"


def _run(protocol: _AgePluginProtocol, stanzas: list[_Stanza], device: _encryption.Device):
    # phase 1 of plugin protocol

    recipients: list[str] = []
    identities: list[str] = []
    file_keys: list[bytes] = []
    wrapped_keys: dict[int, list[_Stanza]] = {}
    for stanza in stanzas:
        match protocol, stanza.arg0:
            case _AgePluginProtocol.RECIPIENT_V1, "add-recipient":
                if len(stanza.args) != 1:
                    raise ValueError("the add-recipient command takes exactly one argument")
                recipients.append(stanza.args[0])
            case _, "add-identity":
                if len(stanza.args) != 1:
                    raise ValueError("the add-identity command takes exactly one argument")
                identities.append(stanza.args[0])
            case _AgePluginProtocol.RECIPIENT_V1, "wrap-file-key":
                if len(stanza.args) != 0:
                    raise ValueError("the wrap-file-key command takes no arguments")
                file_keys.append(stanza.body)
            case _AgePluginProtocol.IDENTITY_V1, "recipient-stanza":
                if len(stanza.args) < 2:
                    raise ValueError("the recipient-stanza takes at least two arguments")
                file_index = int(stanza.args[0])
                file_wrapped_keys = wrapped_keys.get(file_index) or []
                wrapped_keys[file_index] = file_wrapped_keys
                file_wrapped_keys.append(_Stanza(arg0=stanza.args[1], args=stanza.args[2:], body=stanza.body))

    # decoding recipients and identities

    for recipient_index in range(len(recipients)):
        _send_recipient_error(recipient_index, "asymmetric encryption is not supported by this plugin")

    decoded_identities: dict[bytes, tuple[int, _TrezorIdentity]] = {}
    for identity_index in range(len(identities)):
        try:
            identity = _TrezorIdentity.decode(identities[identity_index])
            decoded_identities[identity.id] = (identity_index, identity)
        except Exception as e:
            _send_identity_error(identity_index, str(e))

    # phase 2 of plugin protocol

    match protocol:
        case _AgePluginProtocol.RECIPIENT_V1:
            for file_index in range(len(file_keys)):
                for (identity_index, identity) in decoded_identities.values():
                    wrapped_key = None
                    try:
                        wrapped_key = _WrappedKey.generate(device, identity, file_keys[file_index]).encode()
                    except Exception as e:
                        _send_identity_error(identity_index, str(e))
                    if wrapped_key is not None:
                        _Stanza(
                            arg0="recipient-stanza",
                            args=[str(file_index), wrapped_key.arg0] + wrapped_key.args,
                            body=wrapped_key.body,
                        ).send()
                        if _Stanza.receive().arg0 != "ok":
                            raise Exception("failed to send wrapped key")
        case _AgePluginProtocol.IDENTITY_V1:
            for file_index, stanzas in wrapped_keys.items():
                for recipient in stanzas:
                    if recipient.arg0 == _AGE_RECIPIENT_STANZA:
                        wrapped_key = _WrappedKey.decode(recipient)
                        x = decoded_identities.get(wrapped_key.identity_id)
                        if x is not None:
                            identity_index, identity = x
                            key = wrapped_key.unwrap(device, identity.encryption_params)
                            _Stanza(arg0="file-key", args=[str(file_index)], body=key).send()
                            if _Stanza.receive().arg0 != "ok":
                                raise Exception("failed to send unwrapped key")
                            break

    _Stanza(arg0="done").send()


def _main_inner(args):
    if args.subcommand is None:
        if not args.age_plugin:
            raise Exception("missing age plugin state machine specification")

        match args.age_plugin:
            case "recipient-v1":
                protocol = _AgePluginProtocol.RECIPIENT_V1
            case "identity-v1":
                protocol = _AgePluginProtocol.IDENTITY_V1
            case x:
                raise Exception(f"unsupported age plugin state machine: {repr(x)}")

        stanzas = []
        while True:
            stanza = _Stanza.receive()
            if stanza.arg0 == "done":
                break
            stanzas.append(stanza)

        try:
            if os.environ.get("AGE_PLUGIN_TREZOR_SLIP11_UNSAFE_TEST_MODE") == "true":
                _run(protocol, stanzas, _encryption.FakeDevice())
            else:
                with _trezor.LazyDevice() as device:
                    _run(protocol, stanzas, device)
        except Exception as e:
            logging.exception("exception")
            _send_internal_error(str(e))
    else:
        if args.age_plugin is not None:
            raise Exception("age plugin state machine specified, but not in plugin mode")

        match args.subcommand:
            case "generate-identity":
                encryption_params = _encryption.Params(
                    key=args.key,
                    ask_on_encrypt=not args.dont_ask_on_encrypt,
                    ask_on_decrypt=not args.dont_ask_on_decrypt,
                )
                identity = _TrezorIdentity.generate(encryption_params)
                print(identity.encode())

            case x:
                raise Exception(f"unknown subcommand: {repr(x)}")


def main():
    # debug logging

    debug_file = os.environ.get("AGE_PLUGIN_TREZOR_SLIP11_DEBUG_FILE")
    if debug_file is not None:
        logging.basicConfig(filename=debug_file, level=logging.DEBUG)

    logging.debug(f"called with args: {repr(sys.argv)}")

    # parsing program arguments

    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument("--age-plugin")

    arg_subparsers = arg_parser.add_subparsers(dest="subcommand")

    arg_subparser_generate_identity = arg_subparsers.add_parser("generate-identity")
    arg_subparser_generate_identity.add_argument("--key", required=True)
    arg_subparser_generate_identity.add_argument("--dont-ask-on-encrypt", action="store_true")
    arg_subparser_generate_identity.add_argument("--dont-ask-on-decrypt", action="store_true")

    args = arg_parser.parse_args()

    # work

    try:
        _main_inner(args)
    except:
        logging.exception("fatal")
        raise


if __name__ == "__main__":
    main()
