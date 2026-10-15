import os
import pathlib
import re
import subprocess
import tempfile

import pytest

from conftest import Mode, MODES


class Context:
    def __init__(self, bin_dir: str):
        self.__bin_dir = bin_dir
        self.__serial = 0
        self.mode = Mode.VIRTUAL

    def write_identity(self, tmp_dir: pathlib.Path, identity: str | None = None, key: str = "tests") -> str:
        self.__serial += 1
        if identity is None:
            identity = self.plugin(
                "encode-identity",
                f"--key={key}",
                "--dont-ask-on-encrypt",
                "--dont-ask-on-decrypt",
            ).stdout.decode("utf-8")
        elif not identity.endswith("\n"):
            identity += "\n"
        identity_path = tmp_dir / f"identity-{self.__serial}.txt"
        with open(identity_path, "w") as f:
            f.write(identity)
        return str(identity_path)

    def __run(
            self,
            args: list[str],
            stdin: bytes | None = None,
            check: bool = True,
            env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        env = env or {}
        env["PATH"] = self.__bin_dir + ":" + os.environ["PATH"]
        return subprocess.run(
            args,
            env=env,
            check=check,
            capture_output=True,
            input=stdin,
        )

    def plugin(self, *args: str) -> subprocess.CompletedProcess[bytes]:
        return self.__run(["age-plugin-trezor-slip11"] + list(args))

    def age(self, *args: str, stdin: bytes | None = None, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        env = {}
        if self.mode != Mode.REAL:
            env["AGE_PLUGIN_TREZOR_SLIP11_UNSAFE_TEST_MODE"] = "true"
        return self.__run(["age"] + list(args), stdin=stdin, check=check, env=env)

    def age_keygen(self, tmp_dir: pathlib.Path) -> tuple[str, str]:
        identity = self.__run(["age-keygen"]).stdout.decode().splitlines()[-1].strip()
        recipient = self.__run(["age-keygen", "-y"], stdin=identity.encode()).stdout.decode().strip()
        identity_path = self.write_identity(tmp_dir, identity)
        return identity_path, recipient


@pytest.fixture(scope="session")
def context():
    src_dir = os.path.abspath("./src/")

    with tempfile.TemporaryDirectory() as tmp_dir:
        bin_dir = os.path.join(tmp_dir, "bin")
        os.mkdir(bin_dir)

        plugin_path = os.path.join(bin_dir, "age-plugin-trezor-slip11")
        with open(plugin_path, "w") as f:
            f.write(f"#!/bin/bash\nset -eu\n\nPYTHONPATH='{src_dir}' exec python3 -m age_plugin_trezor_slip11 \"$@\"\n")
        os.chmod(plugin_path, 0o755)

        yield Context(bin_dir)


def test_can_run_age(context: Context, tmp_path):
    context.age("--version")
    context.age_keygen(tmp_path)


def test_encode_identity(context: Context, tmp_path):
    identity_path = context.write_identity(tmp_path)
    with open(identity_path, "r") as f:
        identity = f.read()
    assert re.match(r"^AGE-PLUGIN-TREZOR-SLIP11-1[AC-HJ-NP-Z02-9]+\n$", identity)


@pytest.mark.parametrize("mode", MODES)
def test_simple(context: Context, tmp_path, mode: Mode):
    context.mode = mode

    message = b"sup3r s3cr3t\n"

    if mode == Mode.STORED:
        identity_path = context.write_identity(
            tmp_path,
            "AGE-PLUGIN-TREZOR-SLIP11-1QQQ8GETNW3ESEPWSWU",
        )
        ciphertext = b"""-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IGpsb2MuZnIvYWdlLXBsdWdpbi10cmV6
b3Itc2xpcDExIEFBQjBaWE4wY3cKMVVJaHVSRFdoMFQ4Q3EzbXowWmZoSTlPaU5O
WXFTclZhNUJ5cENQM3ZFMk8wQ1ltbERwMSs2eXJmRUhWTDRtVgpvcGw5YWtFMzA2
Q3hIRXQ4N2tKak93Ci0tLSBzdGtVbVBZNHZrdjNkdVlxdzdNYWJreE16ckZpNEo0
aTk4aVZoSXhLVko4CruZup5FmK4PMHxf1tvV9Hsz4lxS+IHe/RkZqTVhLd8WsVCB
KL/jH4fze5RFEA==
-----END AGE ENCRYPTED FILE-----
"""
    else:
        identity_path = context.write_identity(tmp_path)
        ciphertext = context.age("-i", identity_path, "-e", stdin=message).stdout

    plaintext = context.age("-i", identity_path, "-d", stdin=ciphertext).stdout

    assert plaintext == message


@pytest.mark.parametrize("mode", MODES)
def test_multiple_identities(context: Context, tmp_path, mode: Mode):
    context.mode = mode

    message = b"bloup bloup"

    if mode == Mode.STORED:
        identity1_path = context.write_identity(tmp_path, "AGE-PLUGIN-TREZOR-SLIP11-1QQQ8GETNW3ESEPWSWU")
        identity2_path = context.write_identity(tmp_path, "AGE-PLUGIN-TREZOR-SLIP11-1QQQ8GETNW3EJQVSWMQSV4")
        ciphertext = b"""-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IGpsb2MuZnIvYWdlLXBsdWdpbi10cmV6
b3Itc2xpcDExIEFBQjBaWE4wY3cKNlZ1NDRncFdXME9kbnpaMEJ4bjFaQ0lDRUFq
NU5rQXZickJyM2dtNFFhbDl1bTBpQnVWVVVjTE52eHRFTnlYMgpvcGw5YWtFMzA2
Q3hIRXQ4N2tKak93Ci0+IGpsb2MuZnIvYWdlLXBsdWdpbi10cmV6b3Itc2xpcDEx
IEFBQjBaWE4wY3lBeQovQkJ4enJYY25hUHczdzl0ellsQStsZ2M5UTh5QTFoa2cv
NHMrWG83Rk5hMUxHYUlXNHFDMVJEZmZ6ZUN3bU5WCkVYWHVMbFBjOE80bUlJanRY
bjFNemcKLS0tIEMvZU54SEYvcjEyYmdIRnJCWWljZ2l6UisvQ21sVTJQWnJLOStJ
bFZpRjAKcMtntuJf+DbF0DAfozLxTbvrq2FhrF7dl+ZCVXcrO27uucYxkkjKEC9Q
0A==
-----END AGE ENCRYPTED FILE-----
"""
    else:
        identity1_path = context.write_identity(tmp_path)
        identity2_path = context.write_identity(tmp_path, key="tests 2")
        ciphertext = context.age("-i", identity1_path, "-i", identity2_path, "-e", stdin=message).stdout

    plaintext = context.age("-i", identity1_path, "-d", stdin=ciphertext).stdout
    assert plaintext == message

    plaintext = context.age("-i", identity2_path, "-d", stdin=ciphertext).stdout
    assert plaintext == message

    plaintext = context.age("-i", identity1_path, "-i", identity2_path, "-d", stdin=ciphertext).stdout
    assert plaintext == message


@pytest.mark.parametrize("mode", MODES)
def test_mixed_identity_types(context: Context, tmp_path, mode: Mode):
    context.mode = mode

    message = b"blip"

    if mode == Mode.STORED:
        basic_identity_2_path = context.write_identity(
            tmp_path,
            "AGE-SECRET-KEY-17TQWVP5EXA9Y6YCDSFS7ML627AN5A4L06R0XXH2HWC4F88PNZ6SSKDD2VZ",
        )
        plugin_identity_path = context.write_identity(
            tmp_path,
            "AGE-PLUGIN-TREZOR-SLIP11-1QQQ8GETNW3ESEPWSWU",
        )
        ciphertext = b"""-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBpMlFUMUtTb3dLU2hkY1dN
WTdOTUtySEZLaDJtdnNuZzVjdU9Pd2tWWlQ0CnE0RVVHNVJPcjRKYmhxZldhWWhz
K0wraHdReEtFRjBJWFdKNHdOa3Fhb2cKLT4gamxvYy5mci9hZ2UtcGx1Z2luLXRy
ZXpvci1zbGlwMTEgQUFCMFpYTjBjdwpjckZ6TnorTURRYW5mMUpzYjdINVc3Vk01
dEJ3N3NXOUsxcEpxaGJXSjV0WllLbFJITmI0Q3F5aTVFYk1TMFZRCm9wbDlha0Uz
MDZDeEhFdDg3a0pqT3cKLS0tICtweXRuOTh2MzVONWdnVmlzQXY2dUJ3SllhM2p0
bEdONDhvQjVUdHlEV0EKVgopFqQl1kHDo6BHthuEfHwJfKcnOefQlHfdgtjhaIZ1
VZzp
-----END AGE ENCRYPTED FILE-----
"""
    else:
        _, basic_recipient_1 = context.age_keygen(tmp_path)
        basic_identity_2_path, _ = context.age_keygen(tmp_path)

        plugin_identity_path = context.write_identity(tmp_path)
        ciphertext = context.age("-i", plugin_identity_path, "-r", basic_recipient_1, "-e", stdin=message).stdout

    plaintext = context.age("-i", plugin_identity_path, "-i", basic_identity_2_path, "-d", stdin=ciphertext).stdout

    assert plaintext == message


def test_decrypting_with_wrong_identity(context: Context, tmp_path):
    context.mode = Mode.STORED

    identity_path = context.write_identity(
        tmp_path,
        "AGE-PLUGIN-TREZOR-SLIP11-1QQQ8GETNW3EJQVSWMQSV4",
    )

    ciphertext = b"""-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IGpsb2MuZnIvYWdlLXBsdWdpbi10cmV6
b3Itc2xpcDExIEFBQjBaWE4wY3cKMVVJaHVSRFdoMFQ4Q3EzbXowWmZoSTlPaU5O
WXFTclZhNUJ5cENQM3ZFMk8wQ1ltbERwMSs2eXJmRUhWTDRtVgpvcGw5YWtFMzA2
Q3hIRXQ4N2tKak93Ci0tLSBzdGtVbVBZNHZrdjNkdVlxdzdNYWJreE16ckZpNEo0
aTk4aVZoSXhLVko4CruZup5FmK4PMHxf1tvV9Hsz4lxS+IHe/RkZqTVhLd8WsVCB
KL/jH4fze5RFEA==
-----END AGE ENCRYPTED FILE-----
"""

    out = context.age("-i", identity_path, "-d", stdin=ciphertext, check=False)
    assert out.returncode > 0
    assert "age: error: no identity matched any of the recipients\n" in out.stderr.decode()


def test_decrypting_altered_ciphertext(context: Context, tmp_path):
    context.mode = Mode.STORED

    identity_path = context.write_identity(
        tmp_path,
        "AGE-PLUGIN-TREZOR-SLIP11-1QQQ8GETNW3ESEPWSWU",
    )

    ciphertext = b"""-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IGpsb2MuZnIvYWdlLXBsdWdpbi10cmV6
b3Itc2xpcDExIEFBQjBaWE4wY3cKMVVJaHVSRFdoMFQ4Q3EzbXowWmZoSTlPaU5O
WXFTclZhNUJ5cENqM3ZFMk8wQ1ltbERwMSs2eXJmRUhWTDRtVgpvcGw5YWtFMzA2
Q3hIRXQ4N2tKak93Ci0tLSBzdGtVbVBZNHZrdjNkdVlxdzdNYWJreE16ckZpNEo0
aTk4aVZoSXhLVko4CruZup5FmK4PMHxf1tvV9Hsz4lxS+IHe/RkZqTVhLd8WsVCB
KL/jH4fze5RFEA==
-----END AGE ENCRYPTED FILE-----
"""

    out = context.age("-i", identity_path, "-d", stdin=ciphertext, check=False)
    assert out.returncode > 0
    assert "age: error: trezor-slip11 plugin: message authentication failed\n" in out.stderr.decode()
