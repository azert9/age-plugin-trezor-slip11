import os
import pathlib
import re
import subprocess
import sys
import tempfile

import pytest

from conftest import Backend, ENCRYPTORS, DECRYPTORS

MNEMONIC = "display email academic academic credit violence anatomy package umbrella learn rhyme belong merchant union safari finger curly ugly bike flame"


class Context:
    def __init__(self, bin_dir: str):
        self.__bin_dir = bin_dir
        self.__serial = 0
        self.backend = Backend.STORED

    def write_identity(self, tmp_dir: pathlib.Path, identity: str | None = None, key: str = "tests") -> str:
        """Write a newly generated age identity (or the provided one) to a temporary file."""
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
        try:
            return subprocess.run(
                args,
                env=env,
                check=check,
                capture_output=True,
                input=stdin,
            )
        except subprocess.CalledProcessError as e:
            sys.stderr.write(f"======== command failed: {repr(args)}\n")
            sys.stderr.write(f"======== return code: {e.returncode}\n")
            sys.stderr.write(f"======== stdout:\n")
            sys.stderr.write(e.stdout.decode())
            sys.stderr.write(f"======== stderr:\n")
            sys.stderr.write(e.stderr.decode())
            sys.stderr.write(f"======== end of command output\n")
            raise

    def plugin(self, *args: str) -> subprocess.CompletedProcess[bytes]:
        """Run the age plugin with the given arguments."""
        return self.__run(["age-plugin-trezor-slip11"] + list(args))

    def age(self, *args: str, stdin: bytes | None = None, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        """Run age with the given arguments."""
        env = {}
        match self.backend:
            case Backend.STORED:
                assert False
            case Backend.VIRTUAL:
                env["AGE_PLUGIN_TREZOR_SLIP11_UNSAFE_MNEMONIC"] = MNEMONIC
            case Backend.REAL:
                pass
        return self.__run(["age"] + list(args), stdin=stdin, check=check, env=env)

    def age_keygen(self, tmp_dir: pathlib.Path) -> tuple[str, str]:
        """Use the age-keygen command to generate a key pair. Returns the path to the private key, and the public key."""
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
    context.backend = Backend.VIRTUAL
    context.age("--version")
    context.age_keygen(tmp_path)


def test_encode_identity(context: Context, tmp_path):
    identity_path = context.write_identity(tmp_path)
    with open(identity_path, "r") as f:
        identity = f.read()
    assert re.match(r"^AGE-PLUGIN-TREZOR-SLIP11-1[AC-HJ-NP-Z02-9]+\n$", identity)


@pytest.mark.parametrize("encryptor", ENCRYPTORS)
@pytest.mark.parametrize("decryptor", DECRYPTORS)
def test_simple(context: Context, tmp_path, encryptor: Backend, decryptor: Backend):
    message = b"sup3r s3cr3t\n"

    # encryption

    if encryptor == Backend.STORED:
        identity_path = context.write_identity(
            tmp_path,
            "AGE-PLUGIN-TREZOR-SLIP11-1QQQ8GETNW3ESEPWSWU",
        )
        ciphertext = b"""-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IGpsb2MuZnIvYWdlLXBsdWdpbi10cmV6
b3Itc2xpcDExIEFBQjBaWE4wY3cKa2szUkgyOXZFU2FGSjY3bE9rVzBvNW1VU2Ft
OXJIenN3SVprQ0cxQ1k0VmFkZWJOWFFaTXVXVDMxOXd2dzhiOApHelBYZUlDZjFt
b0xBYWpwMTZTalNnCi0tLSBLVzZRaVFWSzgreTBJYVpaRklIdzQ0ZWp6RmpVci9t
Y3hQMTFKZ3VMK09jCjpv3QU3HdXeoQ2eN96wKlvUsMcxqCQuEplChiusEUxCaQN8
oTG1FQBSzpQ0aw==
-----END AGE ENCRYPTED FILE-----
"""
    else:
        context.backend = encryptor
        identity_path = context.write_identity(tmp_path)
        ciphertext = context.age("-i", identity_path, "-e", stdin=message).stdout

    # decryption

    context.backend = decryptor

    plaintext = context.age("-i", identity_path, "-d", stdin=ciphertext).stdout

    assert plaintext == message


@pytest.mark.parametrize("encryptor", ENCRYPTORS)
@pytest.mark.parametrize("decryptor", DECRYPTORS)
def test_multiple_identities(context: Context, tmp_path, encryptor: Backend, decryptor: Backend):
    message = b"bloup bloup"

    # encryption

    if encryptor == Backend.STORED:
        identity1_path = context.write_identity(tmp_path, "AGE-PLUGIN-TREZOR-SLIP11-1QQQ8GETNW3ESEPWSWU")
        identity2_path = context.write_identity(tmp_path, "AGE-PLUGIN-TREZOR-SLIP11-1QQQ8GETNW3EJQVSWMQSV4")
        ciphertext = b"""-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IGpsb2MuZnIvYWdlLXBsdWdpbi10cmV6
b3Itc2xpcDExIEFBQjBaWE4wY3cKdWtNWUoyQVVDd0Z0RlhlN0I2MVpYSDkzaWM1
MEFhNFhYc1hVeWhLSHUrbSs3QnE3cGYwQ3Y5SnpWMHgxQ1hnRgptUitKd211Nm1L
cXVpVGNVdHcvVy93Ci0+IGpsb2MuZnIvYWdlLXBsdWdpbi10cmV6b3Itc2xpcDEx
IEFBQjBaWE4wY3lBeQpaYnhWbVpOWHE4cFFHeU0wUjk5UndyMFV5eVpOdXFjbU95
YlJKRWVaYWxlaENMK09XTWtnbllUU21HdEtidWttCm1kaHhNaksvVjY4R0MvVTR6
YkNMWXcKLS0tIHRnekJvWjZGZkNHVFBNTk5Kd3NZUWxObDVhZm1HTlRaVG15Q1g4
czYvR1EKuRYva3USFUSLtQfdUGeuZqjVnGtfFBS5ryRoGiuIU8Ja1ae4lYcfHw+J
9Q==
-----END AGE ENCRYPTED FILE-----
"""
    else:
        context.backend = encryptor
        identity1_path = context.write_identity(tmp_path)
        identity2_path = context.write_identity(tmp_path, key="tests 2")
        ciphertext = context.age("-i", identity1_path, "-i", identity2_path, "-e", stdin=message).stdout

    # decryption

    context.backend = decryptor

    plaintext = context.age("-i", identity1_path, "-d", stdin=ciphertext).stdout
    assert plaintext == message

    plaintext = context.age("-i", identity2_path, "-d", stdin=ciphertext).stdout
    assert plaintext == message

    plaintext = context.age("-i", identity1_path, "-i", identity2_path, "-d", stdin=ciphertext).stdout
    assert plaintext == message


@pytest.mark.parametrize("encryptor", ENCRYPTORS)
@pytest.mark.parametrize("decryptor", DECRYPTORS)
def test_mixed_identity_types(context: Context, tmp_path, encryptor: Backend, decryptor: Backend):
    message = b"blip"

    # encryption

    if encryptor == Backend.STORED:
        basic_identity_2_path = context.write_identity(
            tmp_path,
            "AGE-SECRET-KEY-17TQWVP5EXA9Y6YCDSFS7ML627AN5A4L06R0XXH2HWC4F88PNZ6SSKDD2VZ",
        )
        plugin_identity_path = context.write_identity(
            tmp_path,
            "AGE-PLUGIN-TREZOR-SLIP11-1QQQ8GETNW3ESEPWSWU",
        )
        ciphertext = b"""-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBLVXQ3S1g1d0Fma2JrVFMw
enA2bGplSEhsWGJWekZMbXZVZFQ2eFRGV0c4ClFMcTd3NU5GWVRwQzdqeUNHcitr
cUhDeVhxWjhmNE1YOVJFWTVGRGhsOWMKLT4gamxvYy5mci9hZ2UtcGx1Z2luLXRy
ZXpvci1zbGlwMTEgQUFCMFpYTjBjdwpjTjVhZTVZdjBCV0RROU40TEhhMnJ3UUtk
cHpoS2liSXpYUzRvL0RZb3p6TVl5OVdWNHZvbEVYRmtvMHl3VllUClVuTjBaeGNs
K1laWjd3TzIxWjNLTUEKLS0tIHBSa3JrVlJpVXVqcGhhMWVtcStBZ2FIZmx4UitR
RmVILzg5U1h2SUVEM1EKzyrBxz36Ac43lwgXs50+5NGn19WBwl0B3Ig7cBxAIhJN
oZzT
-----END AGE ENCRYPTED FILE-----
"""
    else:
        context.backend = encryptor

        _, basic_recipient_1 = context.age_keygen(tmp_path)
        basic_identity_2_path, _ = context.age_keygen(tmp_path)

        plugin_identity_path = context.write_identity(tmp_path)
        ciphertext = context.age("-i", plugin_identity_path, "-r", basic_recipient_1, "-e", stdin=message).stdout

    # decryption

    context.backend = decryptor

    plaintext = context.age("-i", plugin_identity_path, "-i", basic_identity_2_path, "-d", stdin=ciphertext).stdout

    assert plaintext == message


@pytest.mark.parametrize("decryptor", DECRYPTORS)
def test_decrypting_with_wrong_identity(context: Context, tmp_path, decryptor: Backend):
    identity_path = context.write_identity(
        tmp_path,
        "AGE-PLUGIN-TREZOR-SLIP11-1QQQ8GETNW3EJQVSWMQSV4",
    )

    ciphertext = b"""-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IGpsb2MuZnIvYWdlLXBsdWdpbi10cmV6
b3Itc2xpcDExIEFBQjBaWE4wY3cKa2szUkgyOXZFU2FGSjY3bE9rVzBvNW1VU2Ft
OXJIenN3SVprQ0cxQ1k0VmFkZWJOWFFaTXVXVDMxOXd2dzhiOApHelBYZUlDZjFt
b0xBYWpwMTZTalNnCi0tLSBLVzZRaVFWSzgreTBJYVpaRklIdzQ0ZWp6RmpVci9t
Y3hQMTFKZ3VMK09jCjpv3QU3HdXeoQ2eN96wKlvUsMcxqCQuEplChiusEUxCaQN8
oTG1FQBSzpQ0aw==
-----END AGE ENCRYPTED FILE-----
"""

    context.backend = decryptor

    out = context.age("-i", identity_path, "-d", stdin=ciphertext, check=False)
    assert out.returncode > 0
    assert "age: error: no identity matched any of the recipients\n" in out.stderr.decode()


@pytest.mark.parametrize("decryptor", DECRYPTORS)
def test_decrypting_altered_ciphertext(context: Context, tmp_path, decryptor: Backend):
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

    context.backend = decryptor

    out = context.age("-i", identity_path, "-d", stdin=ciphertext, check=False)
    assert out.returncode > 0
    assert "age: error: trezor-slip11 plugin: message authentication failed\n" in out.stderr.decode()
