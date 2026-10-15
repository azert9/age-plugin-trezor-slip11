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

    def write_identity(self, tmp_dir: pathlib.Path, identity: str | None = None) -> str:
        self.__serial += 1
        if identity is None:
            identity = self.plugin(
                "generate-identity",
                "--key=tests",
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


def test_generate_identity(context: Context, tmp_path):
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
            "AGE-PLUGIN-TREZOR-SLIP11-1U0ZLFCE5L9Y3EGVNUUS37KENY5QQQAR9WD6Q74YU73",
        )
        ciphertext = b"""-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IGpsb2MuZnIvYWdlLXBsdWdpbi10cmV6
b3Itc2xpcDExIDQ4WDA0elQ1U1J5aGsrY2hIMXN6SlEKSDUyYXhFOTRkOThQa2RC
RlVYZFc4WmRGK2dETXRJQzk4cm5tdTVKSTFzL1p5bnUvem9YNWFOazB2YW1IT090
MQp2bEY0aHcwY3IwbTd5cjBSQUExa1N3Ci0tLSBSVDRiVC9TVmtlWmN5UVNnSWtI
ZTJkTDNScUhIaXk0Q0xsTlAxakFjaTV3CvsMZri5j34EyjIrsEHitq0Ba6HQl2iG
MBkyOvZ864jmG/H8xrQnT6l4/cCl8Q==
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
        identity1_path = context.write_identity(
            tmp_path,
            "AGE-PLUGIN-TREZOR-SLIP11-1TQMP96ZW7FYZTG2A94CYT8K8XYQQQAR9WD6QWRT697",
        )
        identity2_path = context.write_identity(
            tmp_path,
            "AGE-PLUGIN-TREZOR-SLIP11-17PVMNAVGDP9H3TXXQ8APJFY66GQQQAR9WD6QHTR94N",
        )
        ciphertext = b"""-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IGpsb2MuZnIvYWdlLXBsdWdpbi10cmV6
b3Itc2xpcDExIFdEWVM2RTd5U0NXaFhTMXdSWjdITVEKYnJLNzE0bE1uUUpURjFo
RE9WZ2M3WlYwNXpWamY0c1pIcmR5TERPYzBJZ3lPL1RqMzVic3EzbzhOSnB5Ry9P
Ngp2bEY0aHcwY3IwbTd5cjBSQUExa1N3Ci0+IGpsb2MuZnIvYWdlLXBsdWdpbi10
cmV6b3Itc2xpcDExIDhGbTU5WWhvUzNpc3hnSDZHU1NhMGcKakQxb3hrT1R0SG1V
eFVCZ3F0Q3FOVS9EQzN3aklXYjJnRDFadzA1cXIzWXlPL1RqMzVic3EzbzhOSnB5
Ry9PNgp2bEY0aHcwY3IwbTd5cjBSQUExa1N3Ci0tLSA3SGh1WExQMEhzVU1zaXdt
eVdZZ2JtaFhkOGo1YnBxdHBKcElaRnFmU3BzChcMpUT2zAH+ZduF/oo5uy2TEg5t
+JFGBAyYEkfAqtLRdnn0UYkV2k8S9R8=
-----END AGE ENCRYPTED FILE-----
"""
    else:
        identity1_path = context.write_identity(tmp_path)
        identity2_path = context.write_identity(tmp_path)
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
            "AGE-PLUGIN-TREZOR-SLIP11-1HWZ0TMJEZ3R4AFAXE6G457WPVUQQQAR9WD6QXSLHA6"
        )
        ciphertext = b"""-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSAwVElKdHFsbzhxSVg3Mkps
dmgweTFoWDR6TnliU1IwN3VuUFoyazVQcFNnClJtL2NxRGpOTUwvSEJiN3ppMUFF
SVJTL3dMQ1lzWUhkbzZYTktLcXgrbkUKLT4gamxvYy5mci9hZ2UtcGx1Z2luLXRy
ZXpvci1zbGlwMTEgdTRUMTdsa1VSMTZucHM2UldubkJadwpyVnp3NXNoL3ZXcEZD
V1F2UHNMSVpaanM4eXJYNXYxTmtSeEcvc05KdlY1alpiRTRwTnJSSmlRMjlWd2cr
eXBsCnZsRjRodzBjcjBtN3lyMFJBQTFrU3cKLS0tIEkrZ3NEWmxDLzl2MHIwVCtN
Yzh2Q0o2SDZHeHVjc0YvUmZPUVJpc3FPTWcKLbnrfLs85pny1FoCiKoFZBmHer5T
coo7ifd3+gAjSNQ3KqOJ
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
        "AGE-PLUGIN-TREZOR-SLIP11-1HWZ0TMJEZ3R4AFAXE6G457WPVUQQQAR9WD6QXSLHA6",
    )

    ciphertext = b"""-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IGpsb2MuZnIvYWdlLXBsdWdpbi10cmV6
b3Itc2xpcDExIDQ4WDA0elQ1U1J5aGsrY2hIMXN6SlEKSDUyYXhFOTRkOThQa2RC
RlVYZFc4WmRGK2dETXRJQzk4cm5tdTVKSTFzL1p5bnUvem9YNWFOazB2YW1IT090
MQp2bEY0aHcwY3IwbTd5cjBSQUExa1N3Ci0tLSBSVDRiVC9TVmtlWmN5UVNnSWtI
ZTJkTDNScUhIaXk0Q0xsTlAxakFjaTV3CvsMZri5j34EyjIrsEHitq0Ba6HQl2iG
MBkyOvZ864jmG/H8xrQnT6l4/cCl8Q==
-----END AGE ENCRYPTED FILE-----
"""

    out = context.age("-i", identity_path, "-d", stdin=ciphertext, check=False)
    assert out.returncode > 0
    assert "age: error: no identity matched any of the recipients\n" in out.stderr.decode()


def test_decrypting_altered_ciphertext(context: Context, tmp_path):
    context.mode = Mode.STORED

    identity_path = context.write_identity(
        tmp_path,
        "AGE-PLUGIN-TREZOR-SLIP11-1U0ZLFCE5L9Y3EGVNUUS37KENY5QQQAR9WD6Q74YU73",
    )

    ciphertext = b"""-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IGpsb2MuZnIvYWdlLXBsdWdpbi10cmV6
b3Itc2xpcDExIDQ4WDA0elQ1U1J5aGsrY2hIMXN6SlEKSDUyYXhFOTRkOThQa2RC
RlVYZFc4WmRGK2dETXRJQzk4cm5tdTVkSTFzL1p5bnUvem9YNWFOazB2YW1IT090
MQp2bEY0aHcwY3IwbTd5cjBSQUExa1N3Ci0tLSBSVDRiVC9TVmtlWmN5UVNnSWtI
ZTJkTDNScUhIaXk0Q0xsTlAxakFjaTV3CvsMZri5j34EyjIrsEHitq0Ba6HQl2iG
MBkyOvZ864jmG/H8xrQnT6l4/cCl8Q==
-----END AGE ENCRYPTED FILE-----
"""

    out = context.age("-i", identity_path, "-d", stdin=ciphertext, check=False)
    assert out.returncode > 0
    assert "age: error: trezor-slip11 plugin: message authentication failed\n" in out.stderr.decode()
