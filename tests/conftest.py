import enum

import pytest


class Backend(enum.Enum):
    VIRTUAL = 0  # encrypt and decrypt with a fake backend
    STORED = 1  # use fixed tests vectors
    REAL = 2  # encrypt and decrypt with a real device or emulator


ENCRYPTORS = [
    Backend.STORED,
    Backend.VIRTUAL,
    Backend.REAL,
]

DECRYPTORS = [
    Backend.VIRTUAL,
    Backend.REAL,
]


def pytest_addoption(parser):
    parser.addoption(
        "--use-device",
        action="store_true",
        default=False,
        help="run tests against a real device, in addition to other tests",
    )


def pytest_collection_modifyitems(config, items):
    if not config.getoption("--use-device"):
        # skip tests that depend on a real device
        skip_real_mode = pytest.mark.skip(reason="tests against a device are not enabled")
        for item in items:
            if getattr(item, "callspec", None) is not None:
                for param in item.callspec.params.values():
                    if param.value == Backend.REAL.value:
                        item.add_marker(skip_real_mode)
