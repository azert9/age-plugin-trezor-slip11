# age-plugin-trezor-slip11

This [age](https://age-encryption.org/) plugin allows you to encrypt data using a Trezor hardware wallet.

Compared to other projects, this one is based on [SLIP-0011](https://slips.readthedocs.io/en/latest/slip-0011/) and does
symmetric encryption.

## Usage

Install the plugin:

```shell
pip install age-plugin-trezor-slip11
```

The next step is to generate an identity, which will represent our secret key. Identities generated
by this plugin don't contain any secret information, they only contain parameters for tweaking encryption.

The `KEY` parameter in the example bellow is what will be displayed on the device's screen when encrypting
or decrypting messages.

```shell
age-plugin-trezor-slip11 generate-identity --key=KEY > identity.txt
```

You can then encrypt or decrypt messages by passing the generated identity to age:

```shell
age -i ./identity.txt -e -a <<<'super secret' > encrypted.age
age -i ./identity.txt -d < ./encrypted.age
```

## Running tests

```shell
# from the root of the project
pip install pytest
pytest  # run tests, excluding those depending on a connection with a device...
pytest --use-device  # ... or including all tests
```

## Development

For debugging, set the environment variable `AGE_PLUGIN_TREZOR_SLIP11_DEBUG_FILE=/path/to/log/file`.

For using a fake backend instead of connecting to a device, set `AGE_PLUGIN_TREZOR_SLIP11_UNSAFE_TEST_MODE=true`.

## References

* [Plugin interface for age](https://c2sp.org/age-plugin)
* [SLIP-0011](https://slips.readthedocs.io/en/latest/slip-0011/) : key/value encryption using a hardware wallet
