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
age-plugin-trezor-slip11 encode-identity --key=KEY > identity.txt
```

You can then encrypt or decrypt messages by passing the generated identity to age:

```shell
age -i ./identity.txt -e -a <<<'super secret' > encrypted.age
age -i ./identity.txt -d < ./encrypted.age
```

## Recovering Data Without a Device

This plugin can directly load a SLIP-0039 mnemonic and reproduce the behavior of a
real device. This is useful for recovery situation, if you have lost access to your
physical device.

The `soft` option should be enabled at install:

```shell
pip install age-plugin-trezor-slip11[soft]
```

You can then pass the mnemonic through an environment variable:

```shell
export AGE_PLUGIN_TREZOR_SLIP11_UNSAFE_MNEMONIC="display email academic ..."
age -i identity -d < ./encrypted.age
```

Please note that mnemonics should normally stay offline, otherwise you are defeating
the whole purpose of a hardware wallet. This feature should be reserved for testing
or desperate situations.

## Running Tests

```shell
# from the root of the project
pip install -r requirements.txt
pytest  # run tests, excluding those depending on a connection with a device...
```

To run tests against a real device or emulator, you first need to initialize it with this
mnemonic:

```
display email academic academic credit violence anatomy package umbrella learn rhyme belong merchant union safari finger curly ugly bike flame
```

You can then run all the tests:

```shell
pytest --use-device
```

## Development

For debugging, set the environment variable `AGE_PLUGIN_TREZOR_SLIP11_DEBUG_FILE=/path/to/log/file`.

For using a fake backend instead of a real device, set this variable to a SLIP-0039 mnemonic:

```shell
export AGE_PLUGIN_TREZOR_SLIP11_UNSAFE_MNEMONIC="display email academic academic credit violence anatomy package umbrella learn rhyme belong merchant union safari finger curly ugly bike flame"
```

## References

* [Plugin interface for age](https://c2sp.org/age-plugin)
* [SLIP-0011](https://slips.readthedocs.io/en/latest/slip-0011/) : key/value encryption using a hardware wallet
