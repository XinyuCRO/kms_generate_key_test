# kms test

This repo demonstrates how to use staking_deposit to generate a key pair and encrypt the private key using AWS KMS. It uses moto to mock the AWS KMS service reponse. Aim to generate testing data.

Check [tests/test_kms.py](tests/test_kms.py) for the example.

Don't use this in production.


## Run

You need to install `poetry` first.

```bash
poetry install
poetry run pytest
```

it will generate a `key_0.json` and `validator_keygen.log` in the project directory.

## Example output

### generated key (before encrypt)

```
keystore: {"crypto": {"kdf": {"function": "scrypt", "params": {"dklen": 32, "n": 262144, "r": 8, "p": 1, "salt": "c96131cb475c793336871a6f2c1ed0dce9959c4895ba83ae4acbca842e6f7d1d"}, "message": ""}, "checksum": {"function": "sha256", "params": {}, "message": "691a5a5e2b8e39bfcf9e8b45b886cd748930170428d39fd1206fc4aa67e37a9a"}, "cipher": {"function": "aes-128-ctr", "params": {"iv": "ead13b7ac425d32023b404d3cd785948"}, "message": "0153477dccab3cc4ec70a8beb780253adc8c5d61de23d848cfa4f228f9b2bc05"}}, "description": "", "pubkey": "96bf57a2edcd4e804f7caaa94a267251b5f7bbb4bd2bb57dcfcda8ea8f6e51f69c484f56b1f9a9a893f7b0db5369fd56", "path": "m/12381/3600/0/0/0", "uuid": "2ffdade1-69a1-471a-9149-fe07985aca31", "version": 4}
password: D2uQyDQG80ViCfoQ-uk
mnemonic: void modify wave begin earn van culture morning dose state merit reject luxury mimic amount document miss recycle final learn float soldier birth okay
```

base64 encoded:

```json
{
    "keystore_b64": "eyJjcnlwdG8iOiB7ImtkZiI6IHsiZnVuY3Rpb24iOiAic2NyeXB0IiwgInBhcmFtcyI6IHsiZGtsZW4iOiAzMiwgIm4iOiAyNjIxNDQsICJyIjogOCwgInAiOiAxLCAic2FsdCI6ICJjOTYxMzFjYjQ3NWM3OTMzMzY4NzFhNmYyYzFlZDBkY2U5OTU5YzQ4OTViYTgzYWU0YWNiY2E4NDJlNmY3ZDFkIn0sICJtZXNzYWdlIjogIiJ9LCAiY2hlY2tzdW0iOiB7ImZ1bmN0aW9uIjogInNoYTI1NiIsICJwYXJhbXMiOiB7fSwgIm1lc3NhZ2UiOiAiNjkxYTVhNWUyYjhlMzliZmNmOWU4YjQ1Yjg4NmNkNzQ4OTMwMTcwNDI4ZDM5ZmQxMjA2ZmM0YWE2N2UzN2E5YSJ9LCAiY2lwaGVyIjogeyJmdW5jdGlvbiI6ICJhZXMtMTI4LWN0ciIsICJwYXJhbXMiOiB7Iml2IjogImVhZDEzYjdhYzQyNWQzMjAyM2I0MDRkM2NkNzg1OTQ4In0sICJtZXNzYWdlIjogIjAxNTM0NzdkY2NhYjNjYzRlYzcwYThiZWI3ODAyNTNhZGM4YzVkNjFkZTIzZDg0OGNmYTRmMjI4ZjliMmJjMDUifX0sICJkZXNjcmlwdGlvbiI6ICIiLCAicHVia2V5IjogIjk2YmY1N2EyZWRjZDRlODA0ZjdjYWFhOTRhMjY3MjUxYjVmN2JiYjRiZDJiYjU3ZGNmY2RhOGVhOGY2ZTUxZjY5YzQ4NGY1NmIxZjlhOWE4OTNmN2IwZGI1MzY5ZmQ1NiIsICJwYXRoIjogIm0vMTIzODEvMzYwMC8wLzAvMCIsICJ1dWlkIjogIjJmZmRhZGUxLTY5YTEtNDcxYS05MTQ5LWZlMDc5ODVhY2EzMSIsICJ2ZXJzaW9uIjogNH0=",
    "password_b64": "RDJ1UXlEUUc4MFZpQ2ZvUS11aw==",
    "mnemonic_b64": "dm9pZCBtb2RpZnkgd2F2ZSBiZWdpbiBlYXJuIHZhbiBjdWx0dXJlIG1vcm5pbmcgZG9zZSBzdGF0ZSBtZXJpdCByZWplY3QgbHV4dXJ5IG1pbWljIGFtb3VudCBkb2N1bWVudCBtaXNzIHJlY3ljbGUgZmluYWwgbGVhcm4gZmxvYXQgc29sZGllciBiaXJ0aCBva2F5"
}
```

### encrypted data

`encrypted_key_password_mnemonic_b64` is the base64 encoded string of json from last step

```json
{
    "web3signer_uuid": "none",
    "chain": "mainnet",
    "pubkey": "96bf57a2edcd4e804f7caaa94a267251b5f7bbb4bd2bb57dcfcda8ea8f6e51f69c484f56b1f9a9a893f7b0db5369fd56",
    "encrypted_key_password_mnemonic_b64": "NDQxMWFkMGYtNDJhYy00OWJhLWFkMTUtNDY4ZWEyYjYxMDhmM4ZyS1/7V3l7Y+1CmSSzj98wwYpvejN96I5hOnixqnPoYge0yY6zCFG44mTauvUCnQ1psKEy6ciVV3ITAo6rXeVW2tuw6F1RCv9xEl59J20KZfh7C7ypwoaA8KFj6hF9LGBvKe0c3E1s5i9kGTiKRZxtF+jvVLnFGx9ue8ru8K2zO2P5eaLJ8BUaz4K2YfxaYfoR7pZCmYBF8DB1WLuGNuGxrx47ch+XpqlLw7OHakSYHCSS/J5PBMt/LX9Q2/FIc3E+Bl1vjYADUJV2EFdiI0X0AkyaMpVOEpzQ0bgCpfnkTAlBKgUlDI/r4F4lcUYFPtGCuturUnLBEovjqNIAPFZSI30eQvS9qBYCD6GVdrWgfA0B7eHOXck88G5thLfC32LyFKz1OdonOkCNC5fZeZvy8J3eSPOQcb4PcRl9eMTvHfIInXdEe6BslDjVw9rkbGIpqwZVJwD8oZPuKtBM/Vv6qEj5XqSd67GtY2U3YEZZaHrQHPf9WeNJyAvYNcj8x3TxMDjuaWwkL9TfCblsDialj6jZG30ODnhWxUzPfl2Pb4LJfPfIceq/tOq1eIBIn6zIMfiQv3n8YFVNPP/UPC6P1Hx1mBkVtDw9xWVFCie+BJCjpGpGp57pdRxFtwv1x+wZhlL0jDxaOMobwf6BwW/vkREoGwO36r/MFV5iazqCWkahKLp6LKyLduuM/mOlq9Nv4tng+t16BhdkHD1U8GbPi/BE8MRlvdWsLsWMHDx89oDT0vVY2gaSSgTlNj+zOjzlUXXukxWoDm1POcCWFhYf/0FmvFX2dzQ5bhYsF9nimOCosd3o0ArL4iNynOism1C5j3/FikVMHk1WDd6huotyEcZNBVe1AORiSIe265MRH97dmQkaA2ZsTaggGjoMP2y2nKwQOJ1KyCBmVnjPP9OwBo/rYlBn3y2vAuadtAtGkvcPSwTP8QZKRDaAAlX9H6FlV4S2YgTTC6M+yBAg9VyTgW11wi4Tdo4eqwKP5Zi8NruvPrW2F1epk2NXFJLjKRuLtzKCqHfx1anxWKN2QEGbqr4K/GeHF6VK9N8XenbbmXhPBoN82prPbh54DOBNeJmsX6OT9JL+ng5SXJ1fCHHBxwgXh7Yxfj59a+fZZowBPndUM/3W0MW9T+8PG4Ti6SRIVIuPYbKsUNMXiQ2+PP/Q9PsQHyyEAJKoFPfGkmfBSC80GCzNEqOCq0c3Sq3zEUY5v0hW5DIPITo5hWAazA4bowSTefIq96q9ZtAX0xFAAY2jorNL5HN+HX2tcsOU1Y/eX8FB2m1BP9pijBuyLx5X7t7ZpnTJsF0lJsv6gzaFDPU6uV/Zs/7yk6KuR8NHq7VQ3WfMygl6MEYT4wAvJPx9/rgxXwNkwtHjkP9yAF+vH5vE3bZG5KPjuKwVuPC6gXgEGtsFEIlR+qvNVxhaf1KW2rtfnfiOnAj2E1+z5wPAlaJUrzv7r6UHC5dj+2HkMwa0JfsUjl9Q2fJA1Blre+Mk56mQxH1ZqRyio6XP0+wmCu2DlzS4rIdy8QqT2qnPzCdwxTrTEF3+jcFkigHfMNTu7zRUY2i0dzjJPyJ9y7P0XPaKQxPiKkzyDllJ8wlyL1oexRFPgkLfzkpbgjzuZQiSj7uhBHniyzRs/UyJLmlM7kacTrMoVV6nd3H78y/WVpAZpWxbAPH6fGD4NI6tDQ==",
    "deposit_json_b64": "W3sicHVia2V5IjogIjk2YmY1N2EyZWRjZDRlODA0ZjdjYWFhOTRhMjY3MjUxYjVmN2JiYjRiZDJiYjU3ZGNmY2RhOGVhOGY2ZTUxZjY5YzQ4NGY1NmIxZjlhOWE4OTNmN2IwZGI1MzY5ZmQ1NiIsICJ3aXRoZHJhd2FsX2NyZWRlbnRpYWxzIjogIjAxMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDZmNGI0NjQyM2ZjNjE4MWEwY2YzNGU2NzE2YzIyMGJkNGQ2YzI0NzEiLCAiYW1vdW50IjogMzIwMDAwMDAwMDAsICJzaWduYXR1cmUiOiAiYWU5ZGU4ZDk4ODJjYjNiZDUxMTQ4NTQ5OTk5MWM4OTM3NWRkY2JlNTQ4YzZhNTU5ZWMxYzQ0ZWQ5NGQwMjJjOGNhOTcxZGRmMDkxNTczNzQ0MGE0OTk2NzgzZTExMThjMDEyNmQwYmZmYzA5NGI0NmNkZTQ0NWE5NTgwODQwYjg5OTczZDE4YzJjNjRmOTdiN2Y1Yjg1ZDgzMDE0NzQ4YjUzM2VmMTRmNzA4NGNkOWM1MDkwMTA5NGZlYTljM2U2IiwgImRlcG9zaXRfbWVzc2FnZV9yb290IjogIjA3MDIwNzk2ZDYyYWJlZDVjMzMzMzRlZThhNWRjZmJlN2I3ZDc5Yzg1N2Y4ZGYxMzhiYWE4YTAzODZhYzE1MWMiLCAiZGVwb3NpdF9kYXRhX3Jvb3QiOiAiNzg4YzI2NmQ1NmJmOGU5NTAyZjg3YWZmMGE3OWIyZjkzMzhmY2UyNzRjMjQ4OGFjMzU2YWNiNzU5OWQwODk5NCIsICJmb3JrX3ZlcnNpb24iOiAiMDAwMDAwMDAiLCAibmV0d29ya19uYW1lIjogIm1haW5uZXQiLCAiZGVwb3NpdF9jbGlfdmVyc2lvbiI6ICIyLjMuMCJ9XQ==",
    "datetime": "2024-03-05T18:04:56.652053",
    "active": true
}
```



## Reference

 - https://github.com/aws-samples/eth-keygen-lambda-sam
