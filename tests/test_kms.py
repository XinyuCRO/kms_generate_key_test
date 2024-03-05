import base64
from datetime import datetime
import json
import logging
import os
import secrets

import boto3
import pytest
from botocore.exceptions import ClientError


from eth_utils import is_hex_address, to_normalized_address
from staking_deposit.settings import get_chain_setting, ALL_CHAINS
from staking_deposit.credentials import Credential
from staking_deposit.utils.validation import (
    validate_deposit,
)
from staking_deposit.key_handling.keystore import (
    Keystore,
)
from staking_deposit.exceptions import ValidationError
from staking_deposit.utils.constants import (
    MNEMONIC_LANG_OPTIONS,
    MAX_DEPOSIT_AMOUNT,
)
from staking_deposit.key_handling.key_derivation.mnemonic import (
    get_mnemonic,
)

from moto import mock_aws

from . import kms_aws_verified


# remove validator_keygen.log file
if os.path.exists("validator_keygen.log"):
    os.remove("validator_keygen.log")

LOG_LEVEL = os.getenv("LOG_LEVEL", "DEBUG")
LOG_FORMAT = "%(levelname)s:%(lineno)s:%(message)s"
handler = logging.FileHandler("validator_keygen.log")
logger = logging.getLogger("validator_keygen")
logger.setLevel(LOG_LEVEL)
logger.addHandler(handler)
logger.propagate = False

PLAINTEXT_VECTORS = [b'0']

words_list_path = "tests/word_lists"

def _get_encoded_value(plaintext):
    if isinstance(plaintext, bytes):
        return plaintext

    return plaintext.encode("utf-8")


def verify_keystore(credential: Credential, keystore: Keystore, password: str) -> bool:
    """Verify keystore"""

    secret_bytes = keystore.decrypt(password)
    return credential.signing_sk == int.from_bytes(secret_bytes, "big")


@pytest.mark.parametrize("plaintext", PLAINTEXT_VECTORS)
@mock_aws
def test_encrypt(plaintext):
    client = boto3.client("kms", region_name="us-west-2")

    key = client.create_key(Description="key")
    key_id = key["KeyMetadata"]["KeyId"]
    key_arn = key["KeyMetadata"]["Arn"]

    response = client.encrypt(KeyId=key_id, Plaintext=plaintext)
    assert response["CiphertextBlob"] != plaintext

    # CiphertextBlob must NOT be base64-encoded
    with pytest.raises(Exception):
        base64.b64decode(response["CiphertextBlob"], validate=True)

    assert response["KeyId"] == key_arn

@pytest.mark.parametrize("plaintext", PLAINTEXT_VECTORS)
@mock_aws
def test_decrypt(plaintext):
    client = boto3.client("kms", region_name="us-west-2")

    key = client.create_key(Description="key")
    key_id = key["KeyMetadata"]["KeyId"]
    key_arn = key["KeyMetadata"]["Arn"]

    encrypt_response = client.encrypt(KeyId=key_id, Plaintext=plaintext)

    client.create_key(Description="key")
    # CiphertextBlob must NOT be base64-encoded
    with pytest.raises(Exception):
        base64.b64decode(encrypt_response["CiphertextBlob"], validate=True)

    decrypt_response = client.decrypt(CiphertextBlob=encrypt_response["CiphertextBlob"])

    # Plaintext must NOT be base64-encoded
    with pytest.raises(Exception):
        base64.b64decode(decrypt_response["Plaintext"], validate=True)

    assert decrypt_response["Plaintext"] == _get_encoded_value(plaintext)
    assert decrypt_response["KeyId"] == key_arn


@pytest.mark.parametrize("plaintext", PLAINTEXT_VECTORS)
@mock_aws
def test_encrypt_2(plaintext):
    """
    Example request
    {
     "num_validators": 2,
     "mnemonic_language": "english",
     "chain": "goerli",
     "eth1_withdrawal_address": "0x6F4b46423fc6181a0cF34e6716c220BD4d6C2471"
    }
    """

    # ===============
    client = boto3.client("kms", region_name="us-west-2")

    key = client.create_key(Description="key")
    key_id = key["KeyMetadata"]["KeyId"]
    key_arn = key["KeyMetadata"]["Arn"]

    # ================

    event = {
       "num_validators": 1,
        "mnemonic_language": "english",
        "chain": "mainnet",
        "eth1_withdrawal_address": "0x6F4b46423fc6181a0cF34e6716c220BD4d6C2471"
        }

    logger.debug("incoming event: {}".format(event))

    num_validators = event.get("num_validators", 1)

    if num_validators not in range(1, 10):
        message = "Number of validators should be between 1 and 10"
        logger.fatal(message)
        raise ValueError(message)

    mnemonic_language = event.get("mnemonic_language", "english")
    mnemonic_language = mnemonic_language.lower()

    if mnemonic_language not in MNEMONIC_LANG_OPTIONS:
        message = "Mnemonic language is invalid"
        logger.fatal(message)
        raise ValueError(message)

    chain = event.get("chain", "goerli")
    chain = chain.lower()

    logger.info("All chains: {}".format(ALL_CHAINS))

    if chain not in ALL_CHAINS:
        message = "Chain is invalid"
        logger.fatal(message)
        raise ValueError(message)

    eth1_withdrawal_address = event.get("eth1_withdrawal_address", None)

    if eth1_withdrawal_address is not None:
        if not is_hex_address(eth1_withdrawal_address):
            message = "Eth1 address is not in hexadecimal encoded form."
            logger.fatal(message)
            raise ValueError(message)

        eth1_withdrawal_address = to_normalized_address(eth1_withdrawal_address)

    logger.info(
        "Start:\nnum_validators = %d\nchain = %s\nmnemonic_language = %s\nwithdrawal_address = %s",
        num_validators,
        chain,
        mnemonic_language,
        eth1_withdrawal_address,
    )

    mnemonic = get_mnemonic(language=mnemonic_language, words_path=words_list_path)

    logger.info("Mnemonic generated!")

    logger.info("mnemonic: {}".format(mnemonic))

    chain_setting = get_chain_setting(chain)
    validator_start_index = 0

    amounts = [MAX_DEPOSIT_AMOUNT] * num_validators

    if len(amounts) != num_validators:
        raise ValueError(
            f"The number of keys ({num_validators}) doesn't equal to the corresponding deposit amounts ({len(amounts)})."
        )

    key_indices = range(validator_start_index, validator_start_index + num_validators)

    # No mnemonic password needed
    mnemonic_password = ""  # nosec

    credentials_list = [
        Credential(
            mnemonic=mnemonic,
            mnemonic_password=mnemonic_password,
            index=index,
            amount=amounts[index - validator_start_index],
            chain_setting=chain_setting,
            hex_eth1_withdrawal_address=eth1_withdrawal_address,
        )
        for index in key_indices
    ]

    validator_key_records = []

    for index, credential in enumerate(credentials_list):
        password = secrets.token_urlsafe(14)
        keystore = credential.signing_keystore(password)
        encrypted_key = keystore.as_json()
        encrypted_key_obj = json.loads(encrypted_key)
        pub_key = encrypted_key_obj["pubkey"]
        logger.info(
            "%d / %d - Encrypted validator key generated - pubkey: %s", index + 1, len(credentials_list), pub_key
        )

        deposit_data_dict = credential.deposit_datum_dict
        deposit_data = json.dumps(deposit_data_dict, default=lambda x: x.hex())
        logger.info("%d / %d - Deposit data generated - pubkey: %s", index + 1, len(credentials_list), pub_key)

        if not verify_keystore(credential=credential, keystore=keystore, password=password):
            message = "Failed to verify the keystores"
            logger.fatal(message)
            raise ValidationError(message)

        if not validate_deposit(json.loads(deposit_data), credential):
            message = "Failed to verify the deposit"
            logger.fatal(message)
            raise ValidationError(message)


        logger.info("keystore: {}".format(encrypted_key))
        logger.info("password: {}".format(password))
        logger.info("mnemonic: {}".format(mnemonic))

        # b64
        logger.info("keystore_b64 :{}".format(base64.b64encode(encrypted_key.encode("ascii")).decode("ascii")))
        logger.info("password_b64 :{}".format(base64.b64encode(password.encode("ascii")).decode("ascii")))
        logger.info("mnemonic_b64 :{}".format(base64.b64encode(mnemonic.encode("ascii")).decode("ascii")))

        to_encrypt_by_kms = {
            "keystore_b64": base64.b64encode(encrypted_key.encode("ascii")).decode("ascii"),
            "password_b64": base64.b64encode(password.encode("ascii")).decode("ascii"),
            "mnemonic_b64": base64.b64encode(mnemonic.encode("ascii")).decode("ascii"),
        }

        logger.info("%d / %d - Encrypting key, password and mnemonic using KMS", index + 1, len(credentials_list))

        try:
            response = client.encrypt(KeyId=key_id, Plaintext=json.dumps(to_encrypt_by_kms).encode())
            # response = client_kms.encrypt(KeyId=kms_key_arn, Plaintext=json.dumps(to_encrypt_by_kms).encode())

        except Exception as e:
            raise Exception("Exception happened sending encryption request to KMS: {}".format(e))

        encrypted_key_password_mnemonic_b64 = base64.standard_b64encode(response["CiphertextBlob"]).decode()

        deposit_data_list = f"[{deposit_data}]"

        record = {
            "web3signer_uuid": "none",
            "chain": chain,
            "pubkey": pub_key,
            "encrypted_key_password_mnemonic_b64": encrypted_key_password_mnemonic_b64,
            "deposit_json_b64": base64.b64encode(deposit_data_list.encode("ascii")).decode("ascii"),
            "datetime": datetime.now().isoformat(),
            "active": True,
        }

        # save record as json file
        with open(f"key_{index}.json", "w") as f:
            json.dump(record, f)

        logger.debug("%d / %d - Record - {}".format(record), index + 1, len(credentials_list))

        validator_key_records.append(record)

    pubkey_list = list(map(lambda record: record["pubkey"], validator_key_records))

    logger.info("pubkey_list: {}".format(pubkey_list))

    assert response["KeyId"] == key_arn
    
    # ======= decypt ==========
    with open("key_0.json", "r") as f:
        record = json.load(f)

    logger.info("record: {}".format(record["encrypted_key_password_mnemonic_b64"]))

    # client.create_key(Description="key")
    logger.info(key.keys)
    decrypt_response = client.decrypt(CiphertextBlob=base64.b64decode(record["encrypted_key_password_mnemonic_b64"], validate=True))

    # Plaintext must NOT be base64-encoded
    with pytest.raises(Exception):
        base64.b64decode(decrypt_response["Plaintext"], validate=True)


    logger.info("decrypt ===================")
    logger.info("decrypted response: {}".format(decrypt_response))
    logger.info("decrypted plaintext: {}".format(decrypt_response["Plaintext"]))

    response_str = decrypt_response["Plaintext"].decode('utf-8')
    logger.info("response_str: {}".format(response_str))

    # turn string into dict
    response_json = json.loads(response_str)


    keystore_response = base64.b64decode(response_json["keystore_b64"]).decode('utf-8')
    password_response = base64.b64decode(response_json["password_b64"]).decode('utf-8')
    mnemonic_response = base64.b64decode(response_json["mnemonic_b64"]).decode('utf-8')
    

    logger.info("keystore decrypted: {}".format(keystore_response))
    logger.info("password decrypted: {}".format(password_response))
    logger.info("mnemonic decrypted: {}".format(mnemonic_response))

    assert keystore_response == encrypted_key
    assert password_response == password
    assert mnemonic_response == mnemonic

