"""
Contains a host of helper functions for managing the Orion database
"""
import base64
import json
from uuid import uuid4

from aiohttp import ClientSession
from support.utils import log_json, log_msg, log_status, run_executable, LogLevel


class OrionDB:
    def __init__(
        self,
        orion_db_url: str,
        username: str,
        client_session: ClientSession,
        private_key_path="",
        log_level=LogLevel.DEBUG,
    ):
        self.__orion_db_url = orion_db_url
        self.__username = username
        self.__private_key_path = (
            private_key_path
            if private_key_path != ""
            else f"crypto/{self.__username}/{self.__username}.key"
        )
        self.__client_session = client_session
        # Holds created databases
        self.databases = []
        self.db_keys = {}
        self.last_block_num = None
        self.log_level = log_level

    def __sign_tx(self, payload):
        """
        Wrapper function for signing a database transaction
        """
        return sign_transaction(payload, self.__private_key_path)

    def __glue_payload(self, payload: dict, signature: str):
        """
        Glues the payload and signature into a dict/json.
        """
        return {"payload": payload, "signature": signature}

    async def query_key(self, db_name, key):
        """
        Query a single key by 'key'
        return: value of database entry as dict
        """
        # More info under: https://labs.hyperledger.org/orion-server/docs/getting-started/transactions/curl/datatx#12-checking-the-existance-of-key1

        # keys need to be send as base64, in order for =/- characters to work.
        # WARN: (aver) watch out if padding = is used, then the request does not work anymore
        enc_key = base64.urlsafe_b64encode(bytes(key, encoding="utf-8")).decode().replace("=", "")

        payload = {"user_id": self.__username, "db_name": db_name, "key": key}
        signature = self.__sign_tx(payload)

        response = await self.__client_session.get(
            url=f"{self.__orion_db_url}/data/db1/{enc_key}",
            headers={"UserID": self.__username, "Signature": signature},
        )

        if not response.ok:
            log_msg("\n\nERRROR HAPPENED\n\n")
            log_msg(f"Returned with {response.status}")
            log_status(response)

        response = await response.json()
        if self.log_level == LogLevel.DEBUG:
            log_json(response)

        enc_value = response["response"].get("value")
        if enc_value is None:
            return None
        self.last_block_num = response["response"].get("metadata").get("version").get("block_num")
        decoded_value = decode_data(enc_value)
        # not the most efficient way, but we store the keys locally, lazily, because we sometimes
        # need to access them quickly
        self.db_keys[db_name][key].update(decoded_value)
        return decoded_value

    async def db_exists(self, db_name: str):
        """
        Check existence of a database with given name
        """
        payload = {"user_id": self.__username, "db_name": db_name}
        signature = self.__sign_tx(payload)
        response = await self.__client_session.get(
            url=f"{self.__orion_db_url}/db/{db_name}",
            headers={"UserID": self.__username, "Signature": signature},
        )

        # TODO: (aver) improve error handling
        if not response.ok:
            print("\n\nERRROR HAPPENED\n\n")
            return False

        status = response.status
        response = await response.json()
        if self.log_level == LogLevel.DEBUG:
            log_msg(f"Returned with {status}")
            log_json(response)

        try:
            return response["response"]["exist"]
        except KeyError:
            return False

    async def check_user(self, username: str):
        """
        Check existence of a user with given name
        """
        payload = {"user_id": self.__username, "target_user_id": username}
        signature = self.__sign_tx(payload)
        response = await self.__client_session.get(
            url=f"{self.__orion_db_url}/user/{username}",
            headers={"UserID": self.__username, "Signature": signature},
        )

        # TODO: (aver) improve error handling
        if not response.ok:
            log_msg("\n\nERRROR HAPPENED\n\n")
            return False

        status = response.status
        response = await response.json()
        if self.log_level == LogLevel.DEBUG:
            log_msg(f"Returned with {status}")
            log_json(response)

        try:
            return response["response"]["user"]["id"] == username
        except KeyError:
            return False

    async def create_database(self, db_name: str):
        """
        Creates a database with given name, but checks first whether it exists
        """
        if db_name not in self.databases:
            self.databases.append(db_name)
            self.db_keys[db_name] = {}

        if await self.db_exists(db_name):
            if self.log_level == LogLevel.DEBUG:
                log_status(f"{db_name}: Already exists")
                log_status("Parsing entries to local dictionary...")
            response = await self.query_all(db_name)

            # only proceed if we have a key-values
            if response["response"].get("KVs") is None:
                return

            for entry in response["response"]["KVs"]:
                value = decode_data(entry["value"])
                # NOTE: (aver) not necessary to keep local copy of database!
                self.db_keys[db_name][entry["key"]] = value
                # self.db_keys[db_name][entry["key"]] = {}
            return

        payload = {
            "user_id": self.__username,
            "tx_id": get_tx_id(),
            "create_dbs": [db_name],
        }
        signature = self.__sign_tx(payload)
        data = self.__glue_payload(payload, signature)

        response = await self.__client_session.post(
            url=f"{self.__orion_db_url}/db/tx", json=data, headers={"TxTimeout": "2s"}
        )

        # TODO: (aver) improve error handling
        if not response.ok:
            print("\n\nERRROR HAPPENED\n\n")
            return

        status = response.status
        response = await response.json()
        if self.log_level == LogLevel.DEBUG:
            log_msg(f"Returned with {status}")
            log_json(response)

        self.databases.append(db_name)

    async def create_user(self, username: str):
        """
        Creates a user with given `username` on request, if not already existing
        """
        if self.log_level == LogLevel.DEBUG:
            if await self.check_user(username):
                log_status(f"{username}: Already exists")
                # return

        with open(f"./crypto/{username}/{username}.pem", "r") as file:
            # skip begin and end line
            certificate = file.readlines()[1:-1]
            # replace newlines, as certificate is broken up
            certificate = "".join(certificate).replace("\n", "")

        headers = {"TxTimeout": "10s"}
        payload = {
            "user_id": self.__username,
            "tx_id": get_tx_id(),
            "user_writes": [
                {
                    "user": {
                        "id": username,
                        "certificate": certificate,
                        # give read write access to the first, and only, database
                        "privilege": {
                            # WARN: This is kind of another mess ... the guide says use 0 for Read
                            # access and 1 for ReadWrite access, but signature fails if numbers are
                            # used, therefore use string of enum `Read` or `ReadWrite`
                            "db_permission": {self.databases[0]: "ReadWrite"}
                        },
                    },
                    # We could further specify access control, by default, undefined, everyone can
                    # read credentials and privilege of the user
                    "acl": {
                        "read_users": {self.__username: True},
                    },
                }
            ],
        }
        signature = self.__sign_tx(payload)
        data = self.__glue_payload(payload, signature)

        response = await self.__client_session.post(
            url=f"{self.__orion_db_url}/user/tx", json=data, headers=headers
        )

        if not response.ok:
            log_status("\n\n\tERRROR HAPPENED with user creation\n\n")
        else:
            if self.log_level == LogLevel.DEBUG:
                log_status(f"Returned with {response.status}")
                response = await response.json()
                log_json(response)

    async def record_key(self, db_name: str, key_name: str, value: dict):
        """
        Record a new key, or update an existin one, this simply overwrites the existing key!
        """
        headers = {"TxTimeout": "2s"}
        encoded_value = encode_data(value)
        payload = {
            "must_sign_user_ids": [self.__username],
            "tx_id": get_tx_id(),
            "db_operations": [
                {
                    "db_name": db_name,
                    "data_writes": [
                        {
                            "key": key_name,
                            "value": encoded_value,
                            "acl": {
                                # NOTE: (aver) remove auditor until we find out what is causing the
                                # freeze in the 2nd issuing.
                                "read_users": {"auditor": True},
                                "read_write_users": {self.__username: True},
                            },
                        },
                    ],
                }
            ],
        }
        signature = self.__sign_tx(payload)
        # cannot use the glue here, possibly multiple signatures expected...
        data = {"payload": payload, "signatures": {self.__username: signature}}

        response = await self.__client_session.post(
            url=f"{self.__orion_db_url}/data/tx", json=data, headers=headers
        )
        if response.ok:
            status = response.status
            response = await response.json()
            if self.log_level == LogLevel.DEBUG:
                log_msg(f"Returned with {status}")
                log_json(response)
            # we also record the keys, as a workaround to not being able to query all keys in the
            # database
            if key_name not in self.db_keys[db_name]:
                # self.db_keys[db_name].append(key_name)
                self.db_keys[db_name][key_name] = {}
            elif self.log_level == LogLevel.DEBUG:
                log_msg(f"ORION: Key {key_name} already recorded: UPDATE!")

            # WARN: remove once debugged
            self.db_keys[db_name][key_name].update(value)
            if self.log_level == LogLevel.DEBUG:
                log_status("ORION: Added to local map")
                log_json(self.db_keys[db_name][key_name])
        else:
            response = await response.json()
            log_status("\n\nERRROR HAPPENED\n\n")
            log_json(response)

    async def query_all(self, db_name: str):
        """
        Query all existing keys on database `db_name`
        """
        start_key = "a"
        enc_start_key = (
            base64.urlsafe_b64encode(bytes(start_key, encoding="utf-8")).decode().replace("=", "")
        )
        end_key = "z"
        enc_end_key = (
            base64.urlsafe_b64encode(bytes(end_key, encoding="utf-8")).decode().replace("=", "")
        )
        limit = str(1000)

        payload = {
            "user_id": self.__username,
            "db_name": db_name,
            "start_key": start_key,
            "end_key": end_key,
            "limit": limit,
        }
        signature = self.__sign_tx(payload)
        response = await self.__client_session.get(
            url=f"{self.__orion_db_url}/data/{db_name}?startkey={enc_start_key}&endkey={enc_end_key}&limit={limit}",
            headers={"UserID": self.__username, "Signature": signature},
        )

        if not response.ok:
            log_status("\n\nERRROR HAPPENED\n\n")

        if self.log_level == LogLevel.DEBUG:
            log_msg(f"Returned with {response.status}")
        try:
            response = await response.json()
            # log_json(response)
            return response
        except Exception:
            log_msg(response)

    async def delete_key(self, db_name: str, key_name: str):
        """
        Remove an existing key from the database
        """
        headers = {"TxTimeout": "2s"}
        _ = await self.query_key(db_name, key_name)
        payload = {
            "must_sign_user_ids": [self.__username],
            "tx_id": get_tx_id(),
            "db_operations": [
                {
                    "db_name": db_name,
                    "data_reads": [
                        {"key": key_name, "version": {"block_num": self.last_block_num}}
                    ],
                    "data_deletes": [{"key": key_name}],
                }
            ],
        }
        signature = self.__sign_tx(payload)
        # cannot use the glue here, possibly multiple signatures expected...
        data = {"payload": payload, "signatures": {self.__username: signature}}
        response = await self.__client_session.post(
            url=f"{self.__orion_db_url}/data/tx", json=data, headers=headers
        )
        if response.ok:
            status = response.status
            response = await response.json()
            if self.log_level == LogLevel.DEBUG:
                log_msg(f"Returned with {status}")
                log_json(response)

            # we also record the keys, as a workaround to not being able to query all keys in the
            # database
            self.db_keys[db_name].pop(key_name)
            if self.log_level == LogLevel.DEBUG:
                log_status(f"ORION: Removed key: {key_name}!")
        else:
            response = await response.json()
            log_status("\n\nERRROR HAPPENED\n\n")
            log_json(response)


def sign_transaction(data: json, privatekey: str):
    """
    Sign a transaction for Hyperledger Orion
    params:
        data: data in json to be signed
        privatekey: location to private key
    """
    prepped_data = json.dumps(data).replace(" ", "")
    # log_msg("Data to be signed:", prepped_data)
    signature = run_executable(
        (
            "./bin/signer",
            f"-data={prepped_data}",
            f"-privatekey={privatekey}",
        )
    )
    return signature


def encode_data(data: json):
    """
    Encodes data into base64
    """
    prepped_data = json.dumps(data).replace(" ", "")
    # log_msg("Data to be encoded:", prepped_data)
    encoded_data = base64.b64encode(bytes(prepped_data, "utf-8")).decode()
    return encoded_data


def decode_data(encoded_data: str):
    """
    Decodes base64 data into a Python dict (JSON) if possible.
    """
    decoded_data = base64.b64decode(encoded_data)
    return json.loads(decoded_data)


def get_tx_id():
    """
    Generate a random uuid4 based id, generally to identify transactions and return as string.
    """
    return str(uuid4())
