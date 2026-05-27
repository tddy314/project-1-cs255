from typing import Optional, Tuple

from util import dict_to_json_str, json_str_to_dict
from util import str_to_bytes, bytes_to_str, encode_bytes, decode_bytes

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# number of iterations for PBKDF2 algorithm
PBKDF2_ITERATIONS = 100000
# we can assume no password is longer than this many characters
MAX_PASSWORD_LENGTH = 64

########## START CODE HERE ##########
# Add any extra constants you may need
########### END CODE HERE ###########


class Keychain:
    def __init__(
        self,
        ########## START CODE HERE ##########
        kvs: dict, # kvs lưu trong ram
        salt: bytes, # lưu salt để tính lại về sau
        domain_key: bytes,
        encryption_key: bytes,
        key_check: bytes
        ########### END CODE HERE ###########
    ):
        """
        Initializes the keychain using the provided information. Note that external users should
        likely never invoke the constructor directly and instead use either Keychain.new or
        Keychain.load.

        Args:
            You may design the constructor with any additional arguments you would like.
        Returns:
            None
        """
        ########## START CODE HERE ##########
        self.data = {
            # Store member variables that you intend to be public here
            # (i.e. information that will not compromise security if an adversary sees).
            # This data should be dumped by the Keychain.dump function.
            # You should store the key-value store (KVS) in the "kvs" item in this dictionary.
            "kvs": kvs,
            "salt": encode_bytes(salt),
            "key_check": encode_bytes(key_check)
        }
        self.secrets = {
            # Store member variables that you intend to be private here
            # (information that an adversary should NOT see).
            "domain_key": domain_key,
            "encryption_key": encryption_key
        }
  
        ########### END CODE HERE ###########

    ########## START CODE HERE ##########
    # Add any helper functions you may want to add here

    def _get_domain_mac(self, domain: str) -> str:
        mac = HMAC.new(
            self.secrets["domain_key"],
            str_to_bytes(domain),
            digestmod=SHA256,
        )
        return encode_bytes(mac.digest())

    ########### END CODE HERE ###########

    @staticmethod
    def new(keychain_password: str) -> "Keychain":
        """
        Creates an empty keychain with the given keychain password.

        Args:
            keychain_password: the password to unlock the keychain
        Returns:
            A Keychain instance
        """
        ########## START CODE HERE ##########

        # Sinh salt gồm 16 bit
        salt = get_random_bytes(16)

        # Sinh master_key sử dụng PBKDF2 với interation = 100000
        master_key = PBKDF2(
            str_to_bytes(keychain_password),
            salt,
            dkLen=32,
            count=PBKDF2_ITERATIONS,
            hmac_hash_module=SHA256
        )

       
        # Sinh domain_key và encryption_key từ master_key

        domain_key = HMAC.new(master_key, b"domain_key", digestmod=SHA256).digest()
        encryption_key = HMAC.new(master_key, b"encryption_key", digestmod=SHA256).digest() 
        key_check = HMAC.new(
            master_key,
            b"key_check",
            digestmod=SHA256
        ).digest()


        # init kvs

        kvs = {}
    
        return Keychain(kvs, salt, domain_key, encryption_key, key_check)
        ########### END CODE HERE ###########

    @staticmethod
    def load(
        keychain_password: str, repr: str, trusted_data_check: Optional[bytes] = None
    ) -> "Keychain":
        """
        Creates a new keychain from an existing key-value store.

        Loads the keychain state from the provided representation (repr). You can assume that
        the representation passed to load is well-formed (i.e., it will be a valid JSON object)
        and was generated from the Keychain.dump function.

        Use the provided `json_str_to_dict` function to convert a JSON string into a nested dictionary.

        Args:
            keychain_password: the password to unlock the keychain
            repr: a JSON-encoded serialization of the contents of the key-value store (string)
            trusted_data_check: an optional SHA-256 checksum of the KVS (bytes or None)
        Returns:
            A Keychain instance containing the data from repr
        Throws:
            ValueError: if the checksum is provided in trusted_data_check and the checksum check fails
            ValueError: if the provided keychain password is not correct for the repr (hint: this is
                thrown for you by HMAC.verify)
        """
        ########## START CODE HERE ##########
        if trusted_data_check is not None:
            check_sum = SHA256.new(str_to_bytes(repr)).digest()
            if check_sum != trusted_data_check:
                raise ValueError("Checksum failed!!!!")
            
        data = json_str_to_dict(repr)
        salt = decode_bytes(data["salt"])

        master_key = PBKDF2(
            str_to_bytes(keychain_password),
            salt,
            dkLen=32,
            count=PBKDF2_ITERATIONS,
            hmac_hash_module=SHA256
        )

        domain_key = HMAC.new(
            master_key,
            b"domain_key",
            digestmod=SHA256,
        ).digest()

        encryption_key = HMAC.new(
            master_key,
            b"encryption_key",
            digestmod=SHA256,
        ).digest()

        key_check_mac = HMAC.new(
            master_key,
            b"key_check",
            digestmod=SHA256,
        )

        key_check_mac.verify(decode_bytes(data["key_check"]))

        return Keychain(
            data["kvs"],
            salt,
            domain_key,
            encryption_key,
            decode_bytes(data["key_check"]),
        )
        
        ########### END CODE HERE ###########

    def dump(self) -> Tuple[str, bytes]:
        """
        Returns a JSON serialization and a checksum of the contents of the keychain that can be
        loaded back using the Keychain.load function.

        For testing purposes, please ensure that the JSON string you return contains the key
        'kvs' with your KVS dict as its value. The KVS should have one key per domain.

        Use the provided `dict_to_json_str` function to convert a nested dictionary into
        its JSON representation.

        Returns:
            A tuple consisting of (1) the JSON serialization of the contents, and (2) the SHA256
            checksum of the JSON serialization
        """
        ########## START CODE HERE ##########
        contents = dict_to_json_str(self.data)
        check_sum = SHA256.new(str_to_bytes(contents)).digest()
        return contents, check_sum
        ########### END CODE HERE ###########

    def get(self, domain: str) -> Optional[str]:
        """
        Fetches the password corresponding to a given domain from the key-value store.

        Args:
            domain: the domain for which the password is requested
        Returns:
            The password for the domain if it exists in the KVS, or None if it does not exist
        """
        ########## START CODE HERE ##########
        domain_id = self._get_domain_mac(domain)

        if domain_id not in self.data["kvs"]:
            return None
        
        record = self.data["kvs"][domain_id]

        nonce = decode_bytes(record["nonce"])
        ciphertext = decode_bytes(record["ciphertext"])
        tag = decode_bytes(record["tag"])

        cipher = AES.new(
            self.secrets["encryption_key"],
            AES.MODE_GCM,
            nonce=nonce,
        )

        cipher.update(str_to_bytes(domain_id))
        padded_password = cipher.decrypt_and_verify(ciphertext, tag)
        password_length = padded_password[0]
        password_bytes = padded_password[1:1 + password_length]
        return bytes_to_str(password_bytes)

        ########### END CODE HERE ###########

    def set(self, domain: str, password: str):
        """
        Inserts the domain and password into the KVS. If the domain is already
        in the password manager, this will update the password for that domain.
        If it is not, a new entry in the password manager is created.

        Args:
            domain: the domain for the provided password. This domain may already exist in the KVS
            password: the password for the provided domain
        """
        ########## START CODE HERE ##########
        password_bytes = str_to_bytes(password)
        if len(password_bytes) > MAX_PASSWORD_LENGTH:
            raise ValueError("Too long!!!")
        
        domain_id = self._get_domain_mac(domain)
        
        # che dấu độ dài thật của password
        # gồm 3 phần: [độ dài thật] [password thật] [byte đệm]  sao cho đủ độ dài 
        padded_password = (bytes([len(password_bytes)])) + password_bytes + bytes(MAX_PASSWORD_LENGTH - len(password_bytes))
        cipher = AES.new(
            self.secrets["encryption_key"],
            AES.MODE_GCM,
        )
        cipher.update(str_to_bytes(domain_id))

        # tính ciphertext của password và tag để verify domain ứng với ciphertext này
        ciphertext, tag = cipher.encrypt_and_digest(padded_password) 
        self.data["kvs"][domain_id] = {
            "nonce": encode_bytes(cipher.nonce),
            "ciphertext": encode_bytes(ciphertext),
            "tag": encode_bytes(tag),
        }
        ########### END CODE HERE ###########

    def remove(self, domain: str) -> bool:
        """
        Removes the domain-password pair for the provided domain from the password manager.
        If the domain does not exist in the password manager, this method deos nothing.

        Args:
            domain: the domain which should be removed from the KVS, along with its password
        Returns:
            True if the domain existed in the KVS and was removed, False otherwise
        """
        ########## START CODE HERE ##########
        domain_id = self._get_domain_mac(domain)
        if domain_id not in self.data["kvs"]:
            return False
        
        del self.data["kvs"][domain_id]
        return True
        ########### END CODE HERE ###########
