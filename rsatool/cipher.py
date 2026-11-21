"""Hybrid encryption: RSA-OAEP for a random key, AES-256-GCM for the data.

RSA alone can encrypt only a few hundred bytes (190 for a 2048-bit key), so
every message gets its own random AES key. The key is encrypted with RSA, the
message with AES-GCM, which also detects any change of the encrypted data.

Format of an encrypted message::

    b'RSAT'            magic, 4 bytes
    version            1 byte, now 1
    key length         2 bytes, big endian
    encrypted key      RSA-OAEP (SHA-256) of the 32-byte AES key
    nonce              12 bytes
    tag                16 bytes
    ciphertext         AES-256-GCM, same length as the message

The header (magic, version and the encrypted key) is authenticated by GCM too.
"""

from __future__ import annotations

import base64
import binascii
import re
import textwrap

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

from .errors import DecryptionError, FormatError

MAGIC = b'RSAT'
VERSION = 1
SESSION_KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16

ARMOR_BEGIN = '-----BEGIN RSATOOL MESSAGE-----'
ARMOR_END = '-----END RSATOOL MESSAGE-----'
_ARMOR = re.compile(re.escape(ARMOR_BEGIN) + r'(.*?)' + re.escape(ARMOR_END), re.S)


def encrypt(data: bytes, public_key: RSA.RsaKey) -> bytes:
    """Encrypt bytes of any length for the owner of the private key."""
    session_key = get_random_bytes(SESSION_KEY_SIZE)
    encrypted_key = PKCS1_OAEP.new(public_key.public_key(), hashAlgo=SHA256).encrypt(session_key)
    header = MAGIC + bytes([VERSION]) + len(encrypted_key).to_bytes(2, 'big') + encrypted_key

    nonce = get_random_bytes(NONCE_SIZE)
    aes = AES.new(session_key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_SIZE)
    aes.update(header)
    ciphertext, tag = aes.encrypt_and_digest(data)
    return header + nonce + tag + ciphertext


def decrypt(data: bytes | str, private_key: RSA.RsaKey) -> bytes:
    """Decrypt a message made by `encrypt`, armored or not.

    Messages of the first version of the scripts (plain RSA-OAEP with SHA-1,
    exactly one key length) are decrypted too.
    """
    if not private_key.has_private():
        raise DecryptionError('A private key is needed to decrypt.')
    blob = dearmor(data) if is_armored(data) else _as_bytes(data)

    if blob.startswith(MAGIC):
        return _decrypt_hybrid(blob, private_key)
    if len(blob) == private_key.size_in_bytes():
        return _decrypt_legacy(blob, private_key)
    raise FormatError('This is not an encrypted message.')


def _decrypt_hybrid(blob: bytes, private_key: RSA.RsaKey) -> bytes:
    if len(blob) < 7:
        raise FormatError('The message is cut off.')
    version = blob[4]
    if version != VERSION:
        raise FormatError(f'Unknown message version {version}, update rsatool.')
    key_length = int.from_bytes(blob[5:7], 'big')
    header_end = 7 + key_length
    if len(blob) < header_end + NONCE_SIZE + TAG_SIZE:
        raise FormatError('The message is cut off.')

    header, encrypted_key = blob[:header_end], blob[7:header_end]
    nonce = blob[header_end:header_end + NONCE_SIZE]
    tag = blob[header_end + NONCE_SIZE:header_end + NONCE_SIZE + TAG_SIZE]
    ciphertext = blob[header_end + NONCE_SIZE + TAG_SIZE:]

    try:
        session_key = PKCS1_OAEP.new(private_key, hashAlgo=SHA256).decrypt(encrypted_key)
    except ValueError:
        raise DecryptionError('The message was encrypted for another key.') from None
    if len(session_key) != SESSION_KEY_SIZE:
        raise DecryptionError('The message is damaged.')

    aes = AES.new(session_key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_SIZE)
    aes.update(header)
    try:
        return aes.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        raise DecryptionError('The message was changed or damaged.') from None


def _decrypt_legacy(blob: bytes, private_key: RSA.RsaKey) -> bytes:
    try:
        return PKCS1_OAEP.new(private_key).decrypt(blob)
    except ValueError:
        raise DecryptionError('The message was encrypted for another key, or it is damaged.') from None


def armor(blob: bytes) -> str:
    """Text form of an encrypted message, to paste into a chat or an email.

    >>> print(armor(b'RSAT' + bytes(5)))
    -----BEGIN RSATOOL MESSAGE-----
    UlNBVAAAAAAA
    -----END RSATOOL MESSAGE-----
    """
    body = '\n'.join(textwrap.wrap(base64.b64encode(blob).decode('ascii'), 64))
    return f'{ARMOR_BEGIN}\n{body}\n{ARMOR_END}'


def is_armored(data: bytes | str) -> bool:
    text = data if isinstance(data, str) else data[:4096].decode('ascii', 'ignore')
    return ARMOR_BEGIN in text


def dearmor(data: bytes | str) -> bytes:
    """Bytes of an armored message. Text around it and any line breaks or
    spaces that a messenger may add are ignored.

    >>> dearmor('Hi! ' + armor(b'secret') + ' Bye')
    b'secret'
    """
    text = data if isinstance(data, str) else data.decode('utf-8', 'replace')
    match = _ARMOR.search(text)
    if match is None:
        raise FormatError(f'The message must end with "{ARMOR_END}".')
    body = re.sub(r'\s+', '', match.group(1))
    try:
        return base64.b64decode(body, validate=True)
    except (binascii.Error, ValueError):
        raise FormatError('The armored message is damaged.') from None


def _as_bytes(data: bytes | str) -> bytes:
    return data.encode('utf-8') if isinstance(data, str) else data
