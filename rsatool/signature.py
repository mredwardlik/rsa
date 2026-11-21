"""Signatures: RSA-PSS with SHA-256.

A signature proves that the data was signed by the owner of the private key
and wasn't changed after that. Anyone with the public key can check it.
"""

from __future__ import annotations

import base64
import binascii

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pss

from .errors import FormatError, KeyFileError


def sign(data: bytes, private_key: RSA.RsaKey) -> bytes:
    if not private_key.has_private():
        raise KeyFileError('A private key is needed to sign.')
    return pss.new(private_key).sign(SHA256.new(data))


def verify(data: bytes, signature: bytes, public_key: RSA.RsaKey) -> bool:
    try:
        pss.new(public_key.public_key()).verify(SHA256.new(data), signature)
    except ValueError:
        return False
    return True


def encode(signature: bytes) -> str:
    """One line of base64, how signatures are saved to `.sig` files."""
    return base64.b64encode(signature).decode('ascii')


def decode(data: bytes | str, public_key: RSA.RsaKey) -> bytes:
    """Signature bytes from a `.sig` file: base64 text or raw bytes."""
    raw = data if isinstance(data, bytes) else data.encode('ascii', 'ignore')
    if len(raw) == public_key.size_in_bytes():
        return raw
    try:
        return base64.b64decode(b''.join(raw.split()), validate=True)
    except (binascii.Error, ValueError):
        raise FormatError('This is not a signature.') from None
