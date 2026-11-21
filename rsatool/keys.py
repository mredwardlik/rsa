"""Generating, saving and loading RSA keys."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from Crypto.PublicKey import RSA

from .errors import KeyFileError, PassphraseRequired

KEY_SIZES = (2048, 3072, 4096)
DEFAULT_KEY_SIZE = 2048

# scrypt makes guessing a passphrase slow, AES-256 encrypts the key itself
PROTECTION = 'scryptAndAES256-CBC'


def generate(bits: int = DEFAULT_KEY_SIZE) -> RSA.RsaKey:
    """Make a new key pair.

    >>> generate(1024)
    Traceback (most recent call last):
    ...
    ValueError: Key size must be one of 2048, 3072, 4096 bits, not 1024.
    """
    if bits not in KEY_SIZES:
        sizes = ', '.join(map(str, KEY_SIZES))
        raise ValueError(f'Key size must be one of {sizes} bits, not {bits}.')
    return RSA.generate(bits)


def export_private(key: RSA.RsaKey, passphrase: str | None = None) -> bytes:
    """PEM of the private key, encrypted with the passphrase if it is given."""
    if not key.has_private():
        raise KeyFileError('This is a public key, the private part is missing.')
    if passphrase:
        return key.export_key(format='PEM', pkcs=8, passphrase=passphrase, protection=PROTECTION)
    return key.export_key(format='PEM', pkcs=8)


def export_public(key: RSA.RsaKey) -> bytes:
    return key.public_key().export_key(format='PEM')


def is_encrypted(data: bytes) -> bool:
    """Whether a PEM private key is protected with a passphrase."""
    return b'ENCRYPTED' in data[:200]


def load(path: str | os.PathLike, passphrase: str | None = None) -> RSA.RsaKey:
    """Read a public or a private key from a PEM file.

    Raises:
        PassphraseRequired: the private key is encrypted and no passphrase
            is given.
        KeyFileError: the file is missing, isn't a key or the passphrase is wrong.
    """
    path = Path(path)
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        raise KeyFileError(f'Key file "{path}" not found.') from None
    except OSError as error:
        raise KeyFileError(f'Can\'t read "{path}": {error.strerror}.') from None

    if is_encrypted(data) and not passphrase:
        raise PassphraseRequired(f'"{path}" is protected with a passphrase.')
    try:
        return RSA.import_key(data, passphrase=passphrase or None)
    except (ValueError, IndexError, TypeError):
        if is_encrypted(data):
            raise KeyFileError(f'Wrong passphrase for "{path}".') from None
        raise KeyFileError(f'"{path}" is not an RSA key.') from None


def load_public(path: str | os.PathLike) -> RSA.RsaKey:
    """A public key. A private key file works too: its public part is used."""
    path = Path(path)
    try:
        data = path.read_bytes()
    except OSError:
        return load(path)
    if is_encrypted(data):
        raise KeyFileError(f'"{path}" is an encrypted private key. Use the public key file.')
    return load(path).public_key()


def load_private(path: str | os.PathLike, passphrase: str | None = None) -> RSA.RsaKey:
    key = load(path, passphrase)
    if not key.has_private():
        raise KeyFileError(f'"{path}" is a public key. A private key is needed.')
    return key


def save(path: str | os.PathLike, data: bytes, *, private: bool, force: bool = False) -> Path:
    """Write a key. Never overwrites an existing file unless `force` is set,
    because a lost private key can't be restored."""
    path = Path(path)
    if path.exists() and not force:
        raise FileExistsError(f'"{path}" already exists.')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    if private and os.name == 'posix':
        path.chmod(0o600)
    return path


def fingerprint(key: RSA.RsaKey) -> str:
    """SHA-256 of the public key, to compare keys over the phone or in a chat.

    The same for the private key and its public key.
    """
    digest = hashlib.sha256(key.public_key().export_key(format='DER')).hexdigest()
    return ':'.join(digest[i:i + 4] for i in range(0, 32, 4))
