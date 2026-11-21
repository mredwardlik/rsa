import pytest

from rsatool import signature
from rsatool.errors import FormatError, KeyFileError


def test_sign_and_verify(key, other_key):
    sig = signature.sign(b'contract', key)
    assert signature.verify(b'contract', sig, key.public_key())
    assert not signature.verify(b'contract!', sig, key.public_key())
    assert not signature.verify(b'contract', sig, other_key.public_key())


def test_encode_decode(key):
    sig = signature.sign(b'data', key)
    assert signature.decode(signature.encode(sig) + '\n', key) == sig
    assert signature.decode(sig, key) == sig
    with pytest.raises(FormatError):
        signature.decode('not base64 !!!', key)


def test_public_key_cant_sign(key):
    with pytest.raises(KeyFileError):
        signature.sign(b'data', key.public_key())
