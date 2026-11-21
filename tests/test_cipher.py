import pytest
from Crypto.Cipher import PKCS1_OAEP

from rsatool import cipher
from rsatool.errors import DecryptionError, FormatError


@pytest.mark.parametrize('data', [b'', b'Hello', 'Привет, мир! 👋'.encode(), bytes(range(256)) * 400])
def test_round_trip(key, data):
    blob = cipher.encrypt(data, key.public_key())
    assert cipher.decrypt(blob, key) == data


def test_long_message_is_longer_than_rsa_limit(key):
    data = b'x' * 10_000  # RSA-OAEP alone takes at most 190 bytes for a 2048-bit key
    assert cipher.decrypt(cipher.encrypt(data, key), key) == data


def test_every_encryption_is_different(key):
    assert cipher.encrypt(b'same', key) != cipher.encrypt(b'same', key)


def test_format(key):
    blob = cipher.encrypt(b'abc', key)
    assert blob[:4] == b'RSAT' and blob[4] == 1
    assert int.from_bytes(blob[5:7], 'big') == 256
    assert len(blob) == 7 + 256 + 12 + 16 + 3


def test_armor_round_trip(key):
    text = cipher.armor(cipher.encrypt(b'secret', key))
    assert text.startswith(cipher.ARMOR_BEGIN) and text.endswith(cipher.ARMOR_END)
    assert all(len(line) <= 64 for line in text.splitlines())
    assert cipher.decrypt(text, key) == b'secret'
    assert cipher.decrypt(text.encode(), key) == b'secret'


def test_armor_survives_a_messenger(key):
    text = cipher.armor(cipher.encrypt(b'secret', key))
    mangled = 'Here it is:\r\n\r\n' + text.replace('\n', '\r\n  ') + '\r\nBye!'
    assert cipher.decrypt(mangled, key) == b'secret'


def test_wrong_key(key, other_key):
    blob = cipher.encrypt(b'secret', key)
    with pytest.raises(DecryptionError, match='another key'):
        cipher.decrypt(blob, other_key)


@pytest.mark.parametrize('position', [10, -1, -20, 4 + 3 + 256 + 5])
def test_changed_byte_is_detected(key, position):
    blob = bytearray(cipher.encrypt(b'pay 100 dollars', key))
    blob[position] ^= 1
    with pytest.raises((DecryptionError, FormatError)):
        cipher.decrypt(bytes(blob), key)


def test_cut_message(key):
    blob = cipher.encrypt(b'secret', key)
    with pytest.raises(FormatError, match='cut off'):
        cipher.decrypt(blob[:100], key)


def test_unknown_version(key):
    blob = bytearray(cipher.encrypt(b'secret', key))
    blob[4] = 9
    with pytest.raises(FormatError, match='version 9'):
        cipher.decrypt(bytes(blob), key)


def test_not_a_message(key):
    with pytest.raises(FormatError):
        cipher.decrypt(b'just some text', key)


def test_damaged_armor(key):
    with pytest.raises(FormatError, match='damaged'):
        cipher.decrypt(f'{cipher.ARMOR_BEGIN}\n@@@\n{cipher.ARMOR_END}', key)
    with pytest.raises(FormatError, match='must end'):
        cipher.decrypt(f'{cipher.ARMOR_BEGIN}\nUlNBVA==', key)


def test_public_key_cant_decrypt(key):
    with pytest.raises(DecryptionError, match='private key'):
        cipher.decrypt(cipher.encrypt(b'x', key), key.public_key())


def test_messages_of_the_first_version(key):
    # encryptor.py of 2021: PKCS1_OAEP with default SHA-1, raw bytes in a file
    legacy = PKCS1_OAEP.new(key.public_key()).encrypt('Старое сообщение'.encode())
    assert cipher.decrypt(legacy, key).decode() == 'Старое сообщение'
