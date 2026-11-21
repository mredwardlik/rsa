import os

import pytest

from rsatool import keys
from rsatool.errors import KeyFileError, PassphraseRequired


def test_sizes():
    assert keys.generate(3072).size_in_bits() == 3072
    with pytest.raises(ValueError):
        keys.generate(512)


def test_save_and_load(tmp_path, key):
    private = keys.save(tmp_path / 'k.pem', keys.export_private(key), private=True)
    public = keys.save(tmp_path / 'k.pub.pem', keys.export_public(key), private=False)
    assert keys.load_private(private) == key
    assert keys.load_public(public) == key.public_key()
    assert b'BEGIN PRIVATE KEY' in private.read_bytes()
    assert b'BEGIN PUBLIC KEY' in public.read_bytes()


@pytest.mark.skipif(os.name != 'posix', reason='file modes are POSIX only')
def test_private_key_is_readable_only_by_owner(tmp_path, key):
    path = keys.save(tmp_path / 'k.pem', keys.export_private(key), private=True)
    assert path.stat().st_mode & 0o777 == 0o600


def test_no_overwrite(tmp_path, key):
    path = keys.save(tmp_path / 'k.pem', keys.export_private(key), private=True)
    with pytest.raises(FileExistsError):
        keys.save(path, b'new', private=True)
    keys.save(path, b'new', private=True, force=True)
    assert path.read_bytes() == b'new'


def test_passphrase(tmp_path, key):
    path = keys.save(tmp_path / 'k.pem', keys.export_private(key, 'correct horse'), private=True)
    assert b'ENCRYPTED PRIVATE KEY' in path.read_bytes()
    with pytest.raises(PassphraseRequired):
        keys.load_private(path)
    with pytest.raises(KeyFileError, match='Wrong passphrase'):
        keys.load_private(path, 'wrong')
    assert keys.load_private(path, 'correct horse') == key


def test_public_from_private_file(key_files, key):
    private, _ = key_files
    loaded = keys.load_public(private)
    assert not loaded.has_private() and loaded == key.public_key()


def test_encrypted_private_is_not_a_public_key(tmp_path, key):
    path = keys.save(tmp_path / 'k.pem', keys.export_private(key, 'pw'), private=True)
    with pytest.raises(KeyFileError, match='public key file'):
        keys.load_public(path)


def test_public_is_not_private(key_files):
    _, public = key_files
    with pytest.raises(KeyFileError, match='private key is needed'):
        keys.load_private(public)


def test_missing_and_broken_files(tmp_path):
    with pytest.raises(KeyFileError, match='not found'):
        keys.load(tmp_path / 'nope.pem')
    (tmp_path / 'bad.pem').write_text('hello')
    with pytest.raises(KeyFileError, match='not an RSA key'):
        keys.load(tmp_path / 'bad.pem')


def test_fingerprint(key, other_key):
    assert keys.fingerprint(key) == keys.fingerprint(key.public_key())
    assert keys.fingerprint(key) != keys.fingerprint(other_key)
    assert len(keys.fingerprint(key).split(':')) == 8
