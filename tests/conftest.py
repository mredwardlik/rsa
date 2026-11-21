import pytest

from rsatool import keys


@pytest.fixture(scope='session')
def key():
    return keys.generate()


@pytest.fixture(scope='session')
def other_key():
    return keys.generate()


@pytest.fixture
def key_files(tmp_path, key):
    """private_key.pem and public_key.pem in a temporary folder."""
    private = keys.save(tmp_path / 'private_key.pem', keys.export_private(key), private=True)
    public = keys.save(tmp_path / 'public_key.pem', keys.export_public(key), private=False)
    return private, public
