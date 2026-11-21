"""The double-click programs, with scripted input()."""

import pytest
from Crypto.Cipher import PKCS1_OAEP

from rsatool import interactive, keys


@pytest.fixture
def answers(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    queue = {'input': [], 'secret': []}
    monkeypatch.setattr('builtins.input', lambda prompt='': queue['input'].pop(0))
    monkeypatch.setattr(interactive.getpass, 'getpass', lambda prompt='': queue['secret'].pop(0))
    return queue


def test_generator_encryptor_decryptor(answers, tmp_path, capsys):
    answers['secret'] = ['']
    interactive.generator()
    assert (tmp_path / 'private_key.pem').exists() and (tmp_path / 'public_key.pem').exists()

    answers['input'] = ['Встречаемся в 7']
    interactive.encryptor()
    assert (tmp_path / 'message.txt').read_text().startswith('-----BEGIN RSATOOL MESSAGE-----')

    capsys.readouterr()
    interactive.decryptor()
    assert 'Decrypted message: Встречаемся в 7' in capsys.readouterr().out


def test_generator_asks_before_replacing(answers, tmp_path):
    answers['secret'] = ['']
    interactive.generator()
    before = (tmp_path / 'private_key.pem').read_bytes()

    answers['input'] = ['n']
    interactive.generator()
    assert (tmp_path / 'private_key.pem').read_bytes() == before

    answers['input'], answers['secret'] = ['y'], ['']
    interactive.generator()
    assert (tmp_path / 'private_key.pem').read_bytes() != before


def test_passphrase(answers, tmp_path, capsys):
    answers['secret'] = ['pw', 'typo', 'pw', 'pw']
    interactive.generator()
    assert "don't match" in capsys.readouterr().out
    assert keys.is_encrypted((tmp_path / 'private_key.pem').read_bytes())

    answers['input'] = ['secret']
    interactive.encryptor()
    answers['secret'] = ['pw']
    interactive.decryptor()
    assert 'Decrypted message: secret' in capsys.readouterr().out


def test_old_binary_message_file(answers, tmp_path, capsys):
    answers['secret'] = ['']
    interactive.generator()
    key = keys.load_public(tmp_path / 'public_key.pem')
    (tmp_path / 'message').write_bytes(PKCS1_OAEP.new(key).encrypt(b'old'))
    interactive.decryptor()
    assert 'Decrypted message: old' in capsys.readouterr().out


def test_errors_are_shown_as_text(answers, capsys, monkeypatch):
    monkeypatch.setattr(interactive.sys, 'stdin', None)  # no pause in tests
    with pytest.raises(SystemExit) as exit_info:
        interactive.run(interactive.encryptor)
    assert exit_info.value.code == 1
    assert 'public_key.pem' in capsys.readouterr().out
