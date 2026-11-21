import io
import subprocess
import sys

import pytest

from rsatool import cipher, keys
from rsatool.cli import PASSPHRASE_ENV, Io, main


class Run:
    """Calls main() with captured streams in a temporary folder."""

    def __init__(self, secrets=()):
        self.secrets = list(secrets)

    def __call__(self, *argv, stdin=''):
        self.out, self.err = io.StringIO(), io.StringIO()
        streams = Io(stdin=io.StringIO(stdin), stdout=self.out, stderr=self.err,
                     ask_secret=lambda prompt: self.secrets.pop(0))
        return main(list(argv), streams)


@pytest.fixture
def run(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(PASSPHRASE_ENV, raising=False)
    return Run()


def test_keygen(run, tmp_path):
    assert run('keygen') == 0
    assert 'fingerprint' in run.out.getvalue()
    private = keys.load_private(tmp_path / 'private_key.pem')
    public = keys.load_public(tmp_path / 'public_key.pem')
    assert private.public_key() == public
    assert keys.fingerprint(public) in run.out.getvalue()


def test_keygen_keeps_existing_keys(run, tmp_path):
    run('keygen')
    before = (tmp_path / 'private_key.pem').read_bytes()
    assert run('keygen') == 1
    assert 'already exists' in run.err.getvalue() and '--force' in run.err.getvalue()
    assert (tmp_path / 'private_key.pem').read_bytes() == before
    assert run('keygen', '--force') == 0
    assert (tmp_path / 'private_key.pem').read_bytes() != before


def test_keygen_custom_paths_and_size(run, tmp_path):
    assert run('keygen', '-b', '3072', '--private', 'alice/key.pem', '--public', 'alice/key.pub') == 0
    assert keys.load(tmp_path / 'alice' / 'key.pem').size_in_bits() == 3072


def test_encrypt_decrypt_text(run):
    run('keygen')
    assert run('encrypt', '-m', 'Привет!') == 0
    armored = run.out.getvalue()
    assert armored.startswith(cipher.ARMOR_BEGIN)
    assert run('decrypt', stdin=armored) == 0
    assert run.out.getvalue() == 'Привет!'  # not a terminal: exactly the encrypted bytes


def test_encrypt_stdin_to_file(run, tmp_path):
    run('keygen')
    assert run('encrypt', '-o', 'msg.txt', stdin='from stdin\n') == 0
    assert 'msg.txt' in run.err.getvalue()
    assert run('decrypt', '-i', 'msg.txt') == 0
    assert run.out.getvalue() == 'from stdin\n'


def test_binary_file(run, tmp_path):
    run('keygen')
    data = bytes(range(256)) * 50
    (tmp_path / 'photo.bin').write_bytes(data)
    assert run('encrypt', '-i', 'photo.bin', '-o', 'photo.enc', '--binary') == 0
    assert (tmp_path / 'photo.enc').read_bytes()[:4] == b'RSAT'
    assert run('decrypt', '-i', 'photo.enc', '-o', 'photo.out') == 0
    assert (tmp_path / 'photo.out').read_bytes() == data


def test_binary_needs_output(run):
    run('keygen')
    with pytest.raises(SystemExit):
        run('encrypt', '-m', 'x', '--binary')


def test_wrong_key(run, tmp_path):
    run('keygen')
    run('encrypt', '-m', 'secret', '-o', 'msg.txt')
    run('keygen', '--force')
    assert run('decrypt', '-i', 'msg.txt') == 1
    assert 'another key' in run.err.getvalue()


def test_missing_key(run):
    assert run('encrypt', '-m', 'x') == 1
    assert 'public_key.pem' in run.err.getvalue() and 'not found' in run.err.getvalue()


def test_missing_input(run):
    run('keygen')
    assert run('encrypt', '-i', 'nope.txt') == 1
    assert 'nope.txt' in run.err.getvalue()


def test_passphrase_prompt(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(PASSPHRASE_ENV, raising=False)
    run = Run(secrets=['', 'one', 'two', 'pw', 'pw', 'pw', 'wrong'])
    assert run('keygen', '-p') == 0   # empty, then a mismatch, then 'pw' twice
    assert "don't match" in run.err.getvalue()
    assert 'passphrase' in run.out.getvalue()
    run('encrypt', '-m', 'hidden', '-o', 'm.txt')
    assert run('decrypt', '-i', 'm.txt') == 0
    assert run.out.getvalue() == 'hidden'
    assert run('decrypt', '-i', 'm.txt') == 1
    assert 'Wrong passphrase' in run.err.getvalue()


def test_passphrase_from_environment(run, monkeypatch):
    monkeypatch.setenv(PASSPHRASE_ENV, 'from env')
    assert run('keygen', '-p') == 0
    run('encrypt', '-m', 'ok', '-o', 'm.txt')
    assert run('decrypt', '-i', 'm.txt') == 0
    assert run.out.getvalue() == 'ok'


def test_sign_verify(run, tmp_path):
    run('keygen')
    (tmp_path / 'doc.txt').write_text('I owe you 10 dollars')
    assert run('sign', '-i', 'doc.txt') == 0
    assert (tmp_path / 'doc.txt.sig').exists()
    assert run('verify', '-i', 'doc.txt') == 0
    assert run.out.getvalue().startswith('OK')

    (tmp_path / 'doc.txt').write_text('I owe you 1000 dollars')
    assert run('verify', '-i', 'doc.txt') == 1
    assert run.err.getvalue().startswith('BAD')


def test_info(run, tmp_path):
    run('keygen')
    assert run('info') == 0
    assert '2048-bit RSA public key' in run.out.getvalue()
    assert run('info', 'private_key.pem') == 0
    assert 'private key' in run.out.getvalue()


def test_decrypt_message_of_the_first_version(run, tmp_path):
    from Crypto.Cipher import PKCS1_OAEP
    run('keygen')
    key = keys.load_public(tmp_path / 'public_key.pem')
    (tmp_path / 'message').write_bytes(PKCS1_OAEP.new(key).encrypt(b'2021'))
    assert run('decrypt', '-i', 'message') == 0
    assert run.out.getvalue() == '2021'


def test_module_entry_point(tmp_path):
    result = subprocess.run([sys.executable, '-m', 'rsatool', '--version'],
                            capture_output=True, text=True, cwd=tmp_path)
    assert result.returncode == 0 and result.stdout.startswith('rsatool ')


def test_pipe(tmp_path):
    def rsatool(*args, data=b''):
        return subprocess.run([sys.executable, '-m', 'rsatool', *args], input=data,
                              capture_output=True, cwd=tmp_path, check=True).stdout

    rsatool('keygen')
    secret = 'Текст через pipe\n'.encode()
    assert rsatool('decrypt', data=rsatool('encrypt', data=secret)) == secret
