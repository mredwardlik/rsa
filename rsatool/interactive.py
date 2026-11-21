"""Three small programs for people who don't use the command line.

``generator``, ``encryptor`` and ``decryptor`` ask everything they need and
work with files next to them, so they can be built into .exe files
(``create.bat``) and started with a double click:

1. The recipient runs **generator** and sends ``public_key.pem`` to the sender.
2. The sender puts ``public_key.pem`` next to **encryptor**, types a message
   and sends the ``message.txt`` it makes.
3. The recipient puts ``message.txt`` next to **decryptor** and reads it.
"""

from __future__ import annotations

import getpass
import sys
from pathlib import Path
from typing import Callable

from . import cipher, keys
from .errors import PassphraseRequired, RsaToolError

PRIVATE_KEY = Path('private_key.pem')
PUBLIC_KEY = Path('public_key.pem')
MESSAGE = Path('message.txt')
LEGACY_MESSAGE = Path('message')  # binary file of the first version


def pause():
    """Keep the console window open after a double click."""
    if sys.stdin is not None and sys.stdin.isatty():
        try:
            input('\nPress Enter to exit...')
        except EOFError:
            pass


def run(program: Callable[[], None]):
    """Run a program, show errors as text, wait for Enter."""
    code = 0
    try:
        program()
    except RsaToolError as error:
        print(f'\nError: {error}')
        code = 1
    except (KeyboardInterrupt, EOFError):
        print('\nCancelled.')
        code = 1
    pause()
    sys.exit(code)


def confirm(question: str) -> bool:
    return input(f'{question} [y/N] ').strip().lower() in ('y', 'yes', 'д', 'да')


def ask_new_passphrase() -> str | None:
    while True:
        first = getpass.getpass('Passphrase for the private key (Enter for none): ')
        if not first:
            return None
        if getpass.getpass('Repeat it: ') == first:
            return first
        print("The passphrases don't match, try again.")


def generator():
    existing = [path for path in (PRIVATE_KEY, PUBLIC_KEY) if path.exists()]
    if existing:
        names = ' and '.join(f'"{path}"' for path in existing)
        print(f'{names} already exist here. Messages for the old key can be read only with it.')
        if not confirm('Replace them with new keys?'):
            print('Kept the old keys.')
            return

    passphrase = ask_new_passphrase()
    print('Making a 2048-bit key pair...')
    key = keys.generate()
    keys.save(PRIVATE_KEY, keys.export_private(key, passphrase), private=True, force=True)
    keys.save(PUBLIC_KEY, keys.export_public(key), private=False, force=True)

    print(f'\nDone. Fingerprint: {keys.fingerprint(key)}')
    print(f'  {PUBLIC_KEY}  - send it to the people who will write to you')
    print(f'  {PRIVATE_KEY} - keep it secret, it opens the messages')


def encryptor():
    if not PUBLIC_KEY.exists():
        raise RsaToolError(f'Put "{PUBLIC_KEY}" of the recipient next to the program.')
    key = keys.load_public(PUBLIC_KEY)
    print(f'Recipient key: {keys.fingerprint(key)}')
    message = input('Put your message: ')
    if not message:
        print('The message is empty, nothing to encrypt.')
        return

    text = cipher.armor(cipher.encrypt(message.encode('utf-8'), key))
    MESSAGE.write_text(text + '\n', encoding='ascii')
    print(f'\n{text}\n\nSaved to "{MESSAGE}". Send the file or the text above to the recipient.')


def decryptor():
    if not PRIVATE_KEY.exists():
        raise RsaToolError(f'There is no "{PRIVATE_KEY}" here. Make keys with the generator first.')
    try:
        key = keys.load_private(PRIVATE_KEY)
    except PassphraseRequired:
        key = keys.load_private(PRIVATE_KEY, getpass.getpass('Passphrase for the private key: '))

    source = MESSAGE if MESSAGE.exists() or not LEGACY_MESSAGE.exists() else LEGACY_MESSAGE
    try:
        data = source.read_bytes()
    except FileNotFoundError:
        raise RsaToolError(f'Put "{MESSAGE}" next to the program.') from None

    plain = cipher.decrypt(data, key)
    print('Decrypted message:', plain.decode('utf-8', 'replace'))
