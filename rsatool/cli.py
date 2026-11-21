"""Command line interface: ``rsatool keygen | encrypt | decrypt | sign | verify | info``."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path
from typing import Callable, Sequence, TextIO

from . import __version__, cipher, keys, signature
from .errors import PassphraseRequired, RsaToolError

PASSPHRASE_ENV = 'RSATOOL_PASSPHRASE'
PRIVATE_KEY = 'private_key.pem'
PUBLIC_KEY = 'public_key.pem'


class Io:
    """Streams and prompts, replaced in tests."""

    def __init__(self, stdin: TextIO | None = None, stdout: TextIO | None = None,
                 stderr: TextIO | None = None, ask_secret: Callable[[str], str] | None = None):
        self.stdin = stdin or sys.stdin
        self.stdout = stdout or sys.stdout
        self.stderr = stderr or sys.stderr
        self.ask_secret = ask_secret or getpass.getpass

    def print(self, *args, file: TextIO | None = None, **kwargs):
        print(*args, file=file or self.stdout, **kwargs)

    def error(self, text: str):
        print(f'rsatool: error: {text}', file=self.stderr)

    @property
    def interactive(self) -> bool:
        return hasattr(self.stdin, 'isatty') and self.stdin.isatty()

    def read_stdin(self) -> bytes:
        buffer = getattr(self.stdin, 'buffer', None)
        return buffer.read() if buffer is not None else self.stdin.read().encode('utf-8')

    def write_stdout(self, data: bytes):
        buffer = getattr(self.stdout, 'buffer', None)
        if buffer is not None:
            self.stdout.flush()
            buffer.write(data)
            buffer.flush()
        else:
            self.stdout.write(data.decode('utf-8'))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='rsatool',
        description='RSA keys, encryption and signatures. Messages of any length are '
                    'encrypted with AES-256-GCM, its key with RSA-OAEP.',
        epilog=f'The passphrase of a private key can be given in the {PASSPHRASE_ENV} '
               'environment variable instead of the prompt.',
    )
    parser.add_argument('-V', '--version', action='version', version=f'%(prog)s {__version__}')
    commands = parser.add_subparsers(dest='command', metavar='COMMAND', required=True)

    p = commands.add_parser('keygen', help='make a key pair',
                            description='Make a private and a public key.')
    p.add_argument('-b', '--bits', type=int, default=keys.DEFAULT_KEY_SIZE, choices=keys.KEY_SIZES,
                   help=f'key size (default: {keys.DEFAULT_KEY_SIZE})')
    p.add_argument('--private', default=PRIVATE_KEY, metavar='PATH',
                   help=f'private key file (default: {PRIVATE_KEY})')
    p.add_argument('--public', default=PUBLIC_KEY, metavar='PATH',
                   help=f'public key file (default: {PUBLIC_KEY})')
    p.add_argument('-p', '--passphrase', action='store_true',
                   help='protect the private key with a passphrase')
    p.add_argument('-f', '--force', action='store_true', help='overwrite existing key files')

    p = commands.add_parser('encrypt', help='encrypt a message or a file',
                            description='Encrypt for the owner of the public key. The text '
                                        'form is printed, or saved with -o.')
    p.add_argument('-k', '--key', default=PUBLIC_KEY, metavar='PATH',
                   help=f'public key of the recipient (default: {PUBLIC_KEY})')
    source = p.add_mutually_exclusive_group()
    source.add_argument('-m', '--message', metavar='TEXT', help='text to encrypt')
    source.add_argument('-i', '--input', metavar='FILE', help='file to encrypt (default: stdin)')
    p.add_argument('-o', '--output', metavar='FILE', help='save to a file')
    p.add_argument('--binary', action='store_true',
                   help='save raw bytes instead of text (needs -o)')

    p = commands.add_parser('decrypt', help='decrypt a message or a file',
                            description='Decrypt with your private key.')
    p.add_argument('-k', '--key', default=PRIVATE_KEY, metavar='PATH',
                   help=f'your private key (default: {PRIVATE_KEY})')
    p.add_argument('-i', '--input', metavar='FILE', help='encrypted file (default: stdin)')
    p.add_argument('-o', '--output', metavar='FILE', help='save to a file (default: print the text)')

    p = commands.add_parser('sign', help='sign a file',
                            description='Sign a file with your private key (RSA-PSS, SHA-256).')
    p.add_argument('-k', '--key', default=PRIVATE_KEY, metavar='PATH',
                   help=f'your private key (default: {PRIVATE_KEY})')
    p.add_argument('-i', '--input', required=True, metavar='FILE', help='file to sign')
    p.add_argument('-o', '--output', metavar='FILE', help='signature file (default: FILE.sig)')

    p = commands.add_parser('verify', help='check a signature',
                            description='Check the signature of a file. Exit code 0 if it is '
                                        'valid, 1 if not.')
    p.add_argument('-k', '--key', default=PUBLIC_KEY, metavar='PATH',
                   help=f'public key of the signer (default: {PUBLIC_KEY})')
    p.add_argument('-i', '--input', required=True, metavar='FILE', help='signed file')
    p.add_argument('-s', '--signature', metavar='FILE', help='signature file (default: FILE.sig)')

    p = commands.add_parser('info', help='show a key size and fingerprint',
                            description='Show what a key file contains.')
    p.add_argument('key', nargs='?', default=PUBLIC_KEY, help=f'key file (default: {PUBLIC_KEY})')
    return parser


def main(argv: Sequence[str] | None = None, io: Io | None = None) -> int:
    io = io or Io()
    args = build_parser().parse_args(argv)
    handler = COMMANDS[args.command]
    try:
        return handler(args, io)
    except RsaToolError as error:
        io.error(str(error))
    except FileExistsError as error:
        io.error(f'{error} Use --force to overwrite it.')
    except OSError as error:
        io.error(f'{error.strerror}: {error.filename}' if error.filename else str(error))
    except KeyboardInterrupt:
        io.error('cancelled')
    return 1


def ask_new_passphrase(io: Io) -> str:
    if os.environ.get(PASSPHRASE_ENV):
        return os.environ[PASSPHRASE_ENV]
    while True:
        first = io.ask_secret('Passphrase: ')
        if not first:
            io.error('the passphrase is empty, try again')
            continue
        if io.ask_secret('Repeat the passphrase: ') == first:
            return first
        io.error("the passphrases don't match, try again")


def load_private(path: str, io: Io):
    try:
        return keys.load_private(path, os.environ.get(PASSPHRASE_ENV))
    except PassphraseRequired:
        return keys.load_private(path, io.ask_secret(f'Passphrase for {path}: '))


def read_input(args, io: Io, prompt: str) -> bytes:
    if getattr(args, 'message', None) is not None:
        return args.message.encode('utf-8')
    if args.input:
        return Path(args.input).read_bytes()
    if io.interactive:
        io.print(prompt, file=io.stderr)
    return io.read_stdin()


def cmd_keygen(args, io: Io) -> int:
    for path in (args.private, args.public):
        if Path(path).exists() and not args.force:
            raise FileExistsError(f'"{path}" already exists.')
    passphrase = ask_new_passphrase(io) if args.passphrase else None

    key = keys.generate(args.bits)
    keys.save(args.private, keys.export_private(key, passphrase), private=True, force=args.force)
    keys.save(args.public, keys.export_public(key), private=False, force=args.force)

    io.print(f'Made a {args.bits}-bit key pair, fingerprint {keys.fingerprint(key)}')
    io.print(f'  private key: {args.private}' + ('  (protected with a passphrase)' if passphrase else ''))
    io.print(f'  public key:  {args.public}')
    io.print('Send the public key to the people who will write to you. Keep the private key secret.')
    return 0


def cmd_encrypt(args, io: Io) -> int:
    if args.binary and not args.output:
        build_parser().error('--binary needs -o FILE')
    key = keys.load_public(args.key)
    data = read_input(args, io, 'Type the message, then Ctrl+D (Ctrl+Z, Enter on Windows):')
    blob = cipher.encrypt(data, key)

    if args.binary:
        Path(args.output).write_bytes(blob)
    elif args.output:
        Path(args.output).write_text(cipher.armor(blob) + '\n', encoding='ascii')
    else:
        io.print(cipher.armor(blob))
    if args.output:
        io.print(f'Encrypted {len(data)} bytes for {keys.fingerprint(key)} into "{args.output}"',
                 file=io.stderr)
    return 0


def cmd_decrypt(args, io: Io) -> int:
    key = load_private(args.key, io)
    data = read_input(args, io, 'Paste the message:')
    plain = cipher.decrypt(data, key)

    if args.output:
        Path(args.output).write_bytes(plain)
        io.print(f'Decrypted {len(plain)} bytes into "{args.output}"', file=io.stderr)
        return 0
    if not getattr(io.stdout, 'isatty', lambda: False)():
        io.write_stdout(plain)  # to a pipe or a file: exactly the encrypted bytes
        return 0
    try:
        text = plain.decode('utf-8')
    except UnicodeDecodeError:
        io.error('the message is binary, save it with -o FILE')
        return 1
    io.print(text, end='' if text.endswith('\n') else '\n')
    return 0


def cmd_sign(args, io: Io) -> int:
    key = load_private(args.key, io)
    data = Path(args.input).read_bytes()
    output = args.output or f'{args.input}.sig'
    Path(output).write_text(signature.encode(signature.sign(data, key)) + '\n', encoding='ascii')
    io.print(f'Signed "{args.input}", the signature is in "{output}"')
    return 0


def cmd_verify(args, io: Io) -> int:
    key = keys.load_public(args.key)
    data = Path(args.input).read_bytes()
    sig = signature.decode(Path(args.signature or f'{args.input}.sig').read_bytes(), key)
    if signature.verify(data, sig, key):
        io.print(f'OK: "{args.input}" is signed by {keys.fingerprint(key)}')
        return 0
    io.print(f'BAD: the signature doesn\'t match "{args.input}" or this key', file=io.stderr)
    return 1


def cmd_info(args, io: Io) -> int:
    try:
        key = keys.load(args.key)
    except PassphraseRequired:
        key = load_private(args.key, io)
    kind = 'private key' if key.has_private() else 'public key'
    io.print(f'{args.key}: {key.size_in_bits()}-bit RSA {kind}')
    io.print(f'fingerprint: {keys.fingerprint(key)}')
    return 0


COMMANDS = {
    'keygen': cmd_keygen,
    'encrypt': cmd_encrypt,
    'decrypt': cmd_decrypt,
    'sign': cmd_sign,
    'verify': cmd_verify,
    'info': cmd_info,
}
