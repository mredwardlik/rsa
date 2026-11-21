class RsaToolError(Exception):
    """Base class for all errors of the package."""


class KeyFileError(RsaToolError):
    """A key file is missing, broken or of the wrong kind."""


class PassphraseRequired(KeyFileError):
    """The private key is encrypted, a passphrase is needed to use it."""


class DecryptionError(RsaToolError):
    """The message was encrypted for another key, or it was changed."""


class FormatError(RsaToolError):
    """The data is not an encrypted message."""
