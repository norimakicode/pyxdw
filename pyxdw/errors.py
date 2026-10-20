"""Exceptions raised by pyxdw."""


class XdwError(Exception):
    """Base exception for pyxdw."""


class XdwFormatError(XdwError):
    """The input does not satisfy the verified XDW structural invariants."""


class XdwLimitError(XdwFormatError):
    """Decoding would exceed a safety limit of :class:`XdwLimits`.

    ``limit_name`` names the limit, ``limit`` its value and ``requested`` the
    size that was declared or reached (``None`` when unknown).
    """

    def __init__(self, message: str, *, limit_name: str, limit: int,
                 requested: int | None = None):
        super().__init__(message)
        self.limit_name = limit_name
        self.limit = limit
        self.requested = requested


class XdwUnsupportedLayoutError(XdwError):
    """The XDW is structurally readable but its page/resource layout is unknown."""


class XdwUnsupportedFeatureError(XdwError, NotImplementedError):
    """The requested feature depends on an XDW structure not decoded yet."""


class XdwVerificationError(XdwError, AssertionError):
    """A write produced output that failed pyxdw's own read-back check.

    The candidate is discarded, never returned. This signals a pyxdw defect or an
    input it does not handle as verified, not a malformed input. It stays an
    ``AssertionError`` for callers that caught the earlier plain one.
    """


class XdwProtectedDocumentError(XdwUnsupportedFeatureError):
    """The document is password/security protected; its pages cannot be decoded.

    ``protection`` carries the :class:`XdwProtectionInfo` (kind, permissions,
    resource tag) when it could be inspected, else ``None``. Nothing is decrypted.
    """

    def __init__(self, message: str, protection=None):
        super().__init__(message)
        self.protection = protection


class XdwNotXdwError(XdwFormatError):
    """The input is not an XDW file (e.g. a PDF, ZIP or DocuWorks binder .xbd).

    ``detected`` names a recognized other format, or is ``None``.
    """

    def __init__(self, message: str, detected: str | None = None):
        super().__init__(message)
        self.detected = detected
