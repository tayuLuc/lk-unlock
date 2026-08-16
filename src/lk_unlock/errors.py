"""Shared exceptions for lk-unlock."""


class LkUnlockError(RuntimeError):
    """Base error for all lk-unlock failures."""


class KeyError_(LkUnlockError):
    """Key file missing or unreadable."""


class PatchError(LkUnlockError):
    """LK image could not be patched."""


class SignError(LkUnlockError):
    """Token could not be signed."""


class FastbootError(LkUnlockError):
    """fastboot is missing or a fastboot command failed."""
