"""Binary patches for MediaTek LK bootloaders (fastboot unlock, warnings).

Patch recipes sourced from r0rt1z2/lkpatcher (GPL-3.0-or-later),
see THIRD_PARTY.md. Each patch is a needle->replacement hex pair;
'00207047' is ARM 'bx lr' - makes the target function return immediately
(0 = unlocked / no warning).
"""

from __future__ import annotations

from liblk.exceptions import NeedleNotFoundException
from liblk.image import LkImage

# Category -> {needle_hex: replacement_hex}
DEFAULT_PATCHES: dict[str, dict[str, str]] = {
    # Unlock fastboot access by forcing the function that checks for the
    # unlock bit in oplusreserve to always return 0 (unlocked)
    "fastboot": {
        "2de9f04fadf5ac5d": "00207047",
        "f0b5adf5925d": "00207047",
    },
    # Disable the warning shown when the device is unlocked with mtkclient
    # by forcing the function that checks the vbmeta state to return 0
    "dm_verity": {
        "30b583b002ab0022": "00207047",
    },
    # Disable the unlocked-warning by forcing the function that checks the
    # current LCS state to always return 0
    "orange_state": {
        "08b50a4b7b441b681b68022b": "00207047",
        "08b50e4b7b441b681b68022b": "00207047",
    },
    # Force the function that prints the device-verification warning to
    # return immediately
    "red_state": {
        "f0b5002489b0": "00207047",
    },
}

WARNING_CATEGORIES = ("dm_verity", "orange_state", "red_state")


def apply_patch_category(
    image: LkImage, category: str, patches: dict[str, str] | None = None
) -> int:
    """Apply one patch category to the image; returns the applied count."""
    recipes = patches or DEFAULT_PATCHES[category]
    applied = 0
    for needle, replacement in recipes.items():
        try:
            image.apply_patch(needle, replacement, partition="lk")
            applied += 1
        except NeedleNotFoundException:
            continue  # needle not present in this image - skip
    return applied


def apply_patch_categories(
    image: LkImage, categories: list[str], patches: dict[str, dict[str, str]] | None = None
) -> dict[str, int]:
    """Apply several patch categories; returns {category: applied_count}."""
    recipes = patches or DEFAULT_PATCHES
    results: dict[str, int] = {}
    for cat in categories:
        if cat not in recipes:
            raise KeyError(f"unknown patch category: {cat}")
        results[cat] = apply_patch_category(image, cat, recipes[cat])
    return results
