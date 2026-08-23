# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Gates for S17-D44: WinPE driver-family staging was hardcoded to Windows 11.

:data:`~scripts.sandbox.provision_windows_guest.WINPE_DRIVER_FAMILY_PREFERENCE`
always ranked ``w11`` first, so :func:`~scripts.sandbox.provision_windows_guest
.select_winpe_driver_packages` picked the Windows 11 virtio-win package for
every guest whenever the medium carried one - including a Windows 10, Server,
or ARM64 guest for which a Windows 11 driver is the wrong OS build entirely.
The WinPE ``DriverPaths`` block WinPE searches before Setup can even see the
virtio-blk system disk is built from this selection, so the wrong family here
means Setup finds no disk for any guest that is not Windows 11 amd64, the
exact failure mode S17-D44's sibling gates already cover for architecture.

These gates are pure descriptor logic: no VM, no ISO, no mounted medium. They
drive the real production functions -
:func:`~scripts.sandbox.provision_windows_guest.resolve_guest_driver_family`,
:func:`~scripts.sandbox.provision_windows_guest.driver_family_preference`, and
:func:`~scripts.sandbox.provision_windows_guest.select_winpe_driver_packages`
itself - against representative OS/architecture descriptors, rather than
restating the family mapping here.
"""

from __future__ import annotations

import pytest

from scripts.sandbox.provision_windows_guest import (
    WINPE_DRIVER_FAMILY_PREFERENCE,
    driver_family_preference,
    resolve_guest_driver_family,
    select_winpe_driver_packages,
)


_DESCRIPTOR_CASES: tuple[tuple[str, str, str, str], ...] = (
    ("windows_10_x64", "Windows 10 Pro", "amd64", "w10\\amd64"),
    ("windows_11_x64", "Windows 11 Pro", "amd64", "w11\\amd64"),
    ("server_2022_x64", "Windows Server 2022 Datacenter", "amd64", "2k22\\amd64"),
    ("server_2019_x64", "Windows Server 2019 Standard", "amd64", "2k19\\amd64"),
    ("windows_11_arm64", "Windows 11 Pro", "ARM64", "w11\\ARM64"),
    ("windows_10_arm64", "Windows 10 Pro", "ARM64", "w10\\ARM64"),
    ("unrecognised_edition", "Windows Vista Ultimate", "amd64", "w11\\amd64"),
)
_DESCRIPTOR_IDS: tuple[str, ...] = tuple(case[0] for case in _DESCRIPTOR_CASES)


@pytest.mark.parametrize(("_id", "image_name", "architecture", "expected"), _DESCRIPTOR_CASES, ids=_DESCRIPTOR_IDS)
def test_resolve_guest_driver_family_matches_the_guest_edition(_id: str, image_name: str, architecture: str, expected: str) -> None:
    r"""The resolved subdirectory names the guest's own OS/arch family.

    Args:
        _id: Parametrize id, unused beyond labelling the case.
        image_name: Windows edition name fed to the production function.
        architecture: Architecture directory name fed to the production
            function.
        expected: ``<family>\\<arch>`` subdirectory the medium should be
            searched under for this guest.
    """
    resolved = resolve_guest_driver_family(image_name, architecture)

    assert resolved == expected, f"{image_name!r} on {architecture!r} resolved to {resolved!r}, expected {expected!r}"


def test_unrecognised_editions_fall_back_to_windows_11_not_something_else() -> None:
    """An edition string with no marker match still resolves to a real family.

    The fallback is pinned to :data:`WINPE_DRIVER_FAMILY_PREFERENCE`'s own
    first entry rather than a duplicated literal, so the two can never drift
    apart.
    """
    resolved = resolve_guest_driver_family("some future SKU nothing here recognises")

    assert resolved.split("\\")[0] == WINPE_DRIVER_FAMILY_PREFERENCE[0], (
        f"an unrecognised edition resolved to {resolved!r} instead of the {WINPE_DRIVER_FAMILY_PREFERENCE[0]!r} fallback"
    )


def test_driver_family_preference_moves_the_guest_family_to_the_front() -> None:
    """Preference reordering is a permutation, not a truncated or padded list.

    A Windows 10 guest must try ``w10`` before ``w11`` - the opposite of what
    :data:`WINPE_DRIVER_FAMILY_PREFERENCE` alone always does - while still
    carrying every other family so a driver the guest's own edition lacks
    still falls back through the rest of the medium.
    """
    preference = driver_family_preference("Windows 10 Pro")

    assert preference[0] == "w10", f"a Windows 10 guest's own preference order starts with {preference[0]!r}, not w10"
    assert set(preference) == set(WINPE_DRIVER_FAMILY_PREFERENCE), (
        "reordering for the guest's own edition lost or invented a family compared to the base preference list"
    )
    assert len(preference) == len(WINPE_DRIVER_FAMILY_PREFERENCE), "reordering changed the number of families in the preference list"


def test_driver_family_preference_is_unchanged_when_windows_11_is_already_first() -> None:
    """A Windows 11 guest's preference is exactly the base fallback order."""
    assert driver_family_preference("Windows 11 Pro") == WINPE_DRIVER_FAMILY_PREFERENCE


def test_select_winpe_driver_packages_prefers_the_guests_own_family_over_windows_11() -> None:
    """The real selection function picks the guest's OS family, not Windows 11's.

    This is the production defect made concrete: a medium carrying both a
    ``w10`` and a ``w11`` package for the same driver used to always yield the
    ``w11`` one, regardless of which edition was actually being installed,
    because :func:`~scripts.sandbox.provision_windows_guest
    .select_winpe_driver_packages` ranked by the hardcoded
    :data:`WINPE_DRIVER_FAMILY_PREFERENCE` alone. Threading
    :func:`driver_family_preference` for the guest's own edition through its
    ``preference`` argument is what fixes that, and this drives the real
    function rather than restating its ranking logic.
    """
    subpaths = (
        "viostor\\w10\\amd64",
        "viostor\\w11\\amd64",
        "NetKVM\\w10\\amd64",
        "NetKVM\\w11\\amd64",
    )

    selected = select_winpe_driver_packages(
        subpaths,
        drivers=("viostor", "NetKVM"),
        preference=driver_family_preference("Windows 10 Pro"),
    )

    assert selected == ("viostor\\w10\\amd64", "NetKVM\\w10\\amd64"), (
        f"a Windows 10 guest with both w10 and w11 packages on the medium selected {selected}, not its own w10 family"
    )


def test_select_winpe_driver_packages_still_falls_back_when_the_guests_own_family_is_absent() -> None:
    """A driver missing the guest's own family still resolves to a real one.

    The medium carries a genuinely different set of families per driver, so a
    Windows 10 guest whose own family is missing for one driver must still
    fall through the rest of :data:`WINPE_DRIVER_FAMILY_PREFERENCE` rather
    than being left with no package for that driver at all.
    """
    subpaths = (
        "viostor\\w11\\amd64",
        "viostor\\2k22\\amd64",
    )

    selected = select_winpe_driver_packages(
        subpaths,
        drivers=("viostor",),
        preference=driver_family_preference("Windows 10 Pro"),
    )

    assert selected == ("viostor\\w11\\amd64",), (
        f"a Windows 10 guest with no w10 package fell back to {selected} instead of the next-preferred existing family"
    )
