# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Win32 version resources for the frozen installer launchers.

``Intellicrack.exe`` and ``Hexbench.exe`` are the two executables the installer
puts in front of the user, so they are the first files Explorer, Task Manager and
every SmartScreen or antivirus reputation heuristic inspect. PyInstaller stamps a
``VS_VERSIONINFO`` resource into a build only when the ``EXE`` call is given a
``version=`` argument; ``icon=`` does not supply one. Without it both shipped
launchers carry entirely empty file properties: no company, no product, no
version.

This module renders that resource for both launcher spec files out of the single
source of truth the rest of the packaging pipeline already uses,
``src/intellicrack/_metadata.py``. No version string is written down here. It is
read from ``__version__`` and mapped onto the four integers Win32 requires with
the same transform ``packaging/stage.ps1`` applies when it derives
``AppVerNumeric`` for the installer, so the launcher resource and the installer's
``VersionInfoVersion`` agree by construction and keep agreeing across a bump.

The rendered text is the ``VSVersionInfo`` serialization PyInstaller reads back
with ``load_version_info_from_text_file``. Emitting that text rather than
building the structure directly keeps this module free of any PyInstaller import,
so it stays importable, lintable and type-checkable on its own.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Final


if TYPE_CHECKING:
    from pathlib import Path


_METADATA_SEGMENTS: Final[tuple[str, ...]] = ("src", "intellicrack", "_metadata.py")
_FIELD_RE: Final[re.Pattern[str]] = re.compile(r'(?m)^__(?P<name>\w+)__\s*:\s*str\s*=\s*"(?P<value>[^"]*)"')
_PRERELEASE_RE: Final[re.Pattern[str]] = re.compile(r"(?i)(a|b|rc|\.dev|\.post)\d+.*$")
_REQUIRED_FIELDS: Final[tuple[str, ...]] = ("author", "copyright", "summary", "version")

_VERSION_PARTS: Final[int] = 4
_MAX_VERSION_COMPONENT: Final[int] = 0xFFFF

_PRODUCT_NAME: Final[str] = "Intellicrack"
_EXECUTABLE_SUFFIX: Final[str] = ".exe"

_STRING_TABLE_KEY: Final[str] = "040904B0"
_LANGUAGE_ID: Final[int] = 0x0409
_CODEPAGE_ID: Final[int] = 0x04B0
_FILE_FLAGS_MASK: Final[int] = 0x3F
_FILE_OS_NT_WINDOWS32: Final[int] = 0x40004
_FILE_TYPE_APP: Final[int] = 0x1


def read_metadata(repo_root: Path) -> dict[str, str]:
    """Read the dunder metadata declared by ``src/intellicrack/_metadata.py``.

    The module is parsed rather than imported. Importing ``intellicrack`` pulls in
    the application's third-party dependencies, and the launcher build has to stay
    runnable with nothing but the standard library present.

    Args:
        repo_root: The repository root that contains ``src/intellicrack``.

    Returns:
        dict[str, str]: Mapping of each declared dunder name, stripped of its
        surrounding underscores, to its string value.

    Raises:
        ValueError: If the metadata module is absent, or does not declare every
            field the version resource is built from.
    """
    metadata_path = repo_root.joinpath(*_METADATA_SEGMENTS)
    if not metadata_path.is_file():
        error_message = f"metadata module not found: {metadata_path}"
        raise ValueError(error_message)

    fields: dict[str, str] = {}
    for match in _FIELD_RE.finditer(metadata_path.read_text(encoding="utf-8")):
        fields[match.group("name")] = match.group("value")

    missing = [f"__{name}__" for name in _REQUIRED_FIELDS if not fields.get(name)]
    if missing:
        error_message = f"{metadata_path} declares no non-empty {', '.join(missing)}"
        raise ValueError(error_message)

    return fields


def derive_file_version(version: str) -> tuple[int, int, int, int]:
    """Map a PEP 440 version onto the four integers a Win32 resource requires.

    The prerelease, dev and post suffixes are stripped and the remaining dotted
    release is zero-padded to exactly four components, which is the transform
    ``packaging/stage.ps1`` applies to ``__version__`` when it derives the
    installer's ``AppVerNumeric``. Keeping the two identical is what makes the
    executable and the installer report the same numeric version.

    Args:
        version: A PEP 440 version string such as ``"0.1.0a1"``.

    Returns:
        tuple[int, int, int, int]: The four-part numeric version, for example
        ``(0, 1, 0, 0)``.

    Raises:
        ValueError: If a release component is not a decimal number, or does not
            fit the 16 bits a version resource stores it in.
    """
    release = _PRERELEASE_RE.sub("", version)
    padding = ["0"] * _VERSION_PARTS
    parts = [*release.split("."), *padding][:_VERSION_PARTS]

    numbers: list[int] = []
    for part in parts:
        if not part.isdecimal():
            error_message = f"version {version!r} has a non-numeric release component {part!r}"
            raise ValueError(error_message)
        number = int(part)
        if number > _MAX_VERSION_COMPONENT:
            error_message = f"version {version!r} component {part!r} exceeds the {_MAX_VERSION_COMPONENT} a version resource holds"
            raise ValueError(error_message)
        numbers.append(number)

    return numbers[0], numbers[1], numbers[2], numbers[3]


def render_version_resource(version: str, author: str, copyright_notice: str, description: str, executable_name: str) -> str:
    """Render the ``VSVersionInfo`` serialization for one launcher executable.

    ``FileVersion`` carries the four-part numeric form, matching what the
    installer stamps as ``VersionInfoVersion``, while ``ProductVersion`` carries
    the full PEP 440 string the installer displays as ``AppVersion``, so the
    exact prerelease is never lost to the numeric mapping.

    Args:
        version: The PEP 440 project version.
        author: The publisher recorded as ``CompanyName``.
        copyright_notice: The notice recorded as ``LegalCopyright``.
        description: The description recorded as ``FileDescription``.
        executable_name: The executable's base name, without its suffix.

    Returns:
        str: The serialized resource, ready for PyInstaller's ``version=``
        argument to read back.
    """
    numbers = derive_file_version(version)
    numeric = ".".join(str(part) for part in numbers)
    entries: tuple[tuple[str, str], ...] = (
        ("CompanyName", author),
        ("FileDescription", description),
        ("FileVersion", numeric),
        ("InternalName", executable_name),
        ("LegalCopyright", copyright_notice),
        ("OriginalFilename", f"{executable_name}{_EXECUTABLE_SUFFIX}"),
        ("ProductName", _PRODUCT_NAME),
        ("ProductVersion", version),
    )

    lines: list[str] = [
        "VSVersionInfo(",
        "    ffi=FixedFileInfo(",
        f"        filevers={numbers!r},",
        f"        prodvers={numbers!r},",
        f"        mask={_FILE_FLAGS_MASK:#x},",
        "        flags=0x0,",
        f"        OS={_FILE_OS_NT_WINDOWS32:#x},",
        f"        fileType={_FILE_TYPE_APP:#x},",
        "        subtype=0x0,",
        "        date=(0, 0),",
        "    ),",
        "    kids=[",
        "        StringFileInfo([",
        f"            StringTable({_STRING_TABLE_KEY!r}, [",
    ]
    lines.extend(f"                StringStruct({name!r}, {value!r})," for name, value in entries)
    lines.extend((
        "            ]),",
        "        ]),",
        f"        VarFileInfo([VarStruct('Translation', [{_LANGUAGE_ID}, {_CODEPAGE_ID}])]),",
        "    ],",
        ")",
    ))
    return "\n".join(lines) + "\n"


def write_version_resource(destination: Path, repo_root: Path, executable_name: str, description: str | None = None) -> Path:
    """Write the version resource for one launcher and return its path.

    Args:
        destination: The file to write, normally under PyInstaller's ``workpath``
            so the generated resource stays out of the tracked tree.
        repo_root: The repository root that contains ``src/intellicrack``.
        executable_name: The executable's base name, without its suffix, as
            passed to ``EXE(name=...)``.
        description: The ``FileDescription`` for this executable. When omitted the
            project summary declared in ``_metadata.py`` is used.

    Returns:
        Path: The written file, for passing to PyInstaller's ``version=``
        argument.
    """
    metadata = read_metadata(repo_root)
    text = render_version_resource(
        version=metadata["version"],
        author=metadata["author"],
        copyright_notice=metadata["copyright"],
        description=metadata["summary"] if description is None else description,
        executable_name=executable_name,
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(text, encoding="utf-8")
    return destination
