# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Persisted sandbox settings shared by the configuration dialog and the sandbox panel.

The sandbox configuration dialog writes a JSON settings document. The sandbox panel reads that document back when creating a QEMU sandbox so
the disk image and guest parameters chosen in the dialog actually reach the QEMU backend instead of being discarded, which previously left
``QEMUConfig.image_path`` permanently unset and made the QEMU sandbox impossible to start from the GUI.

This module deliberately contains no Qt imports so that both the dialog (``intellicrack.ui.sandbox_config``) and the panel
(``intellicrack.ui.panels.sandbox_panel``) can depend on it without creating an import cycle through the ``intellicrack.ui`` package.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

from intellicrack.core.config import get_config_file, get_project_root
from intellicrack.core.logging import get_logger
from intellicrack.sandbox.qemu import GuestOS, QEMUConfig


if TYPE_CHECKING:
    from collections.abc import Mapping


_logger = get_logger(__name__)

SETTINGS_FILENAME: Final[str] = "sandbox.json"

QEMU_IMAGE_PATH_KEY: Final[str] = "qemu_image_path"
QEMU_GUEST_OS_KEY: Final[str] = "qemu_guest_os"
QEMU_CPU_CORES_KEY: Final[str] = "qemu_cpu_cores"
QEMU_MEMORY_MB_KEY: Final[str] = "qemu_memory_mb"
QEMU_ACCELERATION_KEY: Final[str] = "qemu_enable_acceleration"
QEMU_AGENT_TIMEOUT_KEY: Final[str] = "qemu_agent_connect_timeout"
SHARED_FOLDER_KEY: Final[str] = "shared_folder"

QEMU_DEFAULT_GUEST_OS: Final[GuestOS] = GuestOS.LINUX
QEMU_MIN_CPU_CORES: Final[int] = 1
QEMU_MAX_CPU_CORES: Final[int] = 64
QEMU_DEFAULT_CPU_CORES: Final[int] = 2
QEMU_MIN_MEMORY_MB: Final[int] = 256
QEMU_MAX_MEMORY_MB: Final[int] = 131072
QEMU_DEFAULT_MEMORY_MB: Final[int] = 4096
QEMU_MIN_AGENT_TIMEOUT: Final[float] = 5.0
QEMU_MAX_AGENT_TIMEOUT: Final[float] = 1800.0
QEMU_DEFAULT_AGENT_TIMEOUT: Final[float] = 60.0

# Deployment-root-relative directories where a bundled QEMU guest image may live.
# The installer stages the guest at <install_root>/qemu-guest; a development
# checkout keeps guest images under tools/qemu/images.
_BUNDLED_GUEST_DIRS: Final[tuple[tuple[str, ...], ...]] = (
    ("qemu-guest",),
    ("tools", "qemu", "images"),
)

# Name of the bundled Python runtime directory the frozen launcher lays down
# beside the application and spawns the interpreter from
# (``<install_root>/runtime/pythonw.exe``; see packaging/launcher/launcher.py).
# When the running interpreter sits directly inside a directory of this name its
# grandparent is the authoritative install root.
_BUNDLED_RUNTIME_DIR: Final[str] = "runtime"


def get_settings_file() -> Path:
    """Return the path of the persisted sandbox settings document.

    Returns:
        Path: Location of the sandbox JSON settings file.
    """
    return get_config_file(SETTINGS_FILENAME)


def load_sandbox_settings() -> dict[str, object]:
    """Read the persisted sandbox settings document from disk.

    A missing, unreadable, or malformed settings file yields an empty mapping
    so that callers fall back to documented defaults rather than failing.

    Returns:
        dict[str, object]: Parsed settings, or an empty mapping when no usable
        settings document exists.
    """
    settings_file = get_settings_file()
    if not settings_file.exists():
        _logger.debug("sandbox_settings_absent", config_file=str(settings_file))
        return {}

    try:
        with settings_file.open(encoding="utf-8") as handle:
            loaded: object = json.load(handle)
    except (OSError, json.JSONDecodeError):
        _logger.warning(
            "sandbox_settings_load_failed",
            config_file=str(settings_file),
            exc_info=True,
        )
        return {}

    if not isinstance(loaded, dict):
        _logger.warning(
            "sandbox_settings_not_a_mapping",
            config_file=str(settings_file),
            payload_type=type(loaded).__name__,
        )
        return {}

    return cast("dict[str, object]", loaded)


def _coerce_int(value: object, default: int, minimum: int, maximum: int) -> int:
    """Coerce a persisted value into a bounded integer.

    Args:
        value: Raw value read from the settings document.
        default: Value used when ``value`` is absent or not numeric.
        minimum: Lower inclusive bound applied to the result.
        maximum: Upper inclusive bound applied to the result.

    Returns:
        int: The coerced value clamped to ``[minimum, maximum]``.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return default
    return max(minimum, min(maximum, int(value)))


def _coerce_float(value: object, default: float, minimum: float, maximum: float) -> float:
    """Coerce a persisted value into a bounded float.

    Args:
        value: Raw value read from the settings document.
        default: Value used when ``value`` is absent or not numeric.
        minimum: Lower inclusive bound applied to the result.
        maximum: Upper inclusive bound applied to the result.

    Returns:
        float: The coerced value clamped to ``[minimum, maximum]``.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return default
    return max(minimum, min(maximum, float(value)))


def _coerce_bool(value: object, *, default: bool) -> bool:
    """Coerce a persisted value into a boolean.

    Args:
        value: Raw value read from the settings document.
        default: Value used when ``value`` is not a boolean.

    Returns:
        bool: The coerced boolean value.
    """
    if isinstance(value, bool):
        return value
    return default


def _coerce_path(value: object) -> Path | None:
    """Coerce a persisted value into an optional filesystem path.

    Args:
        value: Raw value read from the settings document.

    Returns:
        Path | None: The path when ``value`` is a non-empty string, else None.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    return Path(value)


def _coerce_guest_os(value: object) -> GuestOS:
    """Coerce a persisted value into a guest operating system type.

    Args:
        value: Raw value read from the settings document.

    Returns:
        GuestOS: The matching guest OS, or :data:`QEMU_DEFAULT_GUEST_OS` when
        the value does not name a supported guest.
    """
    if isinstance(value, str):
        normalised = value.strip().lower()
        for guest_os in GuestOS:
            if guest_os.value == normalised:
                return guest_os
    return QEMU_DEFAULT_GUEST_OS


def _deployment_roots() -> list[Path]:
    """Return the deployment roots to probe for a bundled QEMU guest, most authoritative first.

    Two stable anchors are combined so guest discovery does not depend on how
    deep the ``intellicrack`` package sits under the deployment root:

    * **The bundled runtime's install root.** The frozen launcher spawns the
      installed application as ``<install_root>/runtime/pythonw.exe`` (see
      ``packaging/launcher/launcher.py``), so whenever the running interpreter
      lives directly inside a :data:`_BUNDLED_RUNTIME_DIR` directory its
      grandparent is the install root -- the exact directory the installer
      stages ``qemu-guest`` into. Deriving the root from the interpreter rather
      than from ``__file__`` keeps discovery correct across packaging changes and
      when running from a wheel or ``site-packages``, where the package-relative
      heuristic silently points elsewhere.
    * **The package-relative project root** from :func:`get_project_root` and its
      parent, which locates the guest in a development checkout
      (``tools/qemu/images``) and remains a defensive fallback for the installed
      layout.

    Returns:
        list[Path]: De-duplicated candidate deployment roots, most authoritative
        first.
    """
    roots: list[Path] = []

    def _add(candidate: Path | None) -> None:
        if candidate is None:
            return
        try:
            resolved = candidate.resolve()
        except (OSError, RuntimeError, ValueError):
            return
        if resolved not in roots:
            roots.append(resolved)

    executable = sys.executable
    if executable:
        try:
            interpreter: Path | None = Path(executable).resolve()
        except (OSError, RuntimeError, ValueError):
            interpreter = None
        if interpreter is not None and interpreter.parent.name.casefold() == _BUNDLED_RUNTIME_DIR:
            _add(interpreter.parent.parent)

    project_root = get_project_root()
    _add(project_root)
    _add(project_root.parent)

    return roots


def default_qemu_image() -> Path | None:
    """Discover a bundled QEMU guest image when the user has configured none.

    The installer lays the guest image down at ``<install_root>/qemu-guest`` and a
    development checkout keeps guest images under ``tools/qemu/images``. Candidate
    deployment roots are resolved by :func:`_deployment_roots`, which anchors the
    installed layout on the bundled runtime's install root instead of a
    package-depth heuristic, so a freshly installed sandbox has a usable disk
    image without the user first browsing to one. The first ``*.qcow2`` found is
    returned. This never influences backend availability -- it only supplies a
    default disk image.

    Returns:
        Path | None: Path to a discovered bundled guest image, or ``None`` when no
        bundled guest is present.
    """
    seen: set[Path] = set()
    for root in _deployment_roots():
        for segments in _BUNDLED_GUEST_DIRS:
            directory = root.joinpath(*segments)
            if directory in seen or not directory.is_dir():
                continue
            seen.add(directory)
            images = sorted(directory.glob("*.qcow2"))
            if images:
                _logger.info("sandbox_bundled_guest_discovered", image=str(images[0]))
                return images[0]
    return None


def build_qemu_config(settings: Mapping[str, object]) -> QEMUConfig:
    """Build a QEMU backend configuration from persisted settings.

    Args:
        settings: Parsed sandbox settings document.

    Returns:
        QEMUConfig: Backend configuration carrying the configured disk image
        (falling back to a discovered bundled guest when none is configured),
        guest OS, CPU/memory allocation, acceleration preference, guest-agent
        timeout, and shared folder.
    """
    return QEMUConfig(
        guest_os=_coerce_guest_os(settings.get(QEMU_GUEST_OS_KEY)),
        image_path=_coerce_path(settings.get(QEMU_IMAGE_PATH_KEY)) or default_qemu_image(),
        cpu_cores=_coerce_int(
            settings.get(QEMU_CPU_CORES_KEY),
            QEMU_DEFAULT_CPU_CORES,
            QEMU_MIN_CPU_CORES,
            QEMU_MAX_CPU_CORES,
        ),
        memory_mb=_coerce_int(
            settings.get(QEMU_MEMORY_MB_KEY),
            QEMU_DEFAULT_MEMORY_MB,
            QEMU_MIN_MEMORY_MB,
            QEMU_MAX_MEMORY_MB,
        ),
        enable_acceleration=_coerce_bool(settings.get(QEMU_ACCELERATION_KEY), default=True),
        agent_connect_timeout=_coerce_float(
            settings.get(QEMU_AGENT_TIMEOUT_KEY),
            QEMU_DEFAULT_AGENT_TIMEOUT,
            QEMU_MIN_AGENT_TIMEOUT,
            QEMU_MAX_AGENT_TIMEOUT,
        ),
        shared_folder=_coerce_path(settings.get(SHARED_FOLDER_KEY)),
    )


def load_qemu_config() -> QEMUConfig:
    """Load the persisted QEMU backend configuration.

    Returns:
        QEMUConfig: Configuration built from the on-disk sandbox settings,
        falling back to documented defaults when no settings exist.
    """
    return build_qemu_config(load_sandbox_settings())
