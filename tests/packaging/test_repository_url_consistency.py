# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Falsifiable gates that every declared repository URL names the real repository.

The canonical remote is ``https://github.com/ZachFlint/Intellicrack``. That URL is
repeated across packaging and documentation metadata: the ``[project].urls`` table
in ``pyproject.toml``, ``__url__`` in ``src/intellicrack/_metadata.py``, the
installer's ``AppUrl`` define in ``packaging/intellicrack.iss`` (which Windows
shows in Add/Remove Programs), and the Sphinx ``html_context`` that builds the
"Edit on GitHub" source links.

Every one of those locations once pointed at a ``zacharyflint`` account, which is
not the project's owner and differs from ``ZachFlint`` by more than case, so
GitHub's case-insensitive resolution does not rescue it. The package metadata, the
installer's uninstall entry, and every documentation source link resolved to the
wrong account, and nothing detected it.

These gates anchor each location on the canonical URL, so reverting any single one
turns red. They read repository-root files that the sandbox does not mount, so
they are registered ``host_native``.

A companion gate keeps the ``Typing :: Typed`` trove classifier honest: that
classifier promises downstream type checkers a ``py.typed`` marker, and the
promise only holds while the marker actually ships inside the package.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Final, cast


_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]

_PYPROJECT: Final[Path] = _REPO_ROOT / "pyproject.toml"
_METADATA: Final[Path] = _REPO_ROOT / "src" / "intellicrack" / "_metadata.py"
_INSTALLER_ISS: Final[Path] = _REPO_ROOT / "packaging" / "intellicrack.iss"
_DOCS_CONF: Final[Path] = _REPO_ROOT / "docs" / "source" / "conf.py"
_PY_TYPED: Final[Path] = _REPO_ROOT / "src" / "intellicrack" / "py.typed"

_CANONICAL_OWNER: Final[str] = "ZachFlint"
_CANONICAL_REPO: Final[str] = "Intellicrack"
_CANONICAL_URL: Final[str] = f"https://github.com/{_CANONICAL_OWNER}/{_CANONICAL_REPO}"

_METADATA_URL_RE: Final[re.Pattern[str]] = re.compile(r'(?m)^__url__\s*:\s*str\s*=\s*"([^"]+)"')
_ISS_APPURL_RE: Final[re.Pattern[str]] = re.compile(r'(?m)^#define\s+AppUrl\s+"([^"]*)"')
_CONF_GITHUB_USER_RE: Final[re.Pattern[str]] = re.compile(r'"github_user"\s*:\s*"([^"]+)"')
_CONF_GITHUB_REPO_RE: Final[re.Pattern[str]] = re.compile(r'"github_repo"\s*:\s*"([^"]+)"')

_TYPED_CLASSIFIER: Final[str] = "Typing :: Typed"
_GITHUB_HOST: Final[str] = "github.com"


def _read_project_table() -> dict[str, object]:
    """Read the ``[project]`` table from ``pyproject.toml``.

    Returns:
        dict[str, object]: The parsed ``[project]`` table.
    """
    assert _PYPROJECT.is_file(), f"pyproject.toml missing: {_PYPROJECT}"
    data: dict[str, object] = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    project = data["project"]
    assert isinstance(project, dict), "pyproject [project] must be a table"
    return cast("dict[str, object]", project)


def _read_project_urls() -> dict[str, str]:
    """Read the ``[project].urls`` table from ``pyproject.toml``.

    Returns:
        dict[str, str]: Mapping of each declared URL label to its value.
    """
    urls = _read_project_table().get("urls")
    assert isinstance(urls, dict), "pyproject [project].urls must be a table"
    return {label: str(value) for label, value in cast("dict[str, object]", urls).items()}


def test_every_github_project_url_points_at_the_canonical_repository() -> None:
    """Real gate: every GitHub URL in ``[project].urls`` names the real repository.

    These URLs are what a package page and any downstream index render as the
    project's Homepage, Issues, Source, and Changelog links. Pointing them at an
    account that does not own the project sends users to a wrong or missing page.
    """
    urls = _read_project_urls()
    github_urls = {label: url for label, url in urls.items() if _GITHUB_HOST in url}

    assert github_urls, "pyproject [project].urls declares no GitHub URLs to verify"
    for label, url in sorted(github_urls.items()):
        assert url.startswith(_CANONICAL_URL), (
            f"pyproject [project].urls {label!r} is {url!r}, which does not point at the canonical repository {_CANONICAL_URL!r}"
        )


def test_metadata_url_matches_the_pyproject_homepage() -> None:
    """Real gate: ``_metadata.__url__`` equals the declared project Homepage.

    ``__url__`` is the URL the running application reports as its own home. If it
    drifts from the packaging metadata, the app and the package disagree about
    where the project lives.
    """
    assert _METADATA.is_file(), f"metadata module missing: {_METADATA}"
    match = _METADATA_URL_RE.search(_METADATA.read_text(encoding="utf-8"))
    assert match is not None, "could not find __url__ in src/intellicrack/_metadata.py"

    homepage = _read_project_urls().get("Homepage")
    assert homepage is not None, "pyproject [project].urls declares no Homepage"
    assert match.group(1) == homepage, f"_metadata.__url__ is {match.group(1)!r} but pyproject Homepage is {homepage!r}"


def test_installer_appurl_points_at_the_canonical_repository() -> None:
    """Real gate: the installer's ``AppUrl`` define names the real repository.

    Inno Setup writes ``AppUrl`` into the Windows uninstall entry, so a wrong value
    ships to every machine that installs Intellicrack and is visible in Add/Remove
    Programs long after installation.
    """
    assert _INSTALLER_ISS.is_file(), f"installer script missing: {_INSTALLER_ISS}"
    match = _ISS_APPURL_RE.search(_INSTALLER_ISS.read_text(encoding="utf-8-sig"))
    assert match is not None, "packaging/intellicrack.iss declares no AppUrl define"

    assert match.group(1) == _CANONICAL_URL, f"installer AppUrl is {match.group(1)!r}, expected the canonical repository {_CANONICAL_URL!r}"


def test_docs_github_context_names_the_canonical_owner_and_repository() -> None:
    """Real gate: the Sphinx GitHub context names the real owner and repository.

    ``html_context`` drives every "Edit on GitHub" and source link in the built
    documentation. A wrong owner or repository breaks all of them at once, and the
    breakage is invisible until a reader clicks one.
    """
    assert _DOCS_CONF.is_file(), f"Sphinx conf missing: {_DOCS_CONF}"
    text = _DOCS_CONF.read_text(encoding="utf-8")

    user_match = _CONF_GITHUB_USER_RE.search(text)
    repo_match = _CONF_GITHUB_REPO_RE.search(text)
    assert user_match is not None, "docs/source/conf.py html_context declares no github_user"
    assert repo_match is not None, "docs/source/conf.py html_context declares no github_repo"

    assert user_match.group(1) == _CANONICAL_OWNER, f"docs conf.py github_user is {user_match.group(1)!r}, expected {_CANONICAL_OWNER!r}"
    assert repo_match.group(1) == _CANONICAL_REPO, f"docs conf.py github_repo is {repo_match.group(1)!r}, expected {_CANONICAL_REPO!r}"


def test_typed_classifier_is_backed_by_a_py_typed_marker() -> None:
    """Real gate: the ``Typing :: Typed`` classifier ships an actual ``py.typed``.

    The classifier tells downstream type checkers that inline annotations are
    available, but PEP 561 only honours that when a ``py.typed`` marker is inside
    the installed package. Claiming the classifier without the marker advertises
    typing the distribution does not deliver.
    """
    classifiers = _read_project_table().get("classifiers")
    assert isinstance(classifiers, list), "pyproject [project].classifiers must be a list"

    declares_typed = _TYPED_CLASSIFIER in {str(entry) for entry in cast("list[object]", classifiers)}
    ships_marker = _PY_TYPED.is_file()

    assert declares_typed == ships_marker, (
        f"pyproject {'declares' if declares_typed else 'omits'} the {_TYPED_CLASSIFIER!r} "
        f"classifier but the PEP 561 marker at {_PY_TYPED} is "
        f"{'present' if ships_marker else 'missing'}; the two must agree"
    )
