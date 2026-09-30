# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Declarative configuration for third-party Model Context Protocol servers.

Servers are described in ``<config_dir>/mcp.json``. The file shape is Visual Studio Code's ``mcp.json``: a ``servers`` object keyed by
server id, plus an ``inputs`` array declaring the values the user is prompted for. The older ``mcpServers`` root that several other clients
emit is accepted on import and normalized to the native shape, so an existing configuration can be pasted in without hand-editing.

No secret is ever stored here. A value that needs one carries a ``${input:<id>}`` reference which :mod:`intellicrack.mcp.secrets` resolves
from the operating system keyring at connect time; a value that looks like a literal credential is refused at parse time with the offending
field named.
"""

from __future__ import annotations

import enum
import json
import re
from dataclasses import dataclass, field, replace
from pathlib import Path, PureWindowsPath
from typing import TYPE_CHECKING, Any, Final
from urllib.parse import parse_qsl, urlsplit

from intellicrack.core.config import get_config_file
from intellicrack.core.json_payload import JsonObject, is_json_array, is_json_object
from intellicrack.core.logging import get_logger
from intellicrack.mcp.errors import McpConfigError


if TYPE_CHECKING:
    from collections.abc import Collection, Mapping, Sequence


_logger = get_logger(__name__)


SERVER_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
"""Accepted shape of a server id.

Lower-case alphanumerics and hyphens only, at most 32 characters. The hyphen is what keeps the namespace unambiguous at the provider
boundary: the wire layer maps ``.`` to ``__``, and a namespace that can never contain ``_`` or ``.`` can never collide with that separator.
A key written in another client's style, such as ``GitHub`` or ``my_server``, is brought to this shape by :func:`normalize_server_id`.
"""

_SERVER_ID_MAX_CHARS: Final[int] = 32
_SERVER_ID_INVALID_RUN: Final[re.Pattern[str]] = re.compile(r"[^a-z0-9]+")

MCP_CONFIG_FILENAME: Final[str] = "mcp.json"
"""Name of the configuration file inside the Intellicrack config directory."""

NAMESPACE_PREFIX: Final[str] = "mcp-"
"""Prefix every MCP namespace carries, distinguishing it from a bridge."""

INPUT_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
"""Accepted shape of an ``inputs`` entry identifier."""

INPUT_REFERENCE_PATTERN: Final[re.Pattern[str]] = re.compile(r"\$\{input:([A-Za-z0-9][A-Za-z0-9_.-]{0,63})}")
"""Matches one ``${input:<id>}`` reference inside a configuration value."""

DEFAULT_REQUEST_TIMEOUT_S: Final[float] = 60.0
"""Per-call timeout applied when a server declares none."""

MAX_REQUEST_TIMEOUT_S: Final[float] = 3600.0
"""Upper bound on a configured per-call timeout."""

_ERR_NOT_AN_OBJECT = "MCP configuration root must be a JSON object"
_ERR_SERVERS_NOT_AN_OBJECT = "MCP configuration 'servers' must be a JSON object keyed by server id"
_ERR_INPUTS_NOT_AN_ARRAY = "MCP configuration 'inputs' must be a JSON array"
_ERR_SERVER_NOT_AN_OBJECT = "server entry must be a JSON object"
_ERR_DUPLICATE_INPUT = "duplicate input id"
_ERR_UNKNOWN_TRANSPORT = "unknown transport type"
_ERR_NO_TRANSPORT = "server declares neither 'command' (stdio) nor 'url' (http)"


class McpTransportKind(enum.Enum):
    """Transport a configured server is reached over.

    Attributes:
        STDIO: A local child process speaking JSON-RPC over stdin/stdout.
        HTTP: A remote endpoint speaking Streamable HTTP.
        SSE: A remote endpoint declared with the legacy ``sse`` type,
            spoken to over the SDK's HTTP+SSE client in its ``legacy``
            client mode.
    """

    STDIO = "stdio"
    HTTP = "http"
    SSE = "sse"


_TRANSPORT_ALIASES: Final[dict[str, McpTransportKind]] = {
    "stdio": McpTransportKind.STDIO,
    "http": McpTransportKind.HTTP,
    "streamablehttp": McpTransportKind.HTTP,
    "sse": McpTransportKind.SSE,
}
"""Declared ``type`` values, folded to lower case without separators, mapped to the transport they name.

``streamable-http``, ``streamable_http`` and ``streamableHttp`` are how other MCP clients write the Streamable HTTP transport that
Intellicrack calls ``http``.
"""

_TRANSPORT_SEPARATORS: Final[re.Pattern[str]] = re.compile(r"[\s_-]+")


_SECRET_NAME_TOKENS: Final[frozenset[str]] = frozenset({
    "authorization",
    "credential",
    "credentials",
    "cookie",
    "key",
    "passphrase",
    "password",
    "passwd",
    "pat",
    "pwd",
    "secret",
    "token",
})
"""Field-name words that name a credential: any literal value under them is one."""

_WEAK_SECRET_NAME_TOKENS: Final[frozenset[str]] = frozenset({"auth", "private", "signature"})
"""Field-name words that often, but not always, name a credential: ``AUTH_TOKEN`` does, ``AUTH_MODE`` and ``PRIVATE_REPO`` do not.

A value under one of them is refused only when it is itself shaped like a key.
"""

_SECRET_DESCRIPTOR_TOKENS: Final[frozenset[str]] = frozenset({
    "algo",
    "algorithm",
    "alg",
    "dir",
    "enabled",
    "enable",
    "endpoint",
    "expiry",
    "file",
    "format",
    "header",
    "host",
    "id",
    "kind",
    "length",
    "method",
    "mode",
    "name",
    "path",
    "provider",
    "required",
    "scheme",
    "server",
    "size",
    "stdin",
    "strategy",
    "style",
    "timeout",
    "ttl",
    "type",
    "uri",
    "url",
    "version",
})
"""Final name words that describe a setting about a credential rather than the credential: ``TOKEN_TYPE``, ``SIGNATURE_ALGO``,
``API_KEY_HEADER``. A name ending in one is treated like a weak one."""

_SECRET_NAME_WORDS: Final[frozenset[str]] = frozenset({
    "accesstoken",
    "apikey",
    "apisecret",
    "apitoken",
    "authtoken",
    "bearertoken",
    "clientsecret",
    "privatekey",
    "refreshtoken",
    "sessiontoken",
})
"""Glued field names that carry no separator for token splitting to find."""

_SECRET_VALUE_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"^(?:sk|pk|rk|sk-proj|sk-ant)-[A-Za-z0-9_-]{16,}$"),
    re.compile(r"^gh[pousr]_[A-Za-z0-9]{20,}$"),
    re.compile(r"^github_pat_[A-Za-z0-9_]{20,}$"),
    re.compile(r"^xox[abposr]-[A-Za-z0-9-]{10,}$"),
    re.compile(r"^AKIA[0-9A-Z]{16}$"),
    re.compile(r"^ey[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}$"),
    re.compile(r"^[Bb]earer\s+[A-Za-z0-9._~+/-]{16,}=*$"),
    re.compile(r"^-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)
"""Value shapes that are credentials regardless of the field they sit in: each is a vendor's documented key or token format.

Shapes that are merely random are deliberately absent. A 40-character hex git commit, a 32-character hex Notion page id, a Google Drive
file id and a UUID look exactly like keys and are not; a random value used as a key is still caught by the name of the field or option it
is given under.
"""

_MIXED_ENTROPY_MIN_CHARS: Final[int] = 24
"""Length past which a mixed-case alphanumeric run is treated as a credential."""

_NAME_SPLIT_PATTERN: Final[re.Pattern[str]] = re.compile(r"[^a-z0-9]+")

_URL_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://\S+$")
"""A value written as an absolute URL."""

_PATH_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^(?:[A-Za-z]:[\\/]|\\\\|/|~[\\/]|\.{1,2}[\\/]|\$\{[A-Za-z]+}[\\/]|%[A-Za-z_]+%[\\/])",
)
"""A value written as a filesystem path: drive, UNC, POSIX, home, relative or variable-rooted."""

_RELATIVE_FILE_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[\w.-]+(?:[\\/][\w .-]+)+\.[A-Za-z0-9]{1,8}$")
"""A relative path whose last segment carries a file extension."""

_FLAG_PATTERN: Final[re.Pattern[str]] = re.compile(r"^-{1,2}[A-Za-z][A-Za-z0-9_.-]*$")
"""A command-line option name such as ``--api-key`` or ``-t``."""

_OPAQUE_MIN_CHARS: Final[int] = 8
"""Shortest positional option value treated as a possible key."""

_ASSIGNMENT_PATTERN: Final[re.Pattern[str]] = re.compile(r"^(-{0,2}[A-Za-z_][A-Za-z0-9_.-]*)=(.*)$", re.DOTALL)
"""A ``NAME=value`` or ``--name=value`` argument."""

_EMBEDDED_ASSIGNMENT_PATTERN: Final[re.Pattern[str]] = re.compile(r"(?:^|[;&])\s*(-{0,2}[A-Za-z_][A-Za-z0-9_ .-]*?)\s*=\s*([^;&]*)")
"""One ``name=value`` part of a connection string or option list, such as ``Password=...`` in ``Server=db;Password=...``."""

_OPTION_P: Final[str] = "-p"
"""The short option ``mysql``, ``sshpass`` and many others take a password with, and many more take a port or a path with."""

_PASSWORD_MIN_CHARS: Final[int] = 8
_CHARACTER_CLASSES: Final[int] = 3
"""Upper case, lower case and digits: a value mixing all three and any symbol is password-shaped."""

_FEWER_CLASSES: Final[int] = 2
"""Two character classes suffice when the value also carries a symbol names and paths do not use."""
_UNTELLING_SYMBOLS: Final[str] = "-_./:\\"
"""Symbols common in names, paths and versions, which say nothing about whether a value is a password."""

_WEAK: Final[int] = 1
_STRONG: Final[int] = 2


def _name_secret_strength(name: str) -> int:
    """Rate how surely a field name marks its value as a credential.

    Args:
        name: The environment-variable, header, query-parameter or option name.

    Returns:
        int: ``0`` when it does not, :data:`_WEAK` when only a key-shaped value under it is one, :data:`_STRONG` when any literal value
        under it is one.
    """
    lowered = name.lower()
    glued = _NAME_SPLIT_PATTERN.sub("", lowered)
    parts = [part for part in _NAME_SPLIT_PATTERN.split(lowered) if part]
    strength = 0
    if glued in _SECRET_NAME_WORDS or any(part in _SECRET_NAME_TOKENS for part in parts):
        strength = _STRONG
    elif any(part in _WEAK_SECRET_NAME_TOKENS for part in parts):
        strength = _WEAK
    if strength and parts and parts[-1] in _SECRET_DESCRIPTOR_TOKENS:
        strength = _WEAK
    return strength


def _name_looks_secret(name: str) -> bool:
    """Decide whether a field name may mark its value as credential-bearing.

    Args:
        name: The environment-variable, header, or query-parameter name.

    Returns:
        bool: ``True`` when the name names, or may name, a credential.
    """
    return _name_secret_strength(name) > 0


def name_looks_secret(name: str) -> bool:
    """Decide whether a variable, header or parameter name marks its value as a credential.

    Args:
        name: The name.

    Returns:
        bool: ``True`` when the name names a credential, such as
        ``GITHUB_TOKEN`` or ``x-api-key``.
    """
    return _name_looks_secret(name)


def _is_path(value: str) -> bool:
    """Decide whether a value is written as a filesystem path.

    Args:
        value: The candidate value.

    Returns:
        bool: ``True`` for an absolute, home-relative, dot-relative or
        variable-rooted path, or a relative path ending in a file name.
    """
    return bool(_PATH_PATTERN.match(value) or _RELATIVE_FILE_PATTERN.match(value))


def _url_carries_secret(url: str) -> bool:
    """Decide whether a URL embeds a credential.

    A URL names where something is, not a secret, unless it carries a
    password in its user information or a credential in its query string.

    Args:
        url: An absolute URL, with every ``${input:id}`` reference already
            removed.

    Returns:
        bool: ``True`` when the URL embeds a literal credential.
    """
    try:
        parts = urlsplit(url)
        password = parts.password
    except ValueError:
        return False
    if password:
        return True
    return any(value and _named_value_is_secret(name, value) for name, value in parse_qsl(parts.query, keep_blank_values=True))


def _named_value_is_secret(name: str, value: str) -> bool:
    """Decide whether one literal value is a credential, given the name it is filed under.

    Args:
        name: The name the value sits under.
        value: The literal value, with no ``${input:id}`` reference in it.

    Returns:
        bool: ``True`` when the value is shaped like a credential, or the name says it is one.
    """
    candidate = value.strip()
    if not candidate or _URL_PATTERN.match(candidate) or _is_path(candidate):
        return _value_looks_secret(candidate)
    if _value_looks_secret(candidate):
        return True
    strength = _name_secret_strength(name)
    return strength == _STRONG or (strength == _WEAK and _value_is_opaque(candidate))


def _embedded_secret_name(value: str) -> str | None:
    """Find a credential written as one part of a connection string or option list.

    Args:
        value: The literal value, with every ``${input:id}`` reference already removed.

    Returns:
        str | None: The name of the part that holds a credential, such as ``Password``, or ``None``.
    """
    if "=" not in value or not any(separator in value for separator in ";&"):
        return None
    for match in _EMBEDDED_ASSIGNMENT_PATTERN.finditer(value):
        name, part = match.group(1).strip(), match.group(2)
        if _named_value_is_secret(name, part):
            return name
    return None


def _is_password_shaped(value: str) -> bool:
    """Decide whether a value given to ``-p`` is a password rather than a port, path or name.

    Args:
        value: The option's value.

    Returns:
        bool: ``True`` for a value of password length mixing upper case, lower case, digits and a symbol, or three of those where the
        symbol is not one names and paths use.
    """
    candidate = value.strip()
    if len(candidate) < _PASSWORD_MIN_CHARS or any(char.isspace() for char in candidate):
        return False
    if _URL_PATTERN.match(candidate) or _is_path(candidate):
        return False
    symbols = {char for char in candidate if not char.isalnum()}
    classes = sum((
        any(char.isupper() for char in candidate),
        any(char.islower() for char in candidate),
        any(char.isdigit() for char in candidate),
    ))
    telling = symbols - set(_UNTELLING_SYMBOLS)
    return (classes == _CHARACTER_CLASSES and bool(symbols)) or (classes >= _FEWER_CLASSES and bool(telling))


def _value_looks_secret(value: str) -> bool:
    """Decide whether a literal value is shaped like a credential whatever it is filed under.

    Only a vendor's documented key format counts: a random-looking value
    alone does not, since commit hashes and document ids look the same. URLs
    and filesystem paths are locations rather than credentials, so they are
    judged only by whether they embed one.

    Args:
        value: The literal value, with every ``${input:id}`` reference
            already removed.

    Returns:
        bool: ``True`` when the value looks like a credential.
    """
    candidate = value.strip()
    if not candidate:
        return False
    if _URL_PATTERN.match(candidate):
        return _url_carries_secret(candidate)
    if _is_path(candidate):
        return False
    return any(pattern.match(candidate) for pattern in _SECRET_VALUE_PATTERNS)


def _value_is_opaque(value: str) -> bool:
    """Decide whether a value could be a key rather than an ordinary argument.

    Used for an option whose value is only inferred from position, where a
    credential-named flag may be a switch followed by an unrelated argument.

    Args:
        value: The literal value.

    Returns:
        bool: ``True`` for a single token of key-like length that is not a
        URL or path and is not an ordinary word.
    """
    candidate = value.strip()
    if len(candidate) < _OPAQUE_MIN_CHARS or any(char.isspace() for char in candidate):
        return False
    if _URL_PATTERN.match(candidate) or _is_path(candidate):
        return False
    return any(char.isdigit() for char in candidate) or len(candidate) >= _MIXED_ENTROPY_MIN_CHARS


def strip_input_references(value: str) -> str:
    """Remove every ``${input:id}`` reference from a configuration value.

    Args:
        value: The raw configuration value.

    Returns:
        str: ``value`` with each reference replaced by an empty string.
    """
    return INPUT_REFERENCE_PATTERN.sub("", value)


def referenced_input_ids(value: str) -> tuple[str, ...]:
    """List the input ids a configuration value references, in order.

    Args:
        value: The raw configuration value.

    Returns:
        tuple[str, ...]: Referenced input ids, duplicates preserved.
    """
    return tuple(match.group(1) for match in INPUT_REFERENCE_PATTERN.finditer(value))


def literal_secret_problem(name: str, value: str) -> str | None:
    """Judge one named configuration value for a literal credential.

    A value carrying at least one ``${input:id}`` reference supplies its
    secret from the keyring and is accepted even under a credential-shaped
    name, unless the literal text around the reference is itself shaped like
    a credential. A URL or path under a credential-shaped name is accepted
    too: ``TOKEN_URL`` names an endpoint and ``KEY_FILE`` names a file. A
    name that only may name a credential -- ``AUTH_MODE``, ``PRIVATE_REPO``,
    ``SIGNATURE_ALGO`` -- refuses only a key-shaped value. A connection
    string or option list is judged part by part, so the ``Password`` in
    ``Server=db;Password=...`` is found.

    Args:
        name: The field, variable or option name.
        value: The raw value.

    Returns:
        str | None: Why the value is refused, or ``None`` when it is fine.
    """
    references = referenced_input_ids(value)
    remainder = strip_input_references(value)
    if _value_looks_secret(remainder):
        return "holds a value shaped like a credential"
    if (embedded := _embedded_secret_name(remainder)) is not None:
        return f"carries a literal secret in its {embedded!r} part"
    if references:
        return None
    if _named_value_is_secret(name, remainder):
        return "looks like a literal secret"
    return None


def _secret_message(server_id: str, field_name: str, problem: str) -> str:
    """Build the message refusing a literal credential.

    Args:
        server_id: Server the value belongs to.
        field_name: Where the value sits, e.g. ``env.API_KEY`` or ``args[2]``.
        problem: Why it was refused.

    Returns:
        str: The message for the :class:`McpConfigError`.
    """
    return (
        f"server '{server_id}': {field_name} {problem}. "
        f"Store it with an 'inputs' entry and reference it as ${{input:<id>}} instead; "
        f"{MCP_CONFIG_FILENAME} must never contain a credential."
    )


def _reject_literal_secrets(*, server_id: str, section: str, values: Mapping[str, str]) -> None:
    """Refuse a mapping that writes a credential into the configuration file.

    Args:
        server_id: Server the mapping belongs to, for the error message.
        section: Mapping being checked (``"env"``, ``"headers"``, ``"query"``).
        values: The mapping to check.

    Raises:
        McpConfigError: If any value is a literal credential.
    """
    for name, value in values.items():
        problem = literal_secret_problem(name, value)
        if problem is not None:
            raise McpConfigError(_secret_message(server_id, f"{section}.{name}", problem))


def _argument_secret_problem(args: Sequence[str], index: int) -> str | None:
    """Judge one launch argument for a literal credential.

    An argument is judged as ``--name=value`` or ``NAME=value`` when written
    that way, as the value of the option before it when that option has a
    credential-shaped name -- any value at all after ``--password``, a
    key-shaped one after ``--auth`` -- as a password when it follows ``-p``
    or is attached to it and mixes the character classes a password does,
    and otherwise by its shape alone.

    Args:
        args: Every launch argument, in order.
        index: Position of the argument to judge.

    Returns:
        str | None: Why the argument is refused, or ``None`` when it is fine.
    """
    argument = args[index]
    assignment = _ASSIGNMENT_PATTERN.match(argument)
    if assignment is not None:
        return literal_secret_problem(assignment.group(1), assignment.group(2))
    remainder = strip_input_references(argument)
    if _value_looks_secret(remainder):
        return "holds a value shaped like a credential"
    if (embedded := _embedded_secret_name(remainder)) is not None:
        return f"carries a literal secret in its {embedded!r} part"
    if argument.startswith(_OPTION_P) and len(argument) > len(_OPTION_P) and _is_password_shaped(argument[len(_OPTION_P) :]):
        return f"passes a password attached to {_OPTION_P}"
    if index == 0 or referenced_input_ids(argument) or argument.startswith("-"):
        return None
    option = args[index - 1]
    if option == _OPTION_P and _is_password_shaped(argument):
        return f"is the value of {option} and looks like a password"
    if not _FLAG_PATTERN.match(option):
        return None
    strength = _name_secret_strength(option)
    if (strength == _STRONG and not _URL_PATTERN.match(argument) and not _is_path(argument)) or (
        strength == _WEAK and _value_is_opaque(argument)
    ):
        return f"is the value of {option} and looks like a literal secret"
    return None


def _reject_literal_secret_args(*, server_id: str, args: Sequence[str]) -> None:
    """Refuse launch arguments that write a credential into the configuration file.

    Args:
        server_id: Server the arguments belong to, for the error message.
        args: The launch arguments.

    Raises:
        McpConfigError: If any argument is a literal credential.
    """
    for index in range(len(args)):
        problem = _argument_secret_problem(args, index)
        if problem is not None:
            raise McpConfigError(_secret_message(server_id, f"args[{index}]", problem))


def normalize_server_id(key: str) -> str | None:
    """Bring a server key written in another client's style to the id shape.

    Letters are lower-cased and every run of other characters becomes one
    hyphen, so ``GitHub`` becomes ``github`` and ``my_server`` becomes
    ``my-server``. The result is cut to 32 characters.

    Args:
        key: The key the server was stored under.

    Returns:
        str | None: An id matching :data:`SERVER_ID_PATTERN`, or ``None``
        when the key has no letter or digit to build one from.
    """
    folded = _SERVER_ID_INVALID_RUN.sub("-", key.strip().lower()).strip("-")
    candidate = folded[:_SERVER_ID_MAX_CHARS].rstrip("-")
    return candidate if SERVER_ID_PATTERN.match(candidate) else None


def unique_server_id(candidate: str, taken: Collection[str]) -> str:
    """Make a server id unique among those already in use.

    The id itself is kept when it is free; otherwise ``-2``, ``-3`` and so on
    are appended, cutting the id short where needed so the result still fits
    :data:`SERVER_ID_PATTERN`.

    Args:
        candidate: An id matching :data:`SERVER_ID_PATTERN`.
        taken: The ids already in use.

    Returns:
        str: ``candidate``, or the first free numbered variant of it.
    """
    if candidate not in taken:
        return candidate
    number = 2
    while True:
        suffix = f"-{number}"
        variant = f"{candidate[: _SERVER_ID_MAX_CHARS - len(suffix)].rstrip('-')}{suffix}"
        if variant not in taken:
            return variant
        number += 1


@dataclass(frozen=True, slots=True)
class StdioServerSpec:
    """Launch description for a local server started as a child process.

    Attributes:
        command: Executable to run. Resolved without a shell.
        args: Arguments passed to ``command``, each one verbatim.
        cwd: Working directory for the child, or ``None`` to inherit.
        env: Extra environment entries merged over the inherited
            environment. Values may carry ``${input:id}`` references.
        env_file: Path to a ``KEY=VALUE`` file whose entries are merged
            under ``env``, or ``None``.
    """

    command: str
    args: tuple[str, ...] = ()
    cwd: str | None = None
    env: Mapping[str, str] = field(default_factory=dict[str, str])
    env_file: str | None = None


@dataclass(frozen=True, slots=True)
class HttpServerSpec:
    """Connection description for a server reached over HTTP.

    Attributes:
        url: Endpoint URL. Must be ``http`` or ``https``.
        headers: Extra request headers. Values may carry ``${input:id}``
            references.
        query: Query parameters composed onto ``url``, which is how several
            hosted servers carry an API key or a tool-set selection.
        oauth_client_id: Pre-registered OAuth client id, or ``None``.
        oauth_metadata_url: HTTPS URL of a Client ID Metadata Document, used
            as the client id when the authorization server supports CIMD.
    """

    url: str
    headers: Mapping[str, str] = field(default_factory=dict[str, str])
    query: Mapping[str, str] = field(default_factory=dict[str, str])
    oauth_client_id: str | None = None
    oauth_metadata_url: str | None = None


@dataclass(frozen=True, slots=True)
class McpInputSpec:
    """One value the operator is prompted for and the keyring then holds.

    Attributes:
        id: Identifier a ``${input:id}`` reference resolves against.
        description: Prompt text shown when the value is collected.
        password: Whether the value is masked while being entered.
    """

    id: str
    description: str
    password: bool = False


@dataclass(frozen=True, slots=True)
class McpSandboxSpec:
    """Confinement applied to a local server process on Windows.

    What each field actually enforces is set out in
    :mod:`intellicrack.mcp.sandbox_launch`.

    Attributes:
        enabled: Whether the child is created suspended inside a job object,
            with a restricted Low integrity token and an allowlisted
            environment, before it runs.
        allow_write: Absolute directories the child may create files and
            folders in. For as long as the server runs each one carries a
            Low mandatory label that new content inherits; the label is
            removed again when the server stops. Everything the operator
            owns outside them stays unwritable to the child, apart from
            locations Windows itself labels Low such as ``AppData/LocalLow``.
            Reads are not restricted.
        allowed_domains: Hostnames the operator expects the child to reach.
            Recorded and logged only: it is not enforced, and a sandboxed
            server can still connect to any host.
        inherit_env: Names of further variables from Intellicrack's own
            environment the child keeps, beyond the fixed allowlist in
            :mod:`intellicrack.mcp.sandbox_launch`. Nothing is inherited by
            default that could carry a credential; a name listed here is the
            operator's deliberate choice.
        write_existing: Whether files and folders already inside the
            ``allow_write`` directories may be changed too. Off by default,
            so a server can add to a directory without being able to alter
            what was there before it started; either way every label is
            reverted when the server stops.
    """

    enabled: bool = False
    allow_write: tuple[str, ...] = ()
    allowed_domains: tuple[str, ...] = ()
    inherit_env: tuple[str, ...] = ()
    write_existing: bool = False


_DEFAULT_SANDBOX: Final[McpSandboxSpec] = McpSandboxSpec()


def sandbox_limitations(sandbox: McpSandboxSpec) -> tuple[str, ...]:
    """State plainly what a server's sandbox does not protect against.

    Args:
        sandbox: The server's sandbox settings.

    Returns:
        tuple[str, ...]: One sentence per limitation, empty when the sandbox
        is disabled and so claims nothing.
    """
    if not sandbox.enabled:
        return ()
    network = "Network access is not restricted: the server can connect to any host."
    if sandbox.allowed_domains:
        listed = ", ".join(sandbox.allowed_domains)
        network = f"Network access is not restricted: allowedDomains ({listed}) is recorded only and is not enforced."
    return (
        network,
        "Reads are not restricted: the server can read any file your account can read.",
        "Locations Windows labels low-integrity, such as AppData\\LocalLow, stay writable to the server.",
    )


_NPM_NOTE: Final[str] = (
    "npm keeps this server's packages and cache in the server's own sandbox home, so the first start downloads them again, and settings "
    "in your own .npmrc, such as a private registry or a proxy, are not seen. Add NPM_CONFIG_REGISTRY or HTTPS_PROXY under Extra "
    "inherited variables, or set them in the server's environment."
)
_NODE_NOTE: Final[str] = (
    "Node reports the server's sandbox home as its home and temporary directory. Files the server needs from your own profile must be "
    "passed to it by path, and a folder it writes to must be added under Writable folders."
)
_UV_NOTE: Final[str] = (
    "uv keeps its cache, its tools and any Python it downloads in the server's sandbox home, so the first start downloads them again, "
    "and a uv.toml in your own profile is not seen. Set UV_PYTHON in the server's environment to an installed interpreter to avoid "
    "downloading one."
)
_PIPX_NOTE: Final[str] = (
    "pipx installs into the server's sandbox home, so the first start downloads the package again, and pipx settings in your own "
    "profile are not seen."
)
_PYTHON_NOTE: Final[str] = (
    "Python can import what is already installed but cannot install into your own environment; pip installs go to the server's sandbox "
    "home. A virtual environment the server changes must be under Writable folders."
)
_DOCKER_NOTE: Final[str] = (
    "The container engine's pipe does not accept Low integrity clients, so a sandboxed container client cannot start containers. Turn "
    "this server's sandbox off and rely on the container's own isolation, or run the server without a container."
)

LAUNCHER_NOTES: Final[dict[str, tuple[str, ...]]] = {
    "npx": (_NPM_NOTE, _NODE_NOTE),
    "npm": (_NPM_NOTE, _NODE_NOTE),
    "pnpm": (_NODE_NOTE,),
    "node": (_NODE_NOTE,),
    "uvx": (_UV_NOTE,),
    "uv": (_UV_NOTE,),
    "pipx": (_PIPX_NOTE, _PYTHON_NOTE),
    "python": (_PYTHON_NOTE,),
    "py": (_PYTHON_NOTE,),
    "docker": (_DOCKER_NOTE,),
    "podman": (_DOCKER_NOTE,),
}
"""What a sandboxed server started by each common launcher needs the operator to know, keyed by the launcher's name."""

_LAUNCHER_SUFFIXES: Final[frozenset[str]] = frozenset({".exe", ".cmd", ".bat", ".ps1", ".com"})


def launcher_name(command: str) -> str:
    """Reduce a launch command to the name of the launcher it runs.

    Args:
        command: The configured command, a bare name or a path, with or without a suffix.

    Returns:
        str: The launcher's lower-case name, with a version such as the one in ``python3.13`` reduced to ``python``.
    """
    name = PureWindowsPath(command.strip().replace("/", "\\")).name.lower()
    stem, dot, suffix = name.rpartition(".")
    if dot and f".{suffix}" in _LAUNCHER_SUFFIXES:
        name = stem
    return re.sub(r"[\d.]+$", "", name) if name.startswith("python") else name


def launcher_notes(command: str) -> tuple[str, ...]:
    """State what a sandboxed server needs the operator to change or know, for the launcher that starts it.

    Args:
        command: The server's launch command.

    Returns:
        tuple[str, ...]: One sentence group per note, empty for a launcher with nothing to say.
    """
    return LAUNCHER_NOTES.get(launcher_name(command), ())


@dataclass(frozen=True, slots=True)
class McpServerConfig:
    """Everything needed to reach one configured server.

    Attributes:
        server_id: Identifier matching :data:`SERVER_ID_PATTERN`.
        kind: Transport the server is reached over.
        stdio: Launch description when ``kind`` is
            :attr:`McpTransportKind.STDIO`.
        http: Connection description when ``kind`` is
            :attr:`McpTransportKind.HTTP` or :attr:`McpTransportKind.SSE`.
        enabled: Whether the server participates at all. Off until the
            operator turns it on.
        disabled_tools: Tool names, as the server publishes them, that are
            withheld from the model even while the server is enabled.
        sandbox: Confinement applied to a local server process.
        request_timeout_s: Per-call timeout in seconds.
    """

    server_id: str
    kind: McpTransportKind
    stdio: StdioServerSpec | None = None
    http: HttpServerSpec | None = None
    enabled: bool = False
    disabled_tools: frozenset[str] = frozenset()
    sandbox: McpSandboxSpec = _DEFAULT_SANDBOX
    request_timeout_s: float = DEFAULT_REQUEST_TIMEOUT_S

    @property
    def namespace(self) -> str:
        """Tool namespace this server owns.

        Returns:
            str: ``mcp-<server_id>``.
        """
        return f"{NAMESPACE_PREFIX}{self.server_id}"

    @property
    def is_http(self) -> bool:
        """Whether the server is reached over HTTP rather than a child process.

        Returns:
            bool: ``True`` for the HTTP and SSE transports.
        """
        return self.kind in {McpTransportKind.HTTP, McpTransportKind.SSE}

    def validate(self) -> None:
        """Check every invariant the rest of the client relies on.

        Raises:
            McpConfigError: If the id is malformed, the transport block does
                not match the declared kind, a URL is not HTTP, the timeout
                is out of range, OAuth is configured on a local server, a
                sandbox write path is not absolute, or a literal credential
                was written into the file.
        """
        if not SERVER_ID_PATTERN.match(self.server_id):
            message = (
                f"invalid MCP server id {self.server_id!r}: ids must match "
                f"{SERVER_ID_PATTERN.pattern} (lower-case letters, digits and hyphens, at most 32 characters)"
            )
            raise McpConfigError(message)

        if not (0 < self.request_timeout_s <= MAX_REQUEST_TIMEOUT_S):
            message = f"server '{self.server_id}': request timeout must be greater than 0 and at most {MAX_REQUEST_TIMEOUT_S} seconds"
            raise McpConfigError(message)

        if self.kind is McpTransportKind.STDIO:
            self._validate_stdio()
        else:
            self._validate_http()

        for path in self.sandbox.allow_write:
            if not Path(path).is_absolute():
                message = f"server '{self.server_id}': sandbox write path {path!r} must be absolute"
                raise McpConfigError(message)

    def _validate_stdio(self) -> None:
        """Check the invariants specific to a local child-process server.

        Raises:
            McpConfigError: If the launch block is missing, an HTTP block is
                also present, the command is empty, or the environment or an
                argument holds a literal credential.
        """
        if self.stdio is None:
            message = f"server '{self.server_id}': transport is 'stdio' but no command was configured"
            raise McpConfigError(message)
        if self.http is not None:
            message = f"server '{self.server_id}': transport is 'stdio' but an HTTP endpoint was also configured"
            raise McpConfigError(message)
        if not self.stdio.command.strip():
            message = f"server '{self.server_id}': the launch command is empty"
            raise McpConfigError(message)
        _reject_literal_secrets(server_id=self.server_id, section="env", values=self.stdio.env)
        _reject_literal_secret_args(server_id=self.server_id, args=self.stdio.args)

    def _validate_http(self) -> None:
        """Check the invariants specific to a server reached over HTTP.

        Raises:
            McpConfigError: If the HTTP block is missing, a launch block is
                also present, the URL scheme is not HTTP, a CIMD URL is not
                HTTPS with a path, or a header or query value holds a
                literal credential.
        """
        if self.http is None:
            message = f"server '{self.server_id}': transport is '{self.kind.value}' but no URL was configured"
            raise McpConfigError(message)
        if self.stdio is not None:
            message = f"server '{self.server_id}': transport is '{self.kind.value}' but a launch command was also configured"
            raise McpConfigError(message)
        if not self.http.url.lower().startswith(("http://", "https://")):
            message = f"server '{self.server_id}': endpoint {self.http.url!r} must be an http:// or https:// URL"
            raise McpConfigError(message)
        metadata_url = self.http.oauth_metadata_url
        if metadata_url is not None and not _is_valid_metadata_url(metadata_url):
            message = f"server '{self.server_id}': OAuth metadata URL {metadata_url!r} must be an HTTPS URL with a non-root path"
            raise McpConfigError(message)
        _reject_literal_secrets(server_id=self.server_id, section="headers", values=self.http.headers)
        _reject_literal_secrets(server_id=self.server_id, section="query", values=self.http.query)

    def input_ids(self) -> tuple[str, ...]:
        """List every input id this server's values reference.

        Returns:
            tuple[str, ...]: Referenced ids in configuration order, without
            duplicates.
        """
        values: list[str] = []
        if self.stdio is not None:
            values.extend(self.stdio.args)
            values.extend(self.stdio.env.values())
        if self.http is not None:
            values.extend(self.http.headers.values())
            values.extend(self.http.query.values())
        seen: dict[str, None] = {}
        for value in values:
            for input_id in referenced_input_ids(value):
                seen.setdefault(input_id, None)
        return tuple(seen)


TOOL_NAME_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
"""Accepted shape of a tool name as the server publishes it.

Taken verbatim from the 2026-07-28 tools specification. A server's own name is used unchanged, dots included: the canonical name splits on
its first dot only, so every later dot stays part of the tool name and routes correctly.
"""


def to_canonical_name(server_id: str, tool_name: str) -> str:
    """Build the canonical dotted name one server tool is known by.

    Args:
        server_id: The server's configured id.
        tool_name: The tool name the server published, verbatim.

    Returns:
        str: ``mcp-<server_id>.<tool_name>``.
    """
    return f"{NAMESPACE_PREFIX}{server_id}.{tool_name}"


def from_canonical_name(canonical: str) -> tuple[str, str]:
    """Split a canonical MCP name back into its server id and tool name.

    Only the first dot separates the two halves, so a tool whose own name
    contains dots survives the round trip.

    Args:
        canonical: A canonical name produced by :func:`to_canonical_name`.

    Returns:
        tuple[str, str]: The server id and the server's own tool name.

    Raises:
        McpConfigError: If the name does not carry the MCP namespace prefix
            or has no tool component.
    """
    namespace, separator, tool_name = canonical.partition(".")
    if not separator or not namespace.startswith(NAMESPACE_PREFIX) or not tool_name:
        message = f"{canonical!r} is not a canonical MCP tool name (expected '{NAMESPACE_PREFIX}<serverId>.<toolName>')"
        raise McpConfigError(message)
    return namespace[len(NAMESPACE_PREFIX) :], tool_name


def is_mcp_namespace(namespace: str) -> bool:
    """Report whether a tool namespace belongs to an MCP server.

    Args:
        namespace: The namespace half of a canonical tool name.

    Returns:
        bool: ``True`` when the namespace carries the MCP prefix and a
        well-formed server id.
    """
    if not namespace.startswith(NAMESPACE_PREFIX):
        return False
    return bool(SERVER_ID_PATTERN.match(namespace[len(NAMESPACE_PREFIX) :]))


def _is_valid_metadata_url(url: str) -> bool:
    """Check a Client ID Metadata Document URL against the CIMD rule.

    Args:
        url: The candidate URL.

    Returns:
        bool: ``True`` when the URL is HTTPS with a non-root path.
    """
    if not url.lower().startswith("https://"):
        return False
    remainder = url[len("https://") :]
    _, separator, path = remainder.partition("/")
    return bool(separator) and bool(path.split("?", maxsplit=1)[0])


@dataclass(frozen=True, slots=True)
class McpRejectedServer:
    """A server entry left out of a document because it cannot be used.

    Attributes:
        key: The key the entry was stored under.
        reason: Why it was left out, naming the offending field.
        raw: The entry exactly as decoded.
        retained: Whether the entry is written back unchanged when the
            document is saved. Entries read from the configuration file are,
            so saving never deletes what the operator wrote; entries from an
            imported document are not, so a refused credential is never
            written into the file.
    """

    key: str
    reason: str
    raw: object
    retained: bool


@dataclass(frozen=True, slots=True)
class McpConfigDocument:
    """The parsed contents of ``mcp.json``.

    Attributes:
        servers: Configured servers, in file order.
        inputs: Declared inputs, in file order.
        rejected: Server entries that could not be used, each with its
            reason. One bad entry never costs the operator the others.
    """

    servers: tuple[McpServerConfig, ...] = ()
    inputs: tuple[McpInputSpec, ...] = ()
    rejected: tuple[McpRejectedServer, ...] = ()

    def server(self, server_id: str) -> McpServerConfig | None:
        """Look up one configured server by id.

        Args:
            server_id: The id to resolve.

        Returns:
            McpServerConfig | None: The server, or ``None`` when absent.
        """
        return next((server for server in self.servers if server.server_id == server_id), None)

    def input_spec(self, input_id: str) -> McpInputSpec | None:
        """Look up one declared input by id.

        Args:
            input_id: The id to resolve.

        Returns:
            McpInputSpec | None: The input, or ``None`` when absent.
        """
        return next((entry for entry in self.inputs if entry.id == input_id), None)

    def with_server(self, config: McpServerConfig) -> McpConfigDocument:
        """Return a copy with one server added or replaced.

        Args:
            config: The server to store.

        Returns:
            McpConfigDocument: The updated document.
        """
        replaced = tuple(config if existing.server_id == config.server_id else existing for existing in self.servers)
        if all(existing.server_id != config.server_id for existing in self.servers):
            replaced = (*self.servers, config)
        return replace(self, servers=replaced)

    def without_server(self, server_id: str) -> McpConfigDocument:
        """Return a copy with one server removed.

        Args:
            server_id: The id to remove.

        Returns:
            McpConfigDocument: The updated document.
        """
        return replace(self, servers=tuple(entry for entry in self.servers if entry.server_id != server_id))

    def with_input(self, spec: McpInputSpec) -> McpConfigDocument:
        """Return a copy with one input declaration added or replaced.

        Args:
            spec: The input declaration to store.

        Returns:
            McpConfigDocument: The updated document.
        """
        replaced = tuple(spec if existing.id == spec.id else existing for existing in self.inputs)
        if all(existing.id != spec.id for existing in self.inputs):
            replaced = (*self.inputs, spec)
        return replace(self, inputs=replaced)


def _require_object(value: object, message: str) -> JsonObject:
    """Narrow a JSON value to an object.

    Args:
        value: The decoded JSON value.
        message: Error text used when the value is not an object.

    Returns:
        JsonObject: The value as a mapping.

    Raises:
        McpConfigError: If the value is not a JSON object.
    """
    if not is_json_object(value):
        raise McpConfigError(message)
    return value


def _optional_str(data: Mapping[str, Any], key: str, *, server_id: str) -> str | None:
    """Read an optional string field.

    Args:
        data: The server entry.
        key: Field name to read.
        server_id: Server id used in the error message.

    Returns:
        str | None: The field value, or ``None`` when absent or null.

    Raises:
        McpConfigError: If the field is present but not a string.
    """
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        message = f"server '{server_id}': field '{key}' must be a string"
        raise McpConfigError(message)
    return value


def _str_sequence(data: Mapping[str, Any], key: str, *, server_id: str) -> tuple[str, ...]:
    """Read an optional array-of-strings field.

    Args:
        data: The server entry.
        key: Field name to read.
        server_id: Server id used in the error message.

    Returns:
        tuple[str, ...]: The field value, empty when absent.

    Raises:
        McpConfigError: If the field is present but is not an array of
            strings.
    """
    value = data.get(key)
    if value is None:
        return ()
    if not is_json_array(value) or any(not isinstance(item, str) for item in value):
        message = f"server '{server_id}': field '{key}' must be an array of strings"
        raise McpConfigError(message)
    return tuple(item for item in value if isinstance(item, str))


def _str_mapping(data: Mapping[str, Any], key: str, *, server_id: str) -> dict[str, str]:
    """Read an optional string-to-string object field.

    Args:
        data: The server entry.
        key: Field name to read.
        server_id: Server id used in the error message.

    Returns:
        dict[str, str]: The field value, empty when absent.

    Raises:
        McpConfigError: If the field is present but is not an object of
            string values.
    """
    entries: dict[str, str] = {}
    value = data.get(key)
    if value is None:
        return entries
    if not is_json_object(value):
        message = f"server '{server_id}': field '{key}' must be an object"
        raise McpConfigError(message)
    for name, item in value.items():
        if not isinstance(item, str):
            message = f"server '{server_id}': every entry of '{key}' must map a string name to a string value"
            raise McpConfigError(message)
        entries[name] = item
    return entries


def _optional_bool(data: Mapping[str, Any], key: str, *, server_id: str, default: bool) -> bool:
    """Read an optional boolean field.

    Args:
        data: The server entry.
        key: Field name to read.
        server_id: Server id used in the error message.
        default: Value used when the field is absent.

    Returns:
        bool: The field value.

    Raises:
        McpConfigError: If the field is present but not a boolean.
    """
    value = data.get(key)
    if value is None:
        return default
    if not isinstance(value, bool):
        message = f"server '{server_id}': field '{key}' must be true or false"
        raise McpConfigError(message)
    return value


def _optional_timeout(data: Mapping[str, Any], *, server_id: str) -> float:
    """Read the per-call timeout field.

    Args:
        data: The server entry.
        server_id: Server id used in the error message.

    Returns:
        float: The configured timeout, or the default when absent.

    Raises:
        McpConfigError: If the field is present but is not a number.
    """
    value = data.get("requestTimeout")
    if value is None:
        return DEFAULT_REQUEST_TIMEOUT_S
    if isinstance(value, bool) or not isinstance(value, int | float):
        message = f"server '{server_id}': field 'requestTimeout' must be a number of seconds"
        raise McpConfigError(message)
    return float(value)


def _parse_transport_kind(data: Mapping[str, Any], *, server_id: str) -> McpTransportKind:
    """Resolve the transport a server entry declares or implies.

    Args:
        data: The server entry.
        server_id: Server id used in the error message.

    Returns:
        McpTransportKind: The declared type, or the type implied by the
        presence of ``command`` or ``url``.

    Raises:
        McpConfigError: If the declared type is unknown, or no type is
            declared and neither ``command`` nor ``url`` is present.
    """
    declared = _optional_str(data, "type", server_id=server_id)
    if declared is not None:
        kind = _TRANSPORT_ALIASES.get(_TRANSPORT_SEPARATORS.sub("", declared.strip().lower()))
        if kind is None:
            supported = ", ".join(sorted(member.value for member in McpTransportKind))
            message = (
                f"server '{server_id}': {_ERR_UNKNOWN_TRANSPORT} {declared!r}; supported types are {supported} "
                f"(streamable-http and streamableHttp are read as http)"
            )
            raise McpConfigError(message)
        return kind
    if data.get("command") is not None:
        return McpTransportKind.STDIO
    if data.get("url") is not None:
        return McpTransportKind.HTTP
    message = f"server '{server_id}': {_ERR_NO_TRANSPORT}"
    raise McpConfigError(message)


def _parse_sandbox(data: Mapping[str, Any], *, server_id: str) -> McpSandboxSpec:
    """Parse the optional sandbox block of a server entry.

    Args:
        data: The server entry.
        server_id: Server id used in the error message.

    Returns:
        McpSandboxSpec: The parsed block, or the default when absent.

    Raises:
        McpConfigError: If the block is present but is not an object.
    """
    raw = data.get("sandbox")
    if raw is None:
        return _DEFAULT_SANDBOX
    if not is_json_object(raw):
        message = f"server '{server_id}': field 'sandbox' must be an object"
        raise McpConfigError(message)
    return McpSandboxSpec(
        enabled=_optional_bool(raw, "enabled", server_id=server_id, default=False),
        allow_write=_str_sequence(raw, "allowWrite", server_id=server_id),
        allowed_domains=_str_sequence(raw, "allowedDomains", server_id=server_id),
        inherit_env=_str_sequence(raw, "inheritEnv", server_id=server_id),
        write_existing=_optional_bool(raw, "writeExisting", server_id=server_id, default=False),
    )


def _parse_server(server_id: str, raw: object) -> McpServerConfig:
    """Parse one entry of the ``servers`` object.

    Args:
        server_id: The key the entry was stored under.
        raw: The decoded entry.

    Returns:
        McpServerConfig: The validated server configuration.

    Raises:
        McpConfigError: If the entry is malformed or fails validation.
    """
    data = _require_object(raw, f"server '{server_id}': {_ERR_SERVER_NOT_AN_OBJECT}")
    kind = _parse_transport_kind(data, server_id=server_id)

    stdio: StdioServerSpec | None = None
    http: HttpServerSpec | None = None
    if kind is McpTransportKind.STDIO:
        command = _optional_str(data, "command", server_id=server_id)
        if command is None:
            message = f"server '{server_id}': transport is 'stdio' but no 'command' was given"
            raise McpConfigError(message)
        stdio = StdioServerSpec(
            command=command,
            args=_str_sequence(data, "args", server_id=server_id),
            cwd=_optional_str(data, "cwd", server_id=server_id),
            env=_str_mapping(data, "env", server_id=server_id),
            env_file=_optional_str(data, "envFile", server_id=server_id),
        )
    else:
        url = _optional_str(data, "url", server_id=server_id)
        if url is None:
            message = f"server '{server_id}': transport is '{kind.value}' but no 'url' was given"
            raise McpConfigError(message)
        http = HttpServerSpec(
            url=url,
            headers=_str_mapping(data, "headers", server_id=server_id),
            query=_str_mapping(data, "query", server_id=server_id),
            oauth_client_id=_optional_str(data, "oauthClientId", server_id=server_id),
            oauth_metadata_url=_optional_str(data, "oauthMetadataUrl", server_id=server_id),
        )

    config = McpServerConfig(
        server_id=server_id,
        kind=kind,
        stdio=stdio,
        http=http,
        enabled=_optional_bool(data, "enabled", server_id=server_id, default=False),
        disabled_tools=frozenset(_str_sequence(data, "disabledTools", server_id=server_id)),
        sandbox=_parse_sandbox(data, server_id=server_id),
        request_timeout_s=_optional_timeout(data, server_id=server_id),
    )
    config.validate()
    return config


def _parse_servers(
    entries: Mapping[str, object],
    *,
    retain_rejected: bool,
) -> tuple[tuple[McpServerConfig, ...], tuple[McpRejectedServer, ...]]:
    """Parse every entry of the ``servers`` object, keeping the usable ones.

    Keys are brought to the id shape with :func:`normalize_server_id`. Two
    keys that normalize to the same id -- ``GitHub`` and ``github``, or two
    long keys alike in their first 32 characters -- are both kept, so neither
    is lost when the document is saved: a key that already is a valid id
    keeps it, and any other gets the next free numbered id from
    :func:`unique_server_id`. An entry that cannot be used
    -- its key has nothing to build an id from, or it fails validation -- is
    set aside with its reason rather than failing the whole document, and
    still holds its id, so a usable entry never takes the id it would be
    written back under.

    Args:
        entries: The decoded ``servers`` object.
        retain_rejected: Whether set-aside entries are written back on save.

    Returns:
        tuple[tuple[McpServerConfig, ...], tuple[McpRejectedServer, ...]]:
        The usable servers and the set-aside entries, both in file order.
    """
    servers: list[McpServerConfig] = []
    rejected: list[McpRejectedServer] = []
    taken: set[str] = set(entries)
    for key, raw in entries.items():
        normalized = normalize_server_id(key)
        if normalized is None:
            reason = f"invalid MCP server id {key!r}: it has no letter or digit to build an id from"
        else:
            server_id = normalized if normalized == key else unique_server_id(normalized, taken)
            taken.add(server_id)
            try:
                config = _parse_server(server_id, raw)
            except McpConfigError as exc:
                reason = exc.message if server_id == key else f"server key {key!r}: {exc.message}"
            else:
                servers.append(config)
                if server_id != key:
                    _logger.info("mcp_config_server_id_normalized", key=key, server_id=server_id)
                continue
        _logger.warning("mcp_config_server_rejected", key=key, reason=reason)
        rejected.append(McpRejectedServer(key=key, reason=reason, raw=raw, retained=retain_rejected))
    return tuple(servers), tuple(rejected)


def _parse_input(raw: object, index: int) -> McpInputSpec:
    """Parse one entry of the ``inputs`` array.

    Args:
        raw: The decoded entry.
        index: Position of the entry, used in the error message.

    Returns:
        McpInputSpec: The parsed input declaration.

    Raises:
        McpConfigError: If the entry is not an object, the id is missing or
            malformed, or a field has the wrong type.
    """
    data = _require_object(raw, f"inputs[{index}] must be a JSON object")
    raw_id = data.get("id")
    if not isinstance(raw_id, str) or not INPUT_ID_PATTERN.match(raw_id):
        message = f"inputs[{index}]: 'id' must be a string matching {INPUT_ID_PATTERN.pattern}"
        raise McpConfigError(message)
    description = data.get("description", "")
    if not isinstance(description, str):
        message = f"inputs[{index}]: 'description' must be a string"
        raise McpConfigError(message)
    password = data.get("password", False)
    if not isinstance(password, bool):
        message = f"inputs[{index}]: 'password' must be true or false"
        raise McpConfigError(message)
    return McpInputSpec(id=raw_id, description=description, password=password)


def _serialize_server(config: McpServerConfig) -> dict[str, Any]:
    """Render one server configuration back to its JSON shape.

    Only fields that differ from their default are written, so a document
    parsed from a minimal file is written back minimal.

    Args:
        config: The server to render.

    Returns:
        dict[str, Any]: The JSON object for this server.
    """
    data: dict[str, Any] = {"type": config.kind.value}
    if config.stdio is not None:
        data["command"] = config.stdio.command
        if config.stdio.args:
            data["args"] = list(config.stdio.args)
        if config.stdio.cwd is not None:
            data["cwd"] = config.stdio.cwd
        if config.stdio.env:
            data["env"] = dict(config.stdio.env)
        if config.stdio.env_file is not None:
            data["envFile"] = config.stdio.env_file
    if config.http is not None:
        data["url"] = config.http.url
        if config.http.headers:
            data["headers"] = dict(config.http.headers)
        if config.http.query:
            data["query"] = dict(config.http.query)
        if config.http.oauth_client_id is not None:
            data["oauthClientId"] = config.http.oauth_client_id
        if config.http.oauth_metadata_url is not None:
            data["oauthMetadataUrl"] = config.http.oauth_metadata_url
    if config.enabled:
        data["enabled"] = True
    if config.disabled_tools:
        data["disabledTools"] = sorted(config.disabled_tools)
    if config.sandbox != _DEFAULT_SANDBOX:
        sandbox: dict[str, Any] = {"enabled": config.sandbox.enabled}
        if config.sandbox.allow_write:
            sandbox["allowWrite"] = list(config.sandbox.allow_write)
        if config.sandbox.allowed_domains:
            sandbox["allowedDomains"] = list(config.sandbox.allowed_domains)
        if config.sandbox.inherit_env:
            sandbox["inheritEnv"] = list(config.sandbox.inherit_env)
        if config.sandbox.write_existing:
            sandbox["writeExisting"] = True
        data["sandbox"] = sandbox
    if config.request_timeout_s != DEFAULT_REQUEST_TIMEOUT_S:
        data["requestTimeout"] = config.request_timeout_s
    return data


def _decode_document(raw: str) -> JsonObject:
    """Decode configuration JSON text to its root object.

    Args:
        raw: The JSON text.

    Returns:
        JsonObject: The decoded root.

    Raises:
        McpConfigError: If the text is not valid JSON.
    """
    try:
        decoded: object = json.loads(raw)
    except json.JSONDecodeError as exc:
        message = f"invalid JSON in MCP configuration: {exc}"
        raise McpConfigError(message) from exc
    return _require_object(decoded, _ERR_NOT_AN_OBJECT)


class McpConfigStore:
    """Reads and writes ``mcp.json``.

    The store owns the file's location and its two accepted root shapes. It performs no I/O in its constructor, so a caller can build one to
    parse an imported document without touching the configured path.
    """

    def __init__(self, path: Path | None = None) -> None:
        """Initialize the store.

        Args:
            path: Configuration file to read and write. Defaults to
                ``<config_dir>/mcp.json``.
        """
        self._path = path if path is not None else get_config_file(MCP_CONFIG_FILENAME)

    @property
    def path(self) -> Path:
        """Location of the configuration file this store manages.

        Returns:
            Path: The configuration file path.
        """
        return self._path

    def load(self) -> McpConfigDocument:
        """Read and parse the configuration file.

        A missing file is an empty configuration rather than an error, which
        is the state every installation starts in.

        Returns:
            McpConfigDocument: The parsed document.

        Raises:
            McpConfigError: If the file cannot be read, is not valid JSON, or
                fails validation.
        """
        if not self._path.exists():
            _logger.debug("mcp_config_absent", path=str(self._path))
            return McpConfigDocument()
        try:
            raw = self._path.read_text(encoding="utf-8")
        except OSError as exc:
            message = f"cannot read {self._path}: {exc}"
            raise McpConfigError(message) from exc
        document = self.parse_document(_decode_document(raw), retain_rejected=True)
        _logger.info(
            "mcp_config_loaded",
            path=str(self._path),
            server_count=len(document.servers),
            input_count=len(document.inputs),
            rejected_count=len(document.rejected),
        )
        return document

    def save(self, document: McpConfigDocument) -> None:
        """Write a configuration document to disk.

        The file is written through a sibling temporary file and replaced
        atomically, so an interrupted write cannot leave a truncated
        configuration behind.

        Args:
            document: The document to persist.

        Raises:
            McpConfigError: If a server fails validation or the file cannot
                be written.
        """
        for server in document.servers:
            server.validate()
        payload = json.dumps(self.serialize_document(document), indent=2, sort_keys=False)
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self._path.with_name(f"{self._path.name}.tmp")
            _ = temporary.write_text(f"{payload}\n", encoding="utf-8")
            _ = temporary.replace(self._path)
        except OSError as exc:
            message = f"cannot write {self._path}: {exc}"
            raise McpConfigError(message) from exc
        _logger.info("mcp_config_saved", path=str(self._path), server_count=len(document.servers))

    def import_document(self, raw: str) -> McpConfigDocument:
        """Parse a configuration document from JSON text.

        Server entries that cannot be used are reported in
        :attr:`McpConfigDocument.rejected` and the rest are imported.

        Args:
            raw: JSON text in either the ``servers`` or ``mcpServers`` shape.

        Returns:
            McpConfigDocument: The parsed document.

        Raises:
            McpConfigError: If the text is not valid JSON, the decoded
                document fails validation, or it declares servers and not
                one of them can be used.
        """
        document = self.parse_document(_decode_document(raw))
        if document.rejected and not document.servers:
            reasons = "; ".join(entry.reason for entry in document.rejected)
            message = f"no server in the imported MCP configuration can be used: {reasons}"
            raise McpConfigError(message)
        return document

    @staticmethod
    def parse_document(data: Mapping[str, Any], *, retain_rejected: bool = False) -> McpConfigDocument:
        """Parse an already-decoded configuration document.

        Both accepted roots are normalized here: ``servers`` is the native
        shape and ``mcpServers`` is the shape other clients write. A document
        carrying both is refused rather than silently merged. A server entry
        that cannot be used is set aside in
        :attr:`McpConfigDocument.rejected` with its reason, and the others
        are kept.

        Args:
            data: The decoded configuration root.
            retain_rejected: Whether set-aside server entries are written
                back when the document is saved.

        Returns:
            McpConfigDocument: The parsed document.

        Raises:
            McpConfigError: If both roots are present, a root has the wrong
                type, or an input entry is malformed or repeats an id.
        """
        native = data.get("servers")
        legacy = data.get("mcpServers")
        if native is not None and legacy is not None:
            message = "MCP configuration declares both 'servers' and 'mcpServers'; keep one root"
            raise McpConfigError(message)
        raw_servers = native if native is not None else legacy
        servers: tuple[McpServerConfig, ...] = ()
        rejected: tuple[McpRejectedServer, ...] = ()
        if raw_servers is not None:
            entries = _require_object(raw_servers, _ERR_SERVERS_NOT_AN_OBJECT)
            servers, rejected = _parse_servers(entries, retain_rejected=retain_rejected)

        raw_inputs = data.get("inputs")
        inputs: tuple[McpInputSpec, ...] = ()
        if raw_inputs is not None:
            if not is_json_array(raw_inputs):
                raise McpConfigError(_ERR_INPUTS_NOT_AN_ARRAY)
            inputs = tuple(_parse_input(entry, index) for index, entry in enumerate(raw_inputs))
            seen: set[str] = set()
            for entry in inputs:
                if entry.id in seen:
                    message = f"{_ERR_DUPLICATE_INPUT} {entry.id!r}"
                    raise McpConfigError(message)
                seen.add(entry.id)

        return McpConfigDocument(servers=servers, inputs=inputs, rejected=rejected)

    @staticmethod
    def serialize_document(document: McpConfigDocument) -> dict[str, Any]:
        """Render a configuration document to its JSON shape.

        Set-aside server entries marked as retained are written back exactly
        as they were read. One whose key a usable server now holds -- the
        operator renamed a server onto it -- is written under the next free
        numbered key instead, so neither overwrites the other.

        Args:
            document: The document to render.

        Returns:
            dict[str, Any]: The JSON root, always in the native ``servers``
            shape.
        """
        servers: dict[str, Any] = {server.server_id: _serialize_server(server) for server in document.servers}
        for entry in document.rejected:
            if not entry.retained:
                continue
            key = entry.key
            if key in servers:
                key = unique_server_id(normalize_server_id(key) or "server", servers)
                _logger.warning("mcp_config_rejected_entry_rekeyed", key=entry.key, written_as=key)
            servers[key] = entry.raw
        data: dict[str, Any] = {"servers": servers}
        if document.inputs:
            data["inputs"] = [
                {"id": entry.id, "type": "promptString", "description": entry.description, "password": entry.password}
                for entry in document.inputs
            ]
        return data


def missing_input_ids(document: McpConfigDocument, servers: Sequence[McpServerConfig] | None = None) -> tuple[str, ...]:
    """List input ids referenced by servers but never declared.

    Args:
        document: The document whose ``inputs`` declarations are authoritative.
        servers: Servers to inspect, defaulting to every server in
            ``document``.

    Returns:
        tuple[str, ...]: Undeclared ids, in first-reference order.
    """
    declared = {entry.id for entry in document.inputs}
    missing: dict[str, None] = {}
    for server in document.servers if servers is None else servers:
        for input_id in server.input_ids():
            if input_id not in declared:
                missing.setdefault(input_id, None)
    return tuple(missing)
