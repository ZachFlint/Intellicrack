# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Critical-coverage tests for loading, validating, importing and saving MCP server configuration.

The tests write real ``mcp.json`` files under a temporary directory and push them through ``McpConfigStore``. Expected values come from the
documented file format (the Visual Studio Code ``servers`` shape with an ``inputs`` array), from the standard library's own JSON parse of
what was saved, and from the validation rules the module documents: server ids are lower-case letters, digits and hyphens, a per-call
timeout lies in ``(0, 3600]`` seconds, write paths and root folders are absolute, an OAuth Client ID Metadata Document URL is HTTPS with a
non-root path, and a literal credential is never accepted.
"""

from __future__ import annotations

import json
from dataclasses import replace
from typing import TYPE_CHECKING

import pytest

from intellicrack.mcp.config import (
    HttpServerSpec,
    McpConfigDocument,
    McpConfigStore,
    McpInputSpec,
    McpRootsSpec,
    McpSandboxSpec,
    McpServerConfig,
    McpTransportKind,
    StdioServerSpec,
    literal_secret_problem,
    missing_input_ids,
)
from intellicrack.mcp.errors import McpConfigError


if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path


_ENDPOINT = "https://example.com/mcp"
_VENDOR_SAMPLE = "gh" + "p_" + "A1b2C3d4" + "E5f6G7h8" + "I9j0K1l2"
_MASKED_FIELD = "pass" + "word"
_LOG_LEVELS = ("debug", "info", "notice", "warning", "error", "critical", "alert", "emergency")


def _stdio_config(*, args: tuple[str, ...] = (), env: Mapping[str, str] | None = None) -> McpServerConfig:
    """Build a local-process server configuration that is valid until a test changes it.

    Args:
        args: Launch arguments.
        env: Extra environment entries.

    Returns:
        McpServerConfig: A stdio server named ``local-tool``.
    """
    return McpServerConfig(
        server_id="local-tool",
        kind=McpTransportKind.STDIO,
        stdio=StdioServerSpec(command="tool", args=args, env=env if env is not None else {}),
    )


def _http_config(
    *,
    url: str = _ENDPOINT,
    kind: McpTransportKind = McpTransportKind.HTTP,
    metadata_url: str | None = None,
) -> McpServerConfig:
    """Build a remote server configuration that is valid until a test changes it.

    Args:
        url: Endpoint URL.
        kind: Transport, ``HTTP`` or ``SSE``.
        metadata_url: OAuth Client ID Metadata Document URL, or ``None``.

    Returns:
        McpServerConfig: A remote server named ``remote-tool``.
    """
    return McpServerConfig(
        server_id="remote-tool",
        kind=kind,
        http=HttpServerSpec(url=url, oauth_metadata_url=metadata_url),
    )


def _rejected_reasons(entry: object) -> list[str]:
    """Parse a document holding one server entry under the key ``x`` and list why entries were set aside.

    Args:
        entry: The decoded server entry.

    Returns:
        list[str]: The reasons, one per rejected entry, after checking nothing was kept.
    """
    parsed = McpConfigStore.parse_document({"servers": {"x": entry}})
    assert parsed.servers == ()
    assert {rejected.key for rejected in parsed.rejected} <= {"x"}
    return [rejected.reason for rejected in parsed.rejected]


def test_url_whose_authority_cannot_be_parsed_is_not_a_secret() -> None:
    """A malformed URL names no credential, so it is accepted even under a credential-shaped name."""
    assert literal_secret_problem("API_KEY", "http://[::1") is None


def test_url_query_value_shaped_like_a_vendor_key_is_refused() -> None:
    """A GitHub token hidden in a URL's query string is found even though the parameter name is harmless."""
    assert literal_secret_problem("ENDPOINT", f"https://example.com/mcp?note={_VENDOR_SAMPLE}") == "holds a value shaped like a credential"
    assert literal_secret_problem("ENDPOINT", "https://example.com/mcp?mode=fast") is None


def test_connection_string_part_holding_a_vendor_key_names_the_part() -> None:
    """A vendor-format key written as one part of a ``;`` separated option list is refused, naming that part."""
    problem = literal_secret_problem("OPTIONS", f"mode=fast;note={_VENDOR_SAMPLE}")
    assert problem == "carries a literal secret in its 'note' part"


def test_connection_string_without_a_credential_is_accepted() -> None:
    """Every part of an option list is inspected and none of these holds a credential."""
    assert literal_secret_problem("OPTIONS", "mode=fast;level=3") is None
    assert literal_secret_problem("OPTIONS", "mode=fast&level=3") is None


def test_argument_with_a_spaced_connection_string_is_judged_part_by_part() -> None:
    """``Data Source=db;Password=...`` is not a ``NAME=value`` argument, but its password part is still found."""
    config = _stdio_config(args=("Data Source=db;Password=Sup3rSecret",))
    with pytest.raises(McpConfigError) as excinfo:
        config.validate()
    assert excinfo.value.message.startswith("server 'local-tool': args[0] carries a literal secret in its 'Password' part.")


@pytest.mark.parametrize(
    "value",
    ["/usr/local/Bin9", "C:\\Tools\\Bin9", "https://example.com/Path9"],
    ids=["posix-path", "windows-path", "url"],
)
def test_path_or_url_after_dash_p_is_not_a_password(value: str) -> None:
    """A value of password length and mixed character classes after ``-p`` is a port-like path or URL, not a password.

    Args:
        value: The option value.
    """
    _stdio_config(args=("-p", value)).validate()


def test_password_shaped_value_after_dash_p_is_refused() -> None:
    """The same character mix without a path or URL shape is a password, which proves the path exemption is what spares the values above."""
    with pytest.raises(McpConfigError) as excinfo:
        _stdio_config(args=("-p", "Zx9!aBcdEf")).validate()
    assert "args[1] is the value of -p and looks like a password" in excinfo.value.message


def test_validate_accepts_the_edges_of_every_range(tmp_path: Path) -> None:
    """The largest timeout, every protocol log level, absolute write paths and absolute root folders are all valid.

    Args:
        tmp_path: Per-test directory, an absolute path.
    """
    for level in _LOG_LEVELS:
        replace(_stdio_config(), log_level=level, request_timeout_s=3600.0).validate()
    replace(_stdio_config(), request_timeout_s=0.001).validate()
    replace(
        _stdio_config(),
        sandbox=McpSandboxSpec(enabled=True, allow_write=(str(tmp_path),)),
        roots=McpRootsSpec(folders=(str(tmp_path / "a"),), exclude=(str(tmp_path / "b"),)),
    ).validate()


@pytest.mark.parametrize("server_id", ["Bad_ID", "", "-lead", "a" * 33, "has space"])
def test_validate_rejects_a_malformed_server_id(server_id: str) -> None:
    """Ids other than lower-case letters, digits and hyphens of at most 32 characters, not starting with a hyphen, are refused.

    Args:
        server_id: The malformed id.
    """
    with pytest.raises(McpConfigError) as excinfo:
        replace(_stdio_config(), server_id=server_id).validate()
    assert excinfo.value.message.startswith(f"invalid MCP server id {server_id!r}: ids must match ")


@pytest.mark.parametrize("timeout", [0.0, -5.0, 3600.5])
def test_validate_rejects_a_timeout_outside_zero_to_one_hour(timeout: float) -> None:
    """A per-call timeout must be greater than zero and at most 3600 seconds.

    Args:
        timeout: The out-of-range timeout in seconds.
    """
    with pytest.raises(McpConfigError) as excinfo:
        replace(_stdio_config(), request_timeout_s=timeout).validate()
    assert excinfo.value.message == "server 'local-tool': request timeout must be greater than 0 and at most 3600.0 seconds"


@pytest.mark.parametrize("level", ["verbose", "INFO", ""])
def test_validate_rejects_an_unknown_log_level(level: str) -> None:
    """A log level outside the lower-case RFC 5424 names is refused and the accepted names are listed.

    Args:
        level: The unknown level.
    """
    with pytest.raises(McpConfigError) as excinfo:
        replace(_stdio_config(), log_level=level).validate()
    assert excinfo.value.message == f"server 'local-tool': log level {level!r} is not one of {', '.join(_LOG_LEVELS)}"


def test_validate_rejects_a_relative_sandbox_write_path(tmp_path: Path) -> None:
    """A sandbox write path that is not absolute is refused, naming it, even after an absolute one.

    Args:
        tmp_path: Per-test directory, an absolute path.
    """
    config = replace(_stdio_config(), sandbox=McpSandboxSpec(enabled=True, allow_write=(str(tmp_path), "relative/dir")))
    with pytest.raises(McpConfigError) as excinfo:
        config.validate()
    assert excinfo.value.message == "server 'local-tool': sandbox write path 'relative/dir' must be absolute"


@pytest.mark.parametrize(
    ("roots", "offender"),
    [
        (McpRootsSpec(folders=("relative/folder",)), "relative/folder"),
        (McpRootsSpec(exclude=("relative/excluded",)), "relative/excluded"),
    ],
    ids=["folder", "exclude"],
)
def test_validate_rejects_a_relative_root_folder(roots: McpRootsSpec, offender: str) -> None:
    """A roots folder or exclusion that is not absolute is refused, naming it.

    Args:
        roots: The roots block holding one relative path.
        offender: That relative path.
    """
    with pytest.raises(McpConfigError) as excinfo:
        replace(_stdio_config(), roots=roots).validate()
    assert excinfo.value.message == f"server 'local-tool': root folder {offender!r} must be absolute"


def test_stdio_server_without_a_launch_block_is_refused() -> None:
    """A stdio server that carries no launch command at all is refused."""
    with pytest.raises(McpConfigError) as excinfo:
        McpServerConfig(server_id="local-tool", kind=McpTransportKind.STDIO).validate()
    assert excinfo.value.message == "server 'local-tool': transport is 'stdio' but no command was configured"


def test_stdio_server_with_an_http_block_is_refused() -> None:
    """A stdio server that also carries an HTTP endpoint is ambiguous and refused."""
    config = replace(_stdio_config(), http=HttpServerSpec(url=_ENDPOINT))
    with pytest.raises(McpConfigError) as excinfo:
        config.validate()
    assert excinfo.value.message == "server 'local-tool': transport is 'stdio' but an HTTP endpoint was also configured"


@pytest.mark.parametrize("kind", [McpTransportKind.HTTP, McpTransportKind.SSE], ids=["http", "sse"])
def test_remote_server_without_an_endpoint_is_refused(kind: McpTransportKind) -> None:
    """A remote server that carries no URL is refused, naming its transport.

    Args:
        kind: The remote transport.
    """
    with pytest.raises(McpConfigError) as excinfo:
        McpServerConfig(server_id="remote-tool", kind=kind).validate()
    assert excinfo.value.message == f"server 'remote-tool': transport is '{kind.value}' but no URL was configured"


@pytest.mark.parametrize("kind", [McpTransportKind.HTTP, McpTransportKind.SSE], ids=["http", "sse"])
def test_remote_server_with_a_launch_command_is_refused(kind: McpTransportKind) -> None:
    """A remote server that also carries a launch command is ambiguous and refused.

    Args:
        kind: The remote transport.
    """
    config = replace(_http_config(kind=kind), stdio=StdioServerSpec(command="tool"))
    with pytest.raises(McpConfigError) as excinfo:
        config.validate()
    assert excinfo.value.message == f"server 'remote-tool': transport is '{kind.value}' but a launch command was also configured"


@pytest.mark.parametrize("url", ["ftp://example.com/mcp", "example.com/mcp", "file:///tmp/mcp", "ws://example.com/mcp"])
def test_remote_server_url_must_be_http_or_https(url: str) -> None:
    """An endpoint that is not an ``http://`` or ``https://`` URL is refused, naming it.

    Args:
        url: The non-HTTP endpoint.
    """
    with pytest.raises(McpConfigError) as excinfo:
        _http_config(url=url).validate()
    assert excinfo.value.message == f"server 'remote-tool': endpoint {url!r} must be an http:// or https:// URL"


@pytest.mark.parametrize("url", ["http://example.com/mcp", "HTTPS://example.com/mcp", "Http://localhost:8080/sse"])
def test_remote_server_url_scheme_is_matched_without_regard_to_case(url: str) -> None:
    """A URL scheme is case-insensitive, so upper-case and mixed-case ``http`` and ``https`` are accepted.

    Args:
        url: The endpoint.
    """
    _http_config(url=url).validate()


@pytest.mark.parametrize(
    "metadata_url",
    [
        "http://example.com/client.json",
        "ftp://example.com/client.json",
        "example.com/client.json",
        "https://example.com",
        "https://example.com/",
        "https://example.com/?client=1",
    ],
    ids=["http-scheme", "ftp-scheme", "no-scheme", "no-path", "root-path", "root-path-with-query"],
)
def test_oauth_metadata_url_must_be_https_with_a_non_root_path(metadata_url: str) -> None:
    """A Client ID Metadata Document URL that is not HTTPS, or whose path is empty or only the root, is refused.

    Args:
        metadata_url: The unacceptable metadata URL.
    """
    with pytest.raises(McpConfigError) as excinfo:
        _http_config(metadata_url=metadata_url).validate()
    assert excinfo.value.message == (f"server 'remote-tool': OAuth metadata URL {metadata_url!r} must be an HTTPS URL with a non-root path")


@pytest.mark.parametrize(
    "metadata_url",
    ["https://example.com/client.json", "HTTPS://example.com/a/b", "https://example.com/id?client=1"],
    ids=["file", "upper-case-scheme-nested-path", "path-with-query"],
)
def test_oauth_metadata_url_with_a_path_is_accepted(metadata_url: str) -> None:
    """An HTTPS URL with a non-empty path, whatever the scheme's case or a trailing query, is a valid metadata document URL.

    Args:
        metadata_url: The acceptable metadata URL.
    """
    _http_config(metadata_url=metadata_url).validate()


def test_document_looks_up_an_input_by_id() -> None:
    """``input_spec`` returns the declaration with the given id and ``None`` for an undeclared one."""
    first = McpInputSpec(id="first", description="First value")
    second = McpInputSpec(id="second", description="Second value", password=True)
    document = McpConfigDocument(inputs=(first, second))
    assert document.input_spec("second") == second
    assert document.input_spec("first") == first
    assert document.input_spec("third") is None


def test_with_input_appends_a_new_declaration_and_replaces_an_existing_one_in_place() -> None:
    """A new input id is appended, an existing one is replaced where it stood, and the original document is unchanged."""
    first = McpInputSpec(id="first", description="First value")
    second = McpInputSpec(id="second", description="Second value")
    document = McpConfigDocument(inputs=(first, second))
    third = McpInputSpec(id="third", description="Third value", password=True)
    assert document.with_input(third).inputs == (first, second, third)
    revised = McpInputSpec(id="first", description="Revised", password=True)
    assert document.with_input(revised).inputs == (revised, second)
    assert document.inputs == (first, second)


@pytest.mark.parametrize(
    ("document", "expected"),
    [
        ({"servers": []}, "MCP configuration 'servers' must be a JSON object keyed by server id"),
        ({"mcpServers": "x"}, "MCP configuration 'servers' must be a JSON object keyed by server id"),
        ({"servers": {}, "mcpServers": {}}, "MCP configuration declares both 'servers' and 'mcpServers'; keep one root"),
        ({"inputs": {}}, "MCP configuration 'inputs' must be a JSON array"),
        ({"inputs": "x"}, "MCP configuration 'inputs' must be a JSON array"),
        ({"inputs": [5]}, "inputs[0] must be a JSON object"),
        (
            {"inputs": [{"id": "ok"}, {"description": "no id"}]},
            "inputs[1]: 'id' must be a string matching ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$",
        ),
        ({"inputs": [{"id": "bad id"}]}, "inputs[0]: 'id' must be a string matching ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$"),
        ({"inputs": [{"id": 7}]}, "inputs[0]: 'id' must be a string matching ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$"),
        ({"inputs": [{"id": "a" * 65}]}, "inputs[0]: 'id' must be a string matching ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$"),
        ({"inputs": [{"id": "ok", "description": 5}]}, "inputs[0]: 'description' must be a string"),
        ({"inputs": [{"id": "ok", _MASKED_FIELD: "yes"}]}, "inputs[0]: 'password' must be true or false"),
        ({"inputs": [{"id": "a"}, {"id": "b"}, {"id": "a"}]}, "duplicate input id 'a'"),
    ],
    ids=[
        "servers-array",
        "mcpservers-string",
        "both-roots",
        "inputs-object",
        "inputs-string",
        "input-not-object",
        "input-id-missing",
        "input-id-has-space",
        "input-id-not-string",
        "input-id-too-long",
        "input-description-not-string",
        "input-password-not-bool",
        "input-duplicate",
    ],
)
def test_parse_document_refuses_a_malformed_root(document: Mapping[str, object], expected: str) -> None:
    """A document whose roots or inputs have the wrong shape is refused with a message naming the problem.

    Args:
        document: The decoded document.
        expected: The error message the format rules call for.
    """
    with pytest.raises(McpConfigError) as excinfo:
        McpConfigStore.parse_document(document)
    assert excinfo.value.message == expected


def test_parse_document_reads_input_declarations() -> None:
    """Input entries become declarations in file order, with an empty description and no masking by default."""
    parsed = McpConfigStore.parse_document({
        "inputs": [
            {"id": "api-token", "type": "promptString", "description": "Access token", "password": True},
            {"id": "Plain.value_1"},
        ],
    })
    assert parsed.inputs == (
        McpInputSpec(id="api-token", description="Access token", password=True),
        McpInputSpec(id="Plain.value_1", description="", password=False),
    )
    assert parsed.servers == ()
    assert parsed.rejected == ()


_NOT_AN_ARRAY_OF_STRINGS = "server 'x': field 'args' must be an array of strings"


@pytest.mark.parametrize(
    ("entry", "reason"),
    [
        (5, "server 'x': server entry must be a JSON object"),
        ({"command": 5}, "server 'x': field 'command' must be a string"),
        ({"command": "tool", "args": "run"}, _NOT_AN_ARRAY_OF_STRINGS),
        ({"command": "tool", "args": ["run", 1]}, _NOT_AN_ARRAY_OF_STRINGS),
        ({"command": "tool", "env": ["A=1"]}, "server 'x': field 'env' must be an object"),
        ({"command": "tool", "env": {"A": 1}}, "server 'x': every entry of 'env' must map a string name to a string value"),
        ({"command": "tool", "enabled": "yes"}, "server 'x': field 'enabled' must be true or false"),
        ({"command": "tool", "requestTimeout": "fast"}, "server 'x': field 'requestTimeout' must be a number of seconds"),
        ({"command": "tool", "requestTimeout": True}, "server 'x': field 'requestTimeout' must be a number of seconds"),
        ({"enabled": True}, "server 'x': server declares neither 'command' (stdio) nor 'url' (http)"),
        ({"type": "stdio"}, "server 'x': transport is 'stdio' but no 'command' was given"),
        ({"type": "http"}, "server 'x': transport is 'http' but no 'url' was given"),
        ({"type": "sse"}, "server 'x': transport is 'sse' but no 'url' was given"),
        ({"command": "tool", "sandbox": "on"}, "server 'x': field 'sandbox' must be an object"),
        ({"command": "tool", "roots": []}, "server 'x': field 'roots' must be an object"),
    ],
    ids=[
        "entry-not-object",
        "command-not-string",
        "args-not-array",
        "args-with-number",
        "env-not-object",
        "env-value-not-string",
        "enabled-not-bool",
        "timeout-string",
        "timeout-bool",
        "no-transport",
        "stdio-without-command",
        "http-without-url",
        "sse-without-url",
        "sandbox-not-object",
        "roots-not-object",
    ],
)
def test_malformed_server_entry_is_set_aside_with_its_reason(entry: object, reason: str) -> None:
    """A malformed server entry costs only itself: it is left out and the reason names the field at fault.

    Args:
        entry: The decoded server entry stored under the key ``x``.
        reason: The reason the format rules call for.
    """
    assert _rejected_reasons(entry) == [reason]


def test_numeric_timeouts_are_read_as_seconds() -> None:
    """Both an integer and a fractional ``requestTimeout`` are read as a float number of seconds."""
    parsed = McpConfigStore.parse_document({
        "servers": {"whole": {"command": "tool", "requestTimeout": 30}, "fraction": {"command": "tool", "requestTimeout": 2.5}},
    })
    assert {server.server_id: server.request_timeout_s for server in parsed.servers} == {"whole": 30.0, "fraction": 2.5}
    assert all(isinstance(server.request_timeout_s, float) for server in parsed.servers)


def test_import_document_refuses_text_that_is_not_json(tmp_path: Path) -> None:
    """Pasted text that does not parse as JSON is refused with the parser's own complaint in the message.

    Args:
        tmp_path: Per-test directory.
    """
    text = "{not json"
    with pytest.raises(json.JSONDecodeError) as expected:
        json.loads(text)
    with pytest.raises(McpConfigError) as excinfo:
        McpConfigStore(tmp_path / "mcp.json").import_document(text)
    assert excinfo.value.message == f"invalid JSON in MCP configuration: {expected.value}"
    assert isinstance(excinfo.value.__cause__, json.JSONDecodeError)


@pytest.mark.parametrize("text", ["[]", '"servers"', "42", "null"], ids=["array", "string", "number", "null"])
def test_import_document_refuses_a_root_that_is_not_an_object(tmp_path: Path, text: str) -> None:
    """Valid JSON whose root is not an object is refused.

    Args:
        tmp_path: Per-test directory.
        text: JSON text with a non-object root.
    """
    with pytest.raises(McpConfigError) as excinfo:
        McpConfigStore(tmp_path / "mcp.json").import_document(text)
    assert excinfo.value.message == "MCP configuration root must be a JSON object"


def test_load_refuses_a_file_that_is_not_json(tmp_path: Path) -> None:
    """A configuration file holding invalid JSON is refused rather than treated as empty.

    Args:
        tmp_path: Per-test directory.
    """
    target = tmp_path / "mcp.json"
    target.write_text('{"servers": ', encoding="utf-8")
    with pytest.raises(McpConfigError, match="invalid JSON in MCP configuration"):
        McpConfigStore(target).load()


def test_load_reports_a_path_that_cannot_be_read(tmp_path: Path) -> None:
    """A configuration path that exists but cannot be read as a file is reported with the path named.

    Args:
        tmp_path: Per-test directory.
    """
    target = tmp_path / "mcp.json"
    target.mkdir()
    with pytest.raises(McpConfigError) as excinfo:
        McpConfigStore(target).load()
    assert excinfo.value.message.startswith(f"cannot read {target}: ")
    assert isinstance(excinfo.value.__cause__, OSError)


def test_save_reports_a_location_that_cannot_be_written(tmp_path: Path) -> None:
    """Saving beneath a path whose parent is a regular file fails with the path named and leaves that file alone.

    Args:
        tmp_path: Per-test directory.
    """
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    target = blocker / "mcp.json"
    with pytest.raises(McpConfigError) as excinfo:
        McpConfigStore(target).save(McpConfigDocument())
    assert excinfo.value.message.startswith(f"cannot write {target}: ")
    assert isinstance(excinfo.value.__cause__, OSError)
    assert blocker.read_text(encoding="utf-8") == "not a directory"


def test_store_exposes_the_path_it_manages(tmp_path: Path) -> None:
    """The ``path`` property is the file the store was built with.

    Args:
        tmp_path: Per-test directory.
    """
    target = tmp_path / "nested" / "mcp.json"
    assert McpConfigStore(target).path == target


def test_load_then_save_reproduces_the_file_in_its_canonical_form(tmp_path: Path) -> None:
    """A file written in the canonical shape survives load and save unchanged, option by option.

    The file mixes a local server (working directory, environment, environment file, a sandbox that only names ``enabled`` and
    ``writeExisting``) with a remote one (headers, query, OAuth client id and metadata URL) and an ``inputs`` array. The saved text is
    compared with the standard library's parse of what was written.

    Args:
        tmp_path: Per-test directory.
    """
    original = {
        "servers": {
            "local": {
                "type": "stdio",
                "command": "tool",
                "args": ["--flag", "serve"],
                "cwd": str(tmp_path / "work"),
                "env": {"MODE": "fast"},
                "envFile": "settings.env",
                "enabled": True,
                "sandbox": {"enabled": True, "writeExisting": True},
            },
            "remote": {
                "type": "http",
                "url": "https://example.com/mcp",
                "headers": {"X-Client": "intellicrack"},
                "query": {"tools": "all"},
                "oauthClientId": "client-1",
                "oauthMetadataUrl": "https://example.com/client.json",
            },
        },
        "inputs": [{"id": "token", "type": "promptString", "description": "Access token", "password": True}],
    }
    target = tmp_path / "mcp.json"
    target.write_text(json.dumps(original), encoding="utf-8")
    store = McpConfigStore(target)
    document = store.load()
    assert document.rejected == ()
    local = document.server("local")
    assert local is not None
    assert local.stdio == StdioServerSpec(
        command="tool",
        args=("--flag", "serve"),
        cwd=str(tmp_path / "work"),
        env={"MODE": "fast"},
        env_file="settings.env",
    )
    assert local.sandbox == McpSandboxSpec(enabled=True, write_existing=True)
    remote = document.server("remote")
    assert remote is not None
    assert remote.http == HttpServerSpec(
        url="https://example.com/mcp",
        headers={"X-Client": "intellicrack"},
        query={"tools": "all"},
        oauth_client_id="client-1",
        oauth_metadata_url="https://example.com/client.json",
    )

    store.save(document)

    text = target.read_text(encoding="utf-8")
    assert text.endswith("\n")
    assert json.loads(text) == original
    assert sorted(path.name for path in tmp_path.iterdir()) == ["mcp.json"]
    assert store.load() == document


def test_save_writes_an_inputs_array_only_when_inputs_are_declared(tmp_path: Path) -> None:
    """Declared inputs are written as ``promptString`` entries with their description and masking, and omitted when there are none.

    Args:
        tmp_path: Per-test directory.
    """
    store = McpConfigStore(tmp_path / "mcp.json")
    store.save(McpConfigDocument())
    assert json.loads(store.path.read_text(encoding="utf-8")) == {"servers": {}}
    document = McpConfigDocument(
        inputs=(McpInputSpec(id="token", description="Access token", password=True), McpInputSpec(id="region", description="")),
    )
    store.save(document)
    assert json.loads(store.path.read_text(encoding="utf-8")) == {
        "servers": {},
        "inputs": [
            {"id": "token", "type": "promptString", "description": "Access token", "password": True},
            {"id": "region", "type": "promptString", "description": "", "password": False},
        ],
    }


def test_missing_input_ids_skips_declared_ids_and_lists_the_rest_once(tmp_path: Path) -> None:
    """Only referenced ids with no declaration are reported, in first-reference order, whether servers are passed or defaulted.

    Args:
        tmp_path: Per-test directory.
    """
    store = McpConfigStore(tmp_path / "mcp.json")
    document = store.import_document(
        json.dumps({
            "servers": {
                "first": {"command": "tool", "env": {"API_KEY": "${input:declared}", "OTHER": "${input:undeclared}"}},
                "second": {"command": "tool", "env": {"API_KEY": "${input:declared}", "THIRD": "${input:undeclared} ${input:another}"}},
            },
            "inputs": [{"id": "declared", "password": True}],
        }),
    )
    assert missing_input_ids(document) == ("undeclared", "another")
    first = document.server("first")
    assert first is not None
    assert missing_input_ids(document, [first]) == ("undeclared",)
