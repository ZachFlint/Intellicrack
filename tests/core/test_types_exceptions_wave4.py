# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Exact-contract gates for the ProviderError and ToolError exception families.

Each test asserts a specific issubclass relationship, an exact attribute value,
or an exact isinstance/catching behaviour documented by the types module contract.
Every gate goes RED when the corresponding production class definition is mutated
to break the checked property.  Gates cover ModelNotFoundError, ToolNotFoundError,
and InitializationError which have no coverage in existing test files, plus deeper
attribute and cross-family isolation contracts for the full hierarchy.
"""

from __future__ import annotations

import math

from intellicrack.core.types import (
    AttachError,
    AuthenticationError,
    InitializationError,
    IntellicrackError,
    ModelNotFoundError,
    ProviderError,
    RateLimitError,
    ToolError,
    ToolNotFoundError,
)


class TestProviderFamilyIssubclassChain:
    """Exact issubclass relationships for the provider exception family.

    Oracle: Python language MRO guarantees; class hierarchy in types.py.
    Mutation caught: changing any base class in the provider family breaks the
    corresponding issubclass assertion.
    """

    def test_provider_error_direct_subclass_of_intellicrack_error(self) -> None:
        """ProviderError is a direct subclass of IntellicrackError."""
        assert issubclass(ProviderError, IntellicrackError)

    def test_provider_error_transitive_subclass_of_exception(self) -> None:
        """ProviderError is a transitive subclass of the built-in Exception."""
        assert issubclass(ProviderError, Exception)

    def test_authentication_error_direct_subclass_of_provider_error(self) -> None:
        """AuthenticationError is a direct subclass of ProviderError."""
        assert issubclass(AuthenticationError, ProviderError)

    def test_authentication_error_transitive_subclass_of_intellicrack_error(self) -> None:
        """AuthenticationError is a transitive subclass of IntellicrackError."""
        assert issubclass(AuthenticationError, IntellicrackError)

    def test_rate_limit_error_direct_subclass_of_provider_error(self) -> None:
        """RateLimitError is a direct subclass of ProviderError."""
        assert issubclass(RateLimitError, ProviderError)

    def test_rate_limit_error_transitive_subclass_of_intellicrack_error(self) -> None:
        """RateLimitError is a transitive subclass of IntellicrackError."""
        assert issubclass(RateLimitError, IntellicrackError)

    def test_model_not_found_error_direct_subclass_of_provider_error(self) -> None:
        """ModelNotFoundError is a direct subclass of ProviderError."""
        assert issubclass(ModelNotFoundError, ProviderError)

    def test_model_not_found_error_transitive_subclass_of_intellicrack_error(self) -> None:
        """ModelNotFoundError is a transitive subclass of IntellicrackError."""
        assert issubclass(ModelNotFoundError, IntellicrackError)

    def test_model_not_found_error_transitive_subclass_of_exception(self) -> None:
        """ModelNotFoundError is a transitive subclass of the built-in Exception."""
        assert issubclass(ModelNotFoundError, Exception)


class TestToolFamilyIssubclassChain:
    """Exact issubclass relationships for the tool exception family.

    Oracle: Python language MRO guarantees; class hierarchy in types.py.
    Mutation caught: changing any base class in the tool family breaks the
    corresponding issubclass assertion.
    """

    def test_tool_error_direct_subclass_of_intellicrack_error(self) -> None:
        """ToolError is a direct subclass of IntellicrackError."""
        assert issubclass(ToolError, IntellicrackError)

    def test_tool_error_transitive_subclass_of_exception(self) -> None:
        """ToolError is a transitive subclass of the built-in Exception."""
        assert issubclass(ToolError, Exception)

    def test_tool_not_found_error_direct_subclass_of_tool_error(self) -> None:
        """ToolNotFoundError is a direct subclass of ToolError."""
        assert issubclass(ToolNotFoundError, ToolError)

    def test_tool_not_found_error_transitive_subclass_of_intellicrack_error(self) -> None:
        """ToolNotFoundError is a transitive subclass of IntellicrackError."""
        assert issubclass(ToolNotFoundError, IntellicrackError)

    def test_initialization_error_direct_subclass_of_tool_error(self) -> None:
        """InitializationError is a direct subclass of ToolError."""
        assert issubclass(InitializationError, ToolError)

    def test_initialization_error_transitive_subclass_of_intellicrack_error(self) -> None:
        """InitializationError is a transitive subclass of IntellicrackError."""
        assert issubclass(InitializationError, IntellicrackError)

    def test_attach_error_direct_subclass_of_tool_error(self) -> None:
        """AttachError is a direct subclass of ToolError."""
        assert issubclass(AttachError, ToolError)

    def test_attach_error_transitive_subclass_of_intellicrack_error(self) -> None:
        """AttachError is a transitive subclass of IntellicrackError."""
        assert issubclass(AttachError, IntellicrackError)


class TestCrossFamilyIsolation:
    """Provider and tool families must not cross-inherit.

    Oracle: distinct family roots (ProviderError, ToolError) each inherit from
    IntellicrackError independently; there is no cross link.
    Mutation caught: making any provider subclass inherit from ToolError (or
    vice-versa) would satisfy one of these negated issubclass checks.
    """

    def test_provider_error_not_subclass_of_tool_error(self) -> None:
        """ProviderError is not a subclass of ToolError."""
        assert not issubclass(ProviderError, ToolError)

    def test_tool_error_not_subclass_of_provider_error(self) -> None:
        """ToolError is not a subclass of ProviderError."""
        assert not issubclass(ToolError, ProviderError)

    def test_authentication_error_not_subclass_of_tool_error(self) -> None:
        """AuthenticationError is not a subclass of ToolError."""
        assert not issubclass(AuthenticationError, ToolError)

    def test_rate_limit_error_not_subclass_of_tool_error(self) -> None:
        """RateLimitError is not a subclass of ToolError."""
        assert not issubclass(RateLimitError, ToolError)

    def test_model_not_found_error_not_subclass_of_tool_error(self) -> None:
        """ModelNotFoundError is not a subclass of ToolError."""
        assert not issubclass(ModelNotFoundError, ToolError)

    def test_tool_not_found_error_not_subclass_of_provider_error(self) -> None:
        """ToolNotFoundError is not a subclass of ProviderError."""
        assert not issubclass(ToolNotFoundError, ProviderError)

    def test_initialization_error_not_subclass_of_provider_error(self) -> None:
        """InitializationError is not a subclass of ProviderError."""
        assert not issubclass(InitializationError, ProviderError)

    def test_attach_error_not_subclass_of_provider_error(self) -> None:
        """AttachError is not a subclass of ProviderError."""
        assert not issubclass(AttachError, ProviderError)


class TestInstanceAndCatchingContract:
    """isinstance checks verify the catching contract for all exception classes.

    Oracle: Python's except clause uses isinstance() internally (language spec,
    CPython ceval.c exception_matches).  issubclass(A, B) True iff isinstance(A(), B)
    True.  These tests verify the instance side of that guarantee.
    Mutation caught: changing a class's base class would break the isinstance check
    for both the positive and the negative (cross-family) cases.
    """

    def test_authentication_error_instance_is_provider_error(self) -> None:
        """AuthenticationError instance satisfies isinstance(err, ProviderError)."""
        err = AuthenticationError("bad api key")
        assert isinstance(err, ProviderError)

    def test_authentication_error_instance_is_intellicrack_error(self) -> None:
        """AuthenticationError instance satisfies isinstance(err, IntellicrackError)."""
        err = AuthenticationError("bad api key")
        assert isinstance(err, IntellicrackError)

    def test_rate_limit_error_instance_is_provider_error(self) -> None:
        """RateLimitError instance satisfies isinstance(err, ProviderError)."""
        err = RateLimitError("rate limited")
        assert isinstance(err, ProviderError)

    def test_rate_limit_error_instance_is_intellicrack_error(self) -> None:
        """RateLimitError instance satisfies isinstance(err, IntellicrackError)."""
        err = RateLimitError("rate limited")
        assert isinstance(err, IntellicrackError)

    def test_model_not_found_error_instance_is_provider_error(self) -> None:
        """ModelNotFoundError instance satisfies isinstance(err, ProviderError)."""
        err = ModelNotFoundError("model unavailable")
        assert isinstance(err, ProviderError)

    def test_model_not_found_error_instance_is_intellicrack_error(self) -> None:
        """ModelNotFoundError instance satisfies isinstance(err, IntellicrackError)."""
        err = ModelNotFoundError("model unavailable")
        assert isinstance(err, IntellicrackError)

    def test_tool_not_found_error_instance_is_tool_error(self) -> None:
        """ToolNotFoundError instance satisfies isinstance(err, ToolError)."""
        err = ToolNotFoundError("ghidra not found")
        assert isinstance(err, ToolError)

    def test_tool_not_found_error_instance_is_intellicrack_error(self) -> None:
        """ToolNotFoundError instance satisfies isinstance(err, IntellicrackError)."""
        err = ToolNotFoundError("ghidra not found")
        assert isinstance(err, IntellicrackError)

    def test_initialization_error_instance_is_tool_error(self) -> None:
        """InitializationError instance satisfies isinstance(err, ToolError)."""
        err = InitializationError("frida init failed")
        assert isinstance(err, ToolError)

    def test_initialization_error_instance_is_intellicrack_error(self) -> None:
        """InitializationError instance satisfies isinstance(err, IntellicrackError)."""
        err = InitializationError("frida init failed")
        assert isinstance(err, IntellicrackError)

    def test_attach_error_instance_is_tool_error(self) -> None:
        """AttachError instance satisfies isinstance(err, ToolError)."""
        err = AttachError("cannot attach")
        assert isinstance(err, ToolError)

    def test_attach_error_instance_is_intellicrack_error(self) -> None:
        """AttachError instance satisfies isinstance(err, IntellicrackError)."""
        err = AttachError("cannot attach")
        assert isinstance(err, IntellicrackError)

    def test_tool_error_instance_not_provider_error(self) -> None:
        """ToolError instance does NOT satisfy isinstance(err, ProviderError)."""
        err = ToolError("tool exploded")
        assert not isinstance(err, ProviderError)

    def test_provider_error_instance_not_tool_error(self) -> None:
        """ProviderError instance does NOT satisfy isinstance(err, ToolError)."""
        err = ProviderError("api unreachable")
        assert not isinstance(err, ToolError)

    def test_authentication_error_instance_not_tool_error(self) -> None:
        """AuthenticationError instance does NOT satisfy isinstance(err, ToolError)."""
        err = AuthenticationError("invalid credentials")
        assert not isinstance(err, ToolError)

    def test_model_not_found_error_instance_not_tool_error(self) -> None:
        """ModelNotFoundError instance does NOT satisfy isinstance(err, ToolError)."""
        err = ModelNotFoundError("model gone")
        assert not isinstance(err, ToolError)

    def test_tool_not_found_error_instance_not_provider_error(self) -> None:
        """ToolNotFoundError instance does NOT satisfy isinstance(err, ProviderError)."""
        err = ToolNotFoundError("cutter missing")
        assert not isinstance(err, ProviderError)

    def test_initialization_error_instance_not_provider_error(self) -> None:
        """InitializationError instance does NOT satisfy isinstance(err, ProviderError)."""
        err = InitializationError("init failed")
        assert not isinstance(err, ProviderError)

    def test_attach_error_instance_not_provider_error(self) -> None:
        """AttachError instance does NOT satisfy isinstance(err, ProviderError)."""
        err = AttachError("attach denied")
        assert not isinstance(err, ProviderError)


class TestProviderErrorAttributeContract:
    """ProviderError carries exactly the documented attributes on construction.

    Oracle: ProviderError.__init__ signature and attribute assignments in types.py.
    Mutation caught: removing any self.* assignment drops the attribute and makes
    the corresponding assert fail with AttributeError or a wrong value.
    """

    def test_provider_error_message_attribute(self) -> None:
        """ProviderError.message equals the first constructor argument."""
        msg = "connection refused"
        err = ProviderError(msg, provider_name="openai", status_code=503)
        assert err.message == msg

    def test_provider_error_provider_name_attribute(self) -> None:
        """ProviderError.provider_name equals the kwarg passed on construction."""
        err = ProviderError("error", provider_name="anthropic")
        assert err.provider_name == "anthropic"

    def test_provider_error_provider_name_defaults_to_none(self) -> None:
        """ProviderError.provider_name is None when not supplied."""
        err = ProviderError("generic provider error")
        assert err.provider_name is None

    def test_provider_error_status_code_attribute(self) -> None:
        """ProviderError.status_code equals the kwarg passed on construction."""
        err = ProviderError("bad gateway", status_code=502)
        assert err.status_code == 502

    def test_provider_error_status_code_defaults_to_none(self) -> None:
        """ProviderError.status_code is None when not supplied."""
        err = ProviderError("no http code")
        assert err.status_code is None

    def test_provider_error_response_body_attribute(self) -> None:
        """ProviderError.response_body equals the kwarg passed on construction."""
        body = '{"error": "rate limited"}'
        err = ProviderError("rate limited", response_body=body)
        assert err.response_body == body

    def test_provider_error_response_body_defaults_to_none(self) -> None:
        """ProviderError.response_body is None when not supplied."""
        err = ProviderError("no body")
        assert err.response_body is None

    def test_provider_error_error_code_attribute(self) -> None:
        """ProviderError.error_code (inherited from IntellicrackError) is preserved."""
        err = ProviderError("coded error", error_code=4001)
        assert err.error_code == 4001

    def test_provider_error_details_attribute(self) -> None:
        """ProviderError.details (inherited from IntellicrackError) is preserved."""
        d: dict[str, object] = {"retry": True}
        err = ProviderError("with details", details=d)
        assert err.details == {"retry": True}

    def test_provider_error_str_equals_message(self) -> None:
        """str(ProviderError) equals the message (Exception.__str__ contract)."""
        msg = "provider down"
        err = ProviderError(msg)
        assert str(err) == msg


class TestAuthenticationErrorAttributeContract:
    """AuthenticationError inherits ProviderError attributes with no override.

    Oracle: AuthenticationError has no custom __init__; it uses ProviderError.__init__
    verbatim, so all ProviderError attributes must be accessible.
    Mutation caught: if AuthenticationError were given a custom __init__ that dropped
    any attribute, the corresponding assertion would fail.
    """

    def test_authentication_error_message_attribute(self) -> None:
        """AuthenticationError.message equals the first constructor argument."""
        msg = "invalid api key"
        err = AuthenticationError(msg, provider_name="openai", status_code=401)
        assert err.message == msg

    def test_authentication_error_provider_name_attribute(self) -> None:
        """AuthenticationError.provider_name equals the kwarg passed on construction."""
        err = AuthenticationError("bad credentials", provider_name="google")
        assert err.provider_name == "google"

    def test_authentication_error_status_code_attribute(self) -> None:
        """AuthenticationError.status_code equals the HTTP code passed on construction."""
        err = AuthenticationError("forbidden", status_code=403)
        assert err.status_code == 403

    def test_authentication_error_response_body_attribute(self) -> None:
        """AuthenticationError.response_body equals the kwarg passed on construction."""
        body = '{"code": "auth_failed"}'
        err = AuthenticationError("auth failed", response_body=body)
        assert err.response_body == body

    def test_authentication_error_error_code_inherited(self) -> None:
        """AuthenticationError.error_code (from IntellicrackError) survives construction."""
        err = AuthenticationError("expired token", error_code=4011)
        assert err.error_code == 4011

    def test_authentication_error_str_equals_message(self) -> None:
        """str(AuthenticationError) equals the message."""
        msg = "token expired"
        err = AuthenticationError(msg)
        assert str(err) == msg


class TestRateLimitErrorAttributeContract:
    """RateLimitError carries retry_after and limit_type plus all ProviderError attrs.

    Oracle: RateLimitError.__init__ signature and attribute assignments.
    Mutation caught: removing self.retry_after or self.limit_type assignment makes
    the attribute access raise AttributeError.
    """

    def test_rate_limit_error_retry_after_attribute(self) -> None:
        """RateLimitError.retry_after equals the kwarg passed on construction."""
        err = RateLimitError("too many requests", retry_after=30.5)
        assert err.retry_after is not None
        assert math.isclose(err.retry_after, 30.5)

    def test_rate_limit_error_retry_after_defaults_to_none(self) -> None:
        """RateLimitError.retry_after is None when not supplied."""
        err = RateLimitError("rate limited")
        assert err.retry_after is None

    def test_rate_limit_error_limit_type_attribute(self) -> None:
        """RateLimitError.limit_type equals the kwarg passed on construction."""
        err = RateLimitError("rpm exceeded", limit_type="requests_per_minute")
        assert err.limit_type == "requests_per_minute"

    def test_rate_limit_error_limit_type_defaults_to_none(self) -> None:
        """RateLimitError.limit_type is None when not supplied."""
        err = RateLimitError("rate limited")
        assert err.limit_type is None

    def test_rate_limit_error_provider_name_attribute(self) -> None:
        """RateLimitError.provider_name (from ProviderError) is preserved."""
        err = RateLimitError("throttled", provider_name="anthropic", status_code=429)
        assert err.provider_name == "anthropic"
        assert err.status_code == 429

    def test_rate_limit_error_message_and_str(self) -> None:
        """str(RateLimitError) equals the message passed to __init__."""
        msg = "requests per day exceeded"
        err = RateLimitError(msg)
        assert err.message == msg
        assert str(err) == msg


class TestModelNotFoundErrorAttributeContract:
    """ModelNotFoundError carries model_name and available_models plus all ProviderError attrs.

    Oracle: ModelNotFoundError.__init__ signature and attribute assignments.
    Mutation caught: removing self.model_name or self.available_models assignment makes
    the attribute access raise AttributeError or return the wrong default.
    """

    def test_model_not_found_error_model_name_attribute(self) -> None:
        """ModelNotFoundError.model_name equals the kwarg passed on construction."""
        err = ModelNotFoundError("model missing", model_name="gpt-5-turbo")
        assert err.model_name == "gpt-5-turbo"

    def test_model_not_found_error_model_name_defaults_to_none(self) -> None:
        """ModelNotFoundError.model_name is None when not supplied."""
        err = ModelNotFoundError("model not found")
        assert err.model_name is None

    def test_model_not_found_error_available_models_attribute(self) -> None:
        """ModelNotFoundError.available_models equals the list passed on construction."""
        models = ["gpt-4o", "gpt-4o-mini", "o1"]
        err = ModelNotFoundError("unsupported model", available_models=models)
        assert err.available_models == ["gpt-4o", "gpt-4o-mini", "o1"]

    def test_model_not_found_error_available_models_defaults_to_empty_list(self) -> None:
        """ModelNotFoundError.available_models is [] (not None) when not supplied."""
        err = ModelNotFoundError("model not found")
        assert err.available_models == []
        assert isinstance(err.available_models, list)

    def test_model_not_found_error_available_models_none_coerced_to_empty_list(self) -> None:
        """ModelNotFoundError.available_models is [] when available_models=None is explicit."""
        err = ModelNotFoundError("model not found", available_models=None)
        assert err.available_models == []

    def test_model_not_found_error_provider_name_attribute(self) -> None:
        """ModelNotFoundError.provider_name (from ProviderError) is preserved."""
        err = ModelNotFoundError("no such model", provider_name="openai", model_name="gpt-99")
        assert err.provider_name == "openai"

    def test_model_not_found_error_status_code_attribute(self) -> None:
        """ModelNotFoundError.status_code (from ProviderError) is preserved."""
        err = ModelNotFoundError("model gone", status_code=404)
        assert err.status_code == 404

    def test_model_not_found_error_message_and_str(self) -> None:
        """str(ModelNotFoundError) equals the message passed to __init__."""
        msg = "claude-opus-99 not found"
        err = ModelNotFoundError(msg)
        assert err.message == msg
        assert str(err) == msg

    def test_model_not_found_error_error_code_inherited(self) -> None:
        """ModelNotFoundError.error_code (from IntellicrackError) survives construction."""
        err = ModelNotFoundError("missing model", error_code=4041)
        assert err.error_code == 4041


class TestToolErrorAttributeContract:
    """ToolError carries tool_name, exit_code, stderr plus all IntellicrackError attrs.

    Oracle: ToolError.__init__ signature and attribute assignments.
    Mutation caught: removing any self.* assignment in ToolError.__init__ makes the
    attribute access raise AttributeError.
    """

    def test_tool_error_tool_name_attribute(self) -> None:
        """ToolError.tool_name equals the kwarg passed on construction."""
        err = ToolError("ghidra crashed", tool_name="ghidra")
        assert err.tool_name == "ghidra"

    def test_tool_error_tool_name_defaults_to_none(self) -> None:
        """ToolError.tool_name is None when not supplied."""
        err = ToolError("tool failure")
        assert err.tool_name is None

    def test_tool_error_exit_code_attribute(self) -> None:
        """ToolError.exit_code equals the kwarg passed on construction."""
        err = ToolError("process crashed", exit_code=139)
        assert err.exit_code == 139

    def test_tool_error_exit_code_defaults_to_none(self) -> None:
        """ToolError.exit_code is None when not supplied."""
        err = ToolError("no exit code")
        assert err.exit_code is None

    def test_tool_error_stderr_attribute(self) -> None:
        """ToolError.stderr equals the kwarg passed on construction."""
        err = ToolError("stderr captured", stderr="Segmentation fault (core dumped)")
        assert err.stderr == "Segmentation fault (core dumped)"

    def test_tool_error_stderr_defaults_to_none(self) -> None:
        """ToolError.stderr is None when not supplied."""
        err = ToolError("no stderr")
        assert err.stderr is None

    def test_tool_error_message_and_str(self) -> None:
        """str(ToolError) equals the message passed to __init__."""
        msg = "x64dbg connection lost"
        err = ToolError(msg)
        assert err.message == msg
        assert str(err) == msg

    def test_tool_error_error_code_inherited(self) -> None:
        """ToolError.error_code (from IntellicrackError) is preserved."""
        err = ToolError("coded failure", error_code=5001)
        assert err.error_code == 5001


class TestToolNotFoundErrorAttributeContract:
    """ToolNotFoundError carries search_paths and install_hint; exit_code and stderr are always None.

    Oracle: ToolNotFoundError.__init__ passes None, None for exit_code and stderr to
    super().__init__; this is the documented behaviour.
    Mutation caught: (a) removing self.search_paths assignment drops the attribute;
    (b) removing self.install_hint assignment drops it; (c) forwarding exit_code would
    change the always-None guarantee.
    """

    def test_tool_not_found_error_search_paths_attribute(self) -> None:
        """ToolNotFoundError.search_paths equals the list passed on construction."""
        paths = [r"C:\Program Files\Ghidra", r"C:\Tools\ghidra"]
        err = ToolNotFoundError("ghidra not found", tool_name="ghidra", search_paths=paths)
        assert err.search_paths == [r"C:\Program Files\Ghidra", r"C:\Tools\ghidra"]

    def test_tool_not_found_error_search_paths_defaults_to_empty_list(self) -> None:
        """ToolNotFoundError.search_paths is [] (not None) when not supplied."""
        err = ToolNotFoundError("tool missing")
        assert err.search_paths == []
        assert isinstance(err.search_paths, list)

    def test_tool_not_found_error_search_paths_none_coerced_to_empty_list(self) -> None:
        """ToolNotFoundError.search_paths is [] when search_paths=None is explicit."""
        err = ToolNotFoundError("tool missing", search_paths=None)
        assert err.search_paths == []

    def test_tool_not_found_error_install_hint_attribute(self) -> None:
        """ToolNotFoundError.install_hint equals the kwarg passed on construction."""
        hint = "Download from https://ghidra-sre.org/ and extract to C:\\Tools\\Ghidra"
        err = ToolNotFoundError("ghidra not found", install_hint=hint)
        assert err.install_hint == hint

    def test_tool_not_found_error_install_hint_defaults_to_none(self) -> None:
        """ToolNotFoundError.install_hint is None when not supplied."""
        err = ToolNotFoundError("tool missing")
        assert err.install_hint is None

    def test_tool_not_found_error_exit_code_always_none(self) -> None:
        """ToolNotFoundError.exit_code is always None regardless of construction args."""
        err = ToolNotFoundError("tool not found", tool_name="cutter")
        assert err.exit_code is None

    def test_tool_not_found_error_stderr_always_none(self) -> None:
        """ToolNotFoundError.stderr is always None regardless of construction args."""
        err = ToolNotFoundError("tool not found", tool_name="frida")
        assert err.stderr is None

    def test_tool_not_found_error_tool_name_attribute(self) -> None:
        """ToolNotFoundError.tool_name (from ToolError) is preserved."""
        err = ToolNotFoundError("cutter missing", tool_name="cutter")
        assert err.tool_name == "cutter"

    def test_tool_not_found_error_message_and_str(self) -> None:
        """str(ToolNotFoundError) equals the message passed to __init__."""
        msg = "frida binary not found"
        err = ToolNotFoundError(msg)
        assert err.message == msg
        assert str(err) == msg


class TestInitializationErrorAttributeContract:
    """InitializationError carries config_path and missing_dependency plus all ToolError attrs.

    Oracle: InitializationError.__init__ signature and attribute assignments.
    Mutation caught: removing self.config_path or self.missing_dependency assignment
    makes the attribute access raise AttributeError.
    """

    def test_initialization_error_config_path_attribute(self) -> None:
        """InitializationError.config_path equals the kwarg passed on construction."""
        cfg = r"C:\Tools\Ghidra\ghidra_scripts\config.json"
        err = InitializationError("init failed", tool_name="ghidra", config_path=cfg)
        assert err.config_path == cfg

    def test_initialization_error_config_path_defaults_to_none(self) -> None:
        """InitializationError.config_path is None when not supplied."""
        err = InitializationError("init failed")
        assert err.config_path is None

    def test_initialization_error_missing_dependency_attribute(self) -> None:
        """InitializationError.missing_dependency equals the kwarg passed on construction."""
        dep = "frida-tools>=12.0.0"
        err = InitializationError("dependency missing", tool_name="frida", missing_dependency=dep)
        assert err.missing_dependency == dep

    def test_initialization_error_missing_dependency_defaults_to_none(self) -> None:
        """InitializationError.missing_dependency is None when not supplied."""
        err = InitializationError("init failure")
        assert err.missing_dependency is None

    def test_initialization_error_exit_code_attribute(self) -> None:
        """InitializationError.exit_code (from ToolError) is passed through correctly."""
        err = InitializationError("crashed on start", exit_code=1)
        assert err.exit_code == 1

    def test_initialization_error_stderr_attribute(self) -> None:
        """InitializationError.stderr (from ToolError) is passed through correctly."""
        stderr_msg = "ImportError: no module named frida"
        err = InitializationError("startup stderr", stderr=stderr_msg)
        assert err.stderr == stderr_msg

    def test_initialization_error_tool_name_attribute(self) -> None:
        """InitializationError.tool_name (from ToolError) is preserved."""
        err = InitializationError("could not start", tool_name="x64dbg")
        assert err.tool_name == "x64dbg"

    def test_initialization_error_message_and_str(self) -> None:
        """str(InitializationError) equals the message passed to __init__."""
        msg = "ghidra init failed"
        err = InitializationError(msg)
        assert err.message == msg
        assert str(err) == msg

    def test_initialization_error_error_code_inherited(self) -> None:
        """InitializationError.error_code (from IntellicrackError) survives construction."""
        err = InitializationError("init error coded", error_code=5010)
        assert err.error_code == 5010


class TestAttachErrorAttributeContract:
    """AttachError carries pid, process_name, and reason plus all ToolError attrs.

    Oracle: AttachError.__init__ signature and attribute assignments.
    Mutation caught: removing self.pid, self.process_name, or self.reason assignment
    makes the attribute access raise AttributeError.
    """

    def test_attach_error_pid_attribute(self) -> None:
        """AttachError.pid equals the kwarg passed on construction."""
        err = AttachError("attach denied", pid=4321, tool_name="x64dbg")
        assert err.pid == 4321

    def test_attach_error_pid_defaults_to_none(self) -> None:
        """AttachError.pid is None when not supplied."""
        err = AttachError("no pid supplied")
        assert err.pid is None

    def test_attach_error_process_name_attribute(self) -> None:
        """AttachError.process_name equals the kwarg passed on construction."""
        err = AttachError("access denied", process_name="svchost.exe")
        assert err.process_name == "svchost.exe"

    def test_attach_error_process_name_defaults_to_none(self) -> None:
        """AttachError.process_name is None when not supplied."""
        err = AttachError("no process")
        assert err.process_name is None

    def test_attach_error_reason_attribute(self) -> None:
        """AttachError.reason equals the kwarg passed on construction."""
        err = AttachError("attach failed", reason="insufficient privileges")
        assert err.reason == "insufficient privileges"

    def test_attach_error_reason_defaults_to_none(self) -> None:
        """AttachError.reason is None when not supplied."""
        err = AttachError("no reason")
        assert err.reason is None

    def test_attach_error_message_and_str(self) -> None:
        """str(AttachError) equals the message passed to __init__."""
        msg = "could not attach to process"
        err = AttachError(msg)
        assert err.message == msg
        assert str(err) == msg


class TestIntellicrackErrorDetailsInheritance:
    """details dict from IntellicrackError propagates through both exception families.

    Oracle: all subclass __init__ methods call super().__init__(message, error_code,
    details), so the base class stores details without modification.
    Mutation caught: if any intermediate __init__ drops the details kwarg from its
    super() call, the details dict will be empty instead of the supplied value.
    """

    def test_provider_error_details_reach_base(self) -> None:
        """ProviderError.details (from IntellicrackError) holds the supplied dict."""
        d: dict[str, object] = {"endpoint": "https://api.openai.com/v1"}
        err = ProviderError("details test", details=d)
        assert err.details["endpoint"] == "https://api.openai.com/v1"

    def test_authentication_error_details_reach_base(self) -> None:
        """AuthenticationError.details (from IntellicrackError) holds the supplied dict."""
        d: dict[str, object] = {"token_prefix": "sk-"}
        err = AuthenticationError("auth details test", details=d)
        assert err.details["token_prefix"] == "sk-"

    def test_rate_limit_error_details_reach_base(self) -> None:
        """RateLimitError.details (from IntellicrackError) holds the supplied dict."""
        d: dict[str, object] = {"window": "1m", "limit": 60}
        err = RateLimitError("rl details test", details=d)
        assert err.details["window"] == "1m"
        assert err.details["limit"] == 60

    def test_model_not_found_error_details_reach_base(self) -> None:
        """ModelNotFoundError.details (from IntellicrackError) holds the supplied dict."""
        d: dict[str, object] = {"requested": "gpt-5"}
        err = ModelNotFoundError("mnf details test", details=d)
        assert err.details["requested"] == "gpt-5"

    def test_tool_error_details_reach_base(self) -> None:
        """ToolError.details (from IntellicrackError) holds the supplied dict."""
        d: dict[str, object] = {"phase": "startup"}
        err = ToolError("te details test", details=d)
        assert err.details["phase"] == "startup"

    def test_tool_not_found_error_details_reach_base(self) -> None:
        """ToolNotFoundError.details (from IntellicrackError) holds the supplied dict."""
        d: dict[str, object] = {"searched": 3}
        err = ToolNotFoundError("tnf details test", details=d)
        assert err.details["searched"] == 3

    def test_initialization_error_details_reach_base(self) -> None:
        """InitializationError.details (from IntellicrackError) holds the supplied dict."""
        d: dict[str, object] = {"step": "config_load"}
        err = InitializationError("ie details test", details=d)
        assert err.details["step"] == "config_load"

    def test_attach_error_details_reach_base(self) -> None:
        """AttachError.details (from IntellicrackError) holds the supplied dict."""
        d: dict[str, object] = {"os_error": "Access is denied"}
        err = AttachError("ae details test", details=d)
        assert err.details["os_error"] == "Access is denied"
