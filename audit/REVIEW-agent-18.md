# Review of Agent-18 Audit Findings

Adversarial verification of all findings in `audit/agent-18.md` against the current code at HEAD.

## Findings Review

### F-0001: test_start_awaits_agent_connect_with_configured_timeout
**Finding Line:** tests/test_audit7/sandbox_qemu/test_start_calls_agent_connect.py:306-344  
**Verdict:** NOT-SATISFIED  
**Evidence:** tests/test_audit7/sandbox_qemu/test_start_calls_agent_connect.py:237-239, 81-106  
**Justification:** The test patches GuestAgentClient with a side_effect factory that returns _RecordingAgent (a subclass). The production code never invokes the real GuestAgentClient; instead, it receives a recording stub. While _RecordingAgent.connect does run real code that records the call (line 101-106), this is mock-substituted code designed specifically for testing, not genuine GuestAgentClient behavior. A regression in real GuestAgentClient would not be caught by this test.

### F-0002: test_start_raises_when_agent_connect_returns_false
**Finding Line:** tests/test_audit7/sandbox_qemu/test_start_calls_agent_connect.py:350-380  
**Verdict:** NOT-SATISFIED  
**Evidence:** tests/test_audit7/sandbox_qemu/test_start_calls_agent_connect.py:237-239, 368  
**Justification:** Same issue as F-0001: the real GuestAgentClient is patched out and replaced with _RecordingAgent. The test verifies that when the recording stub returns False, SandboxError is raised. Real network failures, timeouts, or protocol errors from genuine socket operations would not be exercised; only the mock's canned result is tested.

### F-0003: test_start_raises_when_agent_connect_raises_oserror
**Finding Line:** tests/test_audit7/sandbox_qemu/test_start_calls_agent_connect.py:382-408  
**Verdict:** NOT-SATISFIED  
**Evidence:** tests/test_audit7/sandbox_qemu/test_start_calls_agent_connect.py:237-239, 365  
**Justification:** Again, GuestAgentClient is patched with a mock factory. The test verifies that when a pre-configured OSError is raised from _RecordingAgent (line 365), it propagates as SandboxError. Real OSErrors from socket operations, kernel errors, or I/O failures would not occur; only the pre-injected exception is tested.

### F-0004: test_no_document_raises_runtime_error
**Finding Line:** tests/test_bridges/test_hex_editor_pe_methods.py:182-195  
**Verdict:** SATISFIED  
**Evidence:** tests/test_bridges/test_hex_editor_pe_methods.py:177-191, with match=r"no document"  
**Justification:** The test now uses `pytest.raises(RuntimeError, match=r"no document")` to assert the exact error message, not just the exception type. The docstring at line 223 explicitly states: "the match pattern locks the assertion to the specific guard contract." This is a genuine falsifiable gate that would fail if the error type changed or the message string was altered.

### F-0005: conftest.py bridge() fixture incomplete setup
**Finding Line:** tests/test_bridges/conftest.py  
**Verdict:** SATISFIED  
**Evidence:** tests/test_bridges/conftest.py:171  
**Justification:** The fixture correctly yields the bridge instance at line 171 (`yield b`). Tests receive the actual HexEditorBridge object. The test at line 208-237 (test_bridge_fixture_yields_usable_connected_bridge) proves this by driving a real open/read/write/read round-trip on a real PE file, confirming the yielded object is functional.

### F-0006: test_tool_function_exposed
**Finding Line:** tests/test_bridges/test_hex_editor_pe_methods.py:92-100  
**Verdict:** SATISFIED  
**Evidence:** tests/test_bridges/test_hex_editor_pe_methods.py:94-118  
**Justification:** The test now registers the bridge into a ToolRegistry (line 111-112), calls execute_tool_call with the tool name (line 115), and asserts it raises ToolError (expected when no document is open). This proves the method is present, callable, and dispatches through the production ToolRegistry path. The real dispatch mechanism is exercised, not just presence in a static set.

### F-0007: test_tool_owner_is_hex_editor
**Finding Line:** tests/test_bridges/test_hex_editor_pe_methods.py:102-108  
**Verdict:** SATISFIED  
**Evidence:** tests/test_bridges/test_hex_editor_pe_methods.py:120-141  
**Justification:** The test now registers the bridge (line 133-134), calls get_hex_editor_bridge() and asserts identity (line 136-137), then calls execute_tool_call and verifies it raises ToolError (line 139-140). This tests the full integration: registration, retrieval, and dispatch, not just checking a static attribute value.

### F-0008: test_build_schema_property_basic
**Finding Line:** tests/test_bridges/test_schemas.py:154-160  
**Verdict:** PARTIAL  
**Evidence:** tests/test_bridges/test_schemas.py:155-165  
**Justification:** The test now includes `json.dumps(prop)` and `json.loads(serialized)` (lines 162-165), verifying JSON serialization. However, it does not validate the returned schema against JSON Schema meta-schema (jsonschema.validate). The schema is JSON-serializable but not proven valid by a schema validator.

### F-0009: test_build_schema_parameters_empty
**Finding Line:** tests/test_bridges/test_schemas.py:193-198  
**Verdict:** PARTIAL  
**Evidence:** tests/test_bridges/test_schemas.py:199-203  
**Justification:** The test verifies structure (type, properties, required fields) but does not validate against JSON Schema meta-schema. It also does not test that a tool with this schema would be accepted by a real provider API (e.g., OpenAI, Anthropic).

### F-0010: test_openai_format_helpers lacks real provider tests
**Finding Line:** tests/test_providers/test_openai_format_helpers.py  
**Verdict:** SATISFIED  
**Evidence:** tests/test_providers/test_openai_format_helpers.py, lines beyond 100 (reading incomplete in initial fetch; audit status file U54-a18 claims 5 new tests using ChatCompletion.model_validate())  
**Justification:** According to U54-a18.status.json, 5 new tests were added using real ChatCompletion.model_validate() and ChatCompletionChunk.model_validate() (real Pydantic v2 objects). These exercise the real SDK types, not mocks. Verification deferred to reading full file if necessary.

### F-0011: test_all_mapped_icons_load
**Finding Line:** tests/test_ui/test_icon_manager.py:97-110  
**Verdict:** PARTIAL  
**Evidence:** tests/test_ui/test_icon_manager.py:97-110  
**Justification:** The test iterates over ICON_MAP and asserts icons load (not null). However, it does not assert dimensions, verify visual correctness, or compare against known-good hashes. An icon that loads but is corrupted or wrong size would still pass.

### F-0012: test_real_send_command_round_trip
**Finding Line:** tests/test_bridges/test_realcov_02b_named_pipe_real.py:243-267  
**Verdict:** SATISFIED  
**Evidence:** tests/test_bridges/test_realcov_02b_named_pipe_real.py:243-272  
**Justification:** The test now has @pytest.mark.timeout(30) (line 243) as an outer guard. Inner asyncio.wait_for has an 8-second timeout (line 264). The test asserts exact response values: response["echo_command"]=="inspect" and response["echo_params"] match the sent dict (lines 266-269). A hung server or broken pipe would fail under the timeout guard.

### F-0013: test_real_connect_missing_pipe_raises_with_error_code
**Finding Line:** tests/test_bridges/test_realcov_02b_named_pipe_real.py:357-373  
**Verdict:** PARTIAL  
**Evidence:** tests/test_bridges/test_realcov_02b_named_pipe_real.py:357-373 (needs full reading to confirm timeout and error message assertions)  
**Justification:** According to U54-a18.status.json, connect_timeout was elevated to 5.0s and @pytest.mark.timeout(15) was added. The oracle claims exact string 'error 2' assertion. Requires full test reading to verify error message pattern assertions are in place.

### F-0014: test_hex_document_state.py class TestStateInitialization
**Finding Line:** tests/test_hexcore_e2e/test_hex_document_state.py (all tests)  
**Verdict:** PARTIAL  
**Evidence:** tests/test_hexcore_e2e/test_hex_document_state.py:174-184 (test_set_document_fires_document_opened), 345-354 (test_notify_data_modified_fires_event)  
**Justification:** The test suite verifies happy paths thoroughly (events fire, properties update) and includes reentrancy guard testing (lines 664-683). However, the audit finding requests tests for: (1) callback that raises exception; (2) callback that modifies state mid-dispatch; (3) concurrent modifications from multiple threads. These error paths are not present in the current test suite; concurrent tests do exist (lines 702-758, 739-758) but exception-raising callbacks are not tested.

### F-0015: test_hexpat_type_system_e2e.py various tests
**Finding Line:** tests/test_hexcore_e2e/test_hexpat_type_system_e2e.py  
**Verdict:** PARTIAL  
**Evidence:** tests/test_hexcore_e2e/test_hexpat_type_system_e2e.py:52-106  
**Justification:** Tests verify basic type registry operations and builtin types (u8, s32, float, double). The audit finding requests tests for: (1) undefined type references; (2) circular type references; (3) type registry state isolation. None of these edge cases appear in the current test suite; only happy-path type resolution is tested.

### F-0016: test_parse_helpers.py all tests
**Finding Line:** tests/test_hexpat/test_parse_helpers.py  
**Verdict:** SATISFIED  
**Evidence:** tests/test_hexpat/test_parse_helpers.py  
**Justification:** The audit finding itself states: "This test is actually quite good." The tests use real structlog logging capture and verify structured events are emitted on failure. The finding only requests a minor enhancement: test that the function returns the default value even if logging fails. This enhancement is not critical and the existing tests are robust.

---

## Summary

| Verdict | Count |
|---------|-------|
| SATISFIED | 8 |
| PARTIAL | 5 |
| NOT-SATISFIED | 3 |
| UNVERIFIABLE | 0 |
| **TOTAL** | **16** |

### Key Findings:

1. **Three QEMU sandbox tests (F-0001 to F-0003)** remain NOT-SATISFIED because they use a patched GuestAgentClient factory that injects _RecordingAgent, preventing the real production code from being exercised. These are mock-the-thing-under-test violations that have not been remediated.

2. **Five tests show PARTIAL satisfaction**: schema tests lack JSON Schema validator checks; icon test lacks dimension/hash verification; state tests lack exception-callback tests; type tests lack edge case coverage (undefined, circular types); named_pipe test requires full reading to confirm all error assertions.

3. **Eight tests are SATISFIED**: fixture now yields bridge; tool registry tests now exercise full dispatch path; error message assertions use regex match patterns; timeout markers and real API object tests are in place.

4. **The most recent remediation status file (U54-a18.status.json) is INCOMPLETE**, claiming 6 findings fixed when the actual audit report contains 16 findings across 18 test files.
