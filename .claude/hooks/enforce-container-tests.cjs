#!/usr/bin/env node
/*
 * PreToolUse hook: force the test suite to run inside the Docker sandbox.
 *
 * Intellicrack's tests must execute in the container (`just test ...` ->
 * `pixi python -m scripts.sandbox.docker_sandbox`), never against the host
 * interpreter. This hook inspects Bash/PowerShell commands (and the local
 * dev-tools pytest/coverage MCP tools) and denies any local test invocation,
 * telling the caller the exact container command to use instead.
 *
 * A command is allowed when it already routes through the sandbox: it mentions
 * `docker_sandbox`, `scripts.sandbox`, `scripts/sandbox`, or a `just test*`
 * recipe. Everything else that launches pytest/coverage on the host is denied.
 */

'use strict';

const fs = require('fs');
const path = require('path');

const LOG_FILE = path.join(__dirname, 'enforce-container-tests.log');

function logToFile(message) {
    try {
        const stamp = new Date().toISOString();
        fs.appendFileSync(LOG_FILE, `[${stamp}] ${message}\n`);
    } catch (_err) {
        /* logging must never break the hook */
    }
}

function allow() {
    process.exit(0);
}

function deny(reason) {
    const response = {
        hookSpecificOutput: {
            hookEventName: 'PreToolUse',
            permissionDecision: 'deny',
            permissionDecisionReason: reason,
        },
    };
    console.log(JSON.stringify(response));
    process.exit(0);
}

// Commands that prove the invocation already runs inside the sandbox, plus the
// sanctioned host-native pass. The host-native runner deliberately executes a
// small, marked subset of tests on the host (Intel XPU, local Ollama, debug
// symbols, raw disk, loopback capture) that the container cannot provide; it
// sets INTELLICRACK_ALLOW_HOST_PROCESS_TESTS and relies on the conftest
// orphan-killer for cleanup, so it is an authorized exception to the ban.
const CONTAINER_MARKERS = [
    /docker_sandbox/i,
    /scripts[./\\]sandbox/i,
    /\bhost_native_tests\b/i,
    /\bjust\s+test(-shell|-rebuild|-clean|-host)?\b/i,
];

// Local test-runner signatures we must intercept.
const LOCAL_TEST_PATTERNS = [
    /\bpy\.test\b/i,
    /\bpytest\b/i,
    /\bpython[0-9.]*\s+-m\s+pytest\b/i,
    /\bpython[0-9.]*\s+-m\s+coverage\b/i,
    /\bcoverage\s+run\b/i,
];

// MCP dev-tools that always run on the host interpreter.
const LOCAL_MCP_TOOLS = new Set([
    'mcp__dev-tools__pytest_run',
    'mcp__dev-tools__pytest_collect',
    'mcp__dev-tools__coverage_run',
]);

function containerCommandHint(command) {
    let pytestArgs = '';
    if (typeof command === 'string') {
        const match = command.match(/\bpy(?:\.test|test)\b(.*)$/is);
        if (match && match[1]) {
            pytestArgs = match[1]
                .replace(/[\r\n]+/g, ' ')
                .replace(/\s+/g, ' ')
                .trim();
        }
    }
    const argHint = pytestArgs
        ? `just test --extra-args "${pytestArgs.replace(/"/g, '\\"')}"`
        : 'just test --extra-args "<pytest args>"';
    return argHint;
}

function evaluateCommand(command) {
    if (typeof command !== 'string' || command.trim() === '') {
        return allow();
    }

    if (CONTAINER_MARKERS.some((re) => re.test(command))) {
        return allow();
    }

    const isLocalTest = LOCAL_TEST_PATTERNS.some((re) => re.test(command));
    if (!isLocalTest) {
        return allow();
    }

    const hint = containerCommandHint(command);
    logToFile(`DENIED local test command: ${command}`);
    return deny(
        'Tests must run in the Docker sandbox, never against the host ' +
            'interpreter. Re-run this through the container instead:\n\n' +
            `    ${hint}\n\n` +
            'The `just test` recipe forwards positional test types and the ' +
            '`--extra-args/-a` string verbatim to pytest inside ' +
            '`scripts.sandbox.docker_sandbox`. Use `--module/-m <path>` to ' +
            'target a single module/file. Direct local pytest, py.test, ' +
            '`python -m pytest`, and host coverage runs are blocked.',
    );
}

function main() {
    let raw = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => {
        raw += chunk;
    });
    process.stdin.on('end', () => {
        let input;
        try {
            input = JSON.parse(raw);
        } catch (_err) {
            // Without parseable input we cannot judge the command; fail open.
            return allow();
        }

        const toolName = input.tool_name || input.toolName || '';
        const toolInput = input.tool_input || input.toolInput || {};

        if (LOCAL_MCP_TOOLS.has(toolName)) {
            logToFile(`DENIED local MCP test tool: ${toolName}`);
            return deny(
                `\`${toolName}\` runs pytest/coverage on the host interpreter, ` +
                    'which is not allowed. Run the suite in the Docker sandbox ' +
                    'instead:\n\n    just test --extra-args "<pytest args>"\n\n' +
                    'That routes through `scripts.sandbox.docker_sandbox`.',
            );
        }

        if (toolName !== 'Bash' && toolName !== 'PowerShell') {
            return allow();
        }

        return evaluateCommand(toolInput.command);
    });
}

main();
