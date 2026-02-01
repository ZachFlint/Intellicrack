#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const os = require('os');

const LOG_FILE = path.join(os.tmpdir(), 'block-ignore-comments.log');
const VIOLATIONS_FILE = path.join(os.tmpdir(), 'claude-ignore-violations.json');

if (!fs.existsSync(LOG_FILE)) {
    fs.writeFileSync(LOG_FILE, '');
}

function logToFile(message) {
    const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
    fs.appendFileSync(LOG_FILE, `[${timestamp}] ${message}\n`);
}

function writeViolations(violations, filePath) {
    const data = {
        timestamp: new Date().toISOString(),
        file: filePath,
        violations: violations,
        resolved: false,
    };
    fs.writeFileSync(VIOLATIONS_FILE, JSON.stringify(data, null, 2));
    logToFile(`Wrote violations to ${VIOLATIONS_FILE}`);
}

function clearViolations() {
    if (fs.existsSync(VIOLATIONS_FILE)) {
        fs.unlinkSync(VIOLATIONS_FILE);
        logToFile('Cleared violations file');
    }
}

const IGNORE_PATTERNS = [
    { pattern: /#\s*noqa\b/i, name: '# noqa', tool: 'flake8/ruff' },
    { pattern: /#\s*noqa:/i, name: '# noqa:', tool: 'flake8/ruff' },
    { pattern: /#\s*type:\s*ignore/i, name: '# type: ignore', tool: 'basedpyright' },
    { pattern: /#\s*mypy:\s*ignore/i, name: '# mypy: ignore', tool: 'basedpyright' },
    { pattern: /#\s*mypy:\s*disable-error-code/i, name: '# mypy: disable-error-code', tool: 'basedpyright' },
    { pattern: /#\s*pyright:\s*ignore/i, name: '# pyright: ignore', tool: 'basedpyright' },
    { pattern: /#\s*pyright:\s*reportGeneralTypeIssues/i, name: '# pyright: reportGeneralTypeIssues', tool: 'basedpyright' },
    { pattern: /#\s*pyright:\s*basic/i, name: '# pyright: basic', tool: 'basedpyright' },
    { pattern: /#\s*pylint:\s*disable/i, name: '# pylint: disable', tool: 'pylint' },
    { pattern: /#\s*pylint:\s*disable-next/i, name: '# pylint: disable-next', tool: 'pylint' },
    { pattern: /#\s*pylint:\s*disable-all/i, name: '# pylint: disable-all', tool: 'pylint' },
    { pattern: /#\s*nosec\b/i, name: '# nosec', tool: 'bandit' },
    { pattern: /#\s*fmt:\s*off/i, name: '# fmt: off', tool: 'black/ruff' },
    { pattern: /#\s*fmt:\s*skip/i, name: '# fmt: skip', tool: 'black/ruff' },
    { pattern: /#\s*isort:\s*skip/i, name: '# isort: skip', tool: 'isort' },
    { pattern: /#\s*isort:\s*off/i, name: '# isort: off', tool: 'isort' },
    { pattern: /#\s*ruff:\s*noqa/i, name: '# ruff: noqa', tool: 'ruff' },
    { pattern: /#\s*flake8:\s*noqa/i, name: '# flake8: noqa', tool: 'flake8' },
    { pattern: /\/\/\s*eslint-disable\b/i, name: '// eslint-disable', tool: 'eslint' },
    { pattern: /\/\*\s*eslint-disable\b/i, name: '/* eslint-disable', tool: 'eslint' },
    { pattern: /eslint-disable-line\b/i, name: 'eslint-disable-line', tool: 'eslint' },
    { pattern: /eslint-disable-next-line\b/i, name: 'eslint-disable-next-line', tool: 'eslint' },
    { pattern: /@ts-ignore\b/i, name: '@ts-ignore', tool: 'typescript' },
    { pattern: /@ts-nocheck\b/i, name: '@ts-nocheck', tool: 'typescript' },
    { pattern: /@ts-expect-error\b/i, name: '@ts-expect-error', tool: 'typescript' },
    { pattern: /tslint:\s*disable/i, name: 'tslint:disable', tool: 'tslint' },
    { pattern: /prettier-ignore\b/i, name: 'prettier-ignore', tool: 'prettier' },
    { pattern: /biome-ignore\b/i, name: 'biome-ignore', tool: 'biome' },
    { pattern: /stylelint-disable\b/i, name: 'stylelint-disable', tool: 'stylelint' },
    { pattern: /shellcheck\s+disable/i, name: 'shellcheck disable', tool: 'shellcheck' },
    { pattern: /#\s*safety:\s*ignore/i, name: '# safety: ignore', tool: 'safety' },
    { pattern: /#\s*pragma:\s*no\s*cover/i, name: '# pragma: no cover', tool: 'coverage' },
    { pattern: /\/\/\s*nolint\b/i, name: '// nolint', tool: 'golint' },
    { pattern: /#\s*rubocop:\s*disable/i, name: '# rubocop:disable', tool: 'rubocop' },
];

function detectIgnoreComments(content) {
    const violations = [];
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        for (const { pattern, name, tool } of IGNORE_PATTERNS) {
            if (pattern.test(line)) {
                violations.push({
                    line: i + 1,
                    pattern: name,
                    tool: tool,
                    content: line.trim().substring(0, 100),
                });
            }
        }
    }

    return violations;
}

function main() {
    let jsonInput = '';

    process.stdin.setEncoding('utf8');

    process.stdin.on('data', (chunk) => {
        jsonInput += chunk;
    });

    process.stdin.on('end', () => {
        logToFile(`Hook triggered with input length: ${jsonInput.length}`);

        let toolName = 'unknown';
        let filePath = '';
        let content = '';

        try {
            const input = JSON.parse(jsonInput);
            toolName = input.tool_name || 'unknown';

            if (input.tool_input) {
                filePath = input.tool_input.file_path || input.tool_input.path || '';
                content = input.tool_input.new_string || input.tool_input.content || '';
            }
        } catch (error) {
            logToFile(`JSON parse error: ${error.message}`);
            process.exit(0);
        }

        logToFile(`Tool: ${toolName}, File: ${filePath}`);

        const normalizedPath = filePath.replace(/\\/g, '/').toLowerCase();
        if (normalizedPath.includes('.claude/hooks/') || normalizedPath.includes('.claude\\hooks\\')) {
            logToFile(`Skipping hook file: ${filePath}`);
            process.exit(0);
        }

        const validTools = [
            'Write',
            'Edit',
            'MultiEdit',
            'mcp__filesystem__write_file',
            'mcp__filesystem__edit_file',
            'mcp__desktop-commander__write_file',
            'mcp__desktop-commander__edit_block',
        ];

        if (!validTools.includes(toolName)) {
            logToFile(`Skipping non-edit tool: ${toolName}`);
            process.exit(0);
        }

        if (!content) {
            logToFile('No content to check, allowing operation');
            clearViolations();
            process.exit(0);
        }

        const violations = detectIgnoreComments(content);

        if (violations.length > 0) {
            const violationSummary = violations.map((v) => `${v.pattern} at line ${v.line}`).join('; ');
            logToFile(`VIOLATIONS FOUND: ${violationSummary}`);

            writeViolations(violations, filePath);

            console.error(`IGNORE COMMENT VIOLATION: ${violationSummary} in ${filePath}`);
            process.exit(0);
        } else {
            logToFile('No ignore comments found, allowing operation');
            clearViolations();
            process.exit(0);
        }
    });
}

main();
