#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const os = require('os');

const LOG_FILE = path.join(os.tmpdir(), 'block-ignore-comments.log');
const VIOLATIONS_FILE = path.join(os.tmpdir(), 'claude-ignore-violations.json');

function logToFile(message) {
    const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
    fs.appendFileSync(LOG_FILE, `[${timestamp}] [STOP] ${message}\n`);
}

function getViolations() {
    if (!fs.existsSync(VIOLATIONS_FILE)) {
        return null;
    }

    try {
        const data = JSON.parse(fs.readFileSync(VIOLATIONS_FILE, 'utf8'));
        return data;
    } catch (error) {
        logToFile(`Error reading violations file: ${error.message}`);
        return null;
    }
}

function checkFileStillHasViolations(filePath, violations) {
    if (!fs.existsSync(filePath)) {
        return false;
    }

    try {
        const content = fs.readFileSync(filePath, 'utf8');

        const IGNORE_PATTERNS = [
            /#\s*noqa\b/i,
            /#\s*noqa:/i,
            /#\s*type:\s*ignore/i,
            /#\s*mypy:\s*ignore/i,
            /#\s*mypy:\s*disable-error-code/i,
            /#\s*pyright:\s*ignore/i,
            /#\s*pyright:\s*reportGeneralTypeIssues/i,
            /#\s*pyright:\s*basic/i,
            /#\s*pylint:\s*disable/i,
            /#\s*pylint:\s*disable-next/i,
            /#\s*pylint:\s*disable-all/i,
            /#\s*nosec\b/i,
            /#\s*fmt:\s*off/i,
            /#\s*fmt:\s*skip/i,
            /#\s*isort:\s*skip/i,
            /#\s*isort:\s*off/i,
            /#\s*ruff:\s*noqa/i,
            /#\s*flake8:\s*noqa/i,
            /\/\/\s*eslint-disable\b/i,
            /\/\*\s*eslint-disable\b/i,
            /eslint-disable-line\b/i,
            /eslint-disable-next-line\b/i,
            /@ts-ignore\b/i,
            /@ts-nocheck\b/i,
            /@ts-expect-error\b/i,
            /tslint:\s*disable/i,
            /prettier-ignore\b/i,
            /biome-ignore\b/i,
            /stylelint-disable\b/i,
            /shellcheck\s+disable/i,
            /#\s*safety:\s*ignore/i,
            /#\s*pragma:\s*no\s*cover/i,
            /\/\/\s*nolint\b/i,
            /#\s*rubocop:\s*disable/i,
        ];

        for (const pattern of IGNORE_PATTERNS) {
            if (pattern.test(content)) {
                return true;
            }
        }

        return false;
    } catch (error) {
        logToFile(`Error checking file: ${error.message}`);
        return false;
    }
}

function clearViolations() {
    if (fs.existsSync(VIOLATIONS_FILE)) {
        fs.unlinkSync(VIOLATIONS_FILE);
        logToFile('Cleared violations file after fix confirmed');
    }
}

function main() {
    let jsonInput = '';

    process.stdin.setEncoding('utf8');

    process.stdin.on('data', (chunk) => {
        jsonInput += chunk;
    });

    process.stdin.on('end', () => {
        logToFile('Stop hook triggered');

        const violationData = getViolations();

        if (!violationData) {
            logToFile('No violations file found, allowing stop');
            process.exit(0);
        }

        const filePath = violationData.file;
        const stillHasViolations = checkFileStillHasViolations(filePath, violationData.violations);

        if (stillHasViolations) {
            logToFile(`File ${filePath} still has ignore comments - BLOCKING STOP`);

            const patterns = violationData.violations.map((v) => v.pattern).join(', ');

            const message = `STOP BLOCKED: You added ignore comments that have NOT been fixed yet.

FILE: ${filePath}
PATTERNS DETECTED: ${patterns}

You MUST remove these ignore comments and fix the underlying issues before you can stop.

REQUIRED ACTIONS:
1. Read the file to see the current state
2. Remove all ignore comments (# noqa, # type: ignore, # pylint: disable, etc.)
3. Fix the actual type errors, lint violations, or other issues
4. The code must pass all linters/type checkers WITHOUT ignore comments

DO NOT stop until the ignore comments are removed and replaced with proper fixes.`;

            console.error(message);
            logToFile('Blocked stop due to unresolved ignore comments');
            process.exit(2);
        } else {
            logToFile('File no longer has ignore comments, allowing stop');
            clearViolations();
            process.exit(0);
        }
    });
}

main();
