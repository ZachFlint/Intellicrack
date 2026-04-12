#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const os = require('os');

const LOG_FILE = path.join(os.tmpdir(), 'hook-validation.log');

if (!fs.existsSync(LOG_FILE)) {
    fs.writeFileSync(LOG_FILE, '');
}

function logToFile(message) {
    const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
    fs.appendFileSync(LOG_FILE, '[' + timestamp + '] ' + message + '\n');
}

function detectViolations(filePath) {
    const violations = [];

    const normalizedPath = filePath.replace(/\\/g, '/').toLowerCase();
    if (
        normalizedPath.includes('.claude/hooks') ||
        normalizedPath.endsWith('post-tool-use.js') ||
        normalizedPath.includes('/tests/') ||
        normalizedPath.includes('test_') ||
        normalizedPath.endsWith('_test.py')
    ) {
        return violations;
    }

    try {
        const content = fs.readFileSync(filePath, 'utf8');
        const lines = content.split('\n');

        const checks = [
            { pattern: 'TODO', msg: 'TODO comment' },
            { pattern: 'FIXME', msg: 'FIXME comment' },
            { pattern: 'NotImplementedError', msg: 'NotImplementedError' },
            { pattern: 'HACK', msg: 'HACK comment' },
            { pattern: 'XXX', msg: 'XXX marker' },
            { pattern: 'return NotImplemented', msg: 'return NotImplemented' },
            { pattern: 'NOT_IMPLEMENTED', msg: 'NOT_IMPLEMENTED constant' },
            { pattern: 'UNIMPLEMENTED', msg: 'UNIMPLEMENTED constant' },
        ];

        const placeholderExclusions = ['setplaceholdertext', 'placeholdertext', 'placeholder_text'];

        const lowerChecks = [
            { pattern: 'placeholder', msg: 'placeholder code', exclusions: placeholderExclusions },
            { pattern: 'stub', msg: 'stub implementation' },
            { pattern: 'mock', msg: 'mock implementation' },
            { pattern: 'dummy', msg: 'Dummy implementation' },
            { pattern: 'fake', msg: 'fake implementation' },
            { pattern: 'simulat', msg: 'Simulation code' },
            { pattern: 'a real implementation', msg: 'real implementation phrase' },
            { pattern: 'implementation would', msg: 'implementation would phrase' },
        ];

        lines.forEach((line, index) => {
            checks.forEach(check => {
                if (line.includes(check.pattern)) {
                    violations.push(check.msg + ' found at: ' + (index + 1));
                }
            });
            lowerChecks.forEach(check => {
                const lower = line.toLowerCase();
                if (lower.includes(check.pattern)) {
                    if (check.exclusions && check.exclusions.some(exc => lower.includes(exc))) {
                        return;
                    }
                    violations.push(check.msg + ' found at: ' + (index + 1));
                }
            });
            if (line.trim() === '...' && !normalizedPath.includes('protocol')) {
                violations.push('Ellipsis-only function body found at: ' + (index + 1));
            }
        });

    } catch (error) {
        logToFile('Error reading file ' + filePath + ': ' + error.message);
    }

    const uniqueViolations = [];
    const seenTypes = new Set();
    violations.forEach((violation) => {
        const type = violation.split(' ')[0];
        if (!seenTypes.has(type)) {
            seenTypes.add(type);
            uniqueViolations.push(violation);
        }
    });

    return uniqueViolations;
}

function main() {
    let jsonInput = '';

    process.stdin.setEncoding('utf8');

    process.stdin.on('data', (chunk) => {
        jsonInput += chunk;
    });

    process.stdin.on('end', () => {
        logToFile('Hook triggered');

        let toolName = 'unknown';
        let filePath = '';

        try {
            const input = JSON.parse(jsonInput);
            toolName = input.tool_name || 'unknown';
            if (input.tool_input) {
                filePath = input.tool_input.file_path || input.tool_input.path || '';
            }
        } catch (error) {
            logToFile('JSON parse error');
            process.exit(0);
        }

        logToFile('Tool: ' + toolName + ', File: ' + filePath);

        const codeTools = ['Write', 'Edit', 'MultiEdit'];
        if (!codeTools.includes(toolName)) {
            logToFile('Skipping non-code tool');
            process.exit(0);
        }

        if (!filePath || !fs.existsSync(filePath)) {
            logToFile('File not found');
            process.exit(0);
        }

        const codeExtensions = ['.py', '.js', '.ts', '.java', '.cpp', '.c', '.rs', '.go', '.rb'];
        const fileExt = path.extname(filePath).toLowerCase();
        if (!codeExtensions.includes(fileExt)) {
            logToFile('Skipping non-code file');
            process.exit(0);
        }

        const violations = detectViolations(filePath);

        if (violations.length > 0) {
            const violationString = violations.join(', ');
            logToFile('VIOLATIONS: ' + violationString);

            const response = {
                decision: 'block',
                reason: 'VIOLATIONS DETECTED: ' + violationString + '\nFile: ' + filePath + '\nFix these violations with production-ready code immediately.',
            };

            console.log(JSON.stringify(response));
            process.exit(0);
        } else {
            logToFile('No violations found');
            process.exit(0);
        }
    });
}

main();
