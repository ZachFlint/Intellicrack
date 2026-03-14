#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const os = require('os');

let input = '';
process.stdin.on('data', (chunk) => (input += chunk));
process.stdin.on('end', () => {
    try {
        const data = JSON.parse(input);

        const cyan = '\x1b[36m';
        const brightMagenta = '\x1b[38;5;213m';
        const green = '\x1b[32m';
        const brightGreen = '\x1b[1;92m';
        const yellow = '\x1b[1;93m';
        const brightRed = '\x1b[1;91m';
        const orangeGold = '\x1b[38;5;214m';
        const reset = '\x1b[0m';

        const model = data.model?.display_name || 'Unknown';
        const modelId = data.model?.id || '';
        const projectName = data.workspace?.current_dir?.split(/[\/\\]/).pop() || 'Unknown';
        const sessionId = data.session_id || '';
        const transcriptPath = data.transcript_path || '';

        const cost = data.cost?.total_cost_usd || 0;
        const formattedCost = `$${cost.toFixed(4)}`;

        const linesAdded = data.cost?.total_lines_added || 0;
        const linesRemoved = data.cost?.total_lines_removed || 0;

        const totalTokens = calculateSessionTokens(sessionId, transcriptPath);
        const contextPercentage = calculateContextPercentage(transcriptPath, modelId, data.context_window);

        const formattedTokens = formatTokenCount(totalTokens);
        const { text: contextText, color: contextColor } =
            formatContextPercentage(contextPercentage);

        const contextColored =
            contextColor === 'green' ? green : contextColor === 'yellow' ? yellow : brightRed;

        console.log(
            `${brightMagenta}${projectName}${reset} ${brightRed}|${reset} ` +
                `${cyan}[${model}]${reset} ${brightRed}|${reset} ` +
                `Tokens: ${orangeGold}${formattedTokens}${reset} ${brightRed}|${reset} ` +
                `${green}${formattedCost}${reset} ${brightRed}|${reset} ` +
                `Context: ${contextColored}${contextText}${reset} ${brightRed}|${reset} ` +
                `Lines added: ${brightGreen}${linesAdded}${reset} ${brightRed}|${reset} ` +
                `Lines removed: ${brightRed}${linesRemoved}${reset}`
        );
    } catch (error) {
        console.log('[Claude] Intellicrack | $0.0000');
    }
});

function calculateSessionTokens(sessionId, transcriptPath) {
    if (!sessionId || !transcriptPath || !fs.existsSync(transcriptPath)) {
        return 0;
    }

    const cacheDir = path.join(os.tmpdir(), 'claude-statusline-tokens');
    const cacheFile = path.join(cacheDir, `${sessionId}.json`);

    try {
        if (!fs.existsSync(cacheDir)) {
            fs.mkdirSync(cacheDir, { recursive: true });
        }

        const now = Date.now();
        let cache = null;

        if (fs.existsSync(cacheFile)) {
            try {
                const cacheData = JSON.parse(fs.readFileSync(cacheFile, 'utf8'));
                if (now - cacheData.timestamp < 1000) {
                    return cacheData.totalTokens;
                }
                cache = cacheData;
            } catch (e) {
                cache = null;
            }
        }

        let baseline = cache?.baseline || 0;
        let maxCumulativeTokens = cache?.maxCumulativeTokens || 0;

        const content = fs.readFileSync(transcriptPath, 'utf8');
        const lines = content
            .trim()
            .split('\n')
            .filter((line) => line.trim());

        let currentMaxTokens = 0;

        for (const line of lines) {
            try {
                const entry = JSON.parse(line);

                if (entry.isSidechain === true) continue;
                if (entry.isApiErrorMessage === true) continue;

                const usage = entry.message?.usage || entry.usage;
                if (!usage) continue;

                const cumulativeTokens =
                    (usage.input_tokens || 0) +
                    (usage.output_tokens || 0) +
                    (usage.cache_read_input_tokens || 0) +
                    (usage.cache_creation_input_tokens || 0);

                if (cumulativeTokens > currentMaxTokens) {
                    currentMaxTokens = cumulativeTokens;
                }
            } catch (e) {
                continue;
            }
        }

        if (currentMaxTokens < maxCumulativeTokens) {
            baseline += maxCumulativeTokens;
            maxCumulativeTokens = currentMaxTokens;
        } else {
            maxCumulativeTokens = currentMaxTokens;
        }

        const totalTokens = baseline + maxCumulativeTokens;

        fs.writeFileSync(
            cacheFile,
            JSON.stringify({
                timestamp: now,
                totalTokens,
                baseline,
                maxCumulativeTokens,
            })
        );

        return totalTokens;
    } catch (error) {
        return 0;
    }
}

function getModelContextLimit(modelId) {
    const modelLimits = {
        'claude-opus-4-6': 1000000,
        'claude-opus-4-5': 1000000,
        'claude-opus-4-1': 1000000,
        'claude-opus-4': 1000000,
        'claude-sonnet-4-6': 200000,
        'claude-sonnet-4-5': 200000,
        'claude-sonnet-4': 200000,
        'claude-haiku-4-5': 200000,
        'claude-haiku-4': 200000,
    };

    for (const [key, limit] of Object.entries(modelLimits)) {
        if (modelId && modelId.toLowerCase().includes(key)) {
            return limit;
        }
    }

    return 200000;
}

function calculateContextPercentage(transcriptPath, modelId, contextWindow) {
    if (contextWindow && typeof contextWindow.used_percentage === 'number') {
        return contextWindow.used_percentage;
    }

    if (
        contextWindow &&
        contextWindow.current_usage &&
        typeof contextWindow.context_window_size === 'number' &&
        contextWindow.context_window_size > 0
    ) {
        const usage = contextWindow.current_usage;
        const totalInputTokens =
            (usage.input_tokens || 0) +
            (usage.cache_read_input_tokens || 0) +
            (usage.cache_creation_input_tokens || 0);
        return Math.min((totalInputTokens / contextWindow.context_window_size) * 100, 100);
    }

    if (!transcriptPath || !fs.existsSync(transcriptPath)) {
        return 0;
    }

    try {
        const content = fs.readFileSync(transcriptPath, 'utf8');
        const lines = content
            .trim()
            .split('\n')
            .filter((line) => line.trim());

        let mostRecentEntry = null;
        let mostRecentTimestamp = 0;

        for (const line of lines) {
            try {
                const entry = JSON.parse(line);

                if (entry.isSidechain === true) continue;
                if (entry.isApiErrorMessage === true) continue;

                const usage = entry.message?.usage || entry.usage;
                if (!usage) continue;

                const timestamp = new Date(entry.timestamp || 0).getTime();
                if (!timestamp) continue;

                if (timestamp > mostRecentTimestamp) {
                    mostRecentTimestamp = timestamp;
                    mostRecentEntry = entry;
                }
            } catch (e) {
                continue;
            }
        }

        if (!mostRecentEntry) {
            return 0;
        }

        const usage = mostRecentEntry.message?.usage || mostRecentEntry.usage;
        const totalInputTokens =
            (usage.input_tokens || 0) +
            (usage.cache_read_input_tokens || 0) +
            (usage.cache_creation_input_tokens || 0);

        const contextLimit =
            (contextWindow && contextWindow.context_window_size > 0
                ? contextWindow.context_window_size
                : null) || getModelContextLimit(modelId);
        const percentage = (totalInputTokens / contextLimit) * 100;
        return Math.min(percentage, 100);
    } catch (error) {
        return 0;
    }
}

function extractTokensFromEntry(entry) {
    const tokens = {
        inputTokens: 0,
        outputTokens: 0,
        cacheCreationTokens: 0,
        cacheReadTokens: 0,
        totalTokens: 0,
    };

    const sources = [];
    const isAssistant = entry.type === 'assistant';

    if (isAssistant) {
        if (entry.message?.usage) sources.push(entry.message.usage);
        if (entry.usage) sources.push(entry.usage);
    } else {
        if (entry.usage) sources.push(entry.usage);
        if (entry.message?.usage) sources.push(entry.message.usage);
    }
    sources.push(entry);

    for (const source of sources) {
        if (!source || typeof source !== 'object') continue;

        const inputFields = ['input_tokens', 'inputTokens', 'prompt_tokens'];
        const outputFields = ['output_tokens', 'outputTokens', 'completion_tokens'];
        const cacheCreationFields = [
            'cache_creation_tokens',
            'cache_creation_input_tokens',
            'cacheCreationInputTokens',
        ];
        const cacheReadFields = [
            'cache_read_input_tokens',
            'cache_read_tokens',
            'cacheReadInputTokens',
        ];

        const input = extractField(source, inputFields);
        const output = extractField(source, outputFields);
        const cacheCreation = extractField(source, cacheCreationFields);
        const cacheRead = extractField(source, cacheReadFields);

        if (input > 0 || output > 0) {
            tokens.inputTokens = input;
            tokens.outputTokens = output;
            tokens.cacheCreationTokens = cacheCreation;
            tokens.cacheReadTokens = cacheRead;
            tokens.totalTokens = input + output + cacheCreation + cacheRead;
            break;
        }
    }

    return tokens;
}

function extractField(obj, fieldNames) {
    for (const field of fieldNames) {
        const value = obj[field];
        if (value && value > 0) {
            return parseInt(value, 10);
        }
    }
    return 0;
}

function formatTokenCount(tokens) {
    if (tokens >= 1000000) {
        return `${(tokens / 1000000).toFixed(1)}M`;
    } else if (tokens >= 1000) {
        return `${(tokens / 1000).toFixed(1)}k`;
    }
    return tokens.toString();
}

function formatContextPercentage(percentage) {
    const formatted = percentage.toFixed(1) + '%';
    let color = 'green';

    if (percentage >= 80) {
        color = 'red';
    } else if (percentage >= 50) {
        color = 'yellow';
    }

    return { text: formatted, color };
}
