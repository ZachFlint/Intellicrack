#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');

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
        const workingDir = data.workspace?.current_dir || process.cwd();

        const gitStats = getGitStats(workingDir);

        const contextPercentage = calculateContextPercentage(
            transcriptPath,
            modelId,
            data.context_window
        );

        const { text: contextText, color: contextColor } =
            formatContextPercentage(contextPercentage);

        const contextColored =
            contextColor === 'green' ? green : contextColor === 'yellow' ? yellow : brightRed;

        const colorFor = (name) =>
            name === 'green' ? green : name === 'yellow' ? yellow : brightRed;

        const fiveHour = formatRateLimit(data.rate_limits?.five_hour);
        const sevenDay = formatRateLimit(data.rate_limits?.seven_day);

        let rateLimitSegment = '';
        if (fiveHour) {
            rateLimitSegment +=
                ` ${brightRed}|${reset} 5h: ${colorFor(fiveHour.color)}${fiveHour.text}${reset}`;
        }
        if (sevenDay) {
            rateLimitSegment +=
                ` ${brightRed}|${reset} 7d: ${colorFor(sevenDay.color)}${sevenDay.text}${reset}`;
        }

        console.log(
            `${brightMagenta}${projectName}${reset} ${brightRed}|${reset} ` +
                `${cyan}[${model}]${reset} ${brightRed}|${reset} ` +
                `Context: ${contextColored}${contextText}${reset} ${brightRed}|${reset} ` +
                `+${brightGreen}${gitStats.added}${reset} ` +
                `-${brightRed}${gitStats.removed}${reset} ${brightRed}|${reset} ` +
                `Last commit: ${yellow}${gitStats.lastCommitAge}${reset}` +
                rateLimitSegment
        );
    } catch (error) {
        console.log('[Claude] Intellicrack | Error');
    }
});

let gitCache = { timestamp: 0, result: null };

function getGitStats(workingDir) {
    const now = Date.now();
    if (gitCache.result && now - gitCache.timestamp < 2000) {
        return gitCache.result;
    }

    const fallback = { added: 0, removed: 0, lastCommitAge: 'unknown' };

    try {
        const execOpts = {
            cwd: workingDir,
            encoding: 'utf8',
            stdio: ['pipe', 'pipe', 'pipe'],
            timeout: 3000,
            windowsHide: true,
        };

        let added = 0;
        let removed = 0;

        try {
            const unstaged = execSync('git diff --numstat', execOpts).trim();
            const staged = execSync('git diff --cached --numstat', execOpts).trim();
            const combined = [unstaged, staged].filter(Boolean).join('\n');

            for (const line of combined.split('\n')) {
                if (!line.trim()) continue;
                const parts = line.split('\t');
                if (parts.length < 3) continue;
                const a = parseInt(parts[0], 10);
                const r = parseInt(parts[1], 10);
                if (!isNaN(a)) added += a;
                if (!isNaN(r)) removed += r;
            }
        } catch (e) {
            // not a git repo or git not available
        }

        let lastCommitAge = 'no commits';
        try {
            const timestamp = execSync('git log -1 --format=%ct', execOpts).trim();
            const commitEpoch = parseInt(timestamp, 10);
            if (!isNaN(commitEpoch)) {
                lastCommitAge = formatRelativeTime(commitEpoch);
            }
        } catch (e) {
            // no commits yet
        }

        const result = { added, removed, lastCommitAge };
        gitCache = { timestamp: now, result };
        return result;
    } catch (error) {
        return fallback;
    }
}

function formatRelativeTime(epochSeconds) {
    const nowSeconds = Math.floor(Date.now() / 1000);
    const diffSeconds = nowSeconds - epochSeconds;

    if (diffSeconds < 0) return 'just now';
    if (diffSeconds < 60) return `${diffSeconds}s ago`;

    const minutes = Math.floor(diffSeconds / 60);
    if (minutes < 60) return `${minutes}m ago`;

    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h ago`;

    const days = Math.floor(hours / 24);
    if (days < 30) return `${days}d ago`;

    const months = Math.floor(days / 30);
    if (months < 12) return `${months}mo ago`;

    const years = Math.floor(days / 365);
    return `${years}y ago`;
}

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

function formatRateLimit(window) {
    if (!window || typeof window.used_percentage !== 'number') {
        return null;
    }

    const percentage = Math.max(0, Math.min(window.used_percentage, 100));
    const formatted = Math.round(percentage) + '%';
    let color = 'green';

    if (percentage >= 80) {
        color = 'red';
    } else if (percentage >= 50) {
        color = 'yellow';
    }

    return { text: formatted, color };
}
