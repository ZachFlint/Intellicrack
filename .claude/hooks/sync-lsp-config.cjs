const fs = require("fs");
const path = require("path");

const CLAUDE_HOME = process.env.HOME || process.env.USERPROFILE || "";

const LSP_JSON_PATHS = [
  path.join(
    CLAUDE_HOME,
    ".claude",
    "plugins",
    "cache",
    "claude-code-lsps",
    "basedpyright",
    "0.1.0",
    ".lsp.json"
  ),
  path.join(
    CLAUDE_HOME,
    ".claude",
    "plugins",
    "marketplaces",
    "claude-code-lsps",
    "basedpyright",
    ".lsp.json"
  ),
];

const MARKETPLACE_JSON_PATH = path.join(
  CLAUDE_HOME,
  ".claude",
  "plugins",
  "marketplaces",
  "claude-code-lsps",
  ".claude-plugin",
  "marketplace.json"
);

const MARKETPLACE_PLUGIN_NAME = "basedpyright";
const WORKSPACE_FOLDER = "D:/Intellicrack";
const WRAPPER_SCRIPT = "D:/Intellicrack/.claude/hooks/basedpyright-wrapper.cjs";
const NODE_PATH = "C:/Users/zachf/AppData/Roaming/fnm/aliases/default/node.exe";
const PYTHON_PATH = "d:\\Intellicrack\\.pixi\\envs\\default\\python.exe";
const VENV_PATH = "d:\\Intellicrack\\.pixi\\envs";
const VENV_NAME = "default";

function buildExpectedLspServers() {
  const pythonSettings = {
    pythonPath: PYTHON_PATH,
    venvPath: VENV_PATH,
    venv: VENV_NAME,
  };
  return {
    python: {
      command: NODE_PATH,
      args: [WRAPPER_SCRIPT],
      extensionToLanguage: { ".py": "python", ".pyi": "python", ".pyw": "python" },
      transport: "stdio",
      workspaceFolder: WORKSPACE_FOLDER,
      initializationOptions: { settings: { python: { ...pythonSettings } } },
      settings: { python: { ...pythonSettings } },
      maxRestarts: 3,
    },
  };
}

function syncConfigAt(lspJsonPath, expectedJson) {
  let currentJson = "";
  try {
    currentJson = fs.readFileSync(lspJsonPath, "utf8");
  } catch {
    // file doesn't exist yet
  }

  if (currentJson.trim() !== expectedJson.trim()) {
    try {
      const dir = path.dirname(lspJsonPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      fs.writeFileSync(lspJsonPath, expectedJson, "utf8");
    } catch {
      // silent
    }
  }
}

function syncLspJsonFiles(expectedJson) {
  for (const lspJsonPath of LSP_JSON_PATHS) {
    syncConfigAt(lspJsonPath, expectedJson);
  }
}

function syncMarketplaceJson(expectedLspServers) {
  let marketplace;
  try {
    marketplace = JSON.parse(fs.readFileSync(MARKETPLACE_JSON_PATH, "utf8"));
  } catch {
    return;
  }

  if (!Array.isArray(marketplace.plugins)) {
    return;
  }

  const plugin = marketplace.plugins.find(
    (entry) => entry && entry.name === MARKETPLACE_PLUGIN_NAME
  );
  if (!plugin) {
    return;
  }

  const expectedJson = JSON.stringify(expectedLspServers);
  const currentJson = JSON.stringify(plugin.lspServers || null);
  if (currentJson === expectedJson) {
    return;
  }

  plugin.lspServers = expectedLspServers;

  try {
    fs.writeFileSync(
      MARKETPLACE_JSON_PATH,
      JSON.stringify(marketplace, null, 2) + "\n",
      "utf8"
    );
  } catch {
    // silent
  }
}

function syncConfig() {
  const expected = buildExpectedLspServers();
  const expectedJson = JSON.stringify(expected, null, 4) + "\n";

  syncLspJsonFiles(expectedJson);
  syncMarketplaceJson(expected);
}

syncConfig();
