const fs = require("fs");
const path = require("path");

const LSP_JSON_PATH = path.join(
  process.env.HOME || process.env.USERPROFILE || "",
  ".claude",
  "plugins",
  "cache",
  "claude-code-lsps",
  "basedpyright",
  "0.1.0",
  ".lsp.json"
);

const WORKSPACE_FOLDER = "D:/Intellicrack";
const WRAPPER_SCRIPT = "D:/Intellicrack/.claude/hooks/basedpyright-wrapper.cjs";
const PYTHON_PATH = "d:\\Intellicrack\\.pixi\\envs\\default\\python.exe";
const VENV_PATH = "d:\\Intellicrack\\.pixi\\envs";
const VENV_NAME = "default";

const ANALYSIS_SETTINGS = {
  extraPaths: ["d:/intellicrack/src"],
  typeCheckingMode: "strict",
  pythonVersion: "3.13",
  pythonPlatform: "Windows",
  useLibraryCodeForTypes: false,
  analyzeUnannotatedFunctions: true,
  enableTypeIgnoreComments: true,
  strictListInference: true,
  strictDictionaryInference: true,
  strictSetInference: true,
  reportMissingImports: "warning",
  reportMissingTypeStubs: false,
  reportMissingModuleSource: "warning",
  reportUndefinedVariable: "error",
  reportGeneralTypeIssues: "error",
};

function buildExpected() {
  const pythonSettings = {
    pythonPath: PYTHON_PATH,
    venvPath: VENV_PATH,
    venv: VENV_NAME,
  };
  const settingsBlock = {
    python: { ...pythonSettings },
    basedpyright: { analysis: { ...ANALYSIS_SETTINGS } },
  };
  return {
    python: {
      command: "node",
      args: [WRAPPER_SCRIPT],
      extensionToLanguage: { ".py": "python", ".pyi": "python", ".pyw": "python" },
      transport: "stdio",
      workspaceFolder: WORKSPACE_FOLDER,
      initializationOptions: { settings: { ...settingsBlock } },
      settings: { ...settingsBlock },
      maxRestarts: 3,
    },
  };
}

function syncConfig() {
  const expected = buildExpected();
  const expectedJson = JSON.stringify(expected, null, 4) + "\n";

  let currentJson = "";
  try {
    currentJson = fs.readFileSync(LSP_JSON_PATH, "utf8");
  } catch {
    // file doesn't exist yet
  }

  if (currentJson.trim() !== expectedJson.trim()) {
    try {
      const dir = path.dirname(LSP_JSON_PATH);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      fs.writeFileSync(LSP_JSON_PATH, expectedJson, "utf8");
    } catch {
      // silent
    }
  }
}

syncConfig();
