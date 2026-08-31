const { spawn } = require("child_process");
const path = require("path");

const PROJECT_ROOT = "D:\\Intellicrack";
const PROJECT_URI = "file:///D:/Intellicrack";
const PYTHON_PATH = "d:\\Intellicrack\\.pixi\\envs\\default\\python.exe";
const VENV_PATH = "d:\\Intellicrack\\.pixi\\envs";
const VENV_NAME = "default";
const LANGSERVER = path.join(
  PROJECT_ROOT, ".pixi", "envs", "default", "Scripts", "basedpyright-langserver.exe"
);

const PYTHON_SETTINGS = {
  pythonPath: PYTHON_PATH,
  venvPath: VENV_PATH,
  venv: VENV_NAME,
};

const child = spawn(LANGSERVER, ["--stdio"], {
  cwd: PROJECT_ROOT,
  stdio: ["pipe", "pipe", "pipe"],
});

function packMsg(obj) {
  const body = Buffer.from(JSON.stringify(obj), "utf8");
  const header = `Content-Length: ${body.length}\r\n\r\n`;
  return Buffer.concat([Buffer.from(header, "ascii"), body]);
}

function extractMessages(buf) {
  const msgs = [];
  let pos = 0;
  while (pos < buf.length) {
    const headerEnd = buf.indexOf("\r\n\r\n", pos);
    if (headerEnd === -1) break;
    const header = buf.slice(pos, headerEnd).toString("ascii");
    const m = header.match(/Content-Length:\s*(\d+)/i);
    if (!m) break;
    const len = parseInt(m[1], 10);
    const bodyStart = headerEnd + 4;
    if (buf.length < bodyStart + len) break;
    msgs.push(buf.slice(bodyStart, bodyStart + len).toString("utf8"));
    pos = bodyStart + len;
  }
  return { msgs, remaining: buf.slice(pos) };
}

let stdinBuf = Buffer.alloc(0);
process.stdin.on("data", (chunk) => {
  stdinBuf = Buffer.concat([stdinBuf, chunk]);
  const { msgs, remaining } = extractMessages(stdinBuf);
  stdinBuf = remaining;

  for (const raw of msgs) {
    let msg;
    try { msg = JSON.parse(raw); } catch { child.stdin.write(packMsg(raw)); continue; }

    if (msg.method === "initialize" && msg.params) {
      msg.params.rootUri = PROJECT_URI;
      msg.params.rootPath = PROJECT_ROOT;
      msg.params.workspaceFolders = [{ uri: PROJECT_URI, name: "Intellicrack" }];
      if (!msg.params.capabilities) msg.params.capabilities = {};
      if (!msg.params.capabilities.window) msg.params.capabilities.window = {};
      msg.params.capabilities.window.workDoneProgress = true;
      if (!msg.params.capabilities.workspace) msg.params.capabilities.workspace = {};
      msg.params.capabilities.workspace.configuration = true;
      msg.params.capabilities.workspace.didChangeConfiguration = { dynamicRegistration: true };
    }

    child.stdin.write(packMsg(msg));
  }
});

let stdoutBuf = Buffer.alloc(0);
child.stdout.on("data", (chunk) => {
  stdoutBuf = Buffer.concat([stdoutBuf, chunk]);
  const { msgs, remaining } = extractMessages(stdoutBuf);
  stdoutBuf = remaining;

  for (const raw of msgs) {
    let msg;
    try { msg = JSON.parse(raw); } catch { process.stdout.write(packMsg(raw)); continue; }

    if (msg.id !== undefined && msg.method) {
      let response;
      switch (msg.method) {
        case "workspace/configuration":
          response = {
            jsonrpc: "2.0", id: msg.id,
            result: (msg.params.items || []).map((item) => {
              if (item.section === "python")
                return PYTHON_SETTINGS;
              return null;
            }),
          };
          break;
        case "window/workDoneProgress/create":
        case "client/registerCapability":
          response = { jsonrpc: "2.0", id: msg.id, result: null };
          break;
        default:
          response = { jsonrpc: "2.0", id: msg.id, result: null };
          break;
      }
      child.stdin.write(packMsg(response));
      continue;
    }

    process.stdout.write(packMsg(msg));
  }
});

child.stderr.pipe(process.stderr);
child.on("exit", (code) => process.exit(code || 0));
process.on("SIGTERM", () => child.kill("SIGTERM"));
process.on("SIGINT", () => child.kill("SIGINT"));
