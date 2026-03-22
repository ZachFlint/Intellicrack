use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, stdout, Write as IoWrite};
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use crossterm::{ExecutableCommand, cursor};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Layout, Margin};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Padding, Paragraph};
use ratatui::Terminal;
use serde::Deserialize;

const MAX_INSTANCES: u8 = 9;
const CONFIG_FILE: &str = "config.toml";
const LOG_FILE: &str = "launcher.log";

struct Logger {
    file: Option<fs::File>,
    path: PathBuf,
}

impl Logger {
    fn new() -> Self {
        let dir = get_temp_dir();
        let _ = fs::create_dir_all(&dir);
        let path = dir.join(LOG_FILE);
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .ok();
        let mut logger = Logger { file, path };
        logger.info("=== CLI Launcher started ===");
        logger
    }

    fn write(&mut self, level: &str, msg: &str) {
        let ts = Self::timestamp();
        let line = format!("[{ts}] [{level}] {msg}\n");
        if let Some(ref mut f) = self.file {
            let _ = f.write_all(line.as_bytes());
            let _ = f.flush();
        }
    }

    fn info(&mut self, msg: &str) {
        self.write("INFO", msg);
    }

    fn warn(&mut self, msg: &str) {
        self.write("WARN", msg);
    }

    fn error(&mut self, msg: &str) {
        self.write("ERROR", msg);
    }

    fn log_path(&self) -> &Path {
        &self.path
    }

    #[cfg(windows)]
    fn timestamp() -> String {
        use windows_sys::Win32::System::SystemInformation::GetLocalTime;
        let mut st = windows_sys::Win32::Foundation::SYSTEMTIME {
            wYear: 0,
            wMonth: 0,
            wDayOfWeek: 0,
            wDay: 0,
            wHour: 0,
            wMinute: 0,
            wSecond: 0,
            wMilliseconds: 0,
        };
        unsafe { GetLocalTime(&mut st) }
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds
        )
    }

    #[cfg(not(windows))]
    fn timestamp() -> String {
        let d = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        format!("{}.{:03}", d.as_secs(), d.subsec_millis())
    }
}

enum AppMode {
    Normal,
    EditingDir { buffer: String, cursor_pos: usize },
    ConfirmDir { dir: String },
}

#[derive(Deserialize, Default, Clone)]
struct Settings {
    #[serde(default)]
    update_preamble: Vec<String>,
}

struct AppState {
    tools: Vec<ToolConfig>,
    colors: Vec<Color>,
    name_width: usize,
    list_state: ListState,
    counts: Vec<u8>,
    marked: Vec<bool>,
    mode: AppMode,
    status_msg: Option<(String, Color)>,
    settings: Settings,
    config_tool_count: usize,
}

impl AppState {
    fn new(tools: Vec<ToolConfig>, settings: Settings) -> Self {
        let config_tool_count = tools.len();
        let mut all_tools = tools;
        all_tools.push(Self::virtual_update_entry());
        let colors: Vec<Color> = all_tools.iter().map(|t| parse_hex_color(&t.color)).collect();
        let name_width = all_tools.iter().map(|t| t.name.len()).max().unwrap_or(10) + 2;
        let len = all_tools.len();
        let mut list_state = ListState::default();
        list_state.select(Some(0));
        AppState {
            tools: all_tools,
            colors,
            name_width,
            list_state,
            counts: vec![1; len],
            marked: vec![false; len],
            mode: AppMode::Normal,
            status_msg: None,
            settings,
            config_tool_count,
        }
    }

    fn selected(&self) -> usize {
        self.list_state.selected().unwrap_or(0)
    }

    fn tool_count(&self) -> usize {
        self.tools.len()
    }

    fn num_marked(&self) -> usize {
        self.marked.iter().filter(|&&m| m).count()
    }

    fn is_virtual(&self, index: usize) -> bool {
        index >= self.config_tool_count
    }

    fn has_update(&self, index: usize) -> bool {
        self.is_virtual(index) || !self.tools[index].update_commands.is_empty()
    }

    fn virtual_update_entry() -> ToolConfig {
        ToolConfig {
            name: "Update All Tools".to_string(),
            description: "Update all CLI coding tools".to_string(),
            color: "#FFA500".to_string(),
            allow_multi: false,
            working_dir: None,
            shell: default_shell(),
            commands: vec![],
            update_commands: vec![],
        }
    }

    fn reload_tools(&mut self, new_tools: Vec<ToolConfig>, settings: Settings) {
        let config_tool_count = new_tools.len();
        let mut all_tools = new_tools;
        all_tools.push(Self::virtual_update_entry());
        let n = all_tools.len();
        self.colors = all_tools.iter().map(|t| parse_hex_color(&t.color)).collect();
        self.name_width = all_tools.iter().map(|t| t.name.len()).max().unwrap_or(10) + 2;
        self.tools = all_tools;
        self.settings = settings;
        self.config_tool_count = config_tool_count;
        self.counts.resize(n, 1);
        self.marked.resize(n, false);
        if self.selected() >= n && n > 0 {
            self.list_state.select(Some(n - 1));
        }
    }
}

#[derive(Deserialize)]
struct Config {
    tool: Vec<ToolConfig>,
    #[serde(default)]
    settings: Settings,
}

#[derive(Deserialize)]
struct ToolConfig {
    name: String,
    description: String,
    color: String,
    #[serde(default = "default_true")]
    allow_multi: bool,
    #[serde(default)]
    working_dir: Option<String>,
    #[serde(default = "default_shell")]
    shell: String,
    commands: Vec<String>,
    #[serde(default)]
    update_commands: Vec<String>,
}

fn default_true() -> bool {
    true
}

fn default_shell() -> String {
    "pwsh".to_string()
}

fn parse_hex_color(hex: &str) -> Color {
    let hex = hex.trim_start_matches('#');
    if hex.len() == 6 {
        let r = u8::from_str_radix(&hex[0..2], 16).unwrap_or(200);
        let g = u8::from_str_radix(&hex[2..4], 16).unwrap_or(200);
        let b = u8::from_str_radix(&hex[4..6], 16).unwrap_or(200);
        Color::Rgb(r, g, b)
    } else {
        Color::White
    }
}

fn get_config_path() -> PathBuf {
    env::current_exe()
        .unwrap_or_else(|_| PathBuf::from("."))
        .parent()
        .unwrap_or(Path::new("."))
        .join(CONFIG_FILE)
}

fn get_temp_dir() -> PathBuf {
    env::temp_dir().join("cli-launcher")
}

fn load_config(path: &Path, log: &mut Logger) -> Result<(Vec<ToolConfig>, Settings), String> {
    log.info(&format!("Loading config from: {}", path.display()));
    let content =
        fs::read_to_string(path).map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
    let config: Config = toml::from_str(&content)
        .map_err(|e| format!("Failed to parse {}: {e}", path.display()))?;
    if config.tool.is_empty() {
        return Err("No tools defined in config".to_string());
    }
    log.info(&format!("Loaded {} tools from config", config.tool.len()));
    Ok((config.tool, config.settings))
}

fn save_working_dir(
    config_path: &Path,
    tool_name: &str,
    new_dir: &str,
    log: &mut Logger,
) -> Result<(), String> {
    log.info(&format!("Saving working_dir for '{tool_name}': {new_dir}"));
    let content = fs::read_to_string(config_path).map_err(|e| e.to_string())?;
    let mut doc: toml_edit::DocumentMut =
        content.parse().map_err(|e: toml_edit::TomlError| e.to_string())?;
    if let Some(tools) = doc.get_mut("tool").and_then(|v| v.as_array_of_tables_mut()) {
        for tool in tools.iter_mut() {
            if tool.get("name").and_then(|v| v.as_str()) == Some(tool_name) {
                tool["working_dir"] = toml_edit::value(new_dir);
                break;
            }
        }
    }
    fs::write(config_path, doc.to_string()).map_err(|e| e.to_string())?;
    log.info("Config saved");
    Ok(())
}

fn pick_folder_dialog(log: &mut Logger) -> Option<String> {
    log.info("Opening folder browser dialog");
    let pwsh = find_pwsh(log)?;
    let output = Command::new(pwsh)
        .args([
            "-NoProfile",
            "-NoLogo",
            "-Command",
            "Add-Type -AssemblyName System.Windows.Forms; \
             $f = New-Object System.Windows.Forms.FolderBrowserDialog; \
             $f.Description = 'Select working directory'; \
             $f.ShowNewFolderButton = $true; \
             if ($f.ShowDialog() -eq 'OK') { $f.SelectedPath }",
        ])
        .creation_flags(0x08000000)
        .output()
        .ok()?;
    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() {
        log.warn("Folder dialog cancelled");
        None
    } else {
        log.info(&format!("Folder selected: {path}"));
        Some(path)
    }
}

fn find_pwsh(log: &mut Logger) -> Option<PathBuf> {
    let candidates = [
        "pwsh.exe",
        "C:\\Program Files\\PowerShell\\7\\pwsh.exe",
        "C:\\Program Files (x86)\\PowerShell\\7\\pwsh.exe",
    ];
    for candidate in &candidates {
        let p = Path::new(candidate);
        if p.is_absolute() && p.exists() {
            return Some(p.to_path_buf());
        }
        if Command::new("where")
            .arg(candidate)
            .creation_flags(0x08000000)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            return Some(PathBuf::from(candidate));
        }
    }
    log.error("pwsh.exe not found");
    None
}

fn write_temp_script(tool: &ToolConfig, log: &mut Logger) -> Option<PathBuf> {
    let dir = get_temp_dir();
    fs::create_dir_all(&dir).ok()?;
    let mut script = String::new();
    if let Some(ref wd) = tool.working_dir {
        script.push_str(&format!(
            "if (-not (Test-Path -LiteralPath '{wd}')) {{\n\
             \x20   Write-Host \"Directory not found: {wd}\" -ForegroundColor Red\n\
             \x20   Write-Host ''\n\
             \x20   Write-Host 'Press any key to exit...' -ForegroundColor Yellow\n\
             \x20   $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')\n\
             \x20   exit 1\n\
             }}\n\
             Set-Location '{wd}'\n"
        ));
    }
    script.push_str("try {\n");
    for cmd in &tool.commands {
        script.push_str(cmd);
        script.push('\n');
    }
    script.push_str(
        "} catch {\n\
         \x20   Write-Host \"Error: $_\" -ForegroundColor Red\n\
         }\n\
         \n\
         Write-Host ''\n\
         Write-Host 'Press any key to exit...' -ForegroundColor Yellow\n\
         $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')\n",
    );
    let filename = format!("{}.ps1", tool.name.replace(' ', ""));
    let path = dir.join(filename);
    fs::write(&path, &script).ok()?;
    log.info(&format!("Wrote temp script: {}", path.display()));
    Some(path)
}

fn write_update_script(
    tool: &ToolConfig,
    preamble: &[String],
    log: &mut Logger,
) -> Option<PathBuf> {
    let dir = get_temp_dir();
    fs::create_dir_all(&dir).ok()?;
    let mut script = String::new();
    for line in preamble {
        script.push_str(line);
        script.push('\n');
    }
    script.push_str(&format!(
        "Write-Host '--- Updating {} ---' -ForegroundColor Cyan\n",
        tool.name
    ));
    script.push_str("Write-Host ''\n");
    for cmd in &tool.update_commands {
        script.push_str(cmd);
        script.push('\n');
    }
    script.push_str("Write-Host ''\n");
    script.push_str(&format!(
        "Write-Host '{} updated!' -ForegroundColor Green\n",
        tool.name
    ));
    script.push_str("Write-Host ''\n");
    script.push_str("Write-Host 'Press any key to continue...' -ForegroundColor Yellow\n");
    script.push_str("$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')\n");
    let filename = format!("Update_{}.ps1", tool.name.replace(' ', ""));
    let path = dir.join(filename);
    fs::write(&path, &script).ok()?;
    log.info(&format!("Wrote update script: {}", path.display()));
    Some(path)
}

fn write_update_all_script(
    tools: &[ToolConfig],
    config_tool_count: usize,
    preamble: &[String],
    log: &mut Logger,
) -> Option<PathBuf> {
    let dir = get_temp_dir();
    fs::create_dir_all(&dir).ok()?;
    let mut script = String::new();
    for line in preamble {
        script.push_str(line);
        script.push('\n');
    }
    script.push_str("Write-Host 'Updating all CLI coding tools...' -ForegroundColor Magenta\n");
    script.push_str("Write-Host ''\n");
    for tool in &tools[..config_tool_count] {
        if tool.update_commands.is_empty() {
            continue;
        }
        script.push_str(&format!(
            "Write-Host '--- Updating {} ---' -ForegroundColor Cyan\n",
            tool.name
        ));
        for cmd in &tool.update_commands {
            script.push_str(cmd);
            script.push('\n');
        }
        script.push_str(&format!(
            "Write-Host '{} updated!' -ForegroundColor Green\n",
            tool.name
        ));
        script.push_str("Write-Host ''\n");
    }
    script.push_str("Write-Host 'All CLI coding tools updated!' -ForegroundColor Magenta\n");
    script.push_str("Write-Host ''\n");
    script.push_str("Write-Host 'Press any key to continue...' -ForegroundColor Yellow\n");
    script.push_str("$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')\n");
    let path = dir.join("UpdateAllTools.ps1");
    fs::write(&path, &script).ok()?;
    log.info(&format!("Wrote update-all script: {}", path.display()));
    Some(path)
}

fn launch_update(script_path: &Path, log: &mut Logger) {
    let pwsh = match find_pwsh(log) {
        Some(p) => p,
        None => return,
    };
    match Command::new("cmd")
        .env("SKIP_PIXI_ACTIVATE", "1")
        .creation_flags(0x08000000)
        .raw_arg("/c start \"\" /max")
        .raw_arg(format!("\"{}\"", pwsh.display()))
        .raw_arg("-NoLogo -ExecutionPolicy Bypass -File")
        .raw_arg(format!("\"{}\"", script_path.display()))
        .spawn()
    {
        Ok(_) => log.info(&format!("Update launched: {}", script_path.display())),
        Err(e) => log.error(&format!("Failed to launch update: {e}")),
    }
}

fn launch_tool_once(tool: &ToolConfig, log: &mut Logger) {
    log.info(&format!("Launching '{}'", tool.name));
    match tool.shell.as_str() {
        "wsl" => {
            let wsl_cmds = tool.commands.join(" && ");
            let full_cmd = if let Some(ref dir) = tool.working_dir {
                format!("cd '{}' && {}", dir.replace('\\', "/"), wsl_cmds)
            } else {
                wsl_cmds
            };
            match Command::new("cmd")
                .env("SKIP_PIXI_ACTIVATE", "1")
                .creation_flags(0x08000000)
                .raw_arg("/c start \"\" /max wsl bash -lc")
                .raw_arg(format!("\"{full_cmd}\""))
                .spawn()
            {
                Ok(_) => log.info(&format!("'{}' launched via WSL", tool.name)),
                Err(e) => log.error(&format!("Failed to launch '{}': {e}", tool.name)),
            }
        }
        _ => {
            let script_path = match write_temp_script(tool, log) {
                Some(p) => p,
                None => return,
            };
            let pwsh = match find_pwsh(log) {
                Some(p) => p,
                None => return,
            };
            match Command::new("cmd")
                .env("SKIP_PIXI_ACTIVATE", "1")
                .creation_flags(0x08000000)
                .raw_arg("/c start \"\" /max")
                .raw_arg(format!("\"{}\"", pwsh.display()))
                .raw_arg("-NoLogo -ExecutionPolicy Bypass -File")
                .raw_arg(format!("\"{}\"", script_path.display()))
                .spawn()
            {
                Ok(_) => log.info(&format!("'{}' launched", tool.name)),
                Err(e) => log.error(&format!("Failed to launch '{}': {e}", tool.name)),
            }
        }
    }
}

fn launch_tool(tool: &ToolConfig, count: u8, log: &mut Logger) {
    for i in 0..count {
        launch_tool_once(tool, log);
        if i + 1 < count {
            thread::sleep(Duration::from_millis(500));
        }
    }
}

fn launch_batch(tools: &[ToolConfig], marked: &[bool], counts: &[u8], log: &mut Logger) {
    let mut first = true;
    for (i, tool) in tools.iter().enumerate() {
        if marked[i] {
            if !first {
                thread::sleep(Duration::from_millis(300));
            }
            launch_tool(tool, counts[i], log);
            first = false;
        }
    }
}

fn open_log_file(log: &mut Logger) {
    let path = log.log_path().to_path_buf();
    let _ = Command::new("cmd")
        .creation_flags(0x08000000)
        .raw_arg(format!("/c start \"\" notepad \"{}\"", path.display()))
        .spawn();
}

#[cfg(windows)]
struct ConsoleModeGuard {
    stdin_handle: windows_sys::Win32::Foundation::HANDLE,
    stdout_handle: windows_sys::Win32::Foundation::HANDLE,
    stdin_mode: u32,
    stdout_mode: u32,
}

#[cfg(windows)]
impl ConsoleModeGuard {
    fn save() -> Option<Self> {
        use windows_sys::Win32::System::Console::{
            GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
        };
        unsafe {
            let stdin_handle = GetStdHandle(STD_INPUT_HANDLE);
            let stdout_handle = GetStdHandle(STD_OUTPUT_HANDLE);
            let mut stdin_mode: u32 = 0;
            let mut stdout_mode: u32 = 0;
            if GetConsoleMode(stdin_handle, &mut stdin_mode) == 0
                || GetConsoleMode(stdout_handle, &mut stdout_mode) == 0
            {
                return None;
            }
            Some(ConsoleModeGuard {
                stdin_handle,
                stdout_handle,
                stdin_mode,
                stdout_mode,
            })
        }
    }

    fn restore(&self) {
        use windows_sys::Win32::System::Console::{
            FlushConsoleInputBuffer, SetConsoleMode,
        };
        unsafe {
            SetConsoleMode(self.stdin_handle, self.stdin_mode);
            SetConsoleMode(self.stdout_handle, self.stdout_mode);
            FlushConsoleInputBuffer(self.stdin_handle);
        }
    }
}

fn main() -> io::Result<()> {
    let mut log = Logger::new();
    let config_path = get_config_path();
    let (tools, settings) = match load_config(&config_path, &mut log) {
        Ok(ts) => ts,
        Err(e) => {
            eprintln!("{e}");
            eprintln!("Expected config at: {}", config_path.display());
            eprintln!("Press Enter to exit...");
            let mut buf = String::new();
            let _ = io::stdin().read_line(&mut buf);
            return Ok(());
        }
    };

    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    stdout().execute(cursor::Hide)?;

    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;
    let mut state = AppState::new(tools, settings);

    let result = run_app(&mut terminal, &mut state, &config_path, &mut log);

    disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;
    stdout().execute(cursor::Show)?;

    if let Err(ref e) = result {
        eprintln!("Error: {e}");
    }
    Ok(())
}

fn build_help(num_marked: usize) -> Line<'static> {
    let d = Style::default().fg(Color::Rgb(80, 80, 100));
    let mut s = vec![
        Span::styled(" [", d),
        Span::styled("\u{2191}\u{2193}", Style::default().fg(Color::Rgb(100, 180, 255)).add_modifier(Modifier::BOLD)),
        Span::styled("] Nav  ", d),
        Span::styled("[", d),
        Span::styled("\u{2190}\u{2192}", Style::default().fg(Color::Rgb(255, 200, 80)).add_modifier(Modifier::BOLD)),
        Span::styled("] Inst  ", d),
        Span::styled("[", d),
        Span::styled("Space", Style::default().fg(Color::Rgb(200, 150, 255)).add_modifier(Modifier::BOLD)),
        Span::styled("] Mark  ", d),
        Span::styled("[", d),
        Span::styled("d", Style::default().fg(Color::Rgb(255, 180, 100)).add_modifier(Modifier::BOLD)),
        Span::styled("] Dir  ", d),
        Span::styled("[", d),
        Span::styled("b", Style::default().fg(Color::Rgb(255, 180, 100)).add_modifier(Modifier::BOLD)),
        Span::styled("] Browse  ", d),
        Span::styled("[", d),
        Span::styled("l", Style::default().fg(Color::Rgb(150, 200, 255)).add_modifier(Modifier::BOLD)),
        Span::styled("] Log  ", d),
        Span::styled("[", d),
        Span::styled("u", Style::default().fg(Color::Rgb(255, 165, 0)).add_modifier(Modifier::BOLD)),
        Span::styled("] Update  ", d),
        Span::styled("[", d),
        Span::styled("Enter", Style::default().fg(Color::Rgb(100, 255, 150)).add_modifier(Modifier::BOLD)),
    ];
    if num_marked > 0 {
        s.push(Span::styled(format!("] Launch {num_marked}  "), d));
    } else {
        s.push(Span::styled("] Launch  ", d));
    }
    s.push(Span::styled("[", d));
    s.push(Span::styled("q", Style::default().fg(Color::Rgb(255, 100, 100)).add_modifier(Modifier::BOLD)));
    s.push(Span::styled("] Quit", d));
    Line::from(s)
}

fn draw_ui(frame: &mut ratatui::Frame, state: &mut AppState) {
    let area = frame.area();
    let num_marked = state.num_marked();
    let selected = state.selected();
    let nw = state.name_width;

    frame.render_widget(
        Block::default().borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Rgb(40, 40, 50)))
            .style(Style::default().bg(Color::Rgb(0, 0, 0))),
        area,
    );

    let inner = area.inner(Margin::new(2, 1));
    let is_editing = matches!(state.mode, AppMode::EditingDir { .. });
    let is_confirming = matches!(state.mode, AppMode::ConfirmDir { .. });
    let bottom_h = if is_editing { 6 } else if is_confirming { 5 } else { 3 };
    let chunks = Layout::vertical([Constraint::Length(5), Constraint::Min(0), Constraint::Length(bottom_h)]).split(inner);

    let subtitle = if num_marked > 0 {
        Span::styled(format!("  {num_marked} tool(s) marked for batch launch"), Style::default().fg(Color::Rgb(200, 150, 255)).add_modifier(Modifier::BOLD))
    } else if let Some((ref msg, color)) = state.status_msg {
        Span::styled(format!("  {msg}"), Style::default().fg(color))
    } else {
        Span::styled("  Select a tool to launch", Style::default().fg(Color::Rgb(140, 140, 160)))
    };

    frame.render_widget(Paragraph::new(vec![
        Line::from(Span::styled("  CLI Coding Tool Launcher", Style::default().fg(Color::Rgb(100, 180, 255)).add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from(subtitle),
    ]), chunks[0]);

    let items: Vec<ListItem> = state.tools.iter().enumerate().map(|(i, tool)| {
        let sel = state.list_state.selected() == Some(i);
        let mk = state.marked.get(i).copied().unwrap_or(false);
        let c = state.colors.get(i).copied().unwrap_or(Color::White);
        let ns = if sel { Style::default().fg(c).add_modifier(Modifier::BOLD) } else { Style::default().fg(c) };
        let cs = if mk { Style::default().fg(Color::Rgb(200, 150, 255)).add_modifier(Modifier::BOLD) } else { Style::default().fg(Color::Rgb(50, 50, 70)) };
        let cv = state.counts.get(i).copied().unwrap_or(1);
        let cd = if tool.allow_multi {
            let cc = if cv > 1 { Color::Rgb(255, 200, 80) } else { Color::Rgb(70, 70, 90) };
            Span::styled(format!(" x{cv}"), Style::default().fg(cc).add_modifier(if cv > 1 { Modifier::BOLD } else { Modifier::empty() }))
        } else { Span::raw("") };
        let dd = if sel && !state.is_virtual(i) {
            Span::styled(format!("  [{}]", tool.working_dir.as_deref().unwrap_or("(none)")), Style::default().fg(Color::Rgb(80, 120, 80)))
        } else { Span::raw("") };
        ListItem::new(Line::from(vec![
            Span::styled(if sel { " > " } else { "   " }, Style::default().fg(Color::Rgb(100, 180, 255)).add_modifier(Modifier::BOLD)),
            Span::styled(if mk { "[*] " } else { "[ ] " }, cs),
            Span::styled(format!("{:<nw$}", tool.name), ns),
            cd,
            Span::styled(format!("  {}", tool.description), Style::default().fg(Color::Rgb(100, 100, 120))),
            dd,
        ]))
    }).collect();

    frame.render_stateful_widget(
        List::new(items)
            .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Rgb(40, 40, 50))).padding(Padding::new(1, 1, 1, 1)))
            .highlight_style(Style::default().bg(Color::Rgb(20, 25, 35)).add_modifier(Modifier::BOLD)),
        chunks[1], &mut state.list_state,
    );

    match state.mode {
        AppMode::EditingDir { ref buffer, cursor_pos } => {
            let ec = Layout::vertical([Constraint::Length(3), Constraint::Length(1), Constraint::Length(2)]).split(chunks[2]);
            let tn = if selected < state.tools.len() { &state.tools[selected].name } else { "" };
            frame.render_widget(Paragraph::new(Line::from(vec![Span::styled(format!("  Working directory for {tn}: "), Style::default().fg(Color::Rgb(255, 180, 100)))])), ec[0]);
            let bc = &buffer[..cursor_pos];
            let cc = buffer.get(cursor_pos..cursor_pos + 1).unwrap_or(" ");
            let ac = if cursor_pos < buffer.len() { &buffer[cursor_pos + 1..] } else { "" };
            frame.render_widget(Paragraph::new(Line::from(vec![
                Span::styled("  ", Style::default()),
                Span::styled(bc.to_string(), Style::default().fg(Color::White)),
                Span::styled(cc.to_string(), Style::default().fg(Color::Black).bg(Color::White)),
                Span::styled(ac.to_string(), Style::default().fg(Color::White)),
            ])), ec[1]);
            frame.render_widget(Paragraph::new(Line::from(vec![Span::styled("  [Enter] Confirm  [Esc] Cancel", Style::default().fg(Color::Rgb(80, 80, 100)))])), ec[2]);
        }
        AppMode::ConfirmDir { ref dir } => {
            let tn = if selected < state.tools.len() { &state.tools[selected].name } else { "" };
            let ec = Layout::vertical([Constraint::Length(2), Constraint::Length(1), Constraint::Length(2)]).split(chunks[2]);
            frame.render_widget(Paragraph::new(Line::from(vec![
                Span::styled(format!("  {tn}"), Style::default().fg(Color::Rgb(100, 180, 255)).add_modifier(Modifier::BOLD)),
                Span::styled(format!(" -> {dir}"), Style::default().fg(Color::White)),
            ])), ec[0]);
            let d = Style::default().fg(Color::Rgb(80, 80, 100));
            frame.render_widget(Paragraph::new(Line::from(vec![
                Span::styled("  [", d),
                Span::styled("s", Style::default().fg(Color::Rgb(100, 255, 150)).add_modifier(Modifier::BOLD)),
                Span::styled("] Save to config  ", d),
                Span::styled("[", d),
                Span::styled("o", Style::default().fg(Color::Rgb(255, 200, 80)).add_modifier(Modifier::BOLD)),
                Span::styled("] One-time launch  ", d),
                Span::styled("[", d),
                Span::styled("Esc", Style::default().fg(Color::Rgb(255, 100, 100)).add_modifier(Modifier::BOLD)),
                Span::styled("] Cancel", d),
            ])), ec[2]);
        }
        AppMode::Normal => {
            frame.render_widget(Paragraph::new(build_help(num_marked)).alignment(Alignment::Center), chunks[2]);
        }
    }
}

fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    state: &mut AppState,
    config_path: &Path,
    log: &mut Logger,
) -> io::Result<()> {
    terminal.draw(|f| draw_ui(f, state))?;

    loop {
        if !event::poll(Duration::from_millis(100))? {
            continue;
        }
        let evt = event::read()?;
        let tc = state.tool_count();
        let sel = state.selected();
        let nm = state.num_marked();

        match evt {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                match state.mode {
                    AppMode::EditingDir { ref mut buffer, ref mut cursor_pos } => match key.code {
                        KeyCode::Esc => { state.mode = AppMode::Normal; }
                        KeyCode::Enter => {
                            let new_dir = buffer.trim().to_string();
                            if !new_dir.is_empty() {
                                state.mode = AppMode::ConfirmDir { dir: new_dir };
                            } else {
                                state.mode = AppMode::Normal;
                            }
                        }
                        KeyCode::Backspace => { if *cursor_pos > 0 { buffer.remove(*cursor_pos - 1); *cursor_pos -= 1; } }
                        KeyCode::Delete => { if *cursor_pos < buffer.len() { buffer.remove(*cursor_pos); } }
                        KeyCode::Left => { if *cursor_pos > 0 { *cursor_pos -= 1; } }
                        KeyCode::Right => { if *cursor_pos < buffer.len() { *cursor_pos += 1; } }
                        KeyCode::Home => *cursor_pos = 0,
                        KeyCode::End => *cursor_pos = buffer.len(),
                        KeyCode::Char(c) => { buffer.insert(*cursor_pos, c); *cursor_pos += 1; }
                        _ => {}
                    },
                    AppMode::ConfirmDir { ref dir } => match key.code {
                        KeyCode::Char('s') | KeyCode::Char('S') => {
                            if sel < state.tools.len() {
                                let tn = state.tools[sel].name.clone();
                                let d = dir.clone();
                                state.tools[sel].working_dir = Some(d.clone());
                                match save_working_dir(config_path, &tn, &d, log) {
                                    Ok(()) => state.status_msg = Some((format!("Directory saved: {d}"), Color::Rgb(100, 255, 150))),
                                    Err(e) => state.status_msg = Some((format!("Save failed: {e}"), Color::Rgb(255, 80, 80))),
                                }
                            }
                            state.mode = AppMode::Normal;
                        }
                        KeyCode::Char('o') | KeyCode::Char('O') => {
                            if sel < state.tools.len() {
                                let d = dir.clone();
                                state.tools[sel].working_dir = Some(d.clone());
                                log.info(&format!("One-time dir for '{}': {d}", state.tools[sel].name));
                                state.status_msg = Some((format!("One-time directory: {d}"), Color::Rgb(255, 200, 80)));
                            }
                            state.mode = AppMode::Normal;
                        }
                        KeyCode::Esc => {
                            state.mode = AppMode::Normal;
                            state.status_msg = None;
                        }
                        _ => {}
                    },
                    AppMode::Normal => match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => { log.info("User quit"); return Ok(()); }
                        KeyCode::Up | KeyCode::Char('k') => {
                            state.list_state.select(Some(if sel == 0 { tc - 1 } else { sel - 1 }));
                            state.status_msg = None;
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            state.list_state.select(Some(if sel >= tc - 1 { 0 } else { sel + 1 }));
                            state.status_msg = None;
                        }
                        KeyCode::Right | KeyCode::Char('+') | KeyCode::Char('=') => {
                            if sel < tc && state.tools[sel].allow_multi
                                && state.counts.get(sel).copied().unwrap_or(1) < MAX_INSTANCES
                                && let Some(c) = state.counts.get_mut(sel)
                            { *c += 1; }
                        }
                        KeyCode::Left | KeyCode::Char('-') => {
                            if sel < tc && state.tools[sel].allow_multi
                                && state.counts.get(sel).copied().unwrap_or(1) > 1
                                && let Some(c) = state.counts.get_mut(sel)
                            { *c -= 1; }
                        }
                        KeyCode::Char(' ') => {
                            if sel < tc && !state.is_virtual(sel)
                                && let Some(m) = state.marked.get_mut(sel)
                            { *m = !*m; }
                        }
                        KeyCode::Char('d') => {
                            if sel < tc && !state.is_virtual(sel) {
                                let cur = state.tools[sel].working_dir.clone().unwrap_or_default();
                                let len = cur.len();
                                state.mode = AppMode::EditingDir { buffer: cur, cursor_pos: len };
                                state.status_msg = None;
                            }
                        }
                        KeyCode::Char('b') => {
                            if sel < tc && !state.is_virtual(sel) {
                                disable_raw_mode()?;
                                stdout().execute(LeaveAlternateScreen)?;
                                stdout().execute(cursor::Show)?;
                                #[cfg(windows)]
                                let console_guard = ConsoleModeGuard::save();
                                let picked = pick_folder_dialog(log);
                                #[cfg(windows)]
                                if let Some(ref guard) = console_guard {
                                    guard.restore();
                                }
                                enable_raw_mode()?;
                                stdout().execute(EnterAlternateScreen)?;
                                stdout().execute(cursor::Hide)?;
                                terminal.clear()?;
                                if let Some(dir) = picked {
                                    state.mode = AppMode::ConfirmDir { dir };
                                }
                            }
                        }
                        KeyCode::Char('l') => { open_log_file(log); }
                        KeyCode::Char('u') => {
                            if sel < tc {
                                if state.is_virtual(sel) {
                                    if let Some(path) = write_update_all_script(
                                        &state.tools,
                                        state.config_tool_count,
                                        &state.settings.update_preamble,
                                        log,
                                    ) {
                                        launch_update(&path, log);
                                        state.status_msg = Some(("Updating all tools...".to_string(), Color::Rgb(255, 165, 0)));
                                    }
                                } else if state.has_update(sel) {
                                    let name = state.tools[sel].name.clone();
                                    if let Some(path) = write_update_script(
                                        &state.tools[sel],
                                        &state.settings.update_preamble,
                                        log,
                                    ) {
                                        launch_update(&path, log);
                                        state.status_msg = Some((format!("Updating {name}..."), Color::Rgb(255, 165, 0)));
                                    }
                                } else {
                                    let name = &state.tools[sel].name;
                                    state.status_msg = Some((format!("No update command for {name}"), Color::Rgb(255, 200, 80)));
                                }
                            }
                        }
                        KeyCode::Char('r') => {
                            match load_config(config_path, log) {
                                Ok((new_tools, new_settings)) => {
                                    let n = new_tools.len();
                                    state.reload_tools(new_tools, new_settings);
                                    state.status_msg = Some((format!("Config reloaded ({n} tools)"), Color::Rgb(100, 255, 150)));
                                }
                                Err(e) => { state.status_msg = Some((format!("Reload failed: {e}"), Color::Rgb(255, 80, 80))); }
                            }
                        }
                        KeyCode::Home => { state.list_state.select(Some(0)); state.status_msg = None; }
                        KeyCode::End => { state.list_state.select(Some(tc - 1)); state.status_msg = None; }
                        KeyCode::Enter => {
                            if nm > 0 {
                                launch_batch(&state.tools[..state.config_tool_count], &state.marked, &state.counts, log);
                                log.info("Batch launch complete, exiting");
                                return Ok(());
                            } else if sel < tc {
                                if state.is_virtual(sel) {
                                    if let Some(path) = write_update_all_script(
                                        &state.tools,
                                        state.config_tool_count,
                                        &state.settings.update_preamble,
                                        log,
                                    ) {
                                        launch_update(&path, log);
                                    }
                                    log.info("Update All launched, exiting");
                                    return Ok(());
                                }
                                launch_tool(&state.tools[sel], state.counts.get(sel).copied().unwrap_or(1), log);
                                log.info("Launch complete, exiting");
                                return Ok(());
                            }
                        }
                        _ => {}
                    },
                }
            }
            Event::Resize(_, _) => {}
            _ => { continue; }
        }

        terminal.draw(|f| draw_ui(f, state))?;
    }
}
