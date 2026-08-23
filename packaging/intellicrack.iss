; Intellicrack installer script (Inno Setup 6).
;
; This script installs the staged Intellicrack platform produced under
; build\stage. Every [Files] Source is anchored to the {#StageRoot} define so
; the staged layout maps 1:1 onto the install directory. The installer writes
; NO environment or PATH entries: the frozen launcher (Intellicrack.exe)
; assembles an ephemeral child environment at runtime, so the machine and user
; environments are never touched.

#define AppName "Intellicrack"
#define AppPublisher "Zachary Flint"
#define AppUrl "https://github.com/zacharyflint/intellicrack"
#define AppVersion "0.1.0a1"
#define AppVerNumeric "0.1.0.0"
#define AppExeName "Intellicrack.exe"
#define StageRoot "..\build\stage"
#define AppIcon StageRoot + "\app\src\intellicrack\assets\icon.ico"

[Setup]
AppId={{4B2F6E3A-9C1D-4A87-B0E5-1F3C7D8A2E64}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppUrl}
AppSupportURL={#AppUrl}
AppUpdatesURL={#AppUrl}
AppComments=Unified desktop platform for binary-analysis workflows, bridging external RE tools and AI providers into one workspace.
VersionInfoVersion={#AppVerNumeric}
VersionInfoProductVersion={#AppVerNumeric}
VersionInfoCompany={#AppPublisher}
VersionInfoDescription={#AppName} Setup
VersionInfoProductName={#AppName}
VersionInfoCopyright=Copyright (C) 2026 {#AppPublisher}
ArchitecturesAllowed=x64os
ArchitecturesInstallIn64BitMode=x64os
PrivilegesRequired=admin
DefaultDirName={autopf}\Intellicrack
DefaultGroupName=Intellicrack
DisableProgramGroupPage=yes
Compression=lzma2/ultra64
SolidCompression=yes
OutputBaseFilename=Intellicrack-Setup
SetupIconFile={#AppIcon}
UninstallDisplayIcon={app}\{#AppExeName}
UninstallDisplayName={#AppName} {#AppVersion}
WizardStyle=modern dynamic
LicenseFile=..\LICENSE
CloseApplications=yes
RestartApplications=yes
SetupLogging=yes
AppMutex=Global\IntellicrackSingleInstance
WizardImageFile=wizard\banner-light.png
WizardImageFileDynamicDark=wizard\banner-dark.png
WizardSmallImageFile=wizard\small.png

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Types]
Name: "full"; Description: "Full installation (all bundled tools and components)"
Name: "compact"; Description: "Compact installation (core platform only)"
Name: "custom"; Description: "Custom installation"; Flags: iscustom

[Components]
Name: "core"; Description: "Intellicrack core platform and Python runtime"; Types: full compact custom; Flags: fixed
Name: "tool_ghidra"; Description: "Ghidra 11.4.2 disassembler and a private, self-contained JDK 21 (uncheck to use your own Ghidra install, configured in Tools -> Tool Settings -> Browse to your install)"; Types: full
Name: "tool_radare2"; Description: "radare2 reverse-engineering framework (uncheck to use your own install, configured in Tools -> Tool Settings -> Browse to your install)"; Types: full
Name: "tool_rizin"; Description: "Cutter / rizin analysis toolkit (uncheck to use your own install, configured in Tools -> Tool Settings -> Browse to your install)"; Types: full
Name: "tool_x64dbg"; Description: "x64dbg debugger with the Intellicrack bridge plugins (uncheck to use your own install, configured in Tools -> Tool Settings -> Browse to your install)"; Types: full
Name: "tool_nasm"; Description: "NASM assembler (uncheck to use your own install, configured in Tools -> Tool Settings -> Browse to your install)"; Types: full
Name: "tool_pmd"; Description: "PMD source analyzer (uncheck to use your own install, configured in Tools -> Tool Settings -> Browse to your install)"; Types: full
Name: "tool_gjf"; Description: "google-java-format formatter (uncheck to use your own install, configured in Tools -> Tool Settings -> Browse to your install)"; Types: full
Name: "tool_adobeinjector"; Description: "Adobe injector helper (uncheck to use your own install, configured in Tools -> Tool Settings -> Browse to your install)"; Types: full
Name: "tool_idmactivator"; Description: "IDM activator helper (uncheck to use your own install, configured in Tools -> Tool Settings -> Browse to your install)"; Types: full
Name: "tool_windowspatch"; Description: "Windows activation helper (uncheck to use your own install, configured in Tools -> Tool Settings -> Browse to your install)"; Types: full
Name: "ml"; Description: "Local ML inference stack (multi-GB: torch + transformers)"; Types: full
Name: "hexbench"; Description: "Hexbench: standalone enhanced hex GUI that runs the hexcore runtime in a separate process, independent of the main app"; Types: full
Name: "qemu"; Description: "Bundled QEMU sandbox backend"; Types: full
Name: "qemu\debianguest"; Description: "Ready-to-run Debian sandbox guest image (~800 MB)"; Types: full

[Files]
; Core platform: launcher, Python runtime, application source, vendor data.
Source: "{#StageRoot}\{#AppExeName}"; DestDir: "{app}"; Flags: ignoreversion; Components: core
Source: "{#StageRoot}\runtime\*"; DestDir: "{app}\runtime"; Flags: ignoreversion recursesubdirs createallsubdirs; Components: core
Source: "{#StageRoot}\app\src\*"; DestDir: "{app}\app\src"; Flags: ignoreversion recursesubdirs createallsubdirs; Components: core
Source: "{#StageRoot}\app\vendor\*"; DestDir: "{app}\app\vendor"; Flags: ignoreversion recursesubdirs createallsubdirs; Components: core

; External tools (each optional, one component per tool).
Source: "{#StageRoot}\app\tools\ghidra\*"; DestDir: "{app}\app\tools\ghidra"; Flags: ignoreversion recursesubdirs createallsubdirs; Components: tool_ghidra
Source: "{#StageRoot}\app\tools\radare2\*"; DestDir: "{app}\app\tools\radare2"; Flags: ignoreversion recursesubdirs createallsubdirs; Components: tool_radare2
Source: "{#StageRoot}\app\tools\cutter\*"; DestDir: "{app}\app\tools\cutter"; Flags: ignoreversion recursesubdirs createallsubdirs; Components: tool_rizin
Source: "{#StageRoot}\app\tools\x64dbg\*"; DestDir: "{app}\app\tools\x64dbg"; Flags: ignoreversion recursesubdirs createallsubdirs; Components: tool_x64dbg
Source: "{#StageRoot}\app\tools\NASM\*"; DestDir: "{app}\app\tools\NASM"; Flags: ignoreversion recursesubdirs createallsubdirs; Components: tool_nasm
Source: "{#StageRoot}\app\tools\pmd\*"; DestDir: "{app}\app\tools\pmd"; Flags: ignoreversion recursesubdirs createallsubdirs; Components: tool_pmd
Source: "{#StageRoot}\app\tools\google-java-format\*"; DestDir: "{app}\app\tools\google-java-format"; Flags: ignoreversion recursesubdirs createallsubdirs; Components: tool_gjf
Source: "{#StageRoot}\app\tools\AdobeInjector\*"; DestDir: "{app}\app\tools\AdobeInjector"; Flags: ignoreversion recursesubdirs createallsubdirs; Components: tool_adobeinjector
Source: "{#StageRoot}\app\tools\IDMActivator\*"; DestDir: "{app}\app\tools\IDMActivator"; Flags: ignoreversion recursesubdirs createallsubdirs; Components: tool_idmactivator
Source: "{#StageRoot}\app\tools\WindowsPatch\*"; DestDir: "{app}\app\tools\WindowsPatch"; Flags: ignoreversion recursesubdirs createallsubdirs; Components: tool_windowspatch
Source: "{#StageRoot}\app\tools\qemu\*"; DestDir: "{app}\app\tools\qemu"; Flags: ignoreversion recursesubdirs createallsubdirs; Components: qemu

; ML overlay: merges into the runtime site-packages tree.
Source: "{#StageRoot}\ml_overlay\Lib\site-packages\*"; DestDir: "{app}\runtime\Lib\site-packages"; Flags: ignoreversion recursesubdirs createallsubdirs; Components: ml

; Hexbench standalone GUI.
Source: "{#StageRoot}\hexbench\*"; DestDir: "{app}\hexbench"; Flags: ignoreversion recursesubdirs createallsubdirs; Components: hexbench

; Optional bundled Debian sandbox guest image.
Source: "{#StageRoot}\qemu-guest\*"; DestDir: "{app}\qemu-guest"; Flags: ignoreversion recursesubdirs createallsubdirs; Components: qemu\debianguest

[Tasks]
Name: "startmenuicon"; Description: "Create a Start menu shortcut"; GroupDescription: "Shortcuts:"
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"; Flags: unchecked
Name: "enablehyperv"; Description: "Enable the Windows Hypervisor Platform (required for QEMU/WHPX sandbox acceleration; may require a reboot)"; GroupDescription: "Sandbox acceleration:"; Components: qemu
Name: "defenderexclusion"; Description: "Add a Microsoft Defender exclusion for the install folder (the bundled activation/injection utilities can trip antivirus heuristics)"; GroupDescription: "Antivirus:"; Flags: unchecked

[Icons]
Name: "{group}\Intellicrack"; Filename: "{app}\{#AppExeName}"; IconFilename: "{app}\{#AppExeName}"; Tasks: startmenuicon
Name: "{group}\Hexbench"; Filename: "{app}\hexbench\hexbench.exe"; IconFilename: "{app}\hexbench\hexbench.exe"; Components: hexbench; Tasks: startmenuicon
Name: "{group}\Uninstall Intellicrack"; Filename: "{uninstallexe}"; Tasks: startmenuicon
Name: "{autodesktop}\Intellicrack"; Filename: "{app}\{#AppExeName}"; IconFilename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExeName}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallDelete]
; Regenerable per-install config/cache created at runtime beside the launcher.
Type: filesandordirs; Name: "{app}\.intellicrack"
Type: files; Name: "{app}\intellicrack.log"
; Sweep any remaining runtime-generated leftovers (logs, __pycache__) LAST so the
; install directory is fully removed. Runs after Inno removes installed files.
Type: filesandordirs; Name: "{app}"

[Code]
const
  { Minimum free space (bytes) recommended when the ML stack is selected: 12 GB. }
  MinMlFreeBytes = 12884901888;
  { DISM exit code signalling the feature was enabled but a reboot is required. }
  DismRebootRequired = 3010;

var
  { Set when enabling the Windows Hypervisor Platform reports a pending reboot,
    so NeedRestart can request one at the end of the wizard. }
  HyperVRestartNeeded: Boolean;

{ Add or remove the Microsoft Defender folder exclusion for the install dir.
  Verb is 'Add' or 'Remove'; the matching *-MpPreference cmdlet is invoked. }
procedure SetDefenderExclusion(const Verb: String);
var
  ResultCode: Integer;
  Params: String;
begin
  Params := '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "' + Verb
    + '-MpPreference -ExclusionPath ''' + ExpandConstant('{app}') + '''"';
  if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'), Params,
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    Log('Defender exclusion (' + Verb + ') could not be launched.')
  else
    Log('Defender exclusion (' + Verb + ') returned exit code ' + IntToStr(ResultCode) + '.');
end;

{ Enable the Windows Hypervisor Platform feature via DISM. A 3010 exit code
  means the feature is staged but a reboot is required to activate it. }
procedure EnableHyperVPlatform();
var
  ResultCode: Integer;
begin
  if Exec(ExpandConstant('{sys}\dism.exe'),
      '/online /enable-feature /featurename:HypervisorPlatform /all /norestart',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    Log('DISM HypervisorPlatform enable returned exit code ' + IntToStr(ResultCode) + '.');
    if ResultCode = DismRebootRequired then
      HyperVRestartNeeded := True;
  end
  else
    Log('DISM could not be launched to enable the Windows Hypervisor Platform.');
end;

function InitializeSetup(): Boolean;
var
  Version: TWindowsVersion;
begin
  Result := True;

  { Guard: refuse anything that is not a 64-bit install. }
  if not Is64BitInstallMode() then
  begin
    MsgBox('Intellicrack requires 64-bit (x64) Windows. Setup cannot continue on this system.',
      mbCriticalError, MB_OK);
    Result := False;
    Exit;
  end;

  { Guard: require Windows 10 (build 10240) or newer. }
  GetWindowsVersionEx(Version);
  if (Version.Major < 10) then
  begin
    MsgBox('Intellicrack requires Windows 10 or Windows 11 (64-bit). '
      + 'The detected Windows version is not supported.',
      mbCriticalError, MB_OK);
    Result := False;
    Exit;
  end;

  { Surface the portable-build minimum-CPU note (x86-64-v2 baseline). The
    bundled hexcore .pyd is compiled for the x86-64-v2 microarchitecture level
    (SSE4.2 + POPCNT). Systems older than that baseline cannot load it. Skipped
    for silent/unattended installs so it never blocks an automated run. }
  if not WizardSilent() then
    MsgBox('Note: Intellicrack ships a portable native runtime built for the '
      + 'x86-64-v2 CPU baseline (SSE4.2 and POPCNT, roughly Intel Nehalem / AMD '
      + 'Bulldozer and newer). Older processors are not supported.',
      mbInformation, MB_OK);
end;

{ Append custom notes to the ready-to-install page. }
function UpdateReadyMemo(Space, NewLine, MemoUserInfoInfo, MemoDirInfo,
  MemoTypeInfo, MemoComponentsInfo, MemoGroupInfo, MemoTasksInfo: String): String;
var
  Memo: String;
  SandboxNote: String;
begin
  Memo := '';

  if MemoDirInfo <> '' then
    Memo := Memo + MemoDirInfo + NewLine + NewLine;
  if MemoTypeInfo <> '' then
    Memo := Memo + MemoTypeInfo + NewLine + NewLine;
  if MemoComponentsInfo <> '' then
    Memo := Memo + MemoComponentsInfo + NewLine + NewLine;
  if MemoGroupInfo <> '' then
    Memo := Memo + MemoGroupInfo + NewLine + NewLine;
  if MemoTasksInfo <> '' then
    Memo := Memo + MemoTasksInfo + NewLine + NewLine;

  Memo := Memo + 'CPU requirement:' + NewLine
    + Space + 'x86-64-v2 baseline (SSE4.2 + POPCNT) required by the native runtime.'
    + NewLine + NewLine;

  { Light detection note for the sandbox virtualization backends. }
  if FileExists(ExpandConstant('{sys}\WindowsSandbox.exe')) then
    SandboxNote := Space + 'Windows Sandbox appears to be available on this system.'
  else
    SandboxNote := Space + 'Windows Sandbox was not detected; enable "Windows Sandbox" '
      + 'in Windows Features, or use the bundled QEMU backend.';

  Memo := Memo + 'Sandbox backends:' + NewLine + SandboxNote + NewLine
    + Space + 'The QEMU/WHPX backend can be enabled from the final page of this installer.';

  Result := Memo;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  FreeBytes: Int64;
  TotalBytes: Int64;
  DriveRoot: String;
begin
  Result := True;

  { When leaving the ready page and the ML stack is selected, verify the
    install drive has enough free space and warn (do not block) otherwise.
    Skipped under silent/unattended installs, which proceed without prompting. }
  if (CurPageID = wpReady) and (not WizardSilent())
    and WizardIsComponentSelected('ml') then
  begin
    DriveRoot := ExtractFileDrive(ExpandConstant('{app}'));
    if DriveRoot <> '' then
      DriveRoot := DriveRoot + '\';

    if GetSpaceOnDisk64(DriveRoot, FreeBytes, TotalBytes) then
    begin
      if FreeBytes < MinMlFreeBytes then
      begin
        if MsgBox('The local ML inference stack (torch + transformers) needs '
          + 'about 12 GB of free space, but the target drive appears to have '
          + 'less than that available. Continue anyway?',
          mbConfirmation, MB_YESNO) = IDNO then
          Result := False;
      end;
    end;
  end;
end;

{ Run the selected post-install system actions with the installer's elevation:
  enable the Windows Hypervisor Platform and/or add the Defender exclusion. }
procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    if WizardIsTaskSelected('enablehyperv') then
      EnableHyperVPlatform();
    if WizardIsTaskSelected('defenderexclusion') then
      SetDefenderExclusion('Add');
  end;
end;

{ Request a reboot only when enabling the Hypervisor Platform reported 3010. }
function NeedRestart(): Boolean;
begin
  Result := HyperVRestartNeeded;
end;

{ On uninstall, undo the Defender exclusion (harmless if none was added) and
  offer to purge the out-of-install user tool cache. Credential files under the
  install directory are never touched here. }
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ToolsDir: String;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    SetDefenderExclusion('Remove');

    ToolsDir := ExpandConstant('{localappdata}\intellicrack_tools');
    if DirExists(ToolsDir) then
    begin
      if MsgBox('Also remove the Intellicrack tool cache outside the install '
          + 'folder (' + ToolsDir + ')?' + #13#10
          + 'Your credential files are not affected.',
          mbConfirmation, MB_YESNO) = IDYES then
        DelTree(ToolsDir, True, True, True);
    end;
  end;
end;
