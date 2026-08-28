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
; Version is single-sourced: packaging/stage.ps1 regenerates version.generated.iss
; from src/intellicrack/_metadata.py, and tests/packaging/test_version_consistency.py
; gates that every copy of the version across the repository agrees.
#include "version.generated.iss"
#define AppExeName "Intellicrack.exe"
#define HexbenchExeName "Hexbench.exe"
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
; Show the welcome page so the wizard banner is seen up front, not only at the end.
DisableWelcomePage=no
Compression=lzma2/ultra64
; Non-solid so a Compact/custom install does not decompress the whole archive just
; to skip the multi-GB optional components the user did not select.
SolidCompression=no
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

[InstallDelete]
; Clear install-managed trees before files are copied so upgrades never leave
; stale files shadowing new ones on PYTHONPATH, and so deselecting a component
; (for example the multi-GB ML overlay merged into the runtime site-packages)
; actually removes it. All user-writable state now lives under %LOCALAPPDATA%,
; never under {app}, so nothing here can touch credentials, config, logs, or data.
Type: filesandordirs; Name: "{app}\runtime"
Type: filesandordirs; Name: "{app}\app\src"
Type: filesandordirs; Name: "{app}\app\tools"
Type: filesandordirs; Name: "{app}\app\vendor"
Type: filesandordirs; Name: "{app}\hexbench"
Type: filesandordirs; Name: "{app}\qemu-guest"

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

; Hexbench standalone GUI: the package source, plus the bootstrapper that runs
; it on the bundled runtime. The editor is not frozen separately -- it imports
; hexcore and webview from {app}\runtime like the main application does.
Source: "{#StageRoot}\hexbench\*"; DestDir: "{app}\hexbench"; Flags: ignoreversion recursesubdirs createallsubdirs; Components: hexbench
Source: "{#StageRoot}\{#HexbenchExeName}"; DestDir: "{app}"; Flags: ignoreversion; Components: hexbench

; Optional bundled Debian sandbox guest image.
Source: "{#StageRoot}\qemu-guest\*"; DestDir: "{app}\qemu-guest"; Flags: ignoreversion recursesubdirs createallsubdirs; Components: qemu\debianguest

[Tasks]
Name: "startmenuicon"; Description: "Create a Start menu shortcut"; GroupDescription: "Shortcuts:"
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"; Flags: unchecked
Name: "enablehyperv"; Description: "Enable the Windows Hypervisor Platform (required for QEMU/WHPX sandbox acceleration; may require a reboot)"; GroupDescription: "Sandbox acceleration:"; Components: qemu; Flags: unchecked
Name: "defenderexclusion"; Description: "Add a Microsoft Defender exclusion for the install folder (the bundled activation/injection utilities can trip antivirus heuristics)"; GroupDescription: "Antivirus:"; Flags: unchecked

[Icons]
Name: "{group}\Intellicrack"; Filename: "{app}\{#AppExeName}"; IconFilename: "{app}\{#AppExeName}"; Tasks: startmenuicon
Name: "{group}\Hexbench"; Filename: "{app}\{#HexbenchExeName}"; IconFilename: "{app}\{#HexbenchExeName}"; Components: hexbench; Tasks: startmenuicon
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
  AppPath: String;
begin
  { Escape single quotes in the install path (PowerShell single-quoted strings
    double an embedded quote) so a directory such as C:\Users\O'Brien\App cannot
    break out of the -ExclusionPath literal. Windows paths cannot contain the
    double quote that wraps the -Command script, so escaping the single quote is
    the complete hardening. }
  AppPath := ExpandConstant('{app}');
  StringChangeEx(AppPath, '''', '''''', True);
  Params := '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "' + Verb
    + '-MpPreference -ExclusionPath ''' + AppPath + '''"';
  if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'), Params,
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    Log('Defender exclusion (' + Verb + ') could not be launched.');
    if (Verb = 'Add') and (not WizardSilent()) then
      MsgBox('The Microsoft Defender exclusion could not be applied automatically. '
        + 'If the bundled utilities are quarantined, add an exclusion for the install '
        + 'folder manually under Windows Security.', mbInformation, MB_OK);
  end
  else
  begin
    Log('Defender exclusion (' + Verb + ') returned exit code ' + IntToStr(ResultCode) + '.');
    if (Verb = 'Add') and (ResultCode <> 0) and (not WizardSilent()) then
      MsgBox('The Microsoft Defender exclusion command returned a non-zero exit code ('
        + IntToStr(ResultCode) + '). The exclusion may not be active; you can add it '
        + 'manually under Windows Security.', mbInformation, MB_OK);
  end;
end;

{ Enable the Windows Hypervisor Platform feature via DISM. A 3010 exit code
  means the feature is staged but a reboot is required to activate it. }
procedure EnableHyperVPlatform();
var
  ResultCode: Integer;
  ProgressPage: TOutputProgressWizardPage;
  Launched: Boolean;
begin
  { Run DISM through ExecAndLogOutput behind a progress page. ExecAndLogOutput
    pumps the message queue while the feature is enabling, so the wizard stays
    responsive instead of going "Not Responding" during the blocking call. }
  ProgressPage := CreateOutputProgressPage('Windows Hypervisor Platform',
    'Enabling the Windows Hypervisor Platform for QEMU/WHPX sandbox acceleration. This can take a minute.');
  ProgressPage.SetProgress(0, 100);
  ProgressPage.Show();
  try
    Launched := ExecAndLogOutput(ExpandConstant('{sys}\dism.exe'),
      '/online /enable-feature /featurename:HypervisorPlatform /all /norestart',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode, nil);
  finally
    ProgressPage.Hide();
  end;

  if not Launched then
  begin
    Log('DISM could not be launched to enable the Windows Hypervisor Platform.');
    if not WizardSilent() then
      MsgBox('Could not launch DISM to enable the Windows Hypervisor Platform. '
        + 'You can enable it later from "Turn Windows features on or off".',
        mbInformation, MB_OK);
    Exit;
  end;

  Log('DISM HypervisorPlatform enable returned exit code ' + IntToStr(ResultCode) + '.');
  if ResultCode = DismRebootRequired then
    HyperVRestartNeeded := True
  else if ResultCode <> 0 then
  begin
    if not WizardSilent() then
      MsgBox('Enabling the Windows Hypervisor Platform failed (DISM exit code '
        + IntToStr(ResultCode) + '). QEMU/WHPX acceleration may be unavailable until '
        + 'it is enabled manually.', mbInformation, MB_OK);
  end;
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
  { The x86-64-v2 CPU-baseline note is surfaced on the ready page (UpdateReadyMemo),
    not as a blocking dialog before the wizard opens. }
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
    + Space + 'The QEMU/WHPX backend can be enabled from the Select Tasks page of this installer.';

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
  { Add the Defender exclusion BEFORE files are extracted. ssInstall fires just
    ahead of the [Files] copy, so the bundled activation/injection utilities are
    excluded before they land on disk and can trip antivirus heuristics. }
  if CurStep = ssInstall then
  begin
    if WizardIsTaskSelected('defenderexclusion') then
      SetDefenderExclusion('Add');
  end;

  { Enable the Hypervisor Platform after the payload is installed. }
  if CurStep = ssPostInstall then
  begin
    if WizardIsTaskSelected('enablehyperv') then
      EnableHyperVPlatform();
  end;
end;

{ Request a reboot only when enabling the Hypervisor Platform reported 3010. }
function NeedRestart(): Boolean;
begin
  Result := HyperVRestartNeeded;
end;

{ On uninstall, undo the Defender exclusion (harmless if none was added) and
  offer to purge the out-of-install user tool cache. Credential and config files
  live under %LOCALAPPDATA%\Intellicrack and are never touched here. }
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
