; The DeepWork installer for Windows (Inno Setup 6.7). Built by
; .github/scripts/package-windows.ps1, which stages the files and runs:
;   ISCC /DVersion=0.1.0 /DArch=x64 /DSource=<staged files> /DOutput=<dir> windows\deepwork.iss
;
; Unattended use:
;   deepwork-<v>-windows-<arch>-setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART [/USER=<SID>] [/LOG=<file>]
;   "C:\Program Files\DeepWork\unins000.exe" /VERYSILENT /SUPPRESSMSGBOXES [/PURGE=1]
; /USER: who may control DeepWork (default: whoever started the installer).
; /PURGE=1: also delete blocks, statistics and settings.

#ifndef Version
  #error Pass /DVersion=x.y.z
#endif
#ifndef Arch
  #error Pass /DArch=x64 or /DArch=arm64
#endif
#ifndef Source
  #error Pass /DSource=<folder with the files to install>
#endif
#ifndef Output
  #define Output "."
#endif

[Setup]
; Never change the AppId: it ties updates and the uninstaller together.
AppId={{6F0E5B2A-6A8B-4D7E-9C59-2E3D1C4B7A10}
AppName=DeepWork
AppVersion={#Version}
AppVerName=DeepWork {#Version}
AppPublisher=DeepWork contributors
AppPublisherURL=https://github.com/ichbinstudent/deepwork
AppSupportURL=https://github.com/ichbinstudent/deepwork/issues
AppUpdatesURL=https://github.com/ichbinstudent/deepwork/releases
VersionInfoVersion={#Version}
VersionInfoDescription=DeepWork setup
DefaultDirName={autopf}\DeepWork
DisableDirPage=auto
DisableProgramGroupPage=yes
PrivilegesRequired=admin
#if Arch == "arm64"
ArchitecturesAllowed=arm64
ArchitecturesInstallIn64BitMode=arm64
#else
; Not x64compatible: an ARM PC gets the native ARM64 installer instead.
ArchitecturesAllowed=x64os
ArchitecturesInstallIn64BitMode=x64os
#endif
; Windows 10 22H2 or later.
MinVersion=10.0.19045
OutputDir={#Output}
OutputBaseFilename=deepwork-{#Version}-windows-{#Arch}-setup
SetupIconFile=deepwork.ico
UninstallDisplayIcon={app}\deepwork.ico
UninstallDisplayName=DeepWork
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
SetupLogging=yes
ChangesEnvironment=yes
CloseApplications=no
RestartApplications=no

[Files]
Source: "{#Source}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\DeepWork"; Filename: "{app}\deepwork.exe"; IconFilename: "{app}\deepwork.ico"; Comment: "Block distracting websites and apps"
; The tray icon at every sign-in.
Name: "{commonstartup}\DeepWork"; Filename: "{app}\deepwork.exe"; Parameters: "--background"; IconFilename: "{app}\deepwork.ico"

[Run]
Filename: "{app}\deepwork.exe"; Description: "Open DeepWork"; Flags: nowait postinstall skipifsilent runasoriginaluser

[Code]
const
  ServiceName = 'DeepWork';
  EnvKey = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment';
  UninstallKey = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{6F0E5B2A-6A8B-4D7E-9C59-2E3D1C4B7A10}_is1';

function Run(const Exe, Params: String): Integer;
var
  Code: Integer;
begin
  if not Exec(Exe, Params, '', SW_HIDE, ewWaitUntilTerminated, Code) then
    Code := -1;
  Log(Format('ran %s %s: exit code %d', [Exe, Params, Code]));
  Result := Code;
end;

function Sys(const Exe, Params: String): Integer;
begin
  Result := Run(ExpandConstant('{sys}\') + Exe, Params);
end;

function ServiceExists: Boolean;
begin
  Result := Sys('sc.exe', 'query ' + ServiceName) = 0;
end;

function DaemonRunning: Boolean;
begin
  Result := Sys('cmd.exe', '/c tasklist /FI "IMAGENAME eq deepwork-daemon.exe" /NH | find /I "deepwork-daemon.exe"') = 0;
end;

{ Stop the service (without it being restarted), the app and versions that
  ran the service from a scheduled task. }
procedure StopDeepWork;
var
  I: Integer;
begin
  if ServiceExists then begin
    Sys('sc.exe', 'failure ' + ServiceName + ' reset= 0 actions= ""');
    Sys('sc.exe', 'stop ' + ServiceName);
  end;
  Sys('schtasks.exe', '/End /TN DeepWork');
  Sys('schtasks.exe', '/Delete /TN DeepWork /F');
  for I := 1 to 20 do begin
    if not DaemonRunning then
      Break;
    Sleep(500);
  end;
  Sys('taskkill.exe', '/F /IM deepwork-daemon.exe');
  Sys('taskkill.exe', '/F /IM deepwork.exe');
  Sleep(500);
end;

{ The installed version, or '' if there is none. }
function InstalledVersion: String;
begin
  if not RegQueryStringValue(HKLM64, UninstallKey, 'DisplayVersion', Result) then
    Result := '';
end;

function InitializeSetup: Boolean;
var
  Old: String;
  OldV, NewV: Int64;
begin
  Result := True;
  Old := InstalledVersion;
  if (Old <> '') and StrToVersion(Old, OldV) and StrToVersion('{#Version}', NewV)
    and (ComparePackedVersion(OldV, NewV) > 0) then begin
    SuppressibleMsgBox('DeepWork ' + Old + ' is installed, which is newer than this version ({#Version}). '
      + 'To go back, uninstall it first.', mbError, MB_OK, IDOK);
    Result := False;
  end;
end;

{ The SID of the user who started the installer (before it asked for
  administrator rights), or the one given with /USER=. }
function OriginalUserSid: String;
var
  F, S: String;
  Lines: TArrayOfString;
  Code, P: Integer;
begin
  Result := ExpandConstant('{param:USER|}');
  if Result <> '' then
    Exit;
  F := ExpandConstant('{%PUBLIC|C:\Users\Public}') + '\deepwork-setup-user.txt';
  DeleteFile(F);
  if ExecAsOriginalUser(ExpandConstant('{sys}\cmd.exe'), '/c whoami /user /fo csv /nh > "' + F + '"',
      '', SW_HIDE, ewWaitUntilTerminated, Code)
    and (Code = 0) and LoadStringsFromFile(F, Lines) and (GetArrayLength(Lines) > 0) then begin
    { "pc\name","S-1-5-21-..." }
    S := Lines[0];
    P := Pos('"S-1-', S);
    if P > 0 then begin
      S := Copy(S, P + 1, Length(S));
      Result := Copy(S, 1, Pos('"', S) - 1);
    end;
  end;
  DeleteFile(F);
  Log('original user: ' + Result);
end;

procedure AddToPath(const Dir: String);
var
  Path: String;
begin
  if not RegQueryStringValue(HKLM, EnvKey, 'Path', Path) then
    Path := '';
  if Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Path) + ';') > 0 then
    Exit;
  if (Path <> '') and (Copy(Path, Length(Path), 1) <> ';') then
    Path := Path + ';';
  RegWriteExpandStringValue(HKLM, EnvKey, 'Path', Path + Dir);
end;

procedure RemoveFromPath(const Dir: String);
var
  Path, Rest, Part, Kept: String;
  P: Integer;
begin
  if not RegQueryStringValue(HKLM, EnvKey, 'Path', Path) then
    Exit;
  Rest := Path + ';';
  Kept := '';
  while Rest <> '' do begin
    P := Pos(';', Rest);
    Part := Copy(Rest, 1, P - 1);
    Rest := Copy(Rest, P + 1, Length(Rest));
    if (Part <> '') and (CompareText(Part, Dir) <> 0) then begin
      if Kept <> '' then
        Kept := Kept + ';';
      Kept := Kept + Part;
    end;
  end;
  if Kept <> Path then
    RegWriteExpandStringValue(HKLM, EnvKey, 'Path', Kept);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  StopDeepWork;
  Result := '';
end;

procedure StartService;
var
  App, Daemon, Sid: String;
  I: Integer;
begin
  App := ExpandConstant('{app}');
  Daemon := App + '\deepwork-daemon.exe';
  Sid := OriginalUserSid;
  if Sid <> '' then
    Run(Daemon, '--allow-user ' + Sid)
  else
    Log('could not tell who started the installer; only administrators may control DeepWork');
  if ServiceExists then
    Sys('sc.exe', 'config ' + ServiceName + ' binPath= "\"' + Daemon + '\" --service" start= auto')
  else
    Sys('sc.exe', 'create ' + ServiceName + ' binPath= "\"' + Daemon + '\" --service" start= auto DisplayName= DeepWork');
  Sys('sc.exe', 'description ' + ServiceName + ' "Blocks distracting websites on this computer (DeepWork)."');
  { Restart after a crash, or after being killed. }
  Sys('sc.exe', 'failure ' + ServiceName + ' reset= 86400 actions= restart/1000/restart/5000/restart/10000');
  Sys('sc.exe', 'failureflag ' + ServiceName + ' 1');
  Sys('sc.exe', 'start ' + ServiceName);
  for I := 1 to 20 do begin
    if Run(App + '\deepworkctl.exe', 'status') = 0 then
      Break;
    Sleep(250);
  end;
  AddToPath(App);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    StartService;
end;

function InitializeUninstall: Boolean;
begin
  Result := True;
  if Run(ExpandConstant('{app}\deepworkctl.exe'), 'locked') = 0 then begin
    SuppressibleMsgBox('A block is locked, or the computer is frozen. DeepWork can be uninstalled once it has ended.',
      mbError, MB_OK, IDOK);
    Result := False;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  App: String;
begin
  App := ExpandConstant('{app}');
  if CurUninstallStep = usUninstall then begin
    StopDeepWork;
    Sys('sc.exe', 'delete ' + ServiceName);
    { Take the blocks out of the hosts file and the browsers. }
    Run(App + '\deepwork-daemon.exe', '--cleanup');
    RemoveFromPath(App);
  end;
  if CurUninstallStep = usPostUninstall then begin
    if (ExpandConstant('{param:PURGE|0}') = '1')
      or (not UninstallSilent and (MsgBox('Also delete your blocks, statistics and settings?',
        mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES)) then
      DelTree(ExpandConstant('{commonappdata}\DeepWork'), True, True, True);
  end;
end;
