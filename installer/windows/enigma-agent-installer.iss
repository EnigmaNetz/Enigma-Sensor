; Enigma Agent Windows Installer
; Requires Inno Setup (https://jrsoftware.org/isinfo.php)

[Setup]
AppName=Enigma Agent
AppVersion=1.0.0
DefaultDirName={autopf}\EnigmaAgent
DefaultGroupName=Enigma Agent
OutputBaseFilename=enigma-agent-installer
Compression=lzma
SolidCompression=yes
PrivilegesRequired=admin

[Files]
Source: "..\\..\\bin\\enigma-agent-windows-amd64.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\\..\\bin\\nssm.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "zeek-runtime-win64.zip"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
Name: "C:\ProgramData\EnigmaAgent\logs"; Flags: uninsalwaysuninstall

[Icons]

[Code]
var
  ApiKeyPage: TInputQueryWizardPage;
  LoggingLevel, LoggingFile, LoggingMaxSize: String;
  CaptureOutputDir, CaptureWindowSeconds: String;
  ConfigExists: Boolean;

procedure InitializeWizard;
begin
  ConfigExists := FileExists('C:\\ProgramData\\EnigmaAgent\\config.json');
  if not ConfigExists then
  begin
    ApiKeyPage := CreateInputQueryPage(wpSelectDir, 'API Key', 'Enter your Enigma API Key', 'This is required.');
    ApiKeyPage.Add('API Key:', False);

    LoggingLevel := 'info';
    LoggingFile := 'logs/enigma-agent.log';
    LoggingMaxSize := '100';
    CaptureOutputDir := './captures';
    CaptureWindowSeconds := '60';
  end;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if not ConfigExists then
  begin
    if CurPageID = ApiKeyPage.ID then
      Result := ApiKeyPage.Values[0] <> '';
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ExitCode: Integer;
begin
  if CurStep = ssInstall then
  begin
    if FileExists(ExpandConstant('{app}\nssm.exe')) then
      Exec(ExpandConstant('{app}\nssm.exe'), 'stop EnigmaAgent', ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, ExitCode);
  end;
  if (CurStep = ssPostInstall) and (not ConfigExists) then
  begin
    SaveStringToFile(
      'C:\\ProgramData\\EnigmaAgent\\config.json',
      '{' + #13#10 +
      '  "logging": {' + #13#10 +
      '    "level": "' + LoggingLevel + '",' + #13#10 +
      '    "file": "logs/enigma-agent.log",' + #13#10 +
      '    "max_size_mb": ' + LoggingMaxSize + #13#10 +
      '  },' + #13#10 +
      '  "capture": {' + #13#10 +
      '    "output_dir": "' + CaptureOutputDir + '",' + #13#10 +
      '    "window_seconds": ' + CaptureWindowSeconds + ',' + #13#10 +
      '    "loop": true' + #13#10 +
      '  },' + #13#10 +
      '  "enigma_api": {' + #13#10 +
      '    "server": "api.enigmaai.net:443",' + #13#10 +
      '    "api_key": "' + ApiKeyPage.Values[0] + '",' + #13#10 +
      '    "upload": true' + #13#10 +
      '  }' + #13#10 +
      '}',
      False
    );
  end;
end;

function InitializeSetup(): Boolean;
begin
  Result := True;
end;

[Run]
Filename: "{app}\nssm.exe"; Parameters: "install EnigmaAgent enigma-agent-windows-amd64.exe"; WorkingDir: "{app}"
Filename: "{app}\nssm.exe"; Parameters: "set EnigmaAgent AppDirectory {app}"; WorkingDir: "{app}"
Filename: "{app}\nssm.exe"; Parameters: "set EnigmaAgent AppStdout C:\\ProgramData\\EnigmaAgent\\logs\\enigma-agent.log"; WorkingDir: "{app}"
Filename: "{app}\nssm.exe"; Parameters: "set EnigmaAgent AppStderr C:\\ProgramData\\EnigmaAgent\\logs\\enigma-agent.log"; WorkingDir: "{app}"
Filename: "{app}\nssm.exe"; Parameters: "set EnigmaAgent Start SERVICE_AUTO_START"; WorkingDir: "{app}"
Filename: "{app}\nssm.exe"; Parameters: "set EnigmaAgent ObjectName LocalSystem"; WorkingDir: "{app}"
Filename: "{app}\nssm.exe"; Parameters: "start EnigmaAgent"; WorkingDir: "{app}"

[UninstallRun]
Filename: "{app}\nssm.exe"; Parameters: "stop EnigmaAgent"
Filename: "{app}\nssm.exe"; Parameters: "remove EnigmaAgent confirm"
