; Enigma Agent Windows Installer
; Requires Inno Setup (https://jrsoftware.org/isinfo.php)

[Setup]
AppName=Enigma Agent
AppVersion=0.1.0
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
  ApiKeyPage, ApiHostPage: TInputQueryWizardPage;
  LoggingLevel, LoggingFile, LoggingMaxSize: String;
  CaptureOutputDir, CaptureWindowSeconds: String;

procedure InitializeWizard;
begin
  ApiKeyPage := CreateInputQueryPage(wpSelectDir, 'API Key', 'Enter your Enigma API Key', 'This is required.');
  ApiKeyPage.Add('API Key:', False);

  ApiHostPage := CreateInputQueryPage(ApiKeyPage.ID, 'API Host', 'Enter your Enigma API Host', 'This is required.');
  ApiHostPage.Add('API Host:', False);
  ApiHostPage.Values[0] := 'https://enigmaai.net/';

  LoggingLevel := 'info';
  LoggingFile := 'logs/enigma-agent.log';
  LoggingMaxSize := '100';
  CaptureOutputDir := './captures';
  CaptureWindowSeconds := '60';
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = ApiKeyPage.ID then
    Result := ApiKeyPage.Values[0] <> ''
  else if CurPageID = ApiHostPage.ID then
    Result := ApiHostPage.Values[0] <> '';
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    SaveStringToFile(
      ExpandConstant('{app}\config.json'),
      '{' + #13#10 +
      '  "logging": {' + #13#10 +
      '    "level": "' + LoggingLevel + '",' + #13#10 +
      '    "file": "' + LoggingFile + '",' + #13#10 +
      '    "max_size_mb": ' + LoggingMaxSize + #13#10 +
      '  },' + #13#10 +
      '  "capture": {' + #13#10 +
      '    "output_dir": "' + CaptureOutputDir + '",' + #13#10 +
      '    "window_seconds": ' + CaptureWindowSeconds + ',' + #13#10 +
      '    "loop": true' + #13#10 +
      '  },' + #13#10 +
      '  "enigma_api": {' + #13#10 +
      '    "server": "' + ApiHostPage.Values[0] + '",' + #13#10 +
      '    "api_key": "' + ApiKeyPage.Values[0] + '",' + #13#10 +
      '    "upload": true' + #13#10 +
      '  }' + #13#10 +
      '}',
      False
    );
  end;
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
