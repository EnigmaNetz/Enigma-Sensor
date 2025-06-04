; Enigma Sensor Windows Installer
; Requires Inno Setup (https://jrsoftware.org/isinfo.php)

[Setup]
AppName=Enigma Sensor
AppVersion=1.1.1
DefaultDirName={autopf}\EnigmaSensor
DefaultGroupName=Enigma Sensor
OutputBaseFilename=enigma-sensor-installer
Compression=lzma
SolidCompression=yes
PrivilegesRequired=admin

[Files]
Source: "..\\..\\bin\\enigma-sensor-windows-amd64.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\\..\\bin\\nssm.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "zeek-runtime-win64.zip"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
Name: "C:\ProgramData\EnigmaSensor\logs"; Flags: uninsalwaysuninstall

[Icons]

[Code]
var
  ApiKeyPage: TInputQueryWizardPage;
  LoggingLevel, LoggingFile, LoggingMaxSize: String;
  CaptureOutputDir, CaptureWindowSeconds: String;
  ConfigExists: Boolean;

procedure InitializeWizard;
begin
  ConfigExists := FileExists('C:\\ProgramData\\EnigmaSensor\\config.json');
  if not ConfigExists then
  begin
    ApiKeyPage := CreateInputQueryPage(wpSelectDir, 'API Key', 'Enter your Enigma API Key', 'This is required.');
    ApiKeyPage.Add('API Key:', False);

    LoggingLevel := 'info';
    LoggingFile := 'logs/enigma-sensor.log';
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
      Exec(ExpandConstant('{app}\nssm.exe'), 'stop EnigmaSensor', ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, ExitCode);
  end;
  if (CurStep = ssPostInstall) and (not ConfigExists) then
  begin
    SaveStringToFile(
      'C:\\ProgramData\\EnigmaSensor\\config.json',
      '{' + #13#10 +
      '  "logging": {' + #13#10 +
      '    "level": "' + LoggingLevel + '",' + #13#10 +
      '    "file": "logs/enigma-sensor.log",' + #13#10 +
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
Filename: "{app}\nssm.exe"; Parameters: "install EnigmaSensor enigma-sensor-windows-amd64.exe"; WorkingDir: "{app}"
Filename: "{app}\nssm.exe"; Parameters: "set EnigmaSensor AppDirectory {app}"; WorkingDir: "{app}"
Filename: "{app}\nssm.exe"; Parameters: "set EnigmaSensor AppStdout C:\\ProgramData\\EnigmaSensor\\logs\\enigma-sensor.log"; WorkingDir: "{app}"
Filename: "{app}\nssm.exe"; Parameters: "set EnigmaSensor AppStderr C:\\ProgramData\\EnigmaSensor\\logs\\enigma-sensor.log"; WorkingDir: "{app}"
Filename: "{app}\nssm.exe"; Parameters: "set EnigmaSensor Start SERVICE_AUTO_START"; WorkingDir: "{app}"
Filename: "{app}\nssm.exe"; Parameters: "set EnigmaSensor ObjectName LocalSystem"; WorkingDir: "{app}"
Filename: "{app}\nssm.exe"; Parameters: "start EnigmaSensor"; WorkingDir: "{app}"

[UninstallRun]
Filename: "{app}\nssm.exe"; Parameters: "stop EnigmaSensor"
Filename: "{app}\nssm.exe"; Parameters: "remove EnigmaSensor confirm"
