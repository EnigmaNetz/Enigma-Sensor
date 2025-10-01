; Enigma Sensor Windows Installer
; Requires Inno Setup (https://jrsoftware.org/isinfo.php)

[Setup]
AppName=Enigma Sensor
AppVersion=1.4.1
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
Source: "..\\..\\zeek-scripts\\*"; DestDir: "{app}\\zeek-scripts"; Flags: ignoreversion recursesubdirs
Source: "..\\..\\config.example.json"; DestDir: "{app}"; Flags: ignoreversion dontcopy

[Dirs]
Name: "C:\ProgramData\EnigmaSensor\logs"; Flags: uninsalwaysuninstall

[Icons]

[Code]
var
  ApiKeyPage: TInputQueryWizardPage;
  ConfigExists: Boolean;

procedure InitializeWizard;
begin
  ConfigExists := FileExists('C:\\ProgramData\\EnigmaSensor\\config.json');
  if not ConfigExists then
  begin
    ApiKeyPage := CreateInputQueryPage(wpSelectDir, 'API Key', 'Enter your Enigma API Key', 'This is required.');
    ApiKeyPage.Add('API Key:', False);
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

function FileReplaceString(const FileName, SearchString, ReplaceString: string): boolean;
var
  MyFile: TStringList;
  MyText: string;
begin
  MyFile := TStringList.Create;
  try
    Result := true;
    try
      MyFile.LoadFromFile(FileName);
      MyText := MyFile.Text;
      if StringChangeEx(MyText, SearchString, ReplaceString, True) > 0 then
      begin
        MyFile.Text := MyText;
        MyFile.SaveToFile(FileName);
      end;
    except
      Result := false;
    end;
  finally
    MyFile.Free;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ExitCode: Integer;
  ConfigPath: string;
begin
  if CurStep = ssInstall then
  begin
    if FileExists(ExpandConstant('{app}\nssm.exe')) then
      Exec(ExpandConstant('{app}\nssm.exe'), 'stop EnigmaSensor', ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, ExitCode);
  end;
  if (CurStep = ssPostInstall) and (not ConfigExists) then
  begin
    ConfigPath := 'C:\ProgramData\EnigmaSensor\config.json';
    ExtractTemporaryFile('config.example.json');
    FileCopy(ExpandConstant('{tmp}\config.example.json'), ConfigPath, False);

    FileReplaceString(ConfigPath, '"api_key": "REPLACE_WITH_YOUR_API_KEY"', '"api_key": "' + ApiKeyPage.Values[0] + '"');
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
