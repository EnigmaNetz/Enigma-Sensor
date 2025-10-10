; Enigma Sensor Windows Installer
; Requires Inno Setup (https://jrsoftware.org/isinfo.php)

[Setup]
AppName=Enigma Sensor
AppVersion=1.4.2
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
  NpcapPage: TInputOptionWizardPage;
  ConfigExists: Boolean;
  InstallNpcap: Boolean;
  NpcapDownloadSuccess: Boolean;

function IsNpcapInstalled: Boolean;
begin
  Result := FileExists(ExpandConstant('{sys}\Npcap\wpcap.dll'));
end;

function ShouldInstallNpcap: Boolean;
begin
  Result := InstallNpcap and NpcapDownloadSuccess and not IsNpcapInstalled;
end;

function DownloadNpcap: Boolean;
var
  DownloadPage: TDownloadWizardPage;
begin
  Result := False;

  if not InstallNpcap then
  begin
    Result := True;
    Exit;
  end;

  if IsNpcapInstalled then
  begin
    Result := True;
    Exit;
  end;

  DownloadPage := CreateDownloadPage(SetupMessage(msgWizardPreparing), SetupMessage(msgPreparingDesc), nil);
  DownloadPage.Clear;
  DownloadPage.Add('https://npcap.com/dist/npcap-1.79.exe', 'npcap-installer.exe', '');

  try
    try
      DownloadPage.Show;
      try
        DownloadPage.Download;
        Result := True;
      except
        if DownloadPage.AbortedByUser then
          Log('Npcap download cancelled by user')
        else
          SuppressibleMsgBox('Failed to download Npcap installer. The sensor will use pktmon instead.' + #13#10#13#10 +
            'You can manually install Npcap later from https://npcap.com/', mbError, MB_OK, IDOK);
        Result := False;
      end;
    finally
      DownloadPage.Hide;
    end;
  except
    Result := False;
  end;
end;

procedure InitializeWizard;
begin
  ConfigExists := FileExists('C:\\ProgramData\\EnigmaSensor\\config.json');

  if not ConfigExists then
  begin
    ApiKeyPage := CreateInputQueryPage(wpSelectDir, 'API Key', 'Enter your Enigma API Key', 'This is required.');
    ApiKeyPage.Add('API Key:', False);
  end;

  NpcapPage := CreateInputOptionPage(wpSelectDir, 'Enhanced Network Capture',
    'Install Npcap for improved packet capture',
    'Npcap enables full network visibility with promiscuous mode. ' +
    'This is recommended for comprehensive network monitoring.' + #13#10#13#10 +
    'Without Npcap, the sensor will use pktmon, which captures only traffic processed by this computer.' + #13#10#13#10 +
    'If you choose to install Npcap, you will see the Npcap installer after this setup completes. ' +
    'Please accept the defaults in the Npcap installer.',
    False, False);
  NpcapPage.Add('Install Npcap (Recommended)');
  NpcapPage.Values[0] := False;
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := False;

  // Skip Npcap page if already installed
  if PageID = NpcapPage.ID then
  begin
    if IsNpcapInstalled then
    begin
      Result := True;
      InstallNpcap := False; // Don't try to install if already there
    end;
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

  if CurPageID = NpcapPage.ID then
  begin
    InstallNpcap := NpcapPage.Values[0];
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
  NpcapDownloadSuccess := False;
  Result := True;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  if InstallNpcap and not IsNpcapInstalled then
  begin
    if DownloadNpcap then
      NpcapDownloadSuccess := True
    else
      NpcapDownloadSuccess := False;
  end;
end;

[Run]
Filename: "{tmp}\npcap-installer.exe"; StatusMsg: "Launching Npcap installer..."; Check: ShouldInstallNpcap; Flags: waituntilterminated
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
