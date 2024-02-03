#define SDB_GUID "{001827e2-fa73-4907-81de-5596bc8e3d37}"

[Setup]
WizardStyle=modern
AppName=SafeDiscShim
AppVersion=0.1.0
AppId={{97FE301F-3933-4406-97C0-480C21D61118}
RestartIfNeededByRun=False
AllowCancelDuringInstall=False
CreateAppDir=False
ShowLanguageDialog=no
DisableProgramGroupPage=yes
AppendDefaultGroupName=False
AllowNoIcons=True
UninstallFilesDir={autocf}\SafeDiscShim
OutputBaseFilename=SafeDiscShim_Setup_{#SetupSetting("AppVersion")}
#ifdef DEBUG
OutputDir=..\src\build\debug
#else
OutputDir=..\src\build\release
#endif
ArchitecturesInstallIn64BitMode=x64
UninstallDisplayName=SafeDiscShim
UninstallDisplayIcon={uninstallexe}
InfoBeforeFile=X:\SafeDiscShim\installer\license.rtf

[Messages]
ReadyLabel1=
ReadyLabel2b=This tool will install a compatibility fix onto your computer, allowing for SafeDisc protected games and programs to run without the Macrovision Security Driver ("secdrv.sys"), which is blocked on updated versions of Windows.%n%nClick Install to continue with the installation.
FinishedHeadingLabel=SafeDiscShim was installed successfully
FinishedLabelNoIcons=SafeDiscShim has been successfully installed onto your computer.
UninstallAppFullTitle=%1 - Uninstaller
ConfirmUninstall=Are you sure you want to remove %1? Games protected with SafeDisc that utilize the Macrovision Security Driver ("secdrv.sys") may stop working.

[Code]
procedure RemoveUninstallEntry();
begin
  RegDeleteKeyIncludingSubkeys(HKEY_LOCAL_MACHINE,
  'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{#SDB_GUID}.sdb');
end;

[Files]
#ifdef DEBUG
Source: "..\src\build\debug\drvmgt.dll"; DestDir: "{syswow64}"; DestName: "drvmgt.dll"; Flags: ignoreversion
#else
Source: "..\src\build\release\drvmgt.dll"; DestDir: "{syswow64}"; DestName: "drvmgt.dll"; Flags: ignoreversion
#endif
Source: "..\SafeDiscShim.sdb"; DestDir: "{tmp}"; DestName: "SafeDiscShim.sdb"; Flags: ignoreversion deleteafterinstall

[Run]
Filename: "sdbinst.exe"; Parameters: "-q SafeDiscShim.sdb"; WorkingDir: "{tmp}"; Flags: runhidden waituntilterminated; Description: "Install SDB database"; AfterInstall: RemoveUninstallEntry

[UninstallRun]
Filename: "sdbinst.exe"; Parameters: "-q -u -g {{#SDB_GUID}"; Flags: runhidden; RunOnceId: "SafeDiscShim_Uninstall"
