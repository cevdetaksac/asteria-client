; Asteria Client Installer Script
; Version is injected by build.ps1 from client_constants.py
!include "MUI2.nsh"
!include "WinVer.nsh"
!include "LogicLib.nsh"

Name "Asteria Client"
OutFile "asteria-client-installer.exe"

!define APPNAME "Asteria Client"
!define COMPANYNAME "Asteria"
!define DESCRIPTION "Asteria Client - Deception Cloud Agent"
!define VERSIONMAJOR 4
!define VERSIONMINOR 9
!define VERSIONBUILD 69

InstallDir "$PROGRAMFILES64\${COMPANYNAME}\${APPNAME}"

; Auto-elevation - will automatically request UAC
RequestExecutionLevel admin

; Modern UI Configuration
!define MUI_ICON "certs\asteria_64.ico"
!define MUI_UNICON "certs\asteria_64.ico"
!define MUI_WELCOMEFINISHPAGE_BITMAP "certs\welcome.bmp"
!define MUI_UNWELCOMEFINISHPAGE_BITMAP "certs\welcome.bmp"

; Interface Settings
!define MUI_ABORTWARNING
!define MUI_CUSTOMFUNCTION_GUIINIT AsteriaOnGuiInit

; Pages — no finish/checkbox wait; app launches when files are done
!define MUI_PAGE_CUSTOMFUNCTION_SHOW AsteriaPageShow
!insertmacro MUI_PAGE_WELCOME
!define MUI_PAGE_CUSTOMFUNCTION_SHOW AsteriaPageShow
!insertmacro MUI_PAGE_LICENSE "LICENSE"
!define MUI_PAGE_CUSTOMFUNCTION_SHOW AsteriaPageShow
!insertmacro MUI_PAGE_COMPONENTS
!define MUI_PAGE_CUSTOMFUNCTION_SHOW AsteriaPageShow
!insertmacro MUI_PAGE_DIRECTORY
!define MUI_PAGE_CUSTOMFUNCTION_SHOW AsteriaPageShow
!insertmacro MUI_PAGE_INSTFILES

; Uninstaller pages
!define MUI_PAGE_CUSTOMFUNCTION_SHOW un.AsteriaPageShow
!insertmacro MUI_UNPAGE_WELCOME
!define MUI_PAGE_CUSTOMFUNCTION_SHOW un.AsteriaPageShow
!insertmacro MUI_UNPAGE_CONFIRM
!define MUI_PAGE_CUSTOMFUNCTION_SHOW un.AsteriaPageShow
!insertmacro MUI_UNPAGE_INSTFILES
!define MUI_PAGE_CUSTOMFUNCTION_SHOW un.AsteriaPageShow
!insertmacro MUI_UNPAGE_FINISH

; Languages
!insertmacro MUI_LANGUAGE "English"

; Close InstFiles page immediately after success (no Finish checkbox screen)
AutoCloseWindow true
ShowInstDetails nevershow

; Variables
Var LogFile
Var UninstallGateCode

; ===================================================================
; UNINSTALL PIN GATE (Control Panel anti-tamper)
; ===================================================================
Function un.RunUninstallGate
    DetailPrint "[PIN] Uninstall authorization gate..."
    StrCpy $UninstallGateCode "2"
    IfFileExists "$INSTDIR\asteria-client.exe" 0 unGateMissing
        IfSilent unGateSilent unGateInteractive
        unGateSilent:
            nsExec::ExecToLog '"$INSTDIR\asteria-client.exe" --uninstall-gate --silent'
            Pop $UninstallGateCode
            Goto unGateAfterExec
        unGateInteractive:
            nsExec::ExecToLog '"$INSTDIR\asteria-client.exe" --uninstall-gate'
            Pop $UninstallGateCode
        unGateAfterExec:
        DetailPrint "[PIN] uninstall-gate exit=$UninstallGateCode"
        Goto unGateDone
    unGateMissing:
        DetailPrint "[PIN] asteria-client.exe missing — allowing cleanup"
        StrCpy $UninstallGateCode "0"
    unGateDone:
FunctionEnd

Function un.onInit
    ; Block casual Apps & Features removal when PIN is set (or user cancels).
    Call un.RunUninstallGate
    ${If} $UninstallGateCode != "0"
        IfSilent unGateAbortQuiet
            MessageBox MB_ICONSTOP|MB_OK "Asteria kaldırma iptal edildi.$\r$\n$\r$\nPIN gerekli veya doğrulama başarısız.$\r$\nPIN unuttuysanız dashboard → GUI PIN sıfırlama kullanın."
        unGateAbortQuiet:
        Abort
    ${EndIf}
    ; Install no longer ships kill-honeypot.ps1 under Program Files — embed it
    ; into the uninstaller payload so GUI/motor DACL kill still works.
    InitPluginsDir
    SetOutPath "$PLUGINSDIR"
    File "scripts\kill-honeypot.ps1"
FunctionEnd

; ===================================================================
; UTILITY FUNCTIONS
; ===================================================================

; Launch app as current (non-elevated) user.
; onedir: DLLs live in $INSTDIR\_internal (no _MEI unpack race).
Function LaunchAsCurrentUser
    SetOutPath "$INSTDIR"

    DetailPrint "[LAUNCH] Stopping leftover Asteria processes before GUI start..."
    nsExec::Exec 'schtasks /end /tn "Asteria-Tray" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "Asteria-Background" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "Asteria-Watchdog" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-Tray" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-Background" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-Watchdog" >nul 2>&1'
    IfFileExists "$PLUGINSDIR\kill-honeypot.ps1" 0 LaunchKillFallback
        nsExec::Exec 'powershell -NoProfile -ExecutionPolicy Bypass -File "$PLUGINSDIR\kill-honeypot.ps1" -Force'
        Pop $0
        Goto LaunchAfterKill
    LaunchKillFallback:
        IfFileExists "$INSTDIR\scripts\kill-honeypot.ps1" 0 LaunchTaskkill
            nsExec::Exec 'powershell -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\scripts\kill-honeypot.ps1" -Force'
            Pop $0
            Goto LaunchAfterKill
    LaunchTaskkill:
        nsExec::Exec 'taskkill /F /T /IM asteria-gui.exe >nul 2>&1'
        nsExec::Exec 'taskkill /F /T /IM asteria-client.exe >nul 2>&1'
        nsExec::Exec 'taskkill /F /T /IM honeypot-client.exe >nul 2>&1'
        Pop $0
    LaunchAfterKill:
    Sleep 1500

    ; Clear stale update lock so kill/watchdog and GUI are not blocked
    ExpandEnvStrings $R9 "%ProgramData%\Asteria\update_in_progress.lock"
    Delete /REBOOTOK "$R9"

    ; Start SYSTEM-capable motor setup from elevated installer, then open the
    ; separate GUI as the interactive user.
    Exec '"$INSTDIR\asteria-client.exe" --mode=daemon --create-tasks'
    ExecShell "open" "$INSTDIR\asteria-gui.exe"
FunctionEnd

; Simple log function
Function WriteLog
    Exch $0  ; Get the text to log
    Push $1
    
    ClearErrors
    FileOpen $1 $LogFile a
    IfErrors LogOpenError
    FileWrite $1 "$0$\r$\n"
    FileClose $1
    Goto LogEnd
    LogOpenError:
    DetailPrint "[LOG ERROR] Log file could not be opened: $LogFile"
    LogEnd:
    Pop $1
    Pop $0
FunctionEnd

; Macro for easy logging
!macro LOG text
    Push "${text}"
    Call WriteLog
    DetailPrint "${text}"
!macroend

; ===================================================================
; DELETE ALL ASTERIA + LEGACY CLOUDHONEYPOT SCHEDULED TASKS
; Uses PowerShell wildcard to catch ALL task name variants
; ===================================================================
Function DeleteAllHoneypotTasks
    Push $0

    DetailPrint "[TASKS] Stopping Asteria / legacy scheduled tasks..."
    ; Current Asteria wire names
    nsExec::Exec 'schtasks /end /tn "Asteria-Background" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "Asteria-Tray" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "Asteria-Watchdog" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "Asteria-Updater" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "Asteria-SilentUpdater" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "Asteria-MemoryRestart" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "AsteriaClientGuard" >nul 2>&1'
    nsExec::Exec 'schtasks /change /tn "AsteriaClientGuard" /disable >nul 2>&1'
    ; Pre-4.9.41 CloudHoneypot / HoneypotClient names
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-Background" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-Tray" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-Watchdog" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-Updater" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-SilentUpdater" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-MemoryRestart" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypotClientBoot" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypotClientLogon" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "HoneypotClientGuard" >nul 2>&1'
    nsExec::Exec 'schtasks /change /tn "HoneypotClientGuard" /disable >nul 2>&1'
    Sleep 300

    DetailPrint "[TASKS] Deleting Asteria / CloudHoneypot / HoneypotClient tasks..."
    nsExec::Exec 'powershell -ExecutionPolicy Bypass -Command "Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $$_.TaskName -like ''Asteria-*'' -or $$_.TaskName -like ''AsteriaClient*'' -or $$_.TaskName -like ''CloudHoneypot*'' -or $$_.TaskName -like ''HoneypotClient*'' } | ForEach-Object { schtasks /end /tn $$_.TaskName 2>$$null; Unregister-ScheduledTask -TaskName $$_.TaskName -Confirm:$$false -ErrorAction SilentlyContinue }"'
    Pop $0

    ; Fallback: explicit deletion of every known task name
    nsExec::Exec 'schtasks /delete /tn "Asteria-Background" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "Asteria-Tray" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "Asteria-Watchdog" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "Asteria-Updater" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "Asteria-SilentUpdater" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "Asteria-MemoryRestart" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "AsteriaClientGuard" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypot-Background" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypot-Tray" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypot-Watchdog" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypot-Updater" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypot-SilentUpdater" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypot-MemoryRestart" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypotClientBoot" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypotClientLogon" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "HoneypotClientGuard" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "Cloud Honeypot Client" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "HoneypotClientAutostart" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypotTray" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypotWatchdog" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypotUpdater" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypotSilentUpdater" /f >nul 2>&1'

    DetailPrint "[TASKS] All Asteria / legacy tasks deleted."
    Pop $0
FunctionEnd

; Uninstaller variant of task deletion
Function un.DeleteAllHoneypotTasks
    Push $0

    DetailPrint "[TASKS] Stopping Asteria / legacy scheduled tasks..."
    nsExec::Exec 'schtasks /end /tn "Asteria-Background" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "Asteria-Tray" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "Asteria-Watchdog" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "Asteria-Updater" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "Asteria-SilentUpdater" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "Asteria-MemoryRestart" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "AsteriaClientGuard" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-Background" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-Tray" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-Watchdog" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-Updater" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-SilentUpdater" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-MemoryRestart" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypotClientBoot" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypotClientLogon" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "HoneypotClientGuard" >nul 2>&1'
    Sleep 500

    nsExec::Exec 'powershell -ExecutionPolicy Bypass -Command "Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $$_.TaskName -like ''Asteria-*'' -or $$_.TaskName -like ''AsteriaClient*'' -or $$_.TaskName -like ''CloudHoneypot*'' -or $$_.TaskName -like ''HoneypotClient*'' } | ForEach-Object { schtasks /end /tn $$_.TaskName 2>$$null; Unregister-ScheduledTask -TaskName $$_.TaskName -Confirm:$$false -ErrorAction SilentlyContinue }"'
    Pop $0

    nsExec::Exec 'schtasks /delete /tn "Asteria-Background" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "Asteria-Tray" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "Asteria-Watchdog" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "Asteria-Updater" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "Asteria-SilentUpdater" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "Asteria-MemoryRestart" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "AsteriaClientGuard" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypot-Background" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypot-Tray" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypot-Watchdog" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypot-Updater" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypot-SilentUpdater" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypot-MemoryRestart" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypotClientBoot" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypotClientLogon" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "HoneypotClientGuard" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "Cloud Honeypot Client" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "HoneypotClientAutostart" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypotTray" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypotWatchdog" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypotUpdater" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypotSilentUpdater" /f >nul 2>&1'

    DetailPrint "[TASKS] All Asteria / legacy tasks deleted."
    Pop $0
FunctionEnd

; ===================================================================
; FAST PRE-KILL — runs at installer startup (before UI pages)
; Uses kill-honeypot.ps1: QUIT socket + SeDebugPrivilege + task purge
; ===================================================================
Function PreInstallKillFast
    DetailPrint "[PRE-KILL] Extracting kill helper..."
    InitPluginsDir
    SetOutPath "$PLUGINSDIR"
    File "scripts\kill-honeypot.ps1"
    File "scripts\prepare-install-dir.ps1"
    File "scripts\remove-legacy-install.ps1"

    DetailPrint "[PRE-KILL] Stopping tasks + DACL-protected processes..."
    ; Legacy guardian service otherwise respawns the old YesNext binary while
    ; the Asteria files are being installed.
    nsExec::Exec 'sc.exe stop AsteriaGuardian >nul 2>&1'
    nsExec::Exec 'sc.exe delete AsteriaGuardian >nul 2>&1'
    nsExec::Exec 'sc.exe stop CloudHoneypotGuardian >nul 2>&1'
    nsExec::Exec 'sc.exe delete CloudHoneypotGuardian >nul 2>&1'
    nsExec::Exec 'sc.exe stop CloudHoneypotMonitor >nul 2>&1'
    nsExec::Exec 'sc.exe delete CloudHoneypotMonitor >nul 2>&1'
    Sleep 500
    nsExec::Exec 'taskkill /F /T /IM asteria-gui.exe >nul 2>&1'
    nsExec::ExecToLog 'powershell -NoProfile -ExecutionPolicy Bypass -File "$PLUGINSDIR\kill-honeypot.ps1" -Force'
    Pop $0
    DetailPrint "[PRE-KILL] kill-honeypot.ps1 exit code: $0"
    DetailPrint "[PRE-KILL] Removing legacy YesNext Program Files trees..."
    ; Prefer 64-bit PowerShell (Sysnative) so WOW64 does not hide C:\Program Files\YesNext.
    IfFileExists "$WINDIR\Sysnative\WindowsPowerShell\v1.0\powershell.exe" 0 LegacyCleanWow64
        nsExec::ExecToLog '"$WINDIR\Sysnative\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$PLUGINSDIR\remove-legacy-install.ps1" -KeepIfSameAs "$INSTDIR"'
        Pop $0
        Goto LegacyCleanDone
    LegacyCleanWow64:
        nsExec::ExecToLog 'powershell -NoProfile -ExecutionPolicy Bypass -File "$PLUGINSDIR\remove-legacy-install.ps1" -KeepIfSameAs "$INSTDIR"'
        Pop $0
    LegacyCleanDone:
    DetailPrint "[PRE-KILL] remove-legacy-install.ps1 exit code: $0"
    ; Direct NSIS purge (64-bit Program Files) — do not rely on WOW64 view alone.
    RMDir /r "$PROGRAMFILES64\YesNext\Cloud Honeypot Client"
    RMDir /r "$PROGRAMFILES64\Asteria"
    RMDir /r "$PROGRAMFILES\YesNext\Cloud Honeypot Client"
    RMDir /r "$PROGRAMFILES\Asteria"
    RMDir "$PROGRAMFILES64\YesNext"
    RMDir "$PROGRAMFILES\YesNext"
FunctionEnd

; Restrict scripts\ to SYSTEM + Administrators (deny interactive Users RX).
Function HardenInstallScriptsAcl
    DetailPrint "[ACL] Hardening helper script folders ..."
    ; $INSTDIR\scripts (memory_restart) + onedir datas scripts (update helper in _internal)
    nsExec::ExecToLog 'icacls "$INSTDIR\scripts" /inheritance:r /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)F" /grant:r "BUILTIN\Administrators:(OI)(CI)F" /remove:g "BUILTIN\Users" /remove:g "Everyone" /remove:g "NT AUTHORITY\Authenticated Users" /C /Q'
    Pop $0
    DetailPrint "[ACL] scripts icacls exit: $0"
    nsExec::ExecToLog 'icacls "$INSTDIR\scripts\*" /inheritance:e /T /C /Q'
    Pop $0
    IfFileExists "$INSTDIR\_internal\scripts" 0 HardenAclDone
        nsExec::ExecToLog 'icacls "$INSTDIR\_internal\scripts" /inheritance:r /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)F" /grant:r "BUILTIN\Administrators:(OI)(CI)F" /remove:g "BUILTIN\Users" /remove:g "Everyone" /remove:g "NT AUTHORITY\Authenticated Users" /C /Q'
        Pop $0
        DetailPrint "[ACL] _internal\scripts icacls exit: $0"
        nsExec::ExecToLog 'icacls "$INSTDIR\_internal\scripts\*" /inheritance:e /T /C /Q'
        Pop $0
        ; Remove kill helper from onedir datas if present (installer-only tool)
        Delete "$INSTDIR\_internal\scripts\kill-honeypot.ps1"
        Delete "$INSTDIR\_internal\scripts\prepare-install-dir.ps1"
    HardenAclDone:
FunctionEnd

; Program Files is executable content only. Standard users may run/read the
; current onedir runtime during migration, but can never modify or replace it.
; Once tray/GUI no longer depend on the motor runtime, _internal is removed.
Function HardenInstallRootAcl
    DetailPrint "[ACL] Hardening Asteria install tree (no user writes) ..."
    ; Set policy only on the root, then make children inherit it. Applying
    ; (OI)(CI) ACEs directly to files via /T can create inherit-only/empty
    ; effective DACLs and make the executables unlaunchable.
    nsExec::ExecToLog 'icacls "$INSTDIR" /inheritance:r /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)F" /grant:r "BUILTIN\Administrators:(OI)(CI)F" /grant:r "BUILTIN\Users:(OI)(CI)RX" /remove:g "Everyone" /remove:g "NT AUTHORITY\Authenticated Users" /C /Q'
    Pop $0
    DetailPrint "[ACL] install root policy exit: $0"
    nsExec::ExecToLog 'icacls "$INSTDIR\*" /inheritance:e /T /C /Q'
    Pop $0
    DetailPrint "[ACL] child inheritance exit: $0"
FunctionEnd

; Motor onedir runtime must stay LoadLibrary-able (Users RX). Blocking Users
; caused: Failed to load Python DLL '...\_internal\python312.dll' / Erişim engellendi
; whenever asteria-client.exe was started outside SYSTEM. Users still cannot
; Modify/replace DLLs (RX only).
Function HardenMotorRuntimeAcl
    IfFileExists "$INSTDIR\_internal\*.*" 0 HardenMotorRuntimeDone
        DetailPrint "[ACL] Motor _internal: SYSTEM/Admins Full, Users RX (no write) ..."
        nsExec::ExecToLog 'icacls "$INSTDIR\_internal" /inheritance:r /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)F" /grant:r "BUILTIN\Administrators:(OI)(CI)F" /grant:r "BUILTIN\Users:(OI)(CI)RX" /remove:g "Everyone" /remove:g "NT AUTHORITY\Authenticated Users" /C /Q'
        Pop $0
        DetailPrint "[ACL] motor runtime icacls exit: $0"
        nsExec::ExecToLog 'icacls "$INSTDIR\_internal\*" /inheritance:e /T /C /Q'
        Pop $0
    HardenMotorRuntimeDone:
FunctionEnd

; Move / copy durable state from YesNext ProgramData trees into Asteria.
Function MigrateProgramData
    DetailPrint "[MIGRATE] ProgramData YesNext → Asteria ..."
    InitPluginsDir
    SetOutPath "$PLUGINSDIR"
    File "scripts\migrate-programdata.ps1"
    nsExec::ExecToLog 'powershell -NoProfile -ExecutionPolicy Bypass -File "$PLUGINSDIR\migrate-programdata.ps1"'
    Pop $0
    DetailPrint "[MIGRATE] migrate-programdata.ps1 exit: $0"
FunctionEnd

; Move locked onedir trees aside so File /r never hits Abort/Retry/Ignore.
Function PrepareInstallDirForOverwrite
    DetailPrint "[PREP-DIR] Making install dir writable (rename locked _internal)..."
    InitPluginsDir
    SetOutPath "$PLUGINSDIR"
    File "scripts\kill-honeypot.ps1"
    File "scripts\prepare-install-dir.ps1"
    File "scripts\remove-legacy-install.ps1"
    nsExec::ExecToLog 'powershell -NoProfile -ExecutionPolicy Bypass -File "$PLUGINSDIR\prepare-install-dir.ps1" -InstallDir "$INSTDIR" -KillScript "$PLUGINSDIR\kill-honeypot.ps1"'
    Pop $0
    DetailPrint "[PREP-DIR] prepare-install-dir.ps1 exit code: $0"
    ; Belt-and-suspenders: purge legacy trees again after kill (in case PreInstall
    ; ran before elevation finished stopping YesNext images).
    IfFileExists "$WINDIR\Sysnative\WindowsPowerShell\v1.0\powershell.exe" 0 PrepLegacyWow64
        nsExec::ExecToLog '"$WINDIR\Sysnative\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$PLUGINSDIR\remove-legacy-install.ps1" -KeepIfSameAs "$INSTDIR"'
        Pop $0
        Goto PrepLegacyDone
    PrepLegacyWow64:
        nsExec::ExecToLog 'powershell -NoProfile -ExecutionPolicy Bypass -File "$PLUGINSDIR\remove-legacy-install.ps1" -KeepIfSameAs "$INSTDIR"'
        Pop $0
    PrepLegacyDone:
    DetailPrint "[PREP-DIR] remove-legacy-install.ps1 exit code: $0"
    RMDir /r "$PROGRAMFILES64\YesNext\Cloud Honeypot Client"
    RMDir /r "$PROGRAMFILES64\Asteria"
    RMDir /r "$PROGRAMFILES\YesNext\Cloud Honeypot Client"
    RMDir /r "$PROGRAMFILES\Asteria"
    RMDir "$PROGRAMFILES64\YesNext"
    RMDir "$PROGRAMFILES\YesNext"
    Sleep 200
FunctionEnd

; Install memory_restart.ps1 without NSIS FileInUse dialog (schtask may lock it).
; Never use NSIS File here — locked targets pop Abort/Retry/Ignore.
Function InstallMemoryRestartScript
    Push $0
    InitPluginsDir
    SetOutPath "$PLUGINSDIR"
    File "memory_restart.ps1"
    File "scripts\install-memory-restart.ps1"
    CreateDirectory "$INSTDIR\scripts"
    nsExec::ExecToLog 'powershell -NoProfile -ExecutionPolicy Bypass -File "$PLUGINSDIR\install-memory-restart.ps1" -InstallDir "$INSTDIR" -SourcePath "$PLUGINSDIR\memory_restart.ps1"'
    Pop $0
    DetailPrint "[FILES] memory_restart.ps1 install exit: $0"
    StrCmp $0 "0" MemoryRestartOk
        DetailPrint "[FILES] WARN: memory_restart.ps1 not written — client will restage on first run"
    MemoryRestartOk:
    Pop $0
FunctionEnd

; ===================================================================
; KILL ASTERIA PROCESSES WITH VERIFICATION (fast: 1 full kill + short poll)
; Motor + GUI + legacy honeypot-client image names.
; ===================================================================
Function KillHoneypotProcesses
    Push $0
    Push $1
    Push $2

    DetailPrint "[KILL] Fast shutdown sequence..."

    ; Skip full script if nothing to kill (e.g. already stopped in .onInit)
    nsExec::ExecToStack 'cmd /c ((tasklist /FI "IMAGENAME eq asteria-client.exe" 2>nul | find /I "asteria-client.exe" >nul) || (tasklist /FI "IMAGENAME eq asteria-gui.exe" 2>nul | find /I "asteria-gui.exe" >nul) || (tasklist /FI "IMAGENAME eq honeypot-client.exe" 2>nul | find /I "honeypot-client.exe" >nul)) && (echo RUNNING) || (echo STOPPED)'
    Pop $0
    Pop $1
    StrCmp $1 "STOPPED" KillDone

    Call PreInstallKillFast

    ; Quick verify: max 3 short polls, cheap taskkill retry (no full script loop)
    StrCpy $2 "0"
    KillWaitLoop:
        nsExec::ExecToStack 'cmd /c ((tasklist /FI "IMAGENAME eq asteria-client.exe" 2>nul | find /I "asteria-client.exe" >nul) || (tasklist /FI "IMAGENAME eq asteria-gui.exe" 2>nul | find /I "asteria-gui.exe" >nul) || (tasklist /FI "IMAGENAME eq honeypot-client.exe" 2>nul | find /I "honeypot-client.exe" >nul)) && (echo RUNNING) || (echo STOPPED)'
        Pop $0
        Pop $1
        StrCmp $1 "STOPPED" KillDone
        IntOp $2 $2 + 1
        IntCmp $2 3 KillForce KillWaitMore KillForce
        KillWaitMore:
            DetailPrint "[KILL] Still running - quick retry $2..."
            nsExec::Exec 'taskkill /F /T /IM asteria-gui.exe >nul 2>&1'
            nsExec::Exec 'taskkill /F /T /IM asteria-client.exe >nul 2>&1'
            nsExec::Exec 'taskkill /F /T /IM honeypot-client.exe >nul 2>&1'
            Pop $0
            Sleep 150
            Goto KillWaitLoop

    KillForce:
        DetailPrint "[KILL] Final kill pass..."
        Call PreInstallKillFast
        Sleep 150

    KillDone:
    DetailPrint "[KILL] Process shutdown complete."
    nsExec::Exec 'cmd /c del "%TEMP%\honeypot_watchdog_token.txt" 2>nul'
    Sleep 300

    Pop $2
    Pop $1
    Pop $0
FunctionEnd

; Uninstaller variant
Function un.KillHoneypotProcesses
    Push $0
    Push $1

    DetailPrint "[KILL] Uninstall shutdown..."
    Call un.PreInstallKillFast

    nsExec::Exec 'taskkill /f /t /im "asteria-gui.exe" >nul 2>&1'
    nsExec::Exec 'taskkill /f /t /im "asteria-client.exe" >nul 2>&1'
    nsExec::Exec 'taskkill /f /t /im "honeypot-client.exe" >nul 2>&1'
    Pop $0
    Sleep 800

    nsExec::Exec 'cmd /c del "%TEMP%\honeypot_watchdog_token.txt" 2>nul'
    nsExec::Exec 'cmd /c del "%ProgramData%\YesNext\CloudHoneypot\watchdog_stop.flag" 2>nul'
    nsExec::Exec 'cmd /c del "%ProgramData%\Asteria\update_in_progress.lock" 2>nul'

    Pop $1
    Pop $0
FunctionEnd

Function un.PreInstallKillFast
    DetailPrint "[PRE-KILL] Uninstall stop sequence..."
    nsExec::Exec 'sc.exe stop AsteriaGuardian >nul 2>&1'
    nsExec::Exec 'sc.exe delete AsteriaGuardian >nul 2>&1'
    nsExec::Exec 'sc.exe stop CloudHoneypotGuardian >nul 2>&1'
    nsExec::Exec 'sc.exe delete CloudHoneypotGuardian >nul 2>&1'
    nsExec::Exec 'sc.exe stop CloudHoneypotMonitor >nul 2>&1'
    nsExec::Exec 'sc.exe delete CloudHoneypotMonitor >nul 2>&1'
    nsExec::Exec 'cmd /c echo stop > "%TEMP%\honeypot_watchdog_token.txt"'
    nsExec::Exec 'cmd /c echo stop > "%APPDATA%\YesNext\CloudHoneypot\watchdog_token.txt"'
    nsExec::Exec 'cmd /c mkdir "%ProgramData%\YesNext\CloudHoneypot" 2>nul'
    nsExec::Exec 'cmd /c echo stop > "%ProgramData%\YesNext\CloudHoneypot\watchdog_stop.flag"'
    nsExec::Exec 'cmd /c mkdir "%APPDATA%\Asteria" 2>nul'
    nsExec::Exec 'cmd /c echo stop > "%APPDATA%\Asteria\watchdog.token"'
    nsExec::Exec 'schtasks /end /tn "AsteriaClientGuard" >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "AsteriaClientGuard" /f >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "HoneypotClientGuard" >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "HoneypotClientGuard" /f >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "Asteria-Watchdog" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "Asteria-Background" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "Asteria-Tray" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "Asteria-Updater" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "Asteria-SilentUpdater" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "Asteria-MemoryRestart" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-Watchdog" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-Background" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-Tray" >nul 2>&1'

    ; Always prefer the kill helper embedded in the uninstaller (see un.onInit).
    ; $INSTDIR\scripts\kill-honeypot.ps1 is intentionally NOT installed anymore.
    IfFileExists "$PLUGINSDIR\kill-honeypot.ps1" 0 UnKillTryInstalled
        nsExec::ExecToLog 'powershell -NoProfile -ExecutionPolicy Bypass -File "$PLUGINSDIR\kill-honeypot.ps1" -Force'
        Pop $0
        Goto UnKillDone

    UnKillTryInstalled:
    IfFileExists "$INSTDIR\scripts\kill-honeypot.ps1" 0 UnKillFallback
        nsExec::ExecToLog 'powershell -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\scripts\kill-honeypot.ps1" -Force'
        Pop $0
        Goto UnKillDone

    UnKillFallback:
        ; QUIT + terminate motor AND GUI (older fallback omitted asteria-gui.exe)
        nsExec::Exec 'powershell -NoProfile -ExecutionPolicy Bypass -Command "try{$$c=New-Object Net.Sockets.TcpClient;$$iar=$$c.BeginConnect(\"127.0.0.1\",58632,$$null,$$null);$$iar.AsyncWaitHandle.WaitOne(800)|Out-Null;if($$c.Connected){$$b=[Text.Encoding]::ASCII.GetBytes(\"QUIT`n\");$$c.GetStream().Write($$b,0,$$b.Length)};$$c.Close()}catch{}"'
        Pop $0
        Sleep 500
        nsExec::Exec 'taskkill /F /T /IM asteria-gui.exe >nul 2>&1'
        nsExec::Exec 'taskkill /F /T /IM asteria-client.exe >nul 2>&1'
        nsExec::Exec 'taskkill /F /T /IM honeypot-client.exe >nul 2>&1'
        nsExec::Exec 'powershell -NoProfile -ExecutionPolicy Bypass -Command "foreach($$n in @(''asteria-gui.exe'',''asteria-client.exe'',''honeypot-client.exe'')){ Get-CimInstance Win32_Process -Filter (\"Name=''$$n''\") -EA SilentlyContinue | ForEach-Object { try{$$_.Terminate()}catch{} } }"'
        Pop $0
        Sleep 400

    UnKillDone:
    Sleep 150
FunctionEnd

; ===================================================================
; INITIALIZATION + WINDOW PLACEMENT
; Heavy kill/cleanup runs in SEC_MAIN — NOT here — so Welcome appears fast.
; ===================================================================
Function CenterAndRaiseInstaller
    ; Center on primary screen + raise above other windows after UAC.
    Push $0
    Push $1
    Push $2
    Push $3
    Push $4
    Push $5
    Push $6
    System::Alloc 16
    Pop $0
    System::Call "user32::GetWindowRect(p$HWNDPARENT, p r0)"
    System::Call "*$0(i .r1, i .r2, i .r3, i .r4)"
    System::Free $0
    IntOp $5 $3 - $1   ; width
    IntOp $6 $4 - $2   ; height
    System::Call "user32::GetSystemMetrics(i 0) i.r1" ; SM_CXSCREEN
    System::Call "user32::GetSystemMetrics(i 1) i.r2" ; SM_CYSCREEN
    IntOp $1 $1 - $5
    IntOp $1 $1 / 2
    IntOp $2 $2 - $6
    IntOp $2 $2 / 2
    ; SWP_NOSIZE|SWP_NOZORDER = 0x0005
    System::Call "user32::SetWindowPos(p$HWNDPARENT, p0, i r1, i r2, i 0, i 0, i 0x0005)"
    System::Call "user32::ShowWindow(p$HWNDPARENT, i 9)" ; SW_RESTORE
    System::Call "kernel32::GetCurrentProcessId() i.r0"
    System::Call "user32::AllowSetForegroundWindow(i r0)"
    System::Call "user32::SetForegroundWindow(p$HWNDPARENT)"
    System::Call "user32::BringWindowToTop(p$HWNDPARENT)"
    ; Brief TOPMOST then NOTOPMOST — reliably wins focus after elevation.
    System::Call "user32::SetWindowPos(p$HWNDPARENT, p-1, i0, i0, i0, i0, i0x0003)"
    Sleep 40
    System::Call "user32::SetWindowPos(p$HWNDPARENT, p-2, i0, i0, i0, i0, i0x0003)"
    System::Call "user32::SetForegroundWindow(p$HWNDPARENT)"
    Pop $6
    Pop $5
    Pop $4
    Pop $3
    Pop $2
    Pop $1
    Pop $0
FunctionEnd

Function AsteriaOnGuiInit
    Call CenterAndRaiseInstaller
FunctionEnd

Function AsteriaPageShow
    Call CenterAndRaiseInstaller
FunctionEnd

Function un.CenterAndRaiseInstaller
    Push $0
    Push $1
    Push $2
    Push $3
    Push $4
    Push $5
    Push $6
    System::Alloc 16
    Pop $0
    System::Call "user32::GetWindowRect(p$HWNDPARENT, p r0)"
    System::Call "*$0(i .r1, i .r2, i .r3, i .r4)"
    System::Free $0
    IntOp $5 $3 - $1
    IntOp $6 $4 - $2
    System::Call "user32::GetSystemMetrics(i 0) i.r1"
    System::Call "user32::GetSystemMetrics(i 1) i.r2"
    IntOp $1 $1 - $5
    IntOp $1 $1 / 2
    IntOp $2 $2 - $6
    IntOp $2 $2 / 2
    System::Call "user32::SetWindowPos(p$HWNDPARENT, p0, i r1, i r2, i 0, i 0, i 0x0005)"
    System::Call "user32::ShowWindow(p$HWNDPARENT, i 9)"
    System::Call "kernel32::GetCurrentProcessId() i.r0"
    System::Call "user32::AllowSetForegroundWindow(i r0)"
    System::Call "user32::SetForegroundWindow(p$HWNDPARENT)"
    System::Call "user32::BringWindowToTop(p$HWNDPARENT)"
    System::Call "user32::SetWindowPos(p$HWNDPARENT, p-1, i0, i0, i0, i0, i0x0003)"
    Sleep 40
    System::Call "user32::SetWindowPos(p$HWNDPARENT, p-2, i0, i0, i0, i0, i0x0003)"
    System::Call "user32::SetForegroundWindow(p$HWNDPARENT)"
    Pop $6
    Pop $5
    Pop $4
    Pop $3
    Pop $2
    Pop $1
    Pop $0
FunctionEnd

Function un.AsteriaPageShow
    Call un.CenterAndRaiseInstaller
FunctionEnd

Function .onInit
    StrCpy $LogFile "$LOCALAPPDATA\asteria-installer.log"
    Delete $LogFile

    Push "=== ASTERIA CLIENT v${VERSIONMAJOR}.${VERSIONMINOR}.${VERSIONBUILD} INSTALLER ==="
    Call WriteLog
    Push "Installation started with admin privileges"
    Call WriteLog
    Push "Log file location: $LogFile"
    Call WriteLog

    ; Instant light stop only — full PreInstallKillFast runs in Phase 1 so the
    ; Welcome page is not blocked by PowerShell / legacy tree cleanup.
    nsExec::Exec 'taskkill /F /T /IM asteria-gui.exe >nul 2>&1'
FunctionEnd

; ===================================================================
; WEBVIEW2 RUNTIME (Control Center / asteria-gui.exe)
; Prefer offline Evergreen Standalone x64 (bundled). Bootstrapper is fallback only.
; ===================================================================
Function WebView2RuntimePresent
    ; Sets $R9 to pv / marker when found, else empty. Same keys as asteria_gui.
    StrCpy $R9 ""
    ReadRegStr $R9 HKLM "SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}" "pv"
    ${If} $R9 != ""
    ${AndIf} $R9 != "0.0.0.0"
        Return
    ${EndIf}
    SetRegView 64
    ReadRegStr $R9 HKLM "SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}" "pv"
    SetRegView 32
    ${If} $R9 != ""
    ${AndIf} $R9 != "0.0.0.0"
        Return
    ${EndIf}
    ReadRegStr $R9 HKCU "SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}" "pv"
    ${If} $R9 != ""
    ${AndIf} $R9 != "0.0.0.0"
        Return
    ${EndIf}
    ; Filesystem fallback (registry lag / Server SKUs)
    ${If} ${FileExists} "$PROGRAMFILES64\Microsoft\EdgeWebView\Application\msedgewebview2.exe"
        StrCpy $R9 "fs64"
        Return
    ${EndIf}
    ${If} ${FileExists} "$PROGRAMFILES\Microsoft\EdgeWebView\Application\msedgewebview2.exe"
        StrCpy $R9 "fs32"
        Return
    ${EndIf}
    StrCpy $R9 ""
FunctionEnd

Function EnsureWebView2
    Call WebView2RuntimePresent
    ${If} $R9 != ""
        !insertmacro LOG "[WEBVIEW2] Runtime present (pv=$R9)"
        Goto Wv2Done
    ${EndIf}

    ; 1) Offline standalone (bundled ~150 MB) — no internet required on target
    IfFileExists "$INSTDIR\MicrosoftEdgeWebView2RuntimeInstallerX64.exe" 0 Wv2TryBootstrap
        !insertmacro LOG "[WEBVIEW2] Runtime missing — installing offline Standalone x64..."
        DetailPrint "Installing Microsoft Edge WebView2 Runtime (offline)..."
        ; ExecWait blocks until done; standalone can take 1–3 minutes.
        ExecWait '"$INSTDIR\MicrosoftEdgeWebView2RuntimeInstallerX64.exe" /silent /install' $R8
        !insertmacro LOG "[WEBVIEW2] Standalone exit=$R8"
        Sleep 1500
        Call WebView2RuntimePresent
        ${If} $R9 != ""
            !insertmacro LOG "[WEBVIEW2] Runtime installed OK via standalone (pv=$R9)"
            Goto Wv2Done
        ${EndIf}
        !insertmacro LOG "[WEBVIEW2] Standalone finished but runtime not detected yet — trying bootstrapper"

    Wv2TryBootstrap:
    IfFileExists "$INSTDIR\MicrosoftEdgeWebview2Setup.exe" 0 Wv2MissingPayload
        !insertmacro LOG "[WEBVIEW2] Trying Evergreen bootstrapper (needs network)..."
        ExecWait '"$INSTDIR\MicrosoftEdgeWebview2Setup.exe" /silent /install' $R8
        !insertmacro LOG "[WEBVIEW2] Bootstrapper exit=$R8"
        Sleep 1500
        Call WebView2RuntimePresent
        ${If} $R9 != ""
            !insertmacro LOG "[WEBVIEW2] Runtime installed OK via bootstrapper (pv=$R9)"
            Goto Wv2Done
        ${EndIf}
        !insertmacro LOG "[WEBVIEW2] WARNING: installers finished but runtime still not registered"
        IfSilent Wv2Done
            MessageBox MB_ICONEXCLAMATION|MB_OK "Microsoft Edge WebView2 Runtime kurulamadı.$\r$\n$\r$\nAsteria motoru çalışır; Control Center için paketi yeniden deneyin veya:$\r$\nhttps://developer.microsoft.com/microsoft-edge/webview2/"
        Goto Wv2Done

    Wv2MissingPayload:
        !insertmacro LOG "[WEBVIEW2] ERROR: no WebView2 installer payload in install dir"
        IfSilent Wv2Done
            MessageBox MB_ICONEXCLAMATION|MB_OK "WebView2 kurulum paketi eksik.$\r$\nControl Center için Evergreen Runtime kurun:$\r$\nhttps://developer.microsoft.com/microsoft-edge/webview2/"
    Wv2Done:
FunctionEnd

; ===================================================================
; MAIN INSTALL SECTION
; ===================================================================
Section "Asteria Client (Required)" SEC_MAIN
    SectionIn RO

    ; =================================================================
    ; PHASE 1: PRE-INSTALLATION CLEANUP
    ; =================================================================
    !insertmacro LOG "[PHASE 1] Starting pre-installation cleanup..."

    ; Full stop + legacy purge (moved here from .onInit so Welcome UI is instant)
    !insertmacro LOG "[PREP] Step 0 - PreInstallKillFast (tasks/processes/legacy)..."
    Call PreInstallKillFast

    ; Step 1: Delete ALL scheduled tasks FIRST (prevents respawn)
    !insertmacro LOG "[PREP] Step 1 - Deleting all scheduled tasks..."
    Call DeleteAllHoneypotTasks
    Sleep 200

    ; Step 2: Kill all honeypot processes with verification
    !insertmacro LOG "[PREP] Step 2 - Killing Asteria / legacy client processes..."
    Call KillHoneypotProcesses

    ; Step 3: Rename locked _internal/exe aside + Defender exclude BEFORE extract
    !insertmacro LOG "[PREP] Step 3 - Prepare install dir for overwrite..."
    Call PrepareInstallDirForOverwrite

    ; Step 4: Brand ProgramData path (copy YesNext → Asteria)
    !insertmacro LOG "[PREP] Step 4 - Migrate ProgramData to Asteria..."
    Call MigrateProgramData

    !insertmacro LOG "[PHASE 1] Pre-installation cleanup complete."

    ; =================================================================
    ; PHASE 2: FILE INSTALLATION
    ; =================================================================
    !insertmacro LOG "[PHASE 2] Starting file installation..."
    !insertmacro LOG "[INSTALL] Target directory: $INSTDIR"
    SetOutPath $INSTDIR
    ; try = skip locked files silently (no Abort/Retry/Ignore). prepare-install-dir
    ; already relocates the hot trees; try is belt-and-suspenders for AV/handle races.
    SetOverwrite try

    ; Install motor files (temporary onedir: exe + _internal next to it)
    !insertmacro LOG "[FILES] Installing application files (onedir)..."
    SetOutPath $INSTDIR
    File /r "dist\asteria-client\*.*"
    ; Separate interactive GUI host (onefile; no motor secrets in WebView).
    File "dist\asteria-gui.exe"
    ; WebView2 Evergreen Standalone x64 (~150 MB) — offline silent install if missing.
    File "vendor\MicrosoftEdgeWebView2RuntimeInstallerX64.exe"
    ; Tiny bootstrapper fallback (needs network) if standalone somehow fails.
    File /nonfatal "vendor\MicrosoftEdgeWebview2Setup.exe"
    ; Extra config copies at install root (also inside _internal via PyInstaller datas)
    File /oname=client_config.json "dist\client_config.json"
    File /oname=client_lang.json "dist\client_lang.json"
    File /oname=LICENSE "dist\LICENSE"
    File /oname=README.md "dist\README.md"
    CreateDirectory "$INSTDIR\scripts"
    ; Do NOT install kill/update helpers into Program Files — any local user can
    ; read+execute them there. Installer embeds them in $PLUGINSDIR only.
    ; Self-update stages update-and-install.ps1 under ProgramData (ACL'd).
    ; Delete leftovers from older builds that shipped these scripts.
    Delete "$INSTDIR\scripts\kill-honeypot.ps1"
    Delete "$INSTDIR\scripts\prepare-install-dir.ps1"
    Delete "$INSTDIR\scripts\update-and-install.ps1"
    ; memory_restart.ps1 is often FileInUse (schtask PowerShell). Relocate then
    ; write via PLUGINSDIR copy with retries — never Abort/Retry/Ignore UI.
    !insertmacro LOG "[FILES] Staging memory_restart.ps1 (lock-safe)..."
    Call InstallMemoryRestartScript
    !insertmacro LOG "[FILES] Application files installed (exe + _internal)."
    Call HardenInstallRootAcl
    ; Helper scripts remain SYSTEM/Admin-only after the root RX policy.
    Call HardenInstallScriptsAcl
    Call HardenMotorRuntimeAcl

    ; =================================================================
    ; PHASE 3: POST-INSTALLATION CONFIGURATION
    ; =================================================================
    !insertmacro LOG "[PHASE 3] Starting post-installation configuration..."

    ; Control Center needs Edge WebView2 Runtime (often missing on Server SKUs).
    Call EnsureWebView2

    ; Windows Defender exclusions — already attempted in prepare-install-dir;
    ; refresh async (Add-MpPreference can hang under nsExec::Exec).
    !insertmacro LOG "[CONFIG] Refreshing Defender exclusions (async)..."
    nsExec::Exec 'cmd /c start "" /b powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command "try{Add-MpPreference -ExclusionPath \"$INSTDIR\" -Force -EA SilentlyContinue;Add-MpPreference -ExclusionProcess \"$INSTDIR\asteria-client.exe\" -Force -EA SilentlyContinue;Add-MpPreference -ExclusionProcess \"$INSTDIR\asteria-gui.exe\" -Force -EA SilentlyContinue}catch{}"'

    ; Create uninstaller
    !insertmacro LOG "[CONFIG] Creating uninstaller..."
    WriteUninstaller "$INSTDIR\Uninstall.exe"

    ; Registry entries for Add/Remove Programs
    !insertmacro LOG "[CONFIG] Writing registry entries..."
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "DisplayName" "${APPNAME}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "UninstallString" "$\"$INSTDIR\Uninstall.exe$\""
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "QuietUninstallString" "$\"$INSTDIR\Uninstall.exe$\" /S"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "InstallLocation" "$\"$INSTDIR$\""
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "DisplayIcon" "$\"$INSTDIR\asteria-gui.exe$\""
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "Publisher" "${COMPANYNAME}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "DisplayVersion" "${VERSIONMAJOR}.${VERSIONMINOR}.${VERSIONBUILD}"
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "VersionMajor" ${VERSIONMAJOR}
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "VersionMinor" ${VERSIONMINOR}
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "NoRepair" 1

    ; Start Menu shortcuts (always)
    !insertmacro LOG "[CONFIG] Creating Start Menu shortcuts..."
    CreateDirectory "$SMPROGRAMS\${COMPANYNAME}"
    CreateShortCut "$SMPROGRAMS\${COMPANYNAME}\Asteria.lnk" "$INSTDIR\asteria-gui.exe"
    CreateShortCut "$SMPROGRAMS\${COMPANYNAME}\Uninstall.lnk" "$INSTDIR\Uninstall.exe"

    ; =================================================================
    ; PHASE 4: AUTO-START
    ; Silent (/S): NEVER start asteria-client here.
    ; update-and-install.ps1 owns kill → install → --create-tasks → daemon/GUI.
    ; Exec mid-install while helper Start-Process -Wait = classic self-deadlock
    ; (new process locks files / Defender / finalize never returns).
    ; =================================================================
    IfSilent 0 InteractiveOnboarding
        ; Self-update helper also restarts, but direct /S installs have no
        ; helper. Async launch occurs after all files/ACL/registry work.
        !insertmacro LOG "[AUTO-START] Silent install — create tasks/start Asteria motor."
        Exec '"$INSTDIR\asteria-client.exe" --mode=daemon --create-tasks'
        Goto SkipAutoStart
    InteractiveOnboarding:
        ; Force visible GUI until user registers / links account (no tray hide)
        ExpandEnvStrings $1 "%ProgramData%\Asteria"
        CreateDirectory "$1"
        FileOpen $0 "$1\force_gui_onboarding.flag" w
        FileWrite $0 "interactive_install$\r$\n"
        FileClose $0
        !insertmacro LOG "[ONBOARDING] force_gui_onboarding.flag written — GUI will stay visible"
        nsExec::Exec 'schtasks /end /tn "Asteria-Tray" >nul 2>&1'
        nsExec::Exec 'schtasks /end /tn "Asteria-Background" >nul 2>&1'
        nsExec::Exec 'schtasks /end /tn "CloudHoneypot-Tray" >nul 2>&1'
        nsExec::Exec 'schtasks /end /tn "CloudHoneypot-Background" >nul 2>&1'
        ; Launch immediately — installer closes (AutoCloseWindow); no Finish checkbox
        Call LaunchAsCurrentUser
        !insertmacro LOG "[AUTO-START] GUI launched after interactive install."
    SkipAutoStart:

    !insertmacro LOG "[FINISH] Installation complete."
SectionEnd

; Optional Components-page checkbox (UNCHECKED by default — user must opt in).
; Start Menu shortcut is always created in SEC_MAIN.
Section /o "Desktop Shortcut" SEC_DESKTOP
    !insertmacro LOG "[CONFIG] Creating desktop shortcut..."
    CreateShortCut "$DESKTOP\Asteria.lnk" "$INSTDIR\asteria-gui.exe"
SectionEnd

; ===================================================================
; UNINSTALLER SECTION
; Must remove everything install writes: motor + GUI + scripts + shortcuts
; + ARP + Defender exclusions + services/tasks (via kill helpers above).
; Locked files use /REBOOTOK so asteria-gui.exe cannot linger after a failed Delete.
; ===================================================================
Section "Uninstall"
    ; Remove compatibility flag
    DeleteRegValue HKCU "Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" "$INSTDIR\asteria-client.exe"
    DeleteRegValue HKCU "Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" "$INSTDIR\asteria-gui.exe"
    DeleteRegValue HKCU "Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" "$INSTDIR\honeypot-client.exe"

    ; Phase 1: Stop everything (tasks, Guardian, motor, GUI)
    DetailPrint "Phase 1: Stopping all services and processes..."
    Call un.DeleteAllHoneypotTasks
    Call un.KillHoneypotProcesses
    ; Extra settle time so WebView2 / onefile GUI release file locks
    Sleep 1000
    nsExec::Exec 'taskkill /F /T /IM asteria-gui.exe >nul 2>&1'
    nsExec::Exec 'taskkill /F /T /IM asteria-client.exe >nul 2>&1'
    Sleep 500

    ; Phase 2: Remove Windows Defender exclusions
    DetailPrint "Removing Windows Defender exclusions..."
    nsExec::ExecToLog 'powershell -ExecutionPolicy Bypass -Command "try { Remove-MpPreference -ExclusionPath \"$INSTDIR\" -Force -EA SilentlyContinue; Remove-MpPreference -ExclusionProcess \"$INSTDIR\asteria-client.exe\" -Force -EA SilentlyContinue; Remove-MpPreference -ExclusionProcess \"$INSTDIR\asteria-gui.exe\" -Force -EA SilentlyContinue } catch { }"'

    ; Phase 3: Remove shortcuts (Asteria + legacy YesNext names)
    DetailPrint "Removing shortcuts..."
    Delete "$DESKTOP\Asteria.lnk"
    Delete "$DESKTOP\Asteria Client.lnk"
    Delete "$DESKTOP\Cloud Honeypot Client.lnk"
    Delete "$DESKTOP\Cloud Honeypot.lnk"
    Delete "$DESKTOP\Honeypot Client.lnk"
    Delete "$SMPROGRAMS\${COMPANYNAME}\Asteria.lnk"
    Delete "$SMPROGRAMS\${COMPANYNAME}\Asteria Client.lnk"
    Delete "$SMPROGRAMS\${COMPANYNAME}\Uninstall.lnk"
    RMDir "$SMPROGRAMS\${COMPANYNAME}"
    RMDir /r "$SMPROGRAMS\YesNext"
    RMDir /r "$SMPROGRAMS\Cloud Honeypot Client"
    RMDir /r "$SMPROGRAMS\CloudHoneypot"

    ; Phase 4: Remove application files
    ; Explicit deletes first (GUI was the common leftover when process still held the lock),
    ; then recursive wipe of $INSTDIR so future added files cannot be forgotten.
    DetailPrint "Removing application files..."
    Delete /REBOOTOK "$INSTDIR\asteria-gui.exe"
    Delete /REBOOTOK "$INSTDIR\asteria-client.exe"
    Delete /REBOOTOK "$INSTDIR\honeypot-client.exe"
    Delete /REBOOTOK "$INSTDIR\Uninstall.exe"
    Delete "$INSTDIR\client_config.json"
    Delete "$INSTDIR\client_lang.json"
    Delete "$INSTDIR\LICENSE"
    Delete "$INSTDIR\README.md"
    Delete "$INSTDIR\MicrosoftEdgeWebview2Setup.exe"
    Delete "$INSTDIR\scripts\kill-honeypot.ps1"
    Delete "$INSTDIR\scripts\prepare-install-dir.ps1"
    Delete "$INSTDIR\scripts\update-and-install.ps1"
    Delete "$INSTDIR\scripts\memory_restart.ps1"
    Delete "$INSTDIR\scripts\install-memory-restart.ps1"
    Delete "$INSTDIR\scripts\reset-agent-identity.ps1"
    RMDir /r "$INSTDIR\scripts"
    RMDir /r "$INSTDIR\_internal"
    RMDir /r "$INSTDIR\runtime"
    ; prepare-install-dir may leave .stale_* trees when files were locked
    nsExec::ExecToLog 'powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -LiteralPath \"$INSTDIR\" -Force -EA SilentlyContinue | Where-Object { $$_.Name -like ''.stale_*'' } | ForEach-Object { Remove-Item -LiteralPath $$_.FullName -Recurse -Force -EA SilentlyContinue }"'
    ; Final wipe — anything remaining (including locked → reboot pending via /REBOOTOK)
    RMDir /r /REBOOTOK "$INSTDIR"
    ; Empty vendor parent if nothing else remains under Program Files\Asteria
    RMDir "$PROGRAMFILES64\${COMPANYNAME}"
    RMDir "$PROGRAMFILES\${COMPANYNAME}"

    ; Phase 5: Remove registry entries
    DetailPrint "Removing registry entries..."
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}"
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Cloud Honeypot Client"
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\CloudHoneypotClient"
    DeleteRegKey HKCU "Software\Asteria"
    DeleteRegKey HKCU "Software\YesNext\CloudHoneypot"
    DeleteRegKey HKLM "Software\Asteria"

    ; Phase 6: Clean staging / stop flags (keep token.dat for optional reinstall continuity)
    DetailPrint "Cleaning update staging and stop flags..."
    nsExec::Exec 'cmd /c del "%APPDATA%\YesNext\CloudHoneypot\watchdog_token.txt" 2>nul'
    nsExec::Exec 'cmd /c del "%ProgramData%\YesNext\CloudHoneypot\watchdog_stop.flag" 2>nul'
    nsExec::Exec 'cmd /c del "%APPDATA%\Asteria\watchdog.token" 2>nul'
    nsExec::Exec 'cmd /c del "%TEMP%\honeypot_watchdog_token.txt" 2>nul'
    nsExec::Exec 'cmd /c del "%ProgramData%\Asteria\update_in_progress.lock" 2>nul'
    nsExec::Exec 'cmd /c del "%ProgramData%\Asteria\force_gui_onboarding.flag" 2>nul'
    nsExec::Exec 'cmd /c rmdir /s /q "%ProgramData%\Asteria\update" 2>nul'
    nsExec::Exec 'cmd /c rmdir /s /q "%ProgramData%\Asteria\runtime" 2>nul'

    DetailPrint "Asteria Client has been completely removed."
SectionEnd

; Section descriptions
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
!insertmacro MUI_DESCRIPTION_TEXT ${SEC_MAIN} "Core Asteria Client application and configuration files. This component is required."
!insertmacro MUI_DESCRIPTION_TEXT ${SEC_DESKTOP} "Optional: create a desktop shortcut. Off by default — check to enable."
!insertmacro MUI_FUNCTION_DESCRIPTION_END
