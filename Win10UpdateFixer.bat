@ECHO off
call :Resume
goto %current%
goto :eof

:: This is script to reset stucked Windows 10 Updates
:: If this will not solve the issue, please reinstall Windows, you can select to keep all your files 

:one
::Add script to Run key
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v %~n0 /d %~dpnx0 /f
echo two >%~dp0current.txt
echo -- Section one --
echo Updating Windows Update AutoUpdate Client ...
powershell.exe -command wuauclt.exe /updatenow
echo System will now restarts, script will continue after restart
pause
shutdown -r -t 0
goto :eof

:two
echo -- Section two --
echo three >%~dp0current.txt
echo Stopping Windows Update Services
net stop wuauserv
net stop cryptSvc
net stop bits
net stop msiserver
echo Cleaning Windows Update files
del /f /s /q "%WINDIR%\SoftwareDistribution\*.*"
del /f /s /q "%WINDIR%\SoftwareDistribution\System32\catroot2\*.*"
echo Starting Update Services
net stop wuauserv
net stop cryptSvc
net stop bits
net stop msiserver
echo It is better to restart the PC now, if you wish so press any key
echo If you Do NOT want to Restart PC now close the window or press Ctrl+C
pause
shutdown -r -t 0
goto :eof

:three
echo -- Section three --
::Remove script from Run key
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v %~n0 /f
del %~dp0current.txt

:resume
if exist %~dp0current.txt (
    set /p current=<%~dp0current.txt
) else (
    set current=one
)
