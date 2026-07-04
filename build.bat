@echo off
REM Builds LagSwitch into a single windowed LagSwitch.exe (admin-required) in
REM this folder, then cleans up the build scratch. Run it whenever you edit the .py.

echo Installing build tools and dependencies...
python -m pip install --upgrade pyinstaller
python -m pip install -r "%~dp0requirements.txt"

echo.
echo Building LagSwitch.exe ...
REM --collect-all pydivert bundles the WinDivert .dll/.sys driver (WINDIVERT method).
pyinstaller --onefile --windowed --uac-admin --name "LagSwitch" ^
    --icon "%~dp0LagSwitch.ico" --add-data "%~dp0LagSwitch.ico;." ^
    --collect-all pydivert ^
    --distpath . --workpath build_tmp --specpath build_tmp "%~dp0legmanlagswitch.py"

echo.
echo Cleaning up...
rmdir /s /q build_tmp 2>nul
rmdir /s /q __pycache__ 2>nul

echo.
echo Done. Your app is:  LagSwitch.exe
pause
