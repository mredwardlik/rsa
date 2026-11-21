@echo off
rem Builds generator.exe, encryptor.exe and decryptor.exe into the dist folder
if not exist .env\Scripts\activate.bat python -m venv .env
call .env\Scripts\activate.bat
pip install . pyinstaller
for %%p in (generator encryptor decryptor) do pyinstaller --onefile --noconfirm %%p.py
echo.
echo Done: dist\generator.exe, dist\encryptor.exe, dist\decryptor.exe
pause
