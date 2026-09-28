@echo off
chcp 65001 >nul
cd /d "%~dp0"
where node >nul 2>&1
if errorlevel 1 (
  echo Instale o Node.js LTS em https://nodejs.org e rode de novo.
  pause
  exit /b
)
if not exist node_modules\express\package.json (
  echo Instalando dependencias, aguarde...
  call npm install
  if errorlevel 1 (
    echo Falha no npm install. Copie a mensagem acima e envie para suporte.
    pause
    exit /b
  )
)
powershell -NoProfile -Command "Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue | Where-Object { (Get-Process -Id $_.OwningProcess).ProcessName -eq 'node' } | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }" >nul 2>&1
if not exist .env copy .env.example .env >nul
start "" cmd /c "timeout /t 3 >nul & start http://localhost:8000"
node --disable-warning=ExperimentalWarning server.js
pause
