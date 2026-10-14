param([string]$PythonExe = (Join-Path $PSScriptRoot '..\.venv\Scripts\python.exe'))
$ErrorActionPreference = 'Stop'
$portalRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Push-Location $portalRoot
try {
  & $PythonExe backend/manage.py check
  if ($LASTEXITCODE -ne 0) { throw 'Django check failed' }
  & $PythonExe backend/manage.py makemigrations --check --dry-run
  if ($LASTEXITCODE -ne 0) { throw 'Migration drift detected' }
  & $PythonExe backend/manage.py test portal --verbosity 1
  if ($LASTEXITCODE -ne 0) { throw 'Critical-path tests failed' }
  & $PythonExe -m pip check
  if ($LASTEXITCODE -ne 0) { throw 'Dependency resolution failed' }
} finally { Pop-Location }
