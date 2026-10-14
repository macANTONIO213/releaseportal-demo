param([ValidateSet('configure','invite','serve','worker','check')][string]$Action = 'check', [string]$PythonExe = (Join-Path $PSScriptRoot '..\.venv\Scripts\python.exe'))
$ErrorActionPreference = 'Stop'
$portalRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$runtimeRoot = if ($env:PORTAL_RUNTIME_DIR) { $env:PORTAL_RUNTIME_DIR } else { Join-Path $env:LOCALAPPDATA 'ReleasePortal-Demo\runtime' }
New-Item -ItemType Directory -Force -Path $runtimeRoot | Out-Null
# Apply the ACL before any configuration or password-related file is written.
$taskSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls.exe $runtimeRoot /inheritance:r /grant:r "*${taskSid}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not restrict runtime access.' }
$env:PORTAL_RUNTIME_DIR = $runtimeRoot
$env:PORTAL_CONFIG_FILE = Join-Path $runtimeRoot 'service-config.dpapi'
if (-not (Test-Path -LiteralPath $env:PORTAL_CONFIG_FILE)) { Remove-Item Env:PORTAL_CONFIG_FILE }
switch ($Action) {
  'configure' { & $PythonExe (Join-Path $PSScriptRoot 'configure.py') }
  'invite' {
    $pilotEmail = Read-Host 'Invited email'
    $pilotRole = Read-Host 'Role: viewer, developer or reviewer'
    & $PythonExe (Join-Path $portalRoot 'backend\manage.py') invite $pilotEmail --role $pilotRole --password
  }
  'serve' { & $PythonExe (Join-Path $PSScriptRoot 'serve.py') }
  'worker' { & $PythonExe (Join-Path $portalRoot 'backend\manage.py') worker }
  'check' { & $PythonExe (Join-Path $portalRoot 'backend\manage.py') pilot_readiness }
}
if ($LASTEXITCODE -ne 0) { throw 'Action failed. No credentials were printed by this helper.' }
