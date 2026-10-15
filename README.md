# ReleasePortal demo

ReleasePortal connects GitHub repository selection, scan/test evidence and independent release review in one portal. This source demo includes a React interface, Django API, migrations, tests, a pinned container recipe and a sandbox pipeline draft.

This copy is prepared for `macANTONIO213/releaseportal-demo`. It contains no assigned AWS application target, AWS provisioning plans, prior execution records, populated secrets, dependencies, runtime database or Git history. Examples using account `111122223333`, a zero-filled instance ID and `example.invalid` are non-operational test fixtures.

## Run locally

Use Python 3.12, Node 22 and pnpm 11.25.0. In PowerShell, from this folder:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.lock.txt
pnpm install --frozen-lockfile
pnpm run build
$env:PORTAL_MODE = 'local'
$env:PORTAL_RUNTIME_DIR = Join-Path $env:LOCALAPPDATA 'ReleasePortalDemo\runtime'
.\.venv\Scripts\python.exe backend\manage.py migrate
.\.venv\Scripts\python.exe scripts\serve.py
```

The local server binds to `127.0.0.1:8055`. There are no default login credentials or seeded releases. GitHub sign-in shows a setup-required state until a real GitHub App is registered and configured. `.env.example` documents settings but is not loaded automatically. Supply actual secrets through a private runtime mechanism; do not commit them.

```powershell
.\scripts\verify-mvp.ps1 -PythonExe .\.venv\Scripts\python.exe
pnpm run test:sites
```

## Demo boundaries

The approved initial owner launch uses `PORTAL_OWNER_SIGNIN_ONLY=1` with only
GitHub user ID284642046 (macANTONIO213) and no reviewer IDs. It retains real GitHub
App sign-in, public HTTPS and PostgreSQL requirements. Release approval remains
unavailable, including for stored users with a former reviewer role. Assign an
independent reviewer and turn off this mode before enabling release review.

Public hosting requires a real HTTPS hostname, trusted proxy ranges, PostgreSQL with verified TLS, persistent artifact storage, GitHub App configuration and approved numeric developer/reviewer identities. GitHub CLI authentication used to publish this repository is separate from the GitHub App authorization used by portal users.

The public launcher explicitly retains Waitress's `X-Forwarded-Proto` header.
It clears other proxy headers and preserves the original socket peer so ingress
middleware can enforce the configured ALB subnet ranges. The hosting security
group must admit the application port only from its dedicated HTTPS ALB.
Default Waitress header filtering would otherwise remove the scheme header and
cause valid HTTPS requests to fail the application's ingress check.

Repository execution requires a reviewed Linux sandbox and restricted egress. The retained pipeline is a Django-layout draft, not a universal build system. Browser cookies are never reused as API credentials. Password and legacy CI modules remain for compatibility tests; the active frontend uses GitHub authorization.

AWS application deployment is disabled at startup even if its environment flags are set. The retained deployment script path contains only a failing stub. Do not treat the test adapter, mock receipts or successful local tests as a live deployment. A new target and deployment adapter must be reviewed separately. The Docker default is shared/pilot mode and deliberately refuses startup until its required configuration is supplied; use the local setup above for local development.

Do not upload `.venv`, `node_modules`, `dist`, runtime files, `.env` files, authentication caches or generated archives. No license has been assigned by this preparation; choose one only if you have authority to license the code. Nothing in this folder proves production acceptance or authorizes cloud provisioning.
