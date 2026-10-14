"""Package only tracked source before test dependency installation.
The pipeline tests this checkout, and later rejects source modifications.
"""
import io
import subprocess
import tarfile
from pathlib import Path, PurePosixPath

files = subprocess.check_output(['git', 'ls-files', '-z']).decode().split('\0')
with tarfile.open('reports/source.tar.gz', 'w:gz') as archive:
    for name in sorted(filter(None, files)):
        path = PurePosixPath(name)
        if path.is_absolute() or '..' in path.parts or '\\' in name:
            raise SystemExit('Unsafe source path')
        local = Path(name)
        if local.is_symlink():
            raise SystemExit('Pilot source archives do not support symbolic links')
        if path.name.startswith('.env') or path.name.endswith(('.sqlite3', '.pem', '.key')) or any(p in ['media', '.venv', 'node_modules'] for p in path.parts):
            raise SystemExit('Tracked data or credential-like file must be removed before packaging')
        data = local.read_bytes()
        item = tarfile.TarInfo(name)
        item.size, item.mode, item.mtime = len(data), 0o644, 0
        archive.addfile(item, io.BytesIO(data))
print('Tracked source packaged. No deployment performed.')
