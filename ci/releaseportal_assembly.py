"""Trusted COPY-only assembly context. Never consume a guest Dockerfile or execute its code."""
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import tarfile


class AssemblyRejected(Exception):
    pass


def members(content):
    if len(content) > 100*1024*1024:
        raise AssemblyRejected('compressed_archive_limit')
    result, total = {}, 0
    with tarfile.open(fileobj=io.BytesIO(content), mode='r:gz') as archive:
        for item in archive:
            path = PurePosixPath(item.name)
            if (not item.isfile() or path.is_absolute() or '..' in path.parts or '\\' in item.name or
                not path.parts or str(path) != item.name or item.name in result or
                any(p in ['.git','.venv','venv','node_modules','media'] for p in path.parts) or
                path.name.startswith('.env') or path.suffix in ['.key','.pem','.sqlite3']):
                raise AssemblyRejected('unsafe_archive_member')
            total += item.size
            if total > 500*1024*1024 or item.size > 25*1024*1024 or len(result) >= 10000:
                raise AssemblyRejected('expanded_archive_limit')
            data = archive.extractfile(item).read(item.size+1)
            if len(data) != item.size:
                raise AssemblyRejected('truncated_archive')
            result[item.name] = data
    if not result:
        raise AssemblyRejected('empty_archive')
    return result


def context(source, artifact, profile, artifact_sha256):
    if hashlib.sha256(artifact).hexdigest() != artifact_sha256:
        raise AssemblyRejected('artifact_digest_mismatch')
    original, compiled = members(source), members(artifact)
    for name, data in original.items():
        if name.startswith('dist/') or compiled.get(name) != data:
            raise AssemblyRejected('source_artifact_mismatch')
    if any(name not in original and not name.startswith('dist/') for name in compiled):
        raise AssemblyRejected('unexpected_artifact_file')
    if 'dist/client/index.html' not in compiled or 'dist/server/index.js' not in compiled:
        raise AssemblyRejected('missing_compiled_frontend')
    for name, expected in profile['source_lock_sha256'].items():
        if hashlib.sha256(original.get(name,b'')).hexdigest() != expected:
            raise AssemblyRejected('dependency_profile_changed')
    migration = {name:hashlib.sha256(data).hexdigest() for name,data in original.items()
                 if name.startswith('backend/portal/migrations/') and name.endswith('.py')}
    encoded = json.dumps(migration,sort_keys=True,separators=(',',':')).encode()
    if hashlib.sha256(encoded).hexdigest() != profile['migration_manifest_sha256']:
        raise AssemblyRejected('migration_profile_changed')
    base = profile['assembly_base']
    if not re.fullmatch(r'[0-9]{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com/[a-z0-9/-]+@sha256:[a-f0-9]{64}',base):
        raise AssemblyRejected('unreviewed_assembly_base')
    # Dockerfile contains no RUN/ADD, entrypoint or source-supplied recipe.
    recipe = (f'FROM {base}\nCOPY backend /app/backend\nCOPY scripts/serve.py /app/scripts/serve.py\n'
              'COPY dist /app/dist\nUSER 10001:10001\n')
    selected = {name:data for name,data in compiled.items() if
                name.startswith(('backend/','dist/')) or name == 'scripts/serve.py'}
    if 'scripts/serve.py' not in selected or 'backend/manage.py' not in selected:
        raise AssemblyRejected('missing_application_files')
    selected['Dockerfile'] = recipe.encode()
    output = io.BytesIO()
    with tarfile.open(fileobj=output,mode='w') as archive:
        for name,data in sorted(selected.items()):
            item=tarfile.TarInfo(name)
            item.size,item.mode,item.mtime=len(data),0o644,0
            archive.addfile(item,io.BytesIO(data))
    return output.getvalue()
