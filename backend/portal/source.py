import hashlib
import io
import tarfile
from pathlib import Path, PurePosixPath
from django.conf import settings
from .services import RuleError

def normalized_archive(data):
    output = io.BytesIO()
    size, count, paths = 0, 0, set()
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as incoming, tarfile.open(fileobj=output, mode='w:gz') as outgoing:
            root = None
            for member in incoming:
                path = PurePosixPath(member.name)
                if path.is_absolute() or '..' in path.parts or '\\' in member.name or not path.parts:
                    raise ValueError()
                root = root or path.parts[0]
                if path.parts[0] != root:
                    raise ValueError()
                relative = PurePosixPath(*path.parts[1:])
                if str(relative) == '.' or member.isdir():
                    continue
                if not member.isfile() or str(relative) in paths:
                    raise ValueError()
                if any(p in ['.git', '.venv', 'venv', 'node_modules', 'media'] for p in relative.parts) or relative.name.startswith('.env') or relative.suffix in ['.sqlite3','.pem','.key']:
                    raise RuleError('source_contains_data', 'Remove credential/data files before building.')
                size += member.size
                count += 1
                if size > 500*1024*1024 or member.size > 25*1024*1024 or count > 10000:
                    raise ValueError()
                content = incoming.extractfile(member).read()
                item = tarfile.TarInfo(str(relative))
                item.size, item.mode, item.mtime = len(content), 0o644, 0
                outgoing.addfile(item, io.BytesIO(content))
                paths.add(str(relative))
        if not count:
            raise ValueError()
        return output.getvalue()
    except RuleError:
        raise
    except Exception:
        raise RuleError('unsafe_source_archive', 'Source archive is unsafe or exceeds pilot limits.')

def directory(run):
    return settings.ARTIFACT_ROOT / str(run.id)

def save_snapshot(run, downloaded):
    content = normalized_archive(downloaded)
    root = directory(run)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    (root/'source.tar.gz').write_bytes(content)
    run.source_sha256 = hashlib.sha256(content).hexdigest()
    run.save(update_fields=['source_sha256'])

def read_artifact(run):
    path = directory(run)/'source.tar.gz'
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 100*1024*1024:
        raise RuleError('artifact_missing', 'The source artifact is unavailable.')
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != (run.artifact_sha256 or run.source_sha256):
        raise RuleError('digest_mismatch', 'The artifact no longer matches the recorded digest.')
    return data
