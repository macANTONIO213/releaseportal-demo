import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import unittest

spec=importlib.util.spec_from_file_location('trusted_releaseportal_assembly',Path(__file__).resolve().parents[2]/'ci/releaseportal_assembly.py')
assembly=importlib.util.module_from_spec(spec)
spec.loader.exec_module(assembly)
context,members,AssemblyRejected=assembly.context,assembly.members,assembly.AssemblyRejected
from .source import normalized_archive
from .errors import RuleError


def archive(files):
    output=io.BytesIO()
    with tarfile.open(fileobj=output,mode='w:gz') as tar:
        for name,data in files.items():
            item=tarfile.TarInfo(name);item.size=len(data)
            tar.addfile(item,io.BytesIO(data))
    return output.getvalue()


class AssemblyTests(unittest.TestCase):
    def setUp(self):
        self.files={'backend/manage.py':b'# fixture', 'scripts/serve.py':b'# fixture',
            'backend/requirements.lock.txt':b'fixture==1', 'backend/portal/migrations/__init__.py':b''}
        self.source=archive(self.files)
        self.compiled={**self.files,'dist/client/index.html':b'<html/>','dist/server/index.js':b'export default {}'}
        migration={'backend/portal/migrations/__init__.py':hashlib.sha256(b'').hexdigest()}
        self.profile={'source_lock_sha256':{'backend/requirements.lock.txt':hashlib.sha256(b'fixture==1').hexdigest()},
            'migration_manifest_sha256':hashlib.sha256(json.dumps(migration,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
            'assembly_base':'111122223333.dkr.ecr.ap-southeast-1.amazonaws.com/portal@sha256:'+'a'*64}

    def assemble(self):
        compiled=archive(self.compiled)
        return context(self.source,compiled,self.profile,hashlib.sha256(compiled).hexdigest())

    def test_recipe_only_copies_verified_application_and_frontend(self):
        output=self.assemble()
        with tarfile.open(fileobj=io.BytesIO(output)) as tar:
            recipe=tar.extractfile('Dockerfile').read().decode()
            self.assertNotIn('RUN ',recipe)
            self.assertNotIn('ADD ',recipe)
            self.assertIn('USER 10001:10001',recipe)
            self.assertNotIn('ci/runner.Dockerfile',tar.getnames())

    def test_source_changes_extra_files_and_dependency_or_migration_changes_stop(self):
        for path in ['backend/manage.py','extra.sh','backend/requirements.lock.txt','backend/portal/migrations/0009_injected.py']:
            original=dict(self.compiled)
            self.compiled[path]=b'changed'
            with self.assertRaises(AssemblyRejected):
                self.assemble()
            self.compiled=original
        self.profile['migration_manifest_sha256']='0'*64
        with self.assertRaises(AssemblyRejected):
            self.assemble()

    def test_unsafe_compiled_paths_and_wrong_artifact_digest_stop(self):
        with self.assertRaises(AssemblyRejected):
            members(archive({'../escape':b'bad'}))
        with self.assertRaises(AssemblyRejected):
            context(self.source,archive(self.compiled),self.profile,'0'*64)

    def test_only_exact_blank_env_example_is_omitted_from_normalized_source(self):
        from django.conf import settings
        template=(settings.BASE_DIR.parent/'.env.example').read_bytes()
        normalized=normalized_archive(archive({'repo/.env.example':template,'repo/backend/manage.py':b'# fixture'}))
        self.assertEqual(set(members(normalized)),{'backend/manage.py'})
        with self.assertRaises(RuleError):
            normalized_archive(archive({'repo/.env.example':template+b'NEW_VALUE=changed\n','repo/app.py':b''}))
