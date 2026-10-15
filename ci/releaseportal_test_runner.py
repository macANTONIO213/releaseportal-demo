"""Trusted sandbox Django runner: export counts, never exception text."""
import json
from pathlib import Path
from django.test.runner import DiscoverRunner


class CountingRunner(DiscoverRunner):
    def run_suite(self, suite, **kwargs):
        result = super().run_suite(suite, **kwargs)
        failed = len(result.failures) + len(result.errors) + len(result.unexpectedSuccesses)
        skipped = len(result.skipped) + len(result.expectedFailures)
        total = result.testsRun
        if min(total, failed, skipped, total - failed - skipped) < 0:
            raise RuntimeError('Invalid test counts.')
        counts = {'passed': total - failed - skipped, 'failed': failed, 'skipped': skipped, 'total': total}
        Path('/output/django-tests.json').write_text(json.dumps(counts))
        return result
