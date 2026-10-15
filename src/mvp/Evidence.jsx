import React from 'react';

export function Evidence({ run }) {
  const evidence = run.evidence || {};
  const tests = evidence.tests;
  return <section className="mvp-card" aria-label="Build evidence">
    <h2>Build evidence</h2>
    <dl className="mvp-facts">
      <div><dt>Revision</dt><dd><code>{run.commit}</code></dd></div>
      <div><dt>Repository</dt><dd>{run.repository}</dd></div>
      <div><dt>Unit tests</dt><dd>{tests ? `${tests.passed} passed · ${tests.failed} failed · ${tests.skipped} skipped` : 'No test report collected'}</dd></div>
      {['source','dependencies', 'secrets'].map(name => <div key={name}><dt>{name === 'source' ? 'Python source scan' : name === 'dependencies' ? 'Dependency scan' : 'Secret scan'}</dt>
        <dd>{evidence.scans?.[name] ? `${evidence.scans[name].status} · ${evidence.scans[name].findings} blocking findings${evidence.scans[name].reviewed_findings ? ` · ${evidence.scans[name].reviewed_findings} reviewed false positives` : ''}` : 'Not collected'}</dd></div>)}
      <div><dt>Artifact</dt><dd>{run.artifact_sha256 ? <><span>{evidence.artifact?.name}</span><code>{run.artifact_sha256}</code><small>The trusted worker verified the tested source and release artifact digests.</small></> : 'No verified artifact collected'}</dd></div>
    </dl>
    {run.status === 'ready' && <a className="btn secondary" href={`/api/artifacts/${run.id}`}>Download verified artifact</a>}
    {run.error_code && <p className="mvp-warning">Run needs attention: <code>{run.error_code}</code>. Ask the pilot operator to inspect the isolated worker; failed checks never become a passing release.</p>}
  </section>;
}
