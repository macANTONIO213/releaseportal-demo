import React, { useCallback, useEffect, useState } from 'react';
import { IconStack2, IconLayoutDashboard, IconGitBranch, IconCube, IconRefresh, IconLogout } from '@tabler/icons-react';
import '@fontsource/inter/400.css';
import '@fontsource/inter/500.css';
import '@fontsource/inter/600.css';
import '@fontsource/inter/700.css';
import '../portal.css';
import './mvp.css';
import { call, date, label } from './api';
import { Evidence } from './Evidence';
import ReleaseDetail from './ReleaseDetail';

function ErrorNotice({ error, clear }) {
  if (!error) return null;
  return <div className="mvp-error" role="alert"><div><strong>{error.message}</strong>{error.reference && <small>Support reference: {error.reference}</small>}</div><button onClick={clear} aria-label="Dismiss error">Dismiss</button></div>;
}

function Login({ session, signedIn, report }) {
  return <main className="mvp-login"><section className="mvp-card"><IconStack2 size={36} /><h1>ReleasePortal</h1><p>Sign in with your GitHub account to select a repository, run checks and review an AWS deployment.</p>
    {session.github_configured ? <a className="btn primary" href="/auth/login">Sign in with GitHub</a> : <div className="mvp-warning">GitHub App configuration is required before sign-in. No GitHub password or browser session is collected here.</div>}
    <p className="mvp-help">Repository access is limited by your permissions and the configured GitHub App installation. {session.ingress_mode === 'public' ? 'This HTTPS portal requires an explicitly approved GitHub identity.' : 'The shared private portal requires VPN access.'}</p>
  </section></main>;
}

function Feedback({ perform }) {
  const [rating, setRating] = useState(4);
  const [task, setTask] = useState('overall');
  const [minutes, setMinutes] = useState('');
  const [comment, setComment] = useState('');
  return <details className="mvp-card"><summary>Share pilot feedback</summary><form onSubmit={e => { e.preventDefault(); perform('/api/feedback', { rating: Number(rating), task, minutes: minutes === '' ? null : Number(minutes), comment }).then(ok => { if (ok) { setComment(''); setMinutes(''); } }); }}>
    <div className="mvp-form-grid"><label className="field">Task<select value={task} onChange={e => setTask(e.target.value)}>{['overall', 'build', 'review', 'deployment'].map(t => <option key={t}>{t}</option>)}</select></label>
      <label className="field">Ease of use<select value={rating} onChange={e => setRating(e.target.value)}>{[1, 2, 3, 4, 5].map(n => <option key={n} value={n}>{n} / 5</option>)}</select></label>
      <label className="field">Hands-on minutes<input type="number" min="0" max="1440" value={minutes} onChange={e => setMinutes(e.target.value)} /></label></div>
    <label className="field">What helped or slowed you down?<textarea maxLength={1000} value={comment} onChange={e => setComment(e.target.value)} /></label>
    <p className="mvp-help">No secrets or employee/application records in feedback.</p><button className="btn secondary">Send feedback</button>
  </form></details>;
}

export default function MvpPortal() {
  const [session, setSession] = useState(null);
  const [data, setData] = useState(null);
  const [page, setPage] = useState('Project');
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState('');
  const [commit, setCommit] = useState('');
  const [repository, setRepository] = useState('');
  const [selectedRun, setSelectedRun] = useState(null);
  const [selectedRelease, setSelectedRelease] = useState(null);
  const [metrics, setMetrics] = useState(null);
  const refresh = useCallback(async () => {
    try { setData(await call('/api/dashboard')); }
    catch (err) { setError(err); if (err.status === 401) setSession(await call('/api/session')); }
  }, []);
  useEffect(() => { call('/api/session').then(setSession).catch(setError); }, []);
  useEffect(() => {
    if (!session?.user) return;
    refresh();
    const timer = setInterval(refresh, 10000);
    return () => clearInterval(timer);
  }, [session?.user?.id, refresh]);
  const perform = async (path, value) => {
    if (busy) return false;
    setBusy(true); setError(null); setNotice('');
    try {
      const result = await call(path, value);
      if (path === '/api/releases') { setSelectedRelease(result.id); setPage('Releases'); }
      if (path === '/api/runs') { setSelectedRun(result.id); setCommit(''); }
      setNotice(path === '/api/feedback' ? 'Feedback saved. Thank you.' : 'Saved.');
      await refresh();
      return true;
    } catch (err) { setError(err); return false; }
    finally { setBusy(false); }
  };
  const errors = <ErrorNotice error={error} clear={() => setError(null)} />;
  if (!session) return <><p className="mvp-loading" role="status">Connecting to ReleasePortalâ€¦</p>{errors}</>;
  if (!session.user) return <>{errors}<Login session={session} signedIn={setSession} report={setError} /></>;
  if (!data) return <>{errors}<p className="mvp-loading" role="status">Loading your projectâ€¦</p><button className="btn secondary" onClick={refresh}>Retry</button></>;
  const run = data.runs.find(r => r.id === selectedRun) || data.runs[0];
  const release = data.releases.find(r => r.id === selectedRelease) || data.releases[0];
  const canBuild = ['developer', 'reviewer'].includes(session.user.role);
  return <div className="shell mvp-shell"><aside className="sidebar"><button className="brand" onClick={() => setPage('Project')}><IconStack2 size={33} /><span>ReleasePortal</span></button>
    <div className="mvp-org">ReleasePortal Demo</div><nav aria-label="Main navigation">{[['Project', IconLayoutDashboard], ['Runs', IconGitBranch], ['Releases', IconCube]].map(([name, Icon]) => <button aria-label={name} aria-current={page === name ? 'page' : undefined} className={page === name ? 'active' : ''} onClick={() => setPage(name)} key={name}><Icon size={24} />{name}</button>)}</nav>
    <div className="sidebar-footer">Development pilot<small>GitHub â†’ checks â†’ AWS</small></div></aside>
    <div className="workspace"><header className="topbar"><div className="breadcrumbs">Demo application / {page}</div><div className="mvp-user"><span>{session.user.name}<small>{session.user.role}</small></span><button aria-label="Sign out" onClick={async () => { try { setSession(await call('/api/logout', {}).then(() => call('/api/session'))); setData(null); } catch (err) { setError(err); } }}><IconLogout size={20} /></button></div></header>
      <main aria-busy={busy}>{session.mode === 'local' && <div className="mvp-warning">Local MVP. Shared pilot onboarding has not been completed.</div>}{errors}{notice && <p className="mvp-notice" role="status">{notice}</p>}
        <div className="page-heading"><div><h1>{page === 'Project' ? data.project.name : page}</h1><p>{data.project.repository} Â· {data.project.environment}</p></div><button className="btn secondary" onClick={refresh}><IconRefresh size={18} />Refresh</button></div>
        {session.owner_signin_only && <div className="mvp-warning">Owner access is enabled. Release approval is unavailable until an independent reviewer is assigned.</div>}
        {!data.pipeline_configured && <div className="mvp-warning">The isolated build runtime is not configured. Pipeline requests are disabled; no simulated runs are shown.</div>}
        {page === 'Project' && <>
          <section className="mvp-card"><h2>Your release workflow</h2><ol className="mvp-journey"><li>Select an authorized GitHub repository and exact commit.</li><li>Run unit tests and code scans in an isolated worker.</li><li>Review the artifact, target, changes and recovery scope.</li><li>After approval, enter three temporary AWS values and deploy.</li></ol><button className="btn primary" onClick={() => setPage('Runs')}>Open runs</button></section>
          <section className="mvp-card"><h2>Configured target</h2><dl className="mvp-facts"><div><dt>Account / region</dt><dd>{data.project.account} / {data.project.region}</dd></div><div><dt>Application access</dt><dd>Existing public HTTPS with application login. {session.ingress_mode === 'public' ? 'Portal: public HTTPS with approved GitHub authorization.' : 'Portal: private/VPN access required.'}</dd></div><div><dt>Application data</dt><dd>Synthetic demo data; email and AI disabled</dd></div><div><dt>Execution</dt><dd>Temporary AWS values are requested after review and held only in the trusted deployment process.</dd></div></dl></section>
          {session.user.role === 'reviewer' && <section className="mvp-card"><h2>Pilot measurements</h2><button className="btn secondary" onClick={async () => { try { setMetrics(await call('/api/metrics')); } catch (err) { setError(err); } }}>Load measurements</button>{metrics && <dl className="mvp-facts">{Object.entries(metrics).map(([key, value]) => <div key={key}><dt>{key.replaceAll('_', ' ')}</dt><dd>{value ?? 'No responses yet'}</dd></div>)}</dl>}</section>}
        </>}
        {page === 'Runs' && <>
          {canBuild && <section className="mvp-card"><h2>Run pipeline</h2><p>Choose a repository authorized for your GitHub App. The first supported repository is releaseportal-demo. Other repositories need a reviewed pipeline adapter.</p><form onSubmit={e => { e.preventDefault(); perform('/api/runs', { repository:repository.trim(), commit: commit.trim(), request_key: crypto.randomUUID() }); }}><label className="field">GitHub repository<input required list="authorized-repositories" value={repository} onChange={e => setRepository(e.target.value)} placeholder="https://github.com/macANTONIO213/repository" /></label><datalist id="authorized-repositories">{(data.repositories || []).map(repo => <option key={repo} value={repo} />)}</datalist><label className="field">Commit SHA<input required pattern="[a-f0-9]{40}" maxLength={40} value={commit} onChange={e => setCommit(e.target.value)} placeholder="40-character commit SHA" /></label><button className="btn primary" disabled={busy || !data.pipeline_configured}>Run scans and tests</button></form></section>}
          <section className="mvp-card"><h2>Pipeline runs</h2>{data.runs.length ? <div className="table-wrap"><table><thead><tr><th>Revision</th><th>Created</th><th>Status</th><th>Repository</th></tr></thead><tbody>{data.runs.map(r => <tr key={r.id}><td><button className="link" onClick={() => setSelectedRun(r.id)}>{r.commit.slice(0, 12)}</button></td><td>{date(r.created_at)}</td><td>{label(r.status)}</td><td>{r.repository}</td></tr>)}</tbody></table></div> : <div className="mvp-empty"><h3>No pipelines yet</h3><p>Select an authorized repository and run the pipeline to collect real evidence.</p></div>}</section>
          {run && <><Evidence run={run} />{canBuild && run.status === 'ready' && !data.releases.some(r => r.run_id === run.id) && <button className="btn primary" disabled={busy} onClick={() => perform('/api/releases', { run_id: run.id })}>Prepare release from this artifact</button>}</>}
        </>}
        {page === 'Releases' && <>
          <section className="mvp-card"><h2>Release history</h2>{data.releases.length ? <div className="table-wrap"><table><thead><tr><th>Revision</th><th>Status</th><th>Created</th></tr></thead><tbody>{data.releases.map(r => <tr key={r.id}><td><button className="link" onClick={() => setSelectedRelease(r.id)}>{r.plan.commit.slice(0, 12)}</button></td><td>{label(r.status)}</td><td>{date(r.created_at)}</td></tr>)}</tbody></table></div> : <div className="mvp-empty"><h3>No release prepared</h3><p>A build with passing tests, scans and a verified artifact is required.</p><button className="link" onClick={() => setPage('Runs')}>Open runs</button></div>}</section>
          {release && <ReleaseDetail key={release.id} release={release} user={session.user} perform={perform} deploymentConfigured={data.deployment_configured} />}
        </>}
        <Feedback perform={perform} />
        <details className="mvp-card"><summary>Recent activity</summary><ul className="mvp-events">{data.events.map((event, i) => <li key={i}><strong>{event.action.replaceAll('_', ' ')}</strong><small>{date(event.created_at)} Â· actor {event.actor || 'service'}</small></li>)}</ul></details>
      </main></div></div>;
}
