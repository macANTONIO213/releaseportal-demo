import React, { useState } from 'react';
import { date, label } from './api';
import AwsCredentials from './AwsCredentials';

export default function ReleaseDetail({ release, user, perform, deploymentConfigured }) {
  const [ack, setAck] = useState(false);
  const [outcome, setOutcome] = useState('uncertain');
  const [reference, setReference] = useState('');
  const [checks, setChecks] = useState({ https: false, login: false, readiness: false });
  const reviewer = user.role === 'reviewer';
  const ecs = release.plan.execution === 'ecs-service-image-v1';
  const direct = ecs || release.plan.execution === 'direct';
  const path = `/api/releases/${release.id}/`;
  const expired = release.approval_expires_at && new Date(release.approval_expires_at) <= new Date();
  return <section className="mvp-card">
    <div className="mvp-section-head"><h2>Release review</h2><span className="mvp-status">{label(release.status)}</span></div>
    <dl className="mvp-facts">
      <div><dt>Target</dt><dd>{ecs ? release.plan.target.service_arn : `${release.plan.account} · ${release.plan.region} · ${release.plan.environment}`}</dd></div>
      <div><dt>Revision</dt><dd><code>{release.plan.commit}</code></dd></div>
      <div><dt>Artifact SHA256</dt><dd><code>{release.artifact_sha256}</code></dd></div>
      <div><dt>Execution</dt><dd>{direct ? 'Trusted worker; temporary credentials entered only after approval.' : 'Recorded supervised handoff.'}</dd></div>
      <div><dt>Approved scope</dt><dd>{release.plan.scope}</dd></div>
      {ecs ? <><div><dt>Image</dt><dd><code>{release.plan.image}</code></dd></div><div><dt>Evidence and profile</dt><dd><code>{release.plan.evidence_sha256}</code><code>{release.plan.profile_sha256}</code></dd></div><div><dt>Runtime baseline</dt><dd><code>{release.plan.baseline_sha256}</code></dd></div></> : <div><dt>Exposure and data</dt><dd>{release.plan.exposure} · {release.plan.data} · Email and AI {release.plan.email_ai?.toLowerCase()}</dd></div>}
      <div><dt>Recovery</dt><dd>{ecs ? 'Stop and reconcile the controller receipt after an uncertain result. Do not repeat the update.' : release.plan.recovery}</dd></div>
      <div><dt>Approval expiry</dt><dd>{date(release.approval_expires_at)}{expired ? ' · Expired' : ''}</dd></div>
    </dl>
    {release.plan.operations && <><h3>Exact AWS operations</h3><ul className="mvp-journey">{release.plan.operations.map(operation => <li key={operation}>{operation}</li>)}</ul><h3>Application changes</h3><ul className="mvp-journey">{release.plan.changes.map(change => <li key={change}>{change}</li>)}</ul><p className="mvp-help">Template digest: <code>{release.plan.template_sha256}</code></p></>}
    <a className="btn secondary" href={`/api/receipts/${release.id}`}>Download handoff and evidence</a>
    {release.status === 'awaiting_approval' && <div className="mvp-actions-block">
      {reviewer && user.id !== release.creator ? <>
        <label className="mvp-check"><input type="checkbox" checked={ack} onChange={e => setAck(e.target.checked)} />I reviewed the evidence, target, exposure and recovery scope.</label>
        <div className="mvp-actions"><button className="btn primary" disabled={!ack} onClick={() => perform(path + 'approve', { acknowledged: ack })}>Approve handoff</button>
          <button className="btn secondary" onClick={() => perform(path + 'reject', {})}>Reject release</button></div>
      </> : <p>Another invited reviewer must make this decision.</p>}
    </div>}
    {release.status === 'approved' && <div className="mvp-actions-block">
      {direct && !expired && (reviewer || user.id === release.creator) && <AwsCredentials release={release} configured={deploymentConfigured} perform={perform} />}
      {reviewer && <div className="mvp-actions">{!direct && <button className="btn primary" disabled={expired} onClick={() => perform(path + 'begin', {})}>Take operator handoff</button>}<button className="btn secondary" onClick={() => perform(path + 'reset', {})}>{expired ? 'Request a new review' : 'Revoke approval'}</button></div>}</div>}
    {['awaiting_operator_result', 'reconciliation_required'].includes(release.status) && <div className="mvp-actions-block">
      <p>The portal is waiting for the operator. Closing this page does not cancel an AWS operation.</p>
      {!ecs && reviewer && user.id === release.operator && <form onSubmit={e => { e.preventDefault(); perform(path + (release.status === 'reconciliation_required' ? 'reconcile' : 'result'), {
        outcome, receipt_reference: reference, checks, artifact_sha256: release.artifact_sha256, plan_digest: release.plan_digest,
      }); }}>
        <label className="field">Outcome<select value={outcome} onChange={e => setOutcome(e.target.value)}><option value="uncertain">Uncertain — needs reconciliation</option><option value="failed">Failed</option><option value="reported_success">Success reported by operator</option></select></label>
        {['https', 'login', 'readiness'].map(name => <label className="mvp-check" key={name}><input type="checkbox" checked={checks[name]} onChange={e => setChecks({ ...checks, [name]: e.target.checked })} />{name} check passed</label>)}
        <label className="field">Non-secret receipt reference<input required maxLength={200} value={reference} onChange={e => setReference(e.target.value)} placeholder="e.g. deployment-receipt-20261013.json" /></label>
        <p className="mvp-help">Use a filename or change identifier. Never paste passwords, tokens, or session credentials.</p>
        <button className="btn primary" type="submit">{release.status === 'reconciliation_required' ? 'Record reconciled outcome' : 'Record operator result'}</button>
      </form>}
    </div>}
    {release.deployment_result?.outcome && <p className="mvp-warning">Evidence source: operator reported. Receipt: {release.deployment_result.receipt_reference}. The portal has not independently verified the website.</p>}
    {release.status === 'reconciliation_required' && <p className="mvp-warning">Do not repeat deployment. The operator must reconcile the existing resources before another handoff.</p>}
    {release.status === 'deploying' && <p role="status">AWS update is running. Closing this page does not cancel an accepted operation. Refresh for its recorded outcome.</p>}
    {release.status === 'deployed' && <div className="mvp-actions-block"><p>{ecs ? 'ECS completed the reviewed image rollout and the HTTPS health endpoint responded. Authenticated application login still requires a human check.' : 'SSM completed and the HTTPS health/login pages responded. An authenticated application login has not been tested by the portal.'}</p><a className="btn primary" href={release.deployment_result.application_url} target="_blank" rel="noopener noreferrer">Open application</a></div>}
  </section>;
}
