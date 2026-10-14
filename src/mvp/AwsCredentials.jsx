import React, { useState } from 'react';

export default function AwsCredentials({ release, configured, perform }) {
  const [pending, setPending] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const secure = globalThis.location?.protocol === 'https:';
  if (!configured) return <p className="mvp-warning">The update template must be reviewed and enabled before credential entry. No AWS values are requested yet.</p>;
  if (!secure) return <p className="mvp-warning">Open the approved VPN-only HTTPS endpoint to enter AWS credentials. This local HTTP view cannot accept them.</p>;
  return <form autoComplete="off" onSubmit={async event => {
    event.preventDefault();
    if (pending || !confirmed) return;
    const form = event.currentTarget;
    const payload = {
      access_key_id: form.elements.namedItem('access_key_id').value.trim(),
      secret_access_key: form.elements.namedItem('secret_access_key').value.trim(),
      session_token: form.elements.namedItem('session_token').value.trim(),
      confirmed, plan_digest: release.plan_digest,
    };
    // No browser storage/state contains AWS values. Clear inputs before the request.
    form.reset(); setConfirmed(false); setPending(true);
    try { await perform(`/api/releases/${release.id}/deploy`, payload); }
    finally {
      payload.access_key_id = payload.secret_access_key = payload.session_token = '';
      setPending(false);
    }
  }}>
    <h3>Temporary AWS access for this deployment</h3>
    <p>Paste the three values from the approved account's access page. They are held only for this attempt and never saved in release records.</p>
    {[['access_key_id','AWS access key ID'],['secret_access_key','AWS secret access key'],['session_token','AWS session token']].map(([name,title]) => <label className="field" key={name}>{title}<input name={name} type="password" required autoComplete="off" spellCheck={false} maxLength={name === 'session_token' ? 12000 : 100} data-1p-ignore="true" /></label>)}
    <label className="mvp-check"><input type="checkbox" checked={confirmed} onChange={e => setConfirmed(e.target.checked)} />I reviewed the exact operations and obtained these credentials for account {release.plan.account}.</label>
    <p className="mvp-help">The selected target is not independent proof of credential identity. No background STS or permission probes run. Expiry or worker restart requires fresh values.</p>
    <button className="btn primary" disabled={!confirmed || pending}>{pending ? 'Starting deployment…' : 'Deploy the reviewed artifact'}</button>
  </form>;
}
