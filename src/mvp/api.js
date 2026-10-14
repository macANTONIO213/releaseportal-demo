let csrf = '';
export async function call(path, data) {
  const response = await fetch(path, {
    method: data === undefined ? 'GET' : 'POST',
    credentials: 'same-origin',
    headers: data === undefined ? {} : { 'Content-Type': 'application/json', 'X-CSRFToken': csrf },
    ...(data === undefined ? {} : { body: JSON.stringify(data) }),
  });
  const value = await response.json().catch(() => ({ error: 'The service returned an unexpected response.' }));
  if (!response.ok) {
    const error = new Error(value.error || 'Request failed.');
    error.code = value.code;
    error.reference = value.correlation_id || response.headers.get('X-Correlation-ID');
    error.status = response.status;
    throw error;
  }
  if (value.csrf) csrf = value.csrf;
  return value;
}

export const labels = {
  fetching_source: 'Fetching authorized source', queued: 'Queued', trigger_pending: 'Needs recovery', running: 'Scans and tests running',
  sync_required: 'Needs synchronization', ready: 'Evidence ready', failed: 'Failed',
  awaiting_approval: 'Awaiting approval', approved: 'Approved · waiting for operator', rejected: 'Rejected',
  awaiting_operator_result: 'Waiting for operator result', operator_reported_success: 'Success reported by operator',
  reconciliation_required: 'Outcome uncertain · reconciliation required',
  deploying: 'AWS deployment running', deployed: 'Deployed · health/login page checked',
};
export const label = value => labels[value] || value;
export const date = value => value ? new Date(value).toLocaleString() : '—';
