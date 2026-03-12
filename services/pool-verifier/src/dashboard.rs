use axum::response::Html;

// Simple HTML dashboard served at GET /
// Uses fetch to call /stats every 2 seconds and render the latest view.
pub(crate) static INDEX_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Veldra Pool Verifier</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root {
      color-scheme: dark;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "SF Pro Text", sans-serif;
    }
      .recent-table td.num {
      text-align: right;
    }

    .recent-table td.mono {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
    }

    .recent-table td.reason {
      max-width: 380px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    body {
      margin: 0;
      padding: 0;
      background: #050712;
      color: #f5f5f5;
      display: flex;
      min-height: 100vh;
      justify-content: center;
      align-items: flex-start;
    }
    .page {
      width: 100%;
      max-width: 1040px;
      padding: 24px 16px 40px;
    }
    h1 {
      font-size: 24px;
      margin: 0 0 4px 0;
    }
    .subtitle {
      font-size: 13px;
      color: #9ba3b4;
      margin-bottom: 20px;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 12px;
      margin-bottom: 20px;
    }
    .grid-wide {
      display: grid;
      grid-template-columns: minmax(0, 2.2fr) minmax(0, 1.5fr);
      gap: 12px;
      margin-top: 6px;
    }
    @media (max-width: 900px) {
      .grid-wide {
        grid-template-columns: 1fr;
      }
    }
    .card {
      background: #0f172a;
      border: 1px solid #1e293b;
      border-radius: 8px;
      padding: 16px;
    }
    .card-title {
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: #9ba3b4;
      margin-bottom: 8px;
    }
    .card-value {
      font-size: 32px;
      font-weight: 600;
      color: #00ff88;
    }
    .card-value.rejected {
      color: #ff4444;
    }
    .card-label {
      font-size: 13px;
      color: #64748b;
      margin-top: 4px;
    }
    .card-label strong {
      color: #f5f5f5;
    }
    .badge {
      display: inline-block;
      background: #10b981;
      color: #fff;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
      margin-top: 8px;
    }
    .badge.reject {
      background: #ef4444;
    }
    .badge.observe {
      background: #8b5cf6;
    }
    .badge.shadow {
      background: #6b7280;
    }
    .link-group {
      display: flex;
      gap: 8px;
      margin-top: 12px;
      flex-wrap: wrap;
    }
    a {
      display: inline-block;
      color: #60a5fa;
      text-decoration: none;
      font-size: 12px;
      padding: 4px 8px;
      border-radius: 4px;
      border: 1px solid transparent;
      transition: all 0.2s;
    }
    a:hover {
      border-color: #60a5fa;
      background: rgba(96, 165, 250, 0.1);
    }
    .recent {
      background: #0f172a;
      border: 1px solid #1e293b;
      border-radius: 8px;
      overflow: hidden;
    }
    .recent-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }
    .recent-table th {
      background: #1e293b;
      color: #9ba3b4;
      font-weight: 600;
      padding: 8px 12px;
      text-align: left;
      border-bottom: 1px solid #334155;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .recent-table td {
      padding: 8px 12px;
      border-bottom: 1px solid #1e293b;
    }
    .recent-table tr:last-child td {
      border-bottom: none;
    }
    .recent-table tr:hover {
      background: #1e293b;
    }
    .section-title {
      font-size: 14px;
      font-weight: 600;
      color: #f5f5f5;
      margin: 24px 0 12px;
      border-bottom: 1px solid #1e293b;
      padding-bottom: 8px;
    }
    .status-ok {
      color: #00ff88;
    }
    .status-err {
      color: #ff4444;
    }
    .info {
      background: #1e293b;
      border-left: 3px solid #60a5fa;
      padding: 8px 12px;
      border-radius: 4px;
      font-size: 12px;
      color: #cbd5e1;
      margin: 12px 0;
    }
    .error-section {
      color: #ff4444;
    }
  </style>
</head>
<body>
  <div class="page">
    <h1>Veldra Pool Verifier</h1>
    <p class="subtitle">Template verdict dashboard</p>

    <!-- Top stats row -->
    <div class="grid">
      <div class="card">
        <div class="card-title">Templates Evaluated</div>
        <div class="card-value" id="total">0</div>
      </div>
      <div class="card">
        <div class="card-title">Accepted</div>
        <div class="card-value" id="accepted">0</div>
        <div class="card-label"><strong id="pct_accepted">0</strong>% of total</div>
      </div>
      <div class="card">
        <div class="card-title">Rejected</div>
        <div class="card-value rejected" id="rejected">0</div>
        <div class="card-label"><strong id="pct_rejected">0</strong>% of total</div>
      </div>
    </div>

    <!-- Policy & Mode section -->
    <div class="grid-wide">
      <div class="card">
        <div class="card-title">Policy Status</div>
        <div id="policy_status">
          <div class="card-label status-err">Initializing...</div>
        </div>
        <div class="link-group">
          <a href="/policy">View Policy</a>
          <a href="/settings">Settings</a>
        </div>
      </div>
      <div class="card">
        <div class="card-title">Deploy Mode</div>
        <div id="mode_badge">
          <div class="badge">shadow</div>
        </div>
        <div class="card-label" id="mode_label">
          Verdicts not persisted to disk
        </div>
      </div>
    </div>

    <div class="section-title">Verdict Breakdown by Reason</div>
    <div class="card">
      <table class="recent-table">
        <thead>
          <tr>
            <th>Reason Code</th>
            <th style="text-align: right;">Count</th>
            <th style="text-align: right;">% of Total</th>
          </tr>
        </thead>
        <tbody id="reasons_tbody">
          <tr><td colspan="3" style="color: #9ba3b4;">No verdicts yet</td></tr>
        </tbody>
      </table>
    </div>

    <div class="section-title">Verdict Breakdown by Fee Tier</div>
    <div class="card">
      <table class="recent-table">
        <thead>
          <tr>
            <th>Fee Tier</th>
            <th style="text-align: right;">Count</th>
            <th style="text-align: right;">% of Total</th>
          </tr>
        </thead>
        <tbody id="tiers_tbody">
          <tr><td colspan="3" style="color: #9ba3b4;">No verdicts yet</td></tr>
        </tbody>
      </table>
    </div>

    <div class="section-title">Last Verdict</div>
    <div class="card" id="last_verdict">
      <div class="card-label">No verdicts logged yet</div>
    </div>

    <div class="section-title">System Status</div>
    <div class="card">
      <div id="system_status">
        <div class="card-label status-err">Connecting...</div>
      </div>
    </div>

    <div class="link-group" style="margin-top: 20px;">
      <a href="/verdicts/log">View Verdict Log</a>
      <a href="/verdicts.csv">Export CSV</a>
      <a href="/mempool">Mempool Proxy</a>
      <a href="/metrics">Prometheus Metrics</a>
    </div>
  </div>

  <script>
    const API_PREFIX = '';

    async function refresh() {
      try {
        // Fetch stats
        const statsRes = await fetch(API_PREFIX + '/stats');
        const stats = await statsRes.json();

        // Update totals
        document.getElementById('total').textContent = stats.total;
        document.getElementById('accepted').textContent = stats.accepted;
        document.getElementById('rejected').textContent = stats.rejected;

        const total = stats.total || 1;
        const pct_accepted = Math.round((stats.accepted / total) * 100);
        const pct_rejected = Math.round((stats.rejected / total) * 100);
        document.getElementById('pct_accepted').textContent = pct_accepted;
        document.getElementById('pct_rejected').textContent = pct_rejected;

        // Render by_reason table
        const tbody_reasons = document.getElementById('reasons_tbody');
        if (Object.keys(stats.by_reason).length === 0) {
          tbody_reasons.innerHTML = '<tr><td colspan="3" style="color: #9ba3b4;">No verdicts yet</td></tr>';
        } else {
          tbody_reasons.innerHTML = '';
          for (const [reason, count] of Object.entries(stats.by_reason)) {
            const pct = Math.round((count / total) * 100);
            const row = document.createElement('tr');
            row.innerHTML = `<td>${reason || 'ok'}</td><td style="text-align: right;">${count}</td><td style="text-align: right;">${pct}%</td>`;
            tbody_reasons.appendChild(row);
          }
        }

        // Render by_tier table
        const tbody_tiers = document.getElementById('tiers_tbody');
        if (Object.keys(stats.by_tier).length === 0) {
          tbody_tiers.innerHTML = '<tr><td colspan="3" style="color: #9ba3b4;">No verdicts yet</td></tr>';
        } else {
          tbody_tiers.innerHTML = '';
          for (const [tier, count] of Object.entries(stats.by_tier)) {
            const pct = Math.round((count / total) * 100);
            const row = document.createElement('tr');
            row.innerHTML = `<td>${tier}</td><td style="text-align: right;">${count}</td><td style="text-align: right;">${pct}%</td>`;
            tbody_tiers.appendChild(row);
          }
        }

        // Last verdict
        if (stats.last) {
          const last = stats.last;
          const reason_str = last.reason_code || last.reason || 'ok';
          const detail_str = last.reason_detail ? ` (${last.reason_detail})` : '';
          const tier_str = last.fee_tier || 'unknown';
          const tier_src = last.tier_source || 'unknown';
          document.getElementById('last_verdict').innerHTML = `
            <table style="width: 100%; font-size: 12px;">
              <tr><td style="color: #9ba3b4;">Template ID:</td><td><strong>${last.template_id}</strong></td></tr>
              <tr><td style="color: #9ba3b4;">Height:</td><td><strong>${last.height}</strong></td></tr>
              <tr><td style="color: #9ba3b4;">Status:</td><td><strong>${last.accepted ? 'ACCEPTED' : 'REJECTED'}</strong></td></tr>
              <tr><td style="color: #9ba3b4;">Reason:</td><td><strong>${reason_str}${detail_str}</strong></td></tr>
              <tr><td style="color: #9ba3b4;">Avg Fee:</td><td><strong>${last.avg_fee_sats_per_tx} sat/vB</strong></td></tr>
              <tr><td style="color: #9ba3b4;">Fee Tier:</td><td><strong>${tier_str} (${tier_src})</strong></td></tr>
              <tr><td style="color: #9ba3b4;">Total Fees:</td><td><strong>${last.total_fees} sat</strong></td></tr>
              <tr><td style="color: #9ba3b4;">Tx Count:</td><td><strong>${last.tx_count}</strong></td></tr>
            </table>
          `;
        }

        // Fetch meta
        const metaRes = await fetch(API_PREFIX + '/meta');
        const meta = await metaRes.json();
        const mode = meta.mode || 'unknown';

        // Update mode badge
        let badgeClass = 'shadow';
        let modeLabel = 'Verdicts not persisted to disk';
        if (mode === 'inline') {
          badgeClass = 'reject';
          modeLabel = 'Live enforcement mode (CRITICAL)';
        } else if (mode === 'observe') {
          badgeClass = 'observe';
          modeLabel = 'Observe mode: verdicts logged, not enforced';
        }
        document.getElementById('mode_badge').innerHTML = `<div class="badge ${badgeClass}">${mode}</div>`;
        document.getElementById('mode_label').textContent = modeLabel;

        // Fetch readiness
        const readyRes = await fetch(API_PREFIX + '/ready');
        const ready = await readyRes.json();

        let statusHtml = '';
        const policyStatus = ready.policy_loaded ? '<span class="status-ok">✓ Loaded</span>' : '<span class="status-err">✗ Not loaded</span>';
        const mempoolStatus = ready.mempool_reachable ? '<span class="status-ok">✓ Connected</span>' : '<span class="status-err">✗ Unreachable</span>';
        const overallStatus = ready.ready ? '<span class="status-ok">✓ Ready</span>' : '<span class="status-err">✗ Not ready</span>';

        statusHtml += `<div class="card-label">Policy: ${policyStatus}</div>`;
        statusHtml += `<div class="card-label">Mempool: ${mempoolStatus}`;
        if (!ready.mempool_reachable && ready.mempool_last_ok_age_secs !== null) {
          statusHtml += ` (last ok ${ready.mempool_last_ok_age_secs}s ago)`;
        }
        statusHtml += `</div>`;
        statusHtml += `<div class="card-label">Overall: ${overallStatus}</div>`;

        document.getElementById('system_status').innerHTML = statusHtml;

        // Fetch policy for policy status
        const policyRes = await fetch(API_PREFIX + '/policy');
        const policy = await policyRes.json();
        let policy_html = '<div class="card-label"><strong>Policy Loaded</strong></div>';
        policy_html += `<div class="card-label">Mempool low: ${policy.low_mempool_tx} tx</div>`;
        policy_html += `<div class="card-label">Mempool high: ${policy.high_mempool_tx} tx</div>`;
        document.getElementById('policy_status').innerHTML = policy_html;

      } catch (err) {
        console.error('Refresh error:', err);
        document.getElementById('system_status').innerHTML = `<div class="card-label error-section">Error fetching data: ${err.message}</div>`;
      }
    }

    // Refresh immediately and then every 2 seconds
    refresh();
    setInterval(refresh, 2000);
  </script>
</body>
</html>"#;

pub(crate) async fn ui_index() -> Html<&'static str> {
    Html(INDEX_HTML)
}
