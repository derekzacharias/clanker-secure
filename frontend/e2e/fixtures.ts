import type { Page } from '@playwright/test';

/**
 * API stubs for the browser tests.
 *
 * These exist only so the UI can be exercised without the FastAPI backend. No
 * stub data ships in the application: production views render whatever the API
 * returns, and show explicit empty/error states when it returns nothing.
 */
export const user = { id: 1, email: 'analyst@example.com', name: 'Dana Ops', role: 'admin' };

const assets = [
  { id: 1, name: 'edge-router', target: '10.0.0.1', environment: 'production', owner: 'netops', notes: null, credentialed: true, created_at: '2026-02-01T10:00:00Z' },
  { id: 2, name: 'build-runner', target: '10.0.4.20', environment: 'ci', owner: 'platform', notes: null, credentialed: false, created_at: '2026-02-02T10:00:00Z' },
  { id: 3, name: 'legacy-jump', target: '10.0.9.9', environment: 'staging', owner: null, notes: 'decommission pending', credentialed: false, created_at: '2026-02-03T10:00:00Z' },
];

const scans = [
  { id: 11, status: 'completed', profile: 'common_tcp_version', created_at: '2026-02-10T09:00:00Z', started_at: '2026-02-10T09:00:05Z', completed_at: '2026-02-10T09:04:00Z' },
  { id: 12, status: 'running', profile: 'quick', created_at: '2026-02-10T10:00:00Z', started_at: '2026-02-10T10:00:02Z', completed_at: null },
];

const findings = [
  {
    id: 101, scan_id: 11, asset_id: 1, host_address: '10.0.0.1', host_os_name: 'Linux', port: 22, protocol: 'tcp',
    service_name: 'ssh', cve_ids: 'CVE-2026-1234', severity: 'critical', status: 'open',
    description: 'OpenSSH server allows pre-authentication memory corruption', detected_at: '2026-02-10T09:03:00Z',
    cvss_v31_base: 9.8, references: ['https://nvd.nist.gov/vuln/detail/CVE-2026-1234'], rule_source: 'openssh-vulners',
    evidence_grade: 'high', why_trace: 'version banner matched 8.9p1', version_confidence: 0.92,
    evidence_types: ['banner'], evidence_summary: 'SSH-2.0-OpenSSH_8.9p1 matched against advisory range',
  },
  {
    id: 102, scan_id: 11, asset_id: 2, host_address: '10.0.4.20', host_os_name: 'Linux', port: 8080, protocol: 'tcp',
    service_name: 'http-proxy', cve_ids: 'CVE-2025-4411', severity: 'high', status: 'open',
    description: 'Proxy request smuggling', detected_at: '2026-02-10T09:03:20Z', cvss_v31_base: 8.1,
    references: [], rule_source: 'http-proxy-rules', evidence_grade: 'medium', why_trace: null,
    version_confidence: 0.5, evidence_types: ['header'], evidence_summary: 'Server header version range',
  },
];

const cvssBands = { critical: 1, high: 1, medium: 0, low: 0, total: 2 };

function json(body: unknown, headers: Record<string, string> = {}) {
  return {
    status: 200,
    contentType: 'application/json',
    headers: { 'access-control-expose-headers': 'X-Total-Count,X-CVSS-Bands', ...headers },
    body: JSON.stringify(body),
  };
}

// Install the stub routes. Call before navigating.
//
// One catch-all handler with exact path matching: the SPA bundle lives under
// /app/assets and the API under /assets, so a loose glob would swallow the
// JavaScript and blank the page.
export async function stubApi(page: Page) {
  await page.route(
    (url) => url.origin === 'http://127.0.0.1:4173' && !url.pathname.startsWith('/app/'),
    (route) => {
      const url = new URL(route.request().url());
      const path = url.pathname;
      const method = route.request().method();
      const reply = (body: unknown, headers: Record<string, string> = {}) => route.fulfill(json(body, headers));

      if (path === '/auth/me') return reply(user);
      if (path === '/auth/refresh') return reply({ access_token: 't', refresh_token: 'r' });
      if (path === '/auth/logout') return reply({});
      if (path === '/assets' && method === 'GET') return reply(assets, { 'X-Total-Count': String(assets.length) });
      if (/^\/assets\/\d+$/.test(path)) return reply(assets[0]);
      if (path === '/scans' && method === 'GET') return reply(scans, { 'X-Total-Count': String(scans.length) });
      if (path === '/scans' && method === 'POST') return reply(scans[1]);
      if (/^\/scans\/\d+\/events$/.test(path)) return reply([]);
      if (/^\/scans\/\d+\/assets$/.test(path)) return reply([]);
      if (/^\/scans\/\d+$/.test(path)) return reply({ scan: scans[0], events: [] });
      if (path.startsWith('/findings/') && path.endsWith('/comments')) return reply([]);
      if (path === '/findings') {
        return reply(findings, { 'X-Total-Count': String(findings.length), 'X-CVSS-Bands': JSON.stringify(cvssBands) });
      }
      if (path.startsWith('/finding_ext/')) return reply({ cpe: 'cpe:/a:openbsd:openssh:8.9p1', source: 'nvd' });
      if (path === '/schedules') return reply([], { 'X-Total-Count': '0' });
      if (path === '/coverage/rule_gaps') return reply({ total: 0, buckets: [] });
      if (path === '/users') return reply([user]);
      if (path === '/audit_logs') return reply([]);
      if (path.startsWith('/metrics')) return reply({});
      return reply({ detail: 'not stubbed: ' + path }, {});
    },
  );
}
