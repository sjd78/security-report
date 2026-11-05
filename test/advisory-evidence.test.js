import test from 'node:test';
import assert from 'node:assert/strict';
import { fetchAdvisoryDetails } from '../src/collectors/advisories.js';
import { normalizePlanFindings, isVersionSafe, selectLatestSafePatch } from '../src/core/advisory-evidence.js';

test('normalizes package advisory constraints, comparator commas, severities, and source references', () => {
  const rows = [{
    packageName: 'brace-expansion',
    id: 'GHSA-MERGED',
    cves: ['CVE-2026-11111'],
    vulnerableVersionRange: '<1.1.22 || >=5.0.0 <5.0.13',
    sources: {
      npmAudit: { advisoryId: 'GHSA-MERGED', urls: ['https://npm.example/advisory'], advisories: [{ advisoryId: '123' }] },
      jira: { ticketKey: 'SEC-1', url: 'https://jira.example/SEC-1', remoteLinks: ['https://github.com/advisories/GHSA-MERGED'] },
      dependabot: { alertNumber: 9, url: 'https://github.example/alerts/9' },
    },
    advisories: [
      {
        id: 'ghsa-merged', cve: 'cve-2026-11111', title: 'First evidence', severity: 'moderate',
        url: 'https://github.com/advisories/GHSA-MERGED',
        affectedVersions: [
          { vulnerableRange: '< 1.1.22', firstPatchedVersion: '1.1.22' },
          { vulnerableRange: '>= 5.0.0, < 5.0.13', firstPatchedVersion: '5.0.13' },
        ],
      },
      {
        id: 'GHSA-MERGED', title: 'Higher severity evidence', severity: 'high',
        affectedVersions: [{ vulnerableRange: '>= 5.0.8 < 5.0.13', firstPatchedVersion: '5.0.13' }],
      },
    ],
  }];
  const findings = normalizePlanFindings(rows, 'brace-expansion');
  const ghsa = findings.find((finding) => finding.id === 'GHSA-MERGED');
  assert.equal(ghsa.severity, 'high');
  assert.deepEqual(ghsa.cves, ['CVE-2026-11111']);
  assert.ok(ghsa.constraints.some((item) => item.vulnerableRange === '>=5.0.0 <5.0.13' && item.firstPatchedVersion === '5.0.13'));
  assert.deepEqual(new Set(ghsa.references.map((item) => item.source)), new Set(['npm-audit', 'jira', 'dependabot', 'advisory']));
  assert.ok(ghsa.references.some((item) => item.url === 'https://jira.example/SEC-1'));
  assert.ok(ghsa.references.some((item) => item.url === 'https://npm.example/advisory'));
  assert.equal(findings.some((finding) => finding.id.includes(':aggregate:')), false);
});

test('safety is tri-state and requires same-line evidence when ranges are absent', () => {
  const findings = [{ id: 'GHSA-LINES', constraints: [
    { vulnerableRange: '<1.1.22', firstPatchedVersion: '1.1.22' },
    { vulnerableRange: '>=5.0.0 <5.0.13', firstPatchedVersion: '5.0.13' },
  ] }];
  assert.equal(isVersionSafe('1.1.18', findings), false);
  assert.equal(isVersionSafe('1.1.22', findings), true);
  assert.equal(isVersionSafe('5.0.9', findings), false);
  assert.equal(isVersionSafe('5.0.13', findings), true);
  assert.equal(isVersionSafe('2.1.7', findings), true);
  assert.equal(isVersionSafe('1.1.22', [{ id: 'floor-only', constraints: [{ vulnerableRange: null, firstPatchedVersion: '1.1.22' }] }]), true);
  assert.equal(isVersionSafe('2.1.7', [{ id: 'floor-only', constraints: [{ vulnerableRange: null, firstPatchedVersion: '1.1.22' }] }]), null);
  assert.equal(isVersionSafe('1.1.22', [{ id: 'invalid', constraints: [{ vulnerableRange: 'not a range', firstPatchedVersion: null }] }]), null);
});

test('known vulnerable intervals override incomplete advisory evidence', () => {
  assert.equal(isVersionSafe('1.0.0', [{ constraints: [
    { vulnerableRange: '<1.2.0', firstPatchedVersion: null },
    { vulnerableRange: 'invalid range', firstPatchedVersion: null },
  ] }]), false);
});

test('GitHub advisory lookup selects the requested npm package and rejects ambiguous catalogs', async () => {
  const originalFetch = global.fetch;
  global.fetch = async () => ({
    ok: true,
    json: async () => ({
      ghsa_id: 'ghsa-test-1234', cve_id: 'cve-2026-12345', summary: 'Test advisory', severity: 'high',
      vulnerabilities: [
        { package: { ecosystem: 'npm', name: 'other' }, vulnerable_version_range: '<2.0.0', first_patched_version: '2.0.0' },
        { package: { ecosystem: 'npm', name: 'wanted' }, vulnerable_version_range: '<1.2.0', first_patched_version: '1.2.0' },
        { package: { ecosystem: 'npm', name: 'wanted' }, vulnerable_version_range: '>=2.0.0 <2.1.0', first_patched_version: '2.1.0' },
      ],
    }),
  });
  try {
    const details = await fetchAdvisoryDetails('GHSA-TEST-1234', { githubApiUrl: 'https://registry.test', packageName: 'wanted' });
    assert.deepEqual(details.affectedVersions, [
      { vulnerableRange: '<1.2.0', firstPatchedVersion: '1.2.0' },
      { vulnerableRange: '>=2.0.0 <2.1.0', firstPatchedVersion: '2.1.0' },
    ]);
    assert.equal(details.packageName, 'wanted');
    assert.equal(await fetchAdvisoryDetails('GHSA-TEST-1234', { githubApiUrl: 'https://registry.test' }), null);
  } finally {
    global.fetch = originalFetch;
  }
});

test('OSV advisory lookup pairs every SEMVER interval and ignores unsupported ecosystems', async () => {
  const originalFetch = global.fetch;
  global.fetch = async () => ({
    ok: true,
    json: async () => ({
      id: 'OSV-2026-123', aliases: ['CVE-2026-12345'],
      affected: [
        { package: { ecosystem: 'npm', name: 'wanted' }, ranges: [
          { type: 'SEMVER', events: [{ introduced: '1.0.0' }, { fixed: '1.2.0' }, { introduced: '2.0.0' }, { fixed: '2.2.0' }, { introduced: '3.0.0' }] },
          { type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '9.9.9' }] },
        ] },
        { package: { ecosystem: 'npm', name: 'other' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.0.0' }] }] },
      ],
    }),
  });
  try {
    const details = await fetchAdvisoryDetails('CVE-2026-12345', { packageName: 'wanted' });
    assert.deepEqual(details.affectedVersions, [
      { vulnerableRange: '>=1.0.0 <1.2.0', firstPatchedVersion: '1.2.0' },
      { vulnerableRange: '>=2.0.0 <2.2.0', firstPatchedVersion: '2.2.0' },
      { vulnerableRange: '>=3.0.0', firstPatchedVersion: null },
    ]);
    assert.equal(await fetchAdvisoryDetails('CVE-2026-12345'), null);
  } finally {
    global.fetch = originalFetch;
  }
});

test('selects the newest published safe patch on the installed major.minor line', () => {
  const findings = [{ constraints: [{ vulnerableRange: '<1.1.20', firstPatchedVersion: '1.1.20' }] }];
  assert.equal(selectLatestSafePatch('1.1.18', ['1.1.20', '1.1.22', '1.2.0', '2.0.0', '1.1.23-beta.1'], findings), '1.1.22');
  const newerUnsafe = [{ constraints: [{ vulnerableRange: '<1.1.22 || =1.1.24', firstPatchedVersion: '1.1.22' }] }];
  assert.equal(selectLatestSafePatch('1.1.18', ['1.1.22', '1.1.23', '1.1.24', '1.2.0'], newerUnsafe), '1.1.23');
  assert.equal(selectLatestSafePatch('1.1.25', ['1.1.24', '1.2.0'], findings), null);
});
