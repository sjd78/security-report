import test from 'node:test';
import assert from 'node:assert/strict';
import { fetchAdvisoryDetails } from '../src/collectors/advisories.js';
import { normalizePlanFindings } from '../src/core/advisory-evidence.js';

const ghsa = 'GHSA-4528-X5FX-H6HG';
const ranges = ['>=17.1.1 <17.13.9', '>=18.0.0 <18.3.1'];
const patches = ['17.13.9', '18.3.1'];

test('global GitHub advisory string patches retain both joi release lines and isolate @hapi/joi', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => Response.json({
    ghsa_id: ghsa, cve_id: 'CVE-2026-118772', vulnerabilities: [
      { package: { ecosystem: 'npm', name: 'joi' }, vulnerable_version_range: '>= 17.1.1, < 17.13.9', first_patched_version: '17.13.9' },
      { package: { ecosystem: 'npm', name: '@hapi/joi' }, vulnerable_version_range: '>=16.0.0 <=17.1.1', first_patched_version: null },
      { package: { ecosystem: 'npm', name: 'joi' }, vulnerable_version_range: '>= 18.0.0, < 18.3.1', first_patched_version: '18.3.1' },
    ],
  }));
  const details = await fetchAdvisoryDetails(ghsa, { packageName: 'joi', githubToken: '' });
  assert.deepEqual(details.patchedVersions, patches);
  const base = details.affectedVersions.map((item) => ({ id: ghsa, affectedVersions: [item] }));
  const rangeOnly = ranges.map((vulnerableVersionRange) => ({ id: ghsa, vulnerableVersionRange }));
  for (const advisories of [[...base, ...rangeOnly], [...rangeOnly, ...base]]) {
    const [finding] = normalizePlanFindings([{ packageName: 'joi', advisories }], 'joi');
    assert.deepEqual(finding.constraints, ranges.map((vulnerableRange, i) => ({ vulnerableRange, firstPatchedVersion: patches[i] })));
  }
  const legacy = await fetchAdvisoryDetails(ghsa, { packageName: '@hapi/joi', githubToken: '' });
  assert.deepEqual(legacy.affectedVersions, [{ vulnerableRange: '>=16.0.0 <=17.1.1', firstPatchedVersion: null }]);
});

test('a known patch does not discard other ranges, other advisories, or conflicting patch evidence', () => {
  const findings = normalizePlanFindings([{ advisories: [
    { id: ghsa, affectedVersions: [
      { vulnerableRange: ranges[0], firstPatchedVersion: null },
      { vulnerableRange: ranges[0], firstPatchedVersion: patches[0] },
      { vulnerableRange: ranges[1], firstPatchedVersion: null },
    ] },
    { id: ghsa, affectedVersions: [{ vulnerableRange: ranges[0], firstPatchedVersion: '17.13.10' }] },
    { id: 'other-advisory', vulnerableVersionRange: ranges[0] },
  ] }], 'joi');
  assert.deepEqual(findings.find((finding) => finding.id === ghsa).constraints, [
    { vulnerableRange: ranges[0], firstPatchedVersion: '17.13.10' },
    { vulnerableRange: ranges[0], firstPatchedVersion: patches[0] },
    { vulnerableRange: ranges[1], firstPatchedVersion: null },
  ]);
  assert.deepEqual(findings.find((finding) => finding.id === 'OTHER-ADVISORY').constraints,
    [{ vulnerableRange: ranges[0], firstPatchedVersion: null }]);
});
