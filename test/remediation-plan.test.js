import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { generateRemediationPlan, writeRemediationPlan } from '../src/report/remediation-reporter.js';
import { readRemediationPlan } from '../src/core/plan-executor.js';

const packageName = 'brace-expansion';
const baseCommit = '0123456789abcdef0123456789abcdef01234567';
const generatedAt = '2026-11-04T12:00:00.000Z';
const publishedVersions = ['1.1.18', '1.1.21', '1.1.22', '1.1.23-beta.1', '2.1.7', '5.0.9', '5.0.11', '5.0.12', '5.0.13'];

function multiLineBranch() {
  const root = {
    name: 'example', version: '1.0.0', workspaces: ['client'],
    dependencies: {
      [packageName]: '^1.1.0',
      'parent-a': '1.0.0', 'parent-b': '1.0.0', 'parent-c': '1.0.0',
    },
  };
  const client = { name: '@example/client', version: '1.0.0', dependencies: { [packageName]: '^5.0.0' } };
  const pkgLock = {
    name: root.name, version: root.version, lockfileVersion: 3,
    packages: {
      '': { name: root.name, version: root.version, dependencies: root.dependencies },
      client: { name: client.name, version: client.version, dependencies: client.dependencies },
      [`node_modules/${packageName}`]: { version: '1.1.18' },
      'client/node_modules/brace-expansion': { version: '5.0.9' },
      'node_modules/parent-a': { version: '1.0.0', dependencies: { [packageName]: '^1.1.0' } },
      [`node_modules/parent-a/node_modules/${packageName}`]: { version: '1.1.21' },
      'node_modules/parent-b': { version: '1.0.0', dependencies: { [packageName]: '^2.1.0' } },
      [`node_modules/parent-b/node_modules/${packageName}`]: { version: '2.1.7' },
      'node_modules/parent-c': { version: '1.0.0', dependencies: { [packageName]: '^5.0.0' } },
      [`node_modules/parent-c/node_modules/${packageName}`]: { version: '5.0.12' },
    },
  };
  return {
    branch: 'release-0.10', baseCommit, pkgJson: root, pkgLock,
    workspaces: [
      { relativePath: 'package.json', name: root.name, pkgJson: root, isRoot: true },
      { relativePath: 'client/package.json', name: client.name, pkgJson: client },
    ],
    vulnerabilities: [{
      id: 'npm-audit:brace-expansion', packageName, title: 'Brace expansion denial of service', severity: 'high',
      vulnerableVersionRange: '<1.1.0 || >=5.0.0, <5.0.11',
      sources: {
        npmAudit: { advisoryId: '123', urls: ['https://www.npmjs.com/advisories/123'] },
        jira: { ticketKey: 'SEC-100', url: 'https://jira.example/browse/SEC-100', summary: 'Sensitive ticket body must not be copied' },
        dependabotAlerts: [{ alertNumber: 7, url: 'https://github.com/acme/example/security/dependabot/7' }],
      },
      advisories: [
        { id: 'GHSA-AAAA-BBBB-CCCC', cves: ['CVE-2026-1001'], title: '1.x line', severity: 'high', url: 'https://github.com/advisories/GHSA-AAAA-BBBB-CCCC',
          affectedVersions: [{ vulnerableRange: '<1.1.21', firstPatchedVersion: '1.1.21' }] },
        { id: 'GHSA-DDDD-EEEE-FFFF', cves: ['CVE-2026-1002'], title: '5.x line', severity: 'critical', url: 'https://github.com/advisories/GHSA-DDDD-EEEE-FFFF',
          affectedVersions: [{ vulnerableRange: '>=5.0.0, <5.0.11', firstPatchedVersion: '5.0.11' }] },
        { id: 'GHSA-GGGG-HHHH-IIII', title: 'Other major line', severity: 'moderate', url: 'https://github.com/advisories/GHSA-GGGG-HHHH-IIII',
          affectedVersions: [{ vulnerableRange: '>=3.0.0 <3.1.0', firstPatchedVersion: '3.1.0' }] },
      ],
    }],
  };
}

function report(branches) {
  return { generatedAt, repository: { name: 'example', org: 'acme', fullName: 'acme/example', path: '/example' }, branches };
}

function catalogs(branch, versions = publishedVersions) {
  return new Map([[branch.branch, new Map([[packageName, { versions, error: null }]])]]);
}

test('schema 2 plans the newest safe patch per vulnerable installed line and preserves exact origins', () => {
  const input = multiLineBranch();
  const plan = generateRemediationPlan(report([input]), { publishedVersionsByBranch: catalogs(input) });
  assert.equal(plan.schemaVersion, '2.0.0');
  const branch = plan.branches[0];
  assert.equal(branch.status, 'ready');
  const pkg = branch.packages[0];
  assert.equal(pkg.status, 'ready');
  assert.deepEqual(pkg.installedVersions, ['1.1.18', '1.1.21', '2.1.7', '5.0.9', '5.0.12']);
  assert.deepEqual(pkg.resolutions.map(({ installedVersion, targetVersion, status, strategy }) => [installedVersion, targetVersion, status, strategy]), [
    ['1.1.18', '1.1.22', 'ready', 'bump-direct'],
    ['5.0.9', '5.0.13', 'ready', 'bump-direct'],
    ['1.1.21', '1.1.21', 'resolved', 'none'],
    ['2.1.7', '2.1.7', 'resolved', 'none'],
    ['5.0.12', '5.0.12', 'resolved', 'none'],
  ]);
  const edits = branch.actions.filter((action) => action.type === 'update-dependency');
  assert.deepEqual(edits.map((action) => [action.file, action.expectedRange, action.targetRange, action.resolutionIds]), [
    ['client/package.json', '^5.0.0', '~5.0.13', [`${packageName}@5.0.9`]],
    ['package.json', '^1.1.0', '~1.1.22', [`${packageName}@1.1.18`]],
  ]);
  assert.ok(branch.actions.every((action) => action.packageNames.includes(packageName) && action.findingIds.length && action.resolutionIds.length));
  assert.ok(!Object.hasOwn(pkg, 'currentVersion') && !Object.hasOwn(pkg, 'targetSafeVersion')
    && !Object.hasOwn(pkg, 'dependencyPaths') && !Object.hasOwn(pkg, 'actions'));
  assert.deepEqual(Object.keys(pkg), ['packageName', 'installedVersions', 'status', 'summary', 'reasons', 'resolutions', 'findings', 'risk']);
  assert.deepEqual(pkg.findings[0] && Object.keys(pkg.findings[0]), ['id', 'cves', 'title', 'severity', 'url', 'constraints', 'references']);
  assert.ok(pkg.findings.every((finding) => !Object.hasOwn(finding, 'patchedVersions') && !Object.hasOwn(finding, 'sources')));
  assert.ok(pkg.findings.flatMap((finding) => finding.references).some((reference) => reference.id === 'SEC-100'));
  assert.ok(!JSON.stringify(plan).includes('Sensitive ticket body'));
  const rootOrigin = pkg.resolutions.find((resolution) => resolution.id === `${packageName}@1.1.18`).instances[0].origins[0];
  const workspaceOrigin = pkg.resolutions.find((resolution) => resolution.id === `${packageName}@5.0.9`).instances[0].origins[0];
  assert.equal(rootOrigin.packageJsonPath, 'package.json');
  assert.equal(rootOrigin.chain.at(-1).location, `node_modules/${packageName}`);
  assert.equal(workspaceOrigin.packageJsonPath, 'client/package.json');
  assert.equal(workspaceOrigin.workspace, '@example/client');
  assert.equal(workspaceOrigin.chain.at(-1).location, `client/node_modules/${packageName}`);
  assert.ok(!pkg.findings.some((finding) => finding.id === `${packageName}:aggregate:npm-audit:brace-expansion`),
    'redundant aggregate range contributes references without duplicating coverage');
});

test('invalid advisory evidence and unavailable catalogs never become executable targets', () => {
  const input = multiLineBranch();
  input.vulnerabilities[0].advisories = [{ id: 'GHSA-BAD-RANGE-1234', vulnerableVersionRange: 'not semver', targetSafeVersion: '1.1.22' }];
  const failedCatalog = new Map([[input.branch, new Map([[packageName, { versions: null, error: 'registry unavailable' }]])]]);
  const plan = generateRemediationPlan(report([input]), { publishedVersionsByBranch: failedCatalog });
  const pkg = plan.branches[0].packages[0];
  assert.equal(pkg.status, 'manual-review');
  assert.ok(pkg.resolutions.every((resolution) => resolution.status === 'manual-review'));
  assert.deepEqual(plan.branches[0].actions, []);
  assert.ok(pkg.findings.some((finding) => finding.constraints.some((constraint) => constraint.vulnerableRange === 'not semver')));
});

test('a vulnerable newest release selects the highest earlier safe patch without downgrading', () => {
  const input = multiLineBranch();
  input.vulnerabilities = [{
    packageName, id: 'GHSA-LINE-ONLY-1234', advisories: [
      { id: 'GHSA-OLD-LINE-1234', affectedVersions: [{ vulnerableRange: '<1.1.22', firstPatchedVersion: '1.1.22' }] },
      { id: 'GHSA-NEW-LINE-1234', affectedVersions: [{ vulnerableRange: '>=1.1.23 <1.1.24', firstPatchedVersion: '1.1.24' }] },
    ],
  }];
  const versions = ['1.1.18', '1.1.20', '1.1.21', '1.1.22', '1.1.23'];
  const plan = generateRemediationPlan(report([input]), { publishedVersionsByBranch: catalogs(input, versions) });
  assert.equal(plan.branches[0].packages[0].resolutions.find((resolution) => resolution.id === `${packageName}@1.1.18`).targetVersion, '1.1.22');
});

test('a line without a safe published patch is no-fix and does not retain partial actions', () => {
  const input = multiLineBranch();
  input.vulnerabilities[0].advisories = [{ id: 'GHSA-NO-LINE-FIX-1234', vulnerableVersionRange: '<1.1.23' }];
  const versions = ['1.1.18', '1.1.21', '1.1.22', '5.0.9', '5.0.13'];
  const plan = generateRemediationPlan(report([input]), { publishedVersionsByBranch: catalogs(input, versions) });
  const pkg = plan.branches[0].packages[0];
  assert.equal(pkg.status, 'no-fix');
  assert.ok(pkg.resolutions.some((resolution) => resolution.status === 'no-fix'
    && resolution.reasons.some((reason) => /No safe patch is available on 1\.1\.x/.test(reason))));
  assert.deepEqual(plan.branches[0].actions, []);
});

test('plan writer round-trips schema 2 and the executor rejects version 1', () => {
  const input = multiLineBranch();
  const plan = generateRemediationPlan(report([input]), { publishedVersionsByBranch: catalogs(input) });
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'remediation-plan-v2-'));
  try {
    const filename = writeRemediationPlan(plan, directory);
    assert.deepEqual(readRemediationPlan(filename), plan);
    const legacy = path.join(directory, 'legacy.json');
    fs.writeFileSync(legacy, JSON.stringify({ schemaVersion: '1.0.0', kind: 'security-remediation-plan', repository: {}, branches: [] }));
    assert.throws(() => readRemediationPlan(legacy), /Expected a version 2\.0\.0 security-remediation-plan/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
