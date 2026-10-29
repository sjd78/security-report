import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { generateRemediationPlan, writeRemediationPlan } from '../src/report/remediation-reporter.js';

const baseCommit = '0123456789abcdef0123456789abcdef01234567';
const generatedAt = '2026-10-29T12:00:00.000Z';

function finding(overrides = {}) {
  return {
    id: 'GHSA-widget', packageName: 'widget', currentVersion: '1.0.0',
    title: 'Widget vulnerability', severity: 'high', cve: 'CVE-2026-1000',
    url: 'https://github.com/advisories/GHSA-widget',
    vulnerableVersionRange: '<1.2.0', targetSafeVersion: '1.2.0',
    patchedVersions: ['1.2.0'], isDirect: true,
    remediation: {
      strategy: 'bump-direct', targetVersion: '1.2.0',
      packageJsonChanges: [{ package: 'widget', section: 'dependencies', packageJsonPath: 'package.json', from: '^1.0.0', to: '^1.2.0' }],
      lockfileUpdates: [],
    },
    ...overrides,
  };
}

function branch(overrides = {}) {
  return {
    branch: 'main', baseCommit,
    pkgJson: { name: 'example', dependencies: { widget: '^1.0.0' } },
    pkgLock: { lockfileVersion: 3, packages: { '': { dependencies: { widget: '^1.0.0' } }, 'node_modules/widget': { version: '1.0.0' } } },
    vulnerabilities: [finding()],
    ...overrides,
  };
}

function report(branches = [branch()]) {
  return { generatedAt, repository: { name: 'example', org: 'acme', fullName: 'acme/example' }, branches };
}

function transitive({ range = '^1.0.0', version = '1.0.0', target = '1.2.0', overrides, extra = {} } = {}) {
  return branch({
    pkgJson: { name: 'example', dependencies: { parent: '^1.0.0' }, ...(overrides ? { overrides } : {}) },
    pkgLock: { lockfileVersion: 3, packages: {
      '': { dependencies: { parent: '^1.0.0' } },
      'node_modules/parent': { version: '1.0.0', dependencies: { widget: range } },
      'node_modules/widget': { version },
    } },
    vulnerabilities: [finding({
      isDirect: false, isIndirect: true, dependencyType: 'Indirect (Transitive)',
      currentVersion: version, targetSafeVersion: target, patchedVersions: [target],
      dependencyPaths: [`parent@1.0.0 -> widget@${version}`],
      dependencyChains: [[{ name: 'parent', version: '1.0.0' }, { name: 'widget', version, requiredRange: range }]],
      remediation: {
        strategy: 'lockfile-update', targetVersion: target, packageJsonChanges: [],
        transientOverrides: [{ package: 'widget', to: `^${target}` }], lockfileUpdates: ['widget'],
      },
    })],
    ...extra,
  });
}

function parentFinding(packageName, parentTarget = '2.0.0') {
  return finding({
    id: `GHSA-${packageName}`, packageName, isDirect: false, isIndirect: true,
    dependencyChains: [[{ name: 'parent', version: '1.0.0' }, { name: packageName, version: '1.0.0', requiredRange: '~1.0.0' }]],
    remediation: {
      strategy: 'bump-direct-parent', targetPackage: 'parent', targetVersion: parentTarget,
      packageJsonChanges: [{ package: 'parent', section: 'dependencies', from: '^1.0.0', to: `^${parentTarget}`, packageJsonPath: 'package.json' }],
      lockfileUpdates: [packageName],
    },
  });
}

function parentBranch(secondTarget = '2.0.0') {
  return branch({
    pkgJson: { dependencies: { parent: '^1.0.0' } },
    pkgLock: { packages: {
      '': { dependencies: { parent: '^1.0.0' } },
      'node_modules/parent': { version: '1.0.0', dependencies: { 'leaf-a': '~1.0.0', 'leaf-b': '~1.0.0' } },
      'node_modules/leaf-a': { version: '1.0.0' }, 'node_modules/leaf-b': { version: '1.0.0' },
    } },
    vulnerabilities: [parentFinding('leaf-b', secondTarget), parentFinding('leaf-a')],
  });
}

function workspaceBranch(patchedVersions = ['2.4.5', '3.1.6']) {
  const root = { name: 'example', workspaces: ['packages/*'] };
  return branch({
    pkgJson: root,
    workspaces: [
      { relativePath: 'package.json', isRoot: true, name: 'example', pkgJson: root },
      { relativePath: 'packages/a/package.json', name: '@example/a', pkgJson: { name: '@example/a', dependencies: { widget: '^2.4.0' } } },
      { relativePath: 'packages/b/package.json', name: '@example/b', pkgJson: { name: '@example/b', devDependencies: { widget: '~3.1.0' } } },
    ],
    pkgLock: { packages: {
      '': {}, 'packages/a': { dependencies: { widget: '^2.4.0' } },
      'packages/b': { devDependencies: { widget: '~3.1.0' } },
      'node_modules/widget': { version: '2.4.0' },
      'packages/b/node_modules/widget': { version: '3.1.0' },
    } },
    vulnerabilities: [finding({
      currentVersion: '2.4.0, 3.1.0', vulnerableVersionRange: '<2.4.5 || >=3.0.0 <3.1.6',
      targetSafeVersion: '2.4.5', patchedVersions,
      remediation: { strategy: 'bump-direct', packageJsonChanges: [
        { package: 'widget', section: 'dependencies', packageJsonPath: 'packages/a/package.json', from: '^2.4.0', to: '^2.4.5' },
        { package: 'widget', section: 'devDependencies', packageJsonPath: 'packages/b/package.json', from: '~3.1.0', to: '~2.4.5' },
      ] },
    })],
  });
}

test('ready direct plan has the standalone canonical contract and stable timestamp', () => {
  const input = report();
  const plan = generateRemediationPlan(input);
  assert.deepEqual(Object.keys(plan), ['schemaVersion', 'kind', 'generatedAt', 'repository', 'summary', 'branches']);
  assert.equal(plan.schemaVersion, '1.0.0');
  assert.equal(plan.kind, 'security-remediation-plan');
  assert.equal(plan.generatedAt, generatedAt);
  assert.deepEqual(plan.summary, { totalBranches: 1, readyPackages: 1, unresolvedPackages: 0 });
  const planned = plan.branches[0];
  assert.equal(planned.baseCommit, baseCommit);
  assert.equal(planned.status, 'ready');
  assert.deepEqual(planned.blockers, []);
  assert.deepEqual(planned.actions, [{
    type: 'update-dependency', file: 'package.json', section: 'dependencies', package: 'widget',
    expectedRange: '^1.0.0', targetRange: '^1.2.0', packageNames: ['widget'], findingIds: ['GHSA-widget'],
  }]);
  assert.deepEqual(planned.packages[0].installedVersions, ['1.0.0']);
  assert.equal(planned.packages[0].status, 'ready');
  assert.deepEqual(JSON.parse(JSON.stringify(plan)), plan);
  assert.deepEqual(generateRemediationPlan(input), plan);
});

test('normalizes every advisory and preserves Jira, Dependabot, npm and advisory links', () => {
  const input = branch();
  input.vulnerabilities = [finding({
    sources: {
      jira: { ticketKey: 'SEC-1', url: 'https://jira.example/browse/SEC-1' },
      dependabotAlerts: [{ alertNumber: 4, url: 'https://github.com/acme/example/security/dependabot/4' }],
      npmAudit: { urls: ['https://www.npmjs.com/advisories/123'] },
    },
    advisories: [
      { id: 'GHSA-a', cve: 'CVE-2026-1000', title: 'First', vulnerableVersionRange: '<1.1.0', patchedVersions: ['1.1.0'], url: 'https://github.com/advisories/GHSA-a' },
      { id: 'GHSA-b', cve: 'CVE-2026-1001', title: 'Second', vulnerableVersionRange: '<1.2.0', targetSafeVersion: '1.2.0', url: 'https://github.com/advisories/GHSA-b' },
    ],
  })];
  const pkg = generateRemediationPlan(report([input])).branches[0].packages[0];
  assert.equal(pkg.status, 'ready');
  assert.equal(pkg.findings.length, 2);
  for (const advisory of pkg.findings) {
    assert.deepEqual(Object.keys(advisory), ['id', 'cve', 'cves', 'title', 'severity', 'url', 'vulnerableVersionRange', 'targetSafeVersion', 'patchedVersions', 'sources']);
    assert.equal(advisory.sources.jira.url, 'https://jira.example/browse/SEC-1');
    assert.equal(advisory.sources.dependabotAlerts[0].alertNumber, 4);
    assert.deepEqual(advisory.sources.npmAudit.urls, ['https://www.npmjs.com/advisories/123']);
  }
  assert.deepEqual(pkg.actions[0].findingIds, ['GHSA-a', 'GHSA-b']);
});

test('reconciles shared parent edits and combines package and finding motivations', () => {
  const planned = generateRemediationPlan(report([parentBranch()])).branches[0];
  assert.equal(planned.status, 'ready');
  const edit = planned.actions.find((action) => action.type === 'update-dependency');
  assert.deepEqual(edit.packageNames, ['leaf-a', 'leaf-b']);
  assert.deepEqual(edit.findingIds, ['GHSA-leaf-a', 'GHSA-leaf-b']);
  assert.equal(edit.targetRange, '^2.0.0');
  assert.equal(planned.actions.filter((action) => action.type === 'update-dependency').length, 1);
  assert.deepEqual(planned.actions.filter((action) => action.type === 'update-lockfile').map((action) => action.package), ['leaf-a', 'leaf-b']);
});

test('blocks incompatible shared manifest targets rather than silently choosing the highest', () => {
  const plan = generateRemediationPlan(report([parentBranch('3.0.0')]));
  assert.equal(plan.branches[0].status, 'blocked');
  assert.match(plan.branches[0].blockers.join(' '), /Conflicting edits.*parent/);
  assert.deepEqual(plan.branches[0].actions, []);
  assert.equal(plan.summary.readyPackages, 0);
  assert.equal(plan.summary.unresolvedPackages, 2);
});

test('blocks stale expected ranges and conflicting raw edit preconditions', () => {
  const input = branch();
  input.vulnerabilities[0].remediation.packageJsonChanges[0].from = '^0.9.0';
  const planned = generateRemediationPlan(report([input])).branches[0];
  assert.equal(planned.status, 'blocked');
  assert.match(planned.blockers.join(' '), /Stale edit precondition/);
  assert.deepEqual(planned.actions, []);
});

test('missing scanned SHA, scan errors and missing dependency snapshots block execution', () => {
  const missingManifest = branch({ branch: 'missing-manifest', pkgJson: null });
  const missingLock = branch({ branch: 'missing-lock', pkgLock: null });
  const plan = generateRemediationPlan(report([
    branch({ branch: 'missing-sha', baseCommit: null }),
    branch({ branch: 'failed', error: 'npm audit collection failed' }),
    missingManifest, missingLock,
  ]));
  for (const planned of plan.branches) {
    assert.equal(planned.status, 'blocked');
    assert.ok(planned.blockers.length > 0);
    assert.deepEqual(planned.actions, []);
  }
  assert.match(plan.branches[0].blockers.join(' '), /base commit SHA/);
  assert.match(plan.branches[1].blockers.join(' '), /npm audit collection failed/);
  assert.match(plan.branches[2].blockers.join(' '), /package.json snapshot/);
  assert.match(plan.branches[3].blockers.join(' '), /package-lock.json snapshot/);
});

test('empty branches are no-op but failed scans never masquerade as clean', () => {
  const planned = generateRemediationPlan(report([
    branch({ vulnerabilities: [] }), branch({ branch: 'failed', vulnerabilities: [], error: 'scan failed' }),
  ])).branches;
  assert.equal(planned[0].status, 'no-op');
  assert.deepEqual(planned[0].packages, []);
  assert.equal(planned[1].status, 'blocked');
});

test('known absent packages do not inherit tracker placeholders or fabricated edits', () => {
  const input = branch({ pkgJson: {}, pkgLock: { packages: { '': {} } } });
  input.vulnerabilities[0].currentVersion = 'downstream-tracker';
  input.vulnerabilities[0].installedVersions = ['1.0.0'];
  const planned = generateRemediationPlan(report([input])).branches[0];
  assert.equal(planned.status, 'no-op');
  assert.equal(planned.packages[0].status, 'not-installed');
  assert.deepEqual(planned.packages[0].installedVersions, []);
  assert.equal(planned.packages[0].findings.length, 1);
  assert.deepEqual(planned.actions, []);
});

test('no-fix findings are retained and disclosed alongside ready packages', () => {
  const input = branch();
  input.pkgLock.packages['node_modules/unpatched'] = { version: '1.0.0' };
  input.vulnerabilities.push(finding({
    id: 'GHSA-unpatched', packageName: 'unpatched', vulnerableVersionRange: '*',
    targetSafeVersion: null, patchedVersions: [], isDirect: false, remediation: { strategy: 'none', packageJsonChanges: [] },
  }));
  const plan = generateRemediationPlan(report([input]));
  const planned = plan.branches[0];
  assert.equal(planned.status, 'ready');
  assert.equal(planned.packages.find((pkg) => pkg.packageName === 'unpatched').status, 'no-fix');
  assert.match(planned.summary, /1 have no known fix/);
  assert.equal(plan.summary.unresolvedPackages, 1);
  assert.equal(planned.packages.find((pkg) => pkg.packageName === 'unpatched').findings[0].id, 'GHSA-unpatched');
});

test('never trusts a resolved flag or a target vulnerable to a second advisory', () => {
  const input = branch();
  input.pkgLock.packages['node_modules/widget'].version = '1.2.0';
  input.vulnerabilities[0] = finding({
    status: 'resolved', resolved: true,
    advisories: [
      { id: 'GHSA-first', vulnerableVersionRange: '<1.2.0', targetSafeVersion: '1.2.0' },
      { id: 'GHSA-second', vulnerableVersionRange: '>=1.2.0 <1.3.0', targetSafeVersion: '1.3.0' },
    ],
  });
  const pkg = generateRemediationPlan(report([input])).branches[0].packages[0];
  assert.equal(pkg.status, 'ready');
  assert.equal(pkg.targetSafeVersion, '1.3.0');
  assert.equal(pkg.actions[0].targetRange, '^1.3.0');
});

test('requires every installed version to be safe and retains an unfixable second finding', () => {
  const input = branch();
  input.pkgLock.packages['node_modules/widget'].version = '1.2.0';
  input.pkgLock.packages['node_modules/parent/node_modules/widget'] = { version: '1.0.0' };
  input.vulnerabilities[0].advisories = [
    { id: 'GHSA-first', vulnerableVersionRange: '<1.2.0', targetSafeVersion: '1.2.0' },
    { id: 'GHSA-unfixable', vulnerableVersionRange: '*', targetSafeVersion: null },
  ];
  const pkg = generateRemediationPlan(report([input])).branches[0].packages[0];
  assert.equal(pkg.status, 'manual-review');
  assert.deepEqual(pkg.installedVersions, ['1.0.0', '1.2.0']);
  assert.deepEqual(pkg.actions, []);
  assert.ok(pkg.findings.some((advisory) => advisory.id === 'GHSA-unfixable'));
});

test('fully safe installed versions are resolved without relying on report status', () => {
  const input = branch();
  input.pkgLock.packages['node_modules/widget'].version = '1.2.0';
  const planned = generateRemediationPlan(report([input])).branches[0];
  assert.equal(planned.packages[0].status, 'resolved');
  assert.equal(planned.status, 'no-op');
  assert.deepEqual(planned.packages[0].actions, []);
});

test('in-range transitive fixes produce npm update intent without temporary overrides', () => {
  const planned = generateRemediationPlan(report([transitive()]), { allowOverrides: false }).branches[0];
  assert.equal(planned.status, 'ready');
  assert.deepEqual(planned.actions.map((action) => action.type), ['update-lockfile']);
  assert.equal(planned.actions[0].package, 'widget');
  assert.ok(!JSON.stringify(planned).includes('transientOverrides'));
  assert.ok(!JSON.stringify(planned).includes('npm update'));
});

test('forbidden incoming ranges require persistent scoped overrides with snapshot preconditions', () => {
  const planned = generateRemediationPlan(report([transitive({ range: '~1.0.0', overrides: { parent: { widget: '1.0.0' } } })])).branches[0];
  assert.equal(planned.status, 'ready');
  const override = planned.actions.find((action) => action.type === 'set-override');
  assert.deepEqual(override, {
    type: 'set-override', file: 'package.json', package: 'widget', scope: ['parent'], expectedValue: '1.0.0',
    targetVersion: '1.2.0', packageNames: ['widget'], findingIds: ['GHSA-widget'],
  });
  assert.ok(planned.actions.some((action) => action.type === 'update-lockfile'));
});

test('disabled overrides leave an override-only package explicit manual-review', () => {
  const planned = generateRemediationPlan(report([transitive({ range: '~1.0.0' })]), { allowOverrides: false }).branches[0];
  assert.equal(planned.status, 'no-op');
  assert.equal(planned.packages[0].status, 'manual-review');
  assert.match(planned.packages[0].reasons.join(' '), /persistent override.*disabled/);
  assert.deepEqual(planned.actions, []);
});

test('inspects all live Arborist incoming edges instead of trusting a lockfile-only strategy', () => {
  const input = transitive();
  const node = { version: '1.0.0', edgesIn: new Set([
    { spec: '^1.0.0', from: { name: 'parent' } },
    { spec: '~1.0.0', from: { name: 'other-parent' } },
  ]) };
  const tree = { inventory: { query: (_field, name) => name === 'widget' ? new Set([node]) : new Set() } };
  tree.root = tree;
  input.arboristTree = tree;
  const planned = generateRemediationPlan(report([input]), { allowOverrides: false }).branches[0];
  assert.equal(planned.packages[0].status, 'manual-review');
  assert.deepEqual(planned.actions, []);
  assert.doesNotThrow(() => JSON.stringify(planned));
});

test('workspace declarations retain their own safe major, section, path and range prefix', () => {
  const planned = generateRemediationPlan(report([workspaceBranch()])).branches[0];
  assert.equal(planned.status, 'ready');
  const edits = planned.actions.filter((action) => action.type === 'update-dependency');
  assert.deepEqual(edits.map((action) => [action.file, action.section, action.expectedRange, action.targetRange]), [
    ['packages/a/package.json', 'dependencies', '^2.4.0', '^2.4.5'],
    ['packages/b/package.json', 'devDependencies', '~3.1.0', '~3.1.6'],
  ]);
});

test('unsupported workspace major fixes become manual rather than downgrading a declaration', () => {
  const planned = generateRemediationPlan(report([workspaceBranch(['2.4.5'])])).branches[0];
  assert.equal(planned.packages[0].status, 'manual-review');
  assert.match(planned.packages[0].reasons.join(' '), /non-downgrading.*packages\/b\/package.json/);
  assert.deepEqual(planned.actions, []);
});

test('multiple installed transitive majors can use their own in-range safe patch lines', () => {
  const input = transitive();
  input.pkgLock.packages['node_modules/other-parent/node_modules/widget'] = { version: '2.0.0' };
  input.vulnerabilities[0].vulnerableVersionRange = '<1.2.0 || >=2.0.0 <2.1.0';
  input.vulnerabilities[0].patchedVersions = ['1.2.0', '2.1.0'];
  input.vulnerabilities[0].dependencyChains.push([{ name: 'other-parent', version: '1.0.0' }, { name: 'widget', version: '2.0.0', requiredRange: '^2.0.0' }]);
  const planned = generateRemediationPlan(report([input]), { allowOverrides: false }).branches[0];
  assert.equal(planned.status, 'ready');
  assert.deepEqual(planned.actions.map((action) => action.type), ['update-lockfile']);
  assert.deepEqual(planned.packages[0].installedVersions, ['1.0.0', '2.0.0']);
});

test('missing incoming ranges never become an unsupported lockfile-only ready plan', () => {
  const input = transitive();
  delete input.vulnerabilities[0].dependencyChains;
  delete input.pkgLock.packages['node_modules/parent'];
  input.pkgJson = {};
  const planned = generateRemediationPlan(report([input])).branches[0];
  assert.equal(planned.packages[0].status, 'manual-review');
  assert.match(planned.packages[0].reasons.join(' '), /Incoming dependency ranges are missing/);
  assert.deepEqual(planned.actions, []);
});

test('unsafe action files and missing workspace manifests block instead of escaping the repository', () => {
  for (const file of ['/tmp/package.json', '../package.json', 'packages/../../package.json', 'C:\\tmp\\package.json', 'packages/missing/package.json']) {
    const input = branch();
    input.vulnerabilities[0].remediation.packageJsonChanges[0].packageJsonPath = file;
    const planned = generateRemediationPlan(report([input])).branches[0];
    assert.equal(planned.status, 'blocked', file);
    assert.deepEqual(planned.actions, [], file);
  }
});

test('non-registry declaration ranges remain manual without throwing', () => {
  const input = branch();
  input.pkgJson.dependencies.widget = 'file:../widget';
  input.vulnerabilities[0].remediation.packageJsonChanges[0].from = 'file:../widget';
  const planned = generateRemediationPlan(report([input])).branches[0];
  assert.equal(planned.packages[0].status, 'manual-review');
  assert.match(planned.packages[0].reasons.join(' '), /registry semver range/);
});

test('generation never mutates report data or target files and excludes runtime snapshots', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'remediation-plan-readonly-'));
  try {
    const manifestPath = path.join(directory, 'package.json');
    const original = '{"dependencies":{"widget":"^1.0.0"}}\n';
    fs.writeFileSync(manifestPath, original);
    const input = report();
    input.branches[0].worktreeDir = directory;
    input.branches[0].sources = { worktreeDir: directory };
    const before = JSON.stringify(input);
    const freeze = (value) => {
      if (value && typeof value === 'object') {
        for (const child of Object.values(value)) freeze(child);
        Object.freeze(value);
      }
    };
    freeze(input);
    const plan = generateRemediationPlan(input);
    assert.equal(JSON.stringify(input), before);
    assert.equal(fs.readFileSync(manifestPath, 'utf8'), original);
    assert.ok(!JSON.stringify(plan).includes(directory));
    assert.ok(!JSON.stringify(plan).includes('pkgLock'));
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('deduplicates repeated package findings but blocks contradictory proposed edits', () => {
  const input = branch();
  input.vulnerabilities.push(finding({ id: 'GHSA-another-widget', cve: 'CVE-2026-2000' }));
  const planned = generateRemediationPlan(report([input])).branches[0];
  assert.equal(planned.status, 'ready');
  assert.equal(planned.packages.length, 1);
  assert.equal(planned.actions.length, 1);
  assert.deepEqual(planned.actions[0].findingIds, ['GHSA-another-widget', 'GHSA-widget']);
  input.vulnerabilities[1].remediation.packageJsonChanges[0].to = '^1.3.0';
  const conflicting = generateRemediationPlan(report([input])).branches[0];
  assert.equal(conflicting.status, 'blocked');
  assert.match(conflicting.blockers.join(' '), /Conflicting proposed manifest edits/);
  assert.deepEqual(conflicting.actions, []);
});

test('a direct and transitive package requires evidence for both kinds of installed instance', () => {
  const input = transitive({ range: '~1.0.0' });
  input.pkgJson.dependencies.widget = '^1.0.0';
  input.vulnerabilities[0].isDirect = true;
  input.vulnerabilities[0].dependencyType = 'Direct & Indirect';
  input.vulnerabilities[0].remediation.strategy = 'bump-direct-and-lockfile';
  const planned = generateRemediationPlan(report([input])).branches[0];
  assert.equal(planned.status, 'ready');
  assert.ok(planned.actions.some((action) => action.type === 'update-dependency' && action.package === 'widget'));
  assert.ok(planned.actions.some((action) => action.type === 'set-override' && action.scope[0] === 'parent'));
  assert.ok(planned.actions.some((action) => action.type === 'update-lockfile'));
  const disabled = generateRemediationPlan(report([input]), { allowOverrides: false }).branches[0];
  assert.equal(disabled.packages[0].status, 'manual-review');
  assert.deepEqual(disabled.actions, []);
});

test('an explicit global persistent override preserves existing nested override entries', () => {
  const input = branch({
    pkgJson: { overrides: { widget: { '.': '1.0.0', unrelated: '3.0.0' } } },
    pkgLock: { packages: { '': {}, 'node_modules/widget': { version: '1.0.0' } } },
    vulnerabilities: [finding({
      isDirect: false, isIndirect: true,
      remediation: {
        strategy: 'package-override', targetVersion: '1.2.0',
        packageJsonChanges: [{ package: 'widget', section: 'overrides', from: null, to: '1.2.0' }],
      },
    })],
  });
  const planned = generateRemediationPlan(report([input])).branches[0];
  assert.equal(planned.status, 'ready');
  const override = planned.actions.find((action) => action.type === 'set-override');
  assert.equal(override.package, '.');
  assert.deepEqual(override.scope, ['widget']);
  assert.equal(override.expectedValue, '1.0.0');
  assert.equal(override.targetVersion, '1.2.0');
  assert.equal(input.pkgJson.overrides.widget.unrelated, '3.0.0');
});

test('invalid advisory ranges are manual rather than silently treated as safe', () => {
  const input = branch();
  input.vulnerabilities[0].vulnerableVersionRange = 'not a semver range';
  const planned = generateRemediationPlan(report([input])).branches[0];
  assert.equal(planned.packages[0].status, 'manual-review');
  assert.deepEqual(planned.actions, []);
  assert.equal(planned.packages[0].findings[0].vulnerableVersionRange, 'not a semver range');
});

test('writer creates only the requested standalone plan artifact using reporter conventions', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'remediation-plan-write-'));
  try {
    const plan = generateRemediationPlan(report());
    const outputDirectory = path.join(directory, 'reports');
    const target = writeRemediationPlan(plan, outputDirectory);
    assert.equal(target, path.resolve(outputDirectory, 'security-remediation-plan.json'));
    assert.deepEqual(JSON.parse(fs.readFileSync(target, 'utf8')), plan);
    assert.deepEqual(fs.readdirSync(outputDirectory), ['security-remediation-plan.json']);
    assert.equal(writeRemediationPlan(plan, directory, 'custom-plan.json'), path.resolve(directory, 'custom-plan.json'));
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
