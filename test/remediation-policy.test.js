import test from 'node:test';
import assert from 'node:assert/strict';
import { classifyPackageFix, isCompatibleUpgrade, reconcilePackageRisk } from '../src/core/remediation-policy.js';

function pkg(overrides = {}) {
  return {
    packageName: 'widget', installedVersions: ['1.0.0'], targetSafeVersion: '1.2.0',
    findings: [{ id: 'GHSA-widget', vulnerableVersionRange: '<1.2.0', patchedVersions: ['1.2.0'] }],
    ...overrides,
  };
}

function dependency(overrides = {}) {
  return {
    type: 'update-dependency', file: 'package.json', section: 'dependencies', package: 'widget',
    expectedRange: '^1.0.0', targetRange: '^1.2.0', packageNames: ['widget'], findingIds: ['GHSA-widget'],
    ...overrides,
  };
}

function override(overrides = {}) {
  return {
    type: 'set-override', file: 'package.json', package: 'widget', scope: [],
    expectedValue: null, targetVersion: '1.2.0', packageNames: ['widget'], findingIds: ['GHSA-widget'],
    ...overrides,
  };
}

const lockfile = { type: 'update-lockfile', package: 'widget', packageNames: ['widget'], findingIds: ['GHSA-widget'] };

function mixedSnapshot() {
  return {
    branch: 'main', pkgJson: { dependencies: { 'parent-a': '^1.0.0', 'parent-b': '^1.0.0' } },
    pkgLock: { packages: {
      '': { dependencies: { 'parent-a': '^1.0.0', 'parent-b': '^1.0.0' } },
      'node_modules/parent-a': { version: '1.0.0', dependencies: { widget: '^1.0.0' } },
      'node_modules/parent-b': { version: '1.0.0', dependencies: { widget: '^2.0.0' } },
      'node_modules/widget': { version: '1.0.0' },
      'node_modules/parent-b/node_modules/widget': { version: '2.0.0' },
    } },
  };
}

test('compatible upgrades follow stable, pre-1.0, and 0.0 version lines', () => {
  for (const [before, after] of [['1.0.0', '1.9.9'], ['0.2.0', '0.2.9'], ['0.0.2', '0.0.2']]) {
    assert.equal(isCompatibleUpgrade(before, after), true, `${before} -> ${after}`);
  }
  for (const [before, after] of [
    ['1.0.0', '2.0.0'], ['0.2.0', '0.3.0'], ['0.0.2', '0.0.3'], ['1.2.0', '1.1.9'],
    ['1.2.0', '1.3.0-beta.1'], ['1.2.0-beta.1', '1.2.0'], ['1.2.0-beta.1', '1.2.0-beta.2'],
    ['unknown', '1.2.0'], ['1.2.0', '^1.3.0'],
  ]) assert.equal(isCompatibleUpgrade(before, after), false, `${before} -> ${after}`);
});

test('safe direct upgrades derive from canonical edits, not raw remediation or saved flags', () => {
  const input = pkg({ isMajorBreaking: true, requiresOverride: true, risk: { fixType: 'breaking-upgrade', breaking: true } });
  const risk = classifyPackageFix(input, [dependency()]);
  assert.equal(risk.fixType, 'safe-fix');
  assert.equal(risk.breaking, false);
  assert.ok(risk.reasons.length > 0);
  assert.deepEqual(input.installedVersions, ['1.0.0']);
});

test('canonical breaking edits cannot be disguised by source fields or package-local actions', () => {
  const input = pkg({ actions: [dependency()], isMajorBreaking: false, risk: { fixType: 'safe-fix', breaking: false } });
  const risk = classifyPackageFix(input, [dependency({ targetRange: '^2.0.0' })]);
  assert.equal(risk.fixType, 'breaking-upgrade');
  assert.equal(risk.breaking, true);
  assert.equal(reconcilePackageRisk(input, [dependency({ targetRange: '^2.0.0' })]).breaking, true);
});

test('dependency ranges that widen into incompatible lines are breaking even with a safe minimum', () => {
  for (const targetRange of ['^1.2.0 || >=2.0.0', '>=1.2.0', '*']) {
    assert.equal(classifyPackageFix(pkg(), [dependency({ targetRange })]).breaking, true, targetRange);
  }
  assert.equal(classifyPackageFix(pkg({ installedVersions: [] }), [dependency({ expectedRange: '*', targetRange: '^1.2.0' })]).breaking, null);
});

test('declared pre-1.0 line changes and downgrades are breaking', () => {
  for (const [before, after] of [['0.2.0', '0.3.0'], ['0.0.2', '0.0.3'], ['1.2.0', '1.1.0']]) {
    const risk = classifyPackageFix(pkg({ installedVersions: [before] }), [dependency({ expectedRange: `^${before}`, targetRange: `^${after}` })]);
    assert.equal(risk.breaking, true, `${before} -> ${after}`);
  }
});

test('parent upgrades have their own type until their canonical change is breaking', () => {
  const safe = classifyPackageFix(pkg(), [dependency({ package: 'parent' })]);
  assert.equal(safe.fixType, 'parent-upgrade');
  assert.equal(safe.breaking, false);
  const breaking = classifyPackageFix(pkg(), [dependency({ package: 'parent', targetRange: '^2.0.0' })]);
  assert.equal(breaking.fixType, 'breaking-upgrade');
  assert.equal(breaking.breaking, true);
  const unknown = classifyPackageFix(pkg(), [dependency({ package: 'parent', expectedRange: '*' })]);
  assert.equal(unknown.fixType, 'parent-upgrade');
  assert.equal(unknown.breaking, null);
});

test('persistent overrides take display precedence without hiding independent breaking risk', () => {
  assert.equal(classifyPackageFix(pkg(), [override()]).fixType, 'override-required');
  assert.equal(classifyPackageFix(pkg(), [override()]).breaking, false);
  const risk = classifyPackageFix(pkg(), [override(), dependency({ package: 'parent', targetRange: '^2.0.0' })]);
  assert.equal(risk.fixType, 'override-required');
  assert.equal(risk.breaking, true);
});

test('global overrides check all installed lines rather than only the vulnerable target line', () => {
  const input = pkg({ installedVersions: ['1.0.0', '2.0.0'] });
  const risk = classifyPackageFix(input, [override()], mixedSnapshot());
  assert.equal(risk.fixType, 'override-required');
  assert.equal(risk.breaking, true);
});

test('scoped overrides resolve hoisted dependency ancestry from the raw snapshot', () => {
  const input = pkg({ installedVersions: ['1.0.0', '2.0.0'] });
  const action = override({ scope: ['parent-a'] });
  assert.equal(classifyPackageFix(input, [action], mixedSnapshot()).breaking, false);
  assert.equal(classifyPackageFix(input, [override({ scope: ['parent-b'] })], mixedSnapshot()).breaking, true);
  assert.equal(classifyPackageFix(input, [action]).breaking, null);
  assert.equal(classifyPackageFix(input, [override({ scope: ['missing-parent'] })], mixedSnapshot()).breaking, null);
});

test('incomplete raw ancestry stays unknown unless dependency chains supply the missing scope evidence', () => {
  const input = pkg({ installedVersions: ['1.0.0', '2.0.0'] });
  const action = override({ scope: ['parent-a'] });
  const snapshot = mixedSnapshot();
  delete snapshot.pkgLock.packages['node_modules/parent-b'].dependencies;
  assert.equal(classifyPackageFix(input, [action], snapshot).breaking, null);
  snapshot.vulnerabilities = [{ dependencyChains: [[
    { name: 'parent-b', version: '1.0.0' }, { name: 'widget', version: '2.0.0' },
  ]] }];
  assert.equal(classifyPackageFix(input, [action], snapshot).breaking, false);
});

test('nested self overrides and version-qualified parent scopes retain their actual target', () => {
  const snapshot = mixedSnapshot();
  const self = override({ package: '.', scope: ['parent-a@^1.0.0', 'widget'] });
  assert.equal(classifyPackageFix(pkg(), [self], snapshot).breaking, false);
  assert.equal(classifyPackageFix(pkg(), [override({ package: '.', scope: ['widget'] })], snapshot).breaking, true);
});

test('raw snapshot baselines take precedence over incomplete report installed versions', () => {
  const input = pkg({ installedVersions: ['1.0.0'] });
  const risk = classifyPackageFix(input, [override()], { rawBranch: mixedSnapshot() });
  assert.equal(risk.breaking, true);
});

test('direct workspace actions compare only the dependency resolved for that manifest', () => {
  const snapshot = {
    branch: 'main', pkgJson: {},
    pkgLock: { packages: {
      '': {}, 'packages/a': { dependencies: { widget: '^1.0.0' } },
      'packages/b': { dependencies: { widget: '^2.0.0' } },
      'node_modules/widget': { version: '1.0.0' },
      'packages/b/node_modules/widget': { version: '2.0.0' },
    } },
  };
  const input = pkg({ installedVersions: ['1.0.0', '2.0.0'] });
  const actions = [dependency({ file: 'packages/a/package.json' }), dependency({ file: 'packages/b/package.json', expectedRange: '^2.0.0', targetRange: '^2.2.0' })];
  assert.equal(classifyPackageFix(input, actions, snapshot).breaking, false);
});

test('mixed-major lockfile fixes remain safe when every installed line has its own compatible patch', () => {
  const input = pkg({
    installedVersions: ['2.4.0', '3.1.0'], targetSafeVersion: '2.4.5',
    findings: [{ id: 'GHSA-widget', vulnerableVersionRange: '<2.4.5 || >=3.0.0 <3.1.6', patchedVersions: ['2.4.5', '3.1.6'] }],
  });
  const risk = classifyPackageFix(input, [lockfile]);
  assert.equal(risk.fixType, 'safe-fix');
  assert.equal(risk.breaking, false);
  assert.equal(classifyPackageFix(pkg({ targetSafeVersion: '2.0.0', findings: [{ vulnerableVersionRange: '<2.0.0', patchedVersions: ['2.0.0'] }] }), [lockfile]).breaking, true);
});

test('lockfile fixes need safe evidence for every advisory and never call missing evidence safe', () => {
  const input = pkg({ targetSafeVersion: '1.2.0', findings: [
    { vulnerableVersionRange: '<1.2.0', patchedVersions: ['1.2.0'] },
    { vulnerableVersionRange: '>=1.2.0 <2.0.0', patchedVersions: [] },
  ] });
  assert.equal(classifyPackageFix(input, [lockfile]).breaking, null);
  assert.equal(classifyPackageFix(pkg({ installedVersions: [] }), [lockfile]).fixType, 'unknown');
  assert.equal(classifyPackageFix(pkg(), []).breaking, null);
  assert.equal(classifyPackageFix(pkg(), [{ type: 'unrecognized' }]).fixType, 'unknown');
});

test('unchanged scoped canonical actions may retain saved snapshot proof after serialization', () => {
  const action = override({ scope: ['parent-a'] });
  const input = pkg({ installedVersions: ['1.0.0', '2.0.0'], actions: [action] });
  input.risk = classifyPackageFix(input, [action], mixedSnapshot());
  const saved = JSON.parse(JSON.stringify(input));
  assert.equal(classifyPackageFix(saved).breaking, null);
  assert.equal(reconcilePackageRisk(saved).breaking, false);
  assert.equal(reconcilePackageRisk(saved, [{ ...action, packageNames: ['widget', 'other'], findingIds: ['other'] }]).breaking, false);
  for (const changed of [
    { ...action, scope: ['parent-b'] }, { ...action, expectedValue: '1.0.0' }, { ...action, targetVersion: '1.3.0' },
  ]) assert.equal(reconcilePackageRisk(saved, [changed]).breaking, null);
});

test('saved safety metadata can never turn missing evidence into a safe-fix or erase breaking intent', () => {
  const missing = pkg({ installedVersions: [], targetSafeVersion: null, findings: [], actions: [lockfile], risk: { fixType: 'safe-fix', breaking: false } });
  assert.equal(reconcilePackageRisk(missing).breaking, null);
  for (const installedVersions of [[], ['unknown'], ['1.0.0', 'unknown']]) {
    const scoped = pkg({ installedVersions, actions: [override({ scope: ['parent-a'] })], risk: { fixType: 'override-required', breaking: false } });
    assert.equal(reconcilePackageRisk(scoped).breaking, null);
  }
  const incomplete = pkg({ installedVersions: ['1.0.0', '2.0.0'], actions: [override({ scope: ['parent-a'] }), lockfile], targetSafeVersion: null, findings: [], risk: { fixType: 'override-required', breaking: false } });
  assert.equal(reconcilePackageRisk(incomplete).breaking, null);
  const savedBreaking = pkg({ actions: [dependency()], risk: { fixType: 'breaking-upgrade', breaking: true, reasons: ['Original scanned major change.'] } });
  const risk = reconcilePackageRisk(savedBreaking);
  assert.equal(risk.breaking, true);
  assert.ok(risk.reasons.includes('Original scanned major change.'));
  const unknown = pkg({ actions: [dependency()], risk: { fixType: 'unknown', breaking: null } });
  assert.equal(reconcilePackageRisk(unknown).breaking, false);
});
