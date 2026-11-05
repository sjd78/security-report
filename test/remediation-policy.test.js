import test from 'node:test';
import assert from 'node:assert/strict';
import { classifyPackageFix, isCompatibleUpgrade, reconcilePackageRisk } from '../src/core/remediation-policy.js';

const findingId = 'GHSA-widget';
const packageName = 'widget';
const resolutionId = `${packageName}@1.0.0`;

function finding(range = '<1.2.0', floor = '1.2.0') {
  return {
    id: findingId, cves: [], title: 'Widget flaw', severity: 'high', url: null,
    constraints: [{ vulnerableRange: range, firstPatchedVersion: floor }], references: [],
  };
}

function origin(version = '1.0.0', { parent = null, parentVersion = null, range = '^1.0.0', location = `node_modules/${packageName}` } = {}) {
  const parentLocation = parent ? `node_modules/${parent}-${parentVersion}` : null;
  const target = { name: packageName, version, location, requiredRange: parent ? range : '^1.0.0' };
  return {
    packageJsonPath: 'package.json', section: 'dependencies', workspace: null,
    chain: parent ? [
      { name: parent, version: parentVersion, location: parentLocation, requiredRange: range },
      target,
    ] : [target],
  };
}

function pkg(overrides = {}) {
  const version = overrides.installedVersion || '1.0.0';
  const targetVersion = overrides.targetVersion || '1.2.0';
  const instances = overrides.instances || [{
    location: `node_modules/${packageName}`,
    incoming: [{ parentName: 'app', parentVersion: '1.0.0', parentLocation: '', requestedRange: '^1.0.0', effectiveRange: '^1.0.0', type: 'prod' }],
    origins: [origin(version)],
  }];
  const resolution = {
    id: `${packageName}@${version}`, installedVersion: version, line: `${version.split('.')[0]}.${version.split('.')[1]}`,
    status: 'ready', targetVersion, strategy: 'bump-direct', findingIds: [findingId], reasons: [], instances,
  };
  const findings = overrides.findings || [finding()];
  return {
    packageName, installedVersions: [version], status: 'ready', summary: '', reasons: [],
    resolutions: overrides.resolutions || [resolution], findings,
    risk: overrides.risk || { fixType: 'unknown', breaking: null, reasons: [] },
  };
}

function dependency({ package: name = packageName, targetRange = '~1.2.0', expectedRange = '^1.0.0', resolutionIds = [resolutionId], ...rest } = {}) {
  return { type: 'update-dependency', file: 'package.json', section: 'dependencies', package: name,
    expectedRange, targetRange, packageNames: [packageName], findingIds: [findingId], resolutionIds, ...rest };
}

function override({ package: selector = 'widget@1.x', targetVersion = '1.2.0', scope = ['parent@1.0.0'], resolutionIds = [resolutionId], ...rest } = {}) {
  return { type: 'set-override', file: 'package.json', package: selector, scope,
    expectedValue: null, targetVersion, packageNames: [packageName], findingIds: [findingId], resolutionIds, ...rest };
}

const lockfile = { type: 'update-lockfile', package: packageName, packageNames: [packageName],
  findingIds: [findingId], resolutionIds: [resolutionId] };

test('compatible upgrades preserve stable, pre-1.0, and 0.0 version-line rules', () => {
  for (const [before, after] of [['1.0.0', '1.9.9'], ['0.2.0', '0.2.9'], ['0.0.2', '0.0.2']]) {
    assert.equal(isCompatibleUpgrade(before, after), true, `${before} -> ${after}`);
  }
  for (const [before, after] of [
    ['1.0.0', '2.0.0'], ['0.2.0', '0.3.0'], ['0.0.2', '0.0.3'], ['1.2.0', '1.1.9'],
    ['1.2.0', '1.3.0-beta.1'], ['1.2.0-beta.1', '1.2.0'], ['unknown', '1.2.0'],
  ]) assert.equal(isCompatibleUpgrade(before, after), false, `${before} -> ${after}`);
});
test('direct and lockfile actions classify from their linked installed resolution, not saved scalar risk', () => {
  const input = pkg({ risk: { fixType: 'breaking-upgrade', breaking: true, reasons: ['Stale risk.'] } });
  assert.deepEqual(classifyPackageFix(input, [dependency()]), {
    fixType: 'safe-fix', breaking: false, reasons: [`${resolutionId}: update-dependency is compatible with the installed line.`],
  });
  assert.equal(classifyPackageFix(input, [lockfile]).breaking, false);
  assert.deepEqual(input.installedVersions, ['1.0.0']);
});
test('widened dependency targets and incompatible lines are breaking', () => {
  for (const targetRange of ['^1.2.0', '^1.2.0 || >=2.0.0', '>=1.2.0', '*']) {
    assert.equal(classifyPackageFix(pkg(), [dependency({ targetRange })]).breaking, true, targetRange);
  }
  for (const [before, target] of [['0.2.0', '0.3.0'], ['0.0.2', '0.0.3'], ['1.2.0', '1.1.0']]) {
    const input = pkg({ installedVersion: before, targetVersion: target, findings: [finding(`<${target}`, target)] });
    assert.equal(classifyPackageFix(input, [dependency({ targetRange: target, resolutionIds: [`${packageName}@${before}`] })]).breaking,
      true, `${before} -> ${target}`);
  }
});

test('every ready resolution needs action coverage and risk is computed per version line', () => {
  const first = {
    ...pkg().resolutions[0], strategy: 'package-override',
    instances: [{ location: `node_modules/parent-1.0.0/node_modules/${packageName}`,
      incoming: [{ parentName: 'parent', parentVersion: '1.0.0', parentLocation: 'node_modules/parent-1.0.0', requestedRange: '^1.0.0', effectiveRange: '^1.0.0', type: 'prod' }],
      origins: [origin('1.0.0', { parent: 'parent', parentVersion: '1.0.0', location: `node_modules/parent-1.0.0/node_modules/${packageName}` })] }],
  };
  const second = {
    ...pkg({ installedVersion: '2.0.0', targetVersion: '2.2.0' }).resolutions[0],
    id: `${packageName}@2.0.0`, line: '2.0', strategy: 'package-override',
    instances: [{ location: `node_modules/parent-2.0.0/node_modules/${packageName}`,
      incoming: [{ parentName: 'parent', parentVersion: '2.0.0', parentLocation: 'node_modules/parent-2.0.0', requestedRange: '^2.0.0', effectiveRange: '^2.0.0', type: 'prod' }],
      origins: [origin('2.0.0', { parent: 'parent', parentVersion: '2.0.0', range: '^2.0.0', location: `node_modules/parent-2.0.0/node_modules/${packageName}` })] }],
  };
  const input = pkg({
    installedVersions: ['1.0.0', '2.0.0'],
    resolutions: [first, second],
    findings: [finding('<1.2.0 || >=2.0.0 <2.1.0', '1.2.0')],
  });
  const actions = [
    { ...override(), resolutionIds: [resolutionId] },
    { ...override({ package: 'widget@2.x', targetVersion: '2.2.0', resolutionIds: [`${packageName}@2.0.0`] }),
      scope: ['parent@2.0.0'] },
  ];
  assert.equal(classifyPackageFix(input, actions).fixType, 'override-required');
  assert.equal(classifyPackageFix(input, actions).breaking, false);
  assert.equal(classifyPackageFix(input, actions.slice(0, 1)).breaking, null);
});

test('override scope must cover every recorded physical incoming edge', () => {
  const parentOrigin = origin('1.0.0', { parent: 'parent', parentVersion: '1.0.0', range: '^1.0.0',
    location: `node_modules/parent-1.0.0/node_modules/${packageName}` });
  const input = pkg({ instances: [{
    location: `node_modules/parent-1.0.0/node_modules/${packageName}`,
    incoming: [{ parentName: 'parent', parentVersion: '1.0.0', parentLocation: 'node_modules/parent-1.0.0', requestedRange: '^1.0.0', effectiveRange: '^1.0.0', type: 'prod' }],
    origins: [parentOrigin],
  }] });
  assert.equal(classifyPackageFix(input, [override()]).breaking, false);
  assert.equal(classifyPackageFix(input, [override({ scope: ['other-parent@1.0.0'] })]).breaking, null);
  const secondOrigin = origin('1.0.0', { parent: 'other-parent', parentVersion: '1.0.0',
    location: `node_modules/other-parent-1.0.0/node_modules/${packageName}` });
  const sharedResolution = pkg({ instances: [
    ...input.resolutions[0].instances,
    { location: `node_modules/other-parent-1.0.0/node_modules/${packageName}`,
      incoming: [{ parentName: 'other-parent', parentVersion: '1.0.0', parentLocation: 'node_modules/other-parent-1.0.0', requestedRange: '^1.0.0', effectiveRange: '^1.0.0', type: 'prod' }],
      origins: [secondOrigin] },
  ] });
  assert.equal(classifyPackageFix(sharedResolution, [override()]).breaking, null);
  const missing = pkg({ instances: [{ location: `node_modules/${packageName}`, incoming: [], origins: [] }] });
  assert.equal(classifyPackageFix(missing, [override()]).breaking, null);
});

test('parent-upgrade risk requires an explicit strategy and a compatible direct origin', () => {
  const parentResolution = {
    ...pkg().resolutions[0], strategy: 'bump-direct-parent',
    instances: [{ location: `node_modules/${packageName}`, incoming: [],
      origins: [origin('1.0.0', { parent: 'parent', parentVersion: '1.0.0' })] }],
  };
  const input = pkg({ resolutions: [parentResolution] });
  const compatible = dependency({ package: 'parent', targetRange: '^1.2.0' });
  assert.equal(classifyPackageFix(input, [compatible]).fixType, 'parent-upgrade');
  assert.equal(classifyPackageFix(input, [compatible]).breaking, false);
  const incompatible = dependency({ package: 'parent', targetRange: '^2.0.0' });
  assert.equal(classifyPackageFix(input, [incompatible]).fixType, 'breaking-upgrade');
  assert.equal(classifyPackageFix(input, [incompatible]).breaking, true);
  assert.equal(classifyPackageFix(pkg(), [compatible]).breaking, null);
});

test('missing or altered action evidence cannot inherit saved safe risk', () => {
  const saved = pkg({ risk: { fixType: 'override-required', breaking: false, reasons: ['Old proof.'] } });
  assert.equal(reconcilePackageRisk(saved, []).breaking, null);
  const widened = dependency({ targetRange: '^1.2.0' });
  assert.equal(reconcilePackageRisk(saved, [widened]).breaking, true);
  const missing = pkg({ resolutions: [{ ...pkg().resolutions[0], instances: [] }], risk: saved.risk });
  assert.equal(reconcilePackageRisk(missing, [override()]).breaking, null);
});
