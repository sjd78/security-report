import test from 'node:test';
import assert from 'node:assert/strict';
import { selectRemediationBranches } from '../src/core/plan-selection.js';

const baseCommit = '0123456789abcdef0123456789abcdef01234567';
const id = (name) => `GHSA-${name}`;

function resolutionId(packageName, version = '1.0.0') {
  return `${packageName}@${version}`;
}

function pkg(packageName, overrides = {}) {
  const installedVersions = overrides.installedVersions ?? ['1.0.0'];
  const status = overrides.status ?? 'ready';
  const findings = overrides.findings ?? [{
    id: id(packageName), cves: [], title: `Finding for ${packageName}`, severity: 'high', url: null,
    constraints: [{ vulnerableRange: '<1.2.0', firstPatchedVersion: '1.2.0' }], references: [],
  }];
  return {
    packageName, installedVersions, summary: `Patch plan for ${packageName}.`,
    status, reasons: ['Reviewed package remediation.'],
    risk: { fixType: 'unknown', breaking: null, reasons: [] },
    resolutions: overrides.resolutions ?? installedVersions.map((installedVersion) => {
      const location = `node_modules/${packageName}`;
      return {
        id: resolutionId(packageName, installedVersion), installedVersion,
        line: installedVersion.split('.').slice(0, 2).join('.'), status,
        targetVersion: status === 'resolved' ? installedVersion : status === 'ready' ? '1.2.0' : null,
        strategy: status === 'ready' ? 'lockfile-update' : 'none',
        findingIds: [id(packageName)], reasons: [],
        instances: [{
          location,
          incoming: [{ parentName: 'example', parentVersion: '1.0.0', parentLocation: '',
            requestedRange: '^1.0.0', effectiveRange: '^1.0.0', type: 'prod' }],
          origins: [{ packageJsonPath: 'package.json', section: 'dependencies', workspace: null,
            chain: [{ name: packageName, version: installedVersion, location, requiredRange: '^1.0.0' }] }],
        }],
      };
    }),
    findings, ...overrides,
  };
}

function parentPkg(packageName, parentName = 'parent') {
  const entry = pkg(packageName);
  const resolution = entry.resolutions[0];
  const parentLocation = `node_modules/${parentName}`;
  const location = `${parentLocation}/node_modules/${packageName}`;
  resolution.strategy = 'bump-direct-parent';
  resolution.instances = [{
    location,
    incoming: [{ parentName, parentVersion: '1.0.0', parentLocation, requestedRange: '^1.0.0',
      effectiveRange: '^1.0.0', type: 'prod' }],
    origins: [{ packageJsonPath: 'package.json', section: 'dependencies', workspace: null,
      chain: [
        { name: parentName, version: '1.0.0', location: parentLocation, requiredRange: '^1.0.0' },
        { name: packageName, version: '1.0.0', location, requiredRange: '^1.0.0' },
      ] }],
  }];
  return entry;
}
function scopedResolutions(packageName) {
  return ['1.0.0', '2.0.0'].map((installedVersion) => {
    const major = installedVersion.split('.')[0];
    const range = `^${major}.0.0`;
    const parentLocation = `node_modules/parent-${installedVersion}`;
    const location = `${parentLocation}/node_modules/${packageName}`;
    return {
      id: resolutionId(packageName, installedVersion), installedVersion, line: `${major}.0`,
      status: 'ready', targetVersion: `${major}.2.0`, strategy: 'package-override',
      findingIds: [id(packageName)], reasons: [],
      instances: [{
        location,
        incoming: [{ parentName: 'parent', parentVersion: installedVersion, parentLocation,
          requestedRange: range, effectiveRange: range, type: 'prod' }],
        origins: [{ packageJsonPath: 'package.json', section: 'dependencies', workspace: null,
          chain: [
            { name: 'parent', version: installedVersion, location: parentLocation, requiredRange: range },
            { name: packageName, version: installedVersion, location, requiredRange: range },
          ] }],
      }],
    };
  });
}

function resolutionIds(packageNames) {
  return packageNames.flatMap((name) => [`${name}@1.0.0`]);
}

function dependency(packageName, targetRange = '~1.2.0', packageNames = [packageName], expectedRange = '^1.0.0') {
  return { type: 'update-dependency', file: 'package.json', section: 'dependencies', package: packageName,
    expectedRange, targetRange, packageNames, findingIds: packageNames.map(id), resolutionIds: resolutionIds(packageNames) };
}

function override(packageName, targetVersion = '1.2.0', packageNames = [packageName], selector = packageName) {
  return { type: 'set-override', file: 'package.json', package: selector, scope: [],
    expectedValue: null, targetVersion, packageNames, findingIds: packageNames.map(id), resolutionIds: resolutionIds(packageNames) };
}

function lockfile(packageName, packageNames = [packageName]) {
  return { type: 'update-lockfile', package: packageName, packageNames,
    findingIds: packageNames.map(id), resolutionIds: resolutionIds(packageNames) };
}

function branch(packages, actions, overrides = {}) {
  return {
    branch: 'main', baseCommit, status: actions.length ? 'ready' : 'no-op', summary: 'Original summary.', blockers: [],
    packages: packages.map((entry) => ({ ...entry })),
    actions, ...overrides,
  };
}

function plan(...branches) {
  return { schemaVersion: '2.0.0', kind: 'security-remediation-plan', generatedAt: '2026-10-29T12:00:00.000Z',
    repository: { path: '/repository' }, branches };
}

function deepFreeze(value) {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function names(selected) {
  return selected.packages.filter((entry) => entry.status === 'ready').map((entry) => entry.packageName);
}

function categoryPlan() {
  return plan(branch([
    pkg('safe'), pkg('overridden'), parentPkg('leaf'), pkg('breaking'),
    pkg('unknown', { installedVersions: ['1.0.0'],
      resolutions: [{ id: resolutionId('unknown'), installedVersion: '1.0.0', line: '1.0', status: 'ready',
        targetVersion: '1.2.0', strategy: 'lockfile-update', findingIds: [id('unknown')], reasons: [], instances: [] }],
      findings: [{ id: id('unknown'), cves: [], title: 'Unknown finding', severity: 'high', url: null,
        constraints: [{ vulnerableRange: 'invalid-range', firstPatchedVersion: null }], references: [] }] }),
  ], [dependency('safe'), override('overridden'), dependency('parent', '^1.2.0', ['leaf']),
    dependency('breaking', '^2.0.0'), lockfile('unknown')]));
}

test('fix type alternatives OR together while package, branch and safety selectors intersect', () => {
  const input = categoryPlan();
  input.branches.push(branch([pkg('release-only')], [dependency('release-only')], { branch: 'release/1.x' }));
  const [selected] = selectRemediationBranches(input, {
    branches: ' main ', packages: 'safe,overridden,leaf,breaking', fixTypes: ['safe-fix', 'override-required'], allowBreaking: false,
  });
  assert.deepEqual(names(selected), ['safe', 'overridden']);
  assert.deepEqual(selected.selection.selectedPackages, ['safe', 'overridden']);
  assert.deepEqual(selected.selection.skippedPackages.map((entry) => entry.packageName), ['leaf', 'breaking', 'unknown']);
  assert.deepEqual(selected.actions.map((action) => action.package), ['safe', 'overridden']);
  assert.match(selected.summary, /2 package\(s\) selected.*3 skipped/);
  assert.deepEqual(selectRemediationBranches(input, { fixTypes: 'parent-upgrade' })[0].selection.selectedPackages, ['leaf']);
});

test('comma strings and arrays select multiple packages and branches without selecting other branches', () => {
  const input = plan(
    branch([pkg('one'), pkg('@scope/two')], [dependency('one'), dependency('@scope/two')]),
    branch([pkg('one'), pkg('three')], [dependency('one'), dependency('three')], { branch: 'release/1.x' }),
    branch([pkg('one')], [dependency('one')], { branch: 'release/2.x' }),
  );
  for (const branches of ['main,release/1.x', ['main', ' release/1.x ']]) {
    const selected = selectRemediationBranches(input, { branches, packages: [' @scope/two ', 'three', '@scope/two'] });
    assert.deepEqual(selected.map((entry) => entry.branch), ['main', 'release/1.x']);
    assert.deepEqual(selected.map(names), [['@scope/two'], ['three']]);
  }
  const [empty] = selectRemediationBranches(input, { branches: ['main', 'release/1.x'], packages: 'three' });
  assert.equal(empty.status, 'no-op');
  assert.deepEqual(empty.actions, []);
  assert.deepEqual(empty.selection.selectedPackages, []);
});

test('override display precedence does not conceal independent breaking risk', () => {
  const input = plan(branch([pkg('compatible'), pkg('breaking')], [override('compatible'), override('breaking', '2.0.0')]));
  const [allOverrides] = selectRemediationBranches(input, { fixTypes: 'override-required' });
  assert.deepEqual(names(allOverrides), ['compatible', 'breaking']);
  assert.equal(allOverrides.packages[1].risk.fixType, 'override-required');
  assert.equal(allOverrides.packages[1].risk.breaking, true);
  const [nonbreaking] = selectRemediationBranches(input, { fixTypes: 'override-required', allowBreaking: false });
  assert.deepEqual(names(nonbreaking), ['compatible']);
  assert.match(nonbreaking.packages[1].reasons.join(' '), /--no-breaking.*breaking upgrade/);
  assert.deepEqual(selectRemediationBranches(input, { fixTypes: 'breaking-upgrade' })[0].actions, []);
});

test('shared parent targets and preconditions remain whole while excluded motivations are pruned', () => {
  const shared = dependency('parent', '^2.0.0', ['leaf-a', 'leaf-b']);
  const input = plan(branch([parentPkg('leaf-a'), parentPkg('leaf-b')], [shared, lockfile('leaf-a'), lockfile('leaf-b')]));
  const [selected] = selectRemediationBranches(input, { packages: 'leaf-a' });
  assert.deepEqual(selected.actions, [{ ...shared, packageNames: ['leaf-a'], findingIds: [id('leaf-a')], resolutionIds: [resolutionId('leaf-a')] },
    lockfile('leaf-a')]);
  assert.equal(selected.actions[0].targetRange, '^2.0.0');
  assert.equal(selected.actions[0].expectedRange, '^1.0.0');
  assert.equal(selected.packages[0].risk.fixType, 'breaking-upgrade');
  assert.equal(selected.packages[0].risk.breaking, true);
  assert.equal('actions' in selected.packages[0], false);
  assert.equal(selected.packages[1].status, 'skipped');
  assert.equal('actions' in selected.packages[1], false);
  assert.deepEqual(selected.packages[1].findings, input.branches[0].packages[1].findings);
  assert.match(selected.selection.skippedPackages[0].reasons.join(' '), /shared action.*remains skipped/);
  assert.ok(selected.actions.every((action) => !action.packageNames.includes('leaf-b') && !action.findingIds.includes(id('leaf-b'))
    && !action.resolutionIds.includes(resolutionId('leaf-b'))));
});

test('shared overrides retain their approved scope and version rather than being weakened for one package', () => {
  const shared = { ...override('shared-dependency', '2.0.0', ['leaf-a', 'leaf-b'], 'parent@1'), scope: ['parent@1'] };
  const input = plan(branch([pkg('leaf-a'), pkg('leaf-b')], [shared]));
  const [selected] = selectRemediationBranches(input, { packages: 'leaf-a' });
  assert.deepEqual(selected.actions, [{ ...shared, packageNames: ['leaf-a'], findingIds: [id('leaf-a')], resolutionIds: [resolutionId('leaf-a')] }]);
  assert.equal('actions' in selected.packages[0], false);
  assert.equal(selected.packages[0].risk.fixType, 'override-required');
  assert.match(selected.packages[1].reasons.join(' '), /shared action/);
});

test('safe selection never keeps a package by dropping its required override or parent action', () => {
  const input = plan(branch([pkg('combined')], [dependency('combined'), override('combined'), lockfile('combined')]));
  const [safe] = selectRemediationBranches(input, { fixTypes: 'safe-fix' });
  assert.equal(safe.status, 'no-op');
  assert.equal(safe.packages[0].status, 'skipped');
  assert.deepEqual(safe.actions, []);
  const [selected] = selectRemediationBranches(input, { fixTypes: 'override-required' });
  assert.equal(selected.actions.length, 3);
  assert.equal('actions' in selected.packages[0], false);
  const parent = plan(branch([parentPkg('leaf')], [dependency('parent', '^1.2.0', ['leaf']), lockfile('leaf')]));
  assert.deepEqual(selectRemediationBranches(parent, { fixTypes: 'safe-fix' })[0].actions, []);
  assert.equal(selectRemediationBranches(parent, { fixTypes: 'parent-upgrade' })[0].actions.length, 2);
});

test('risk labels follow canonical branch actions, not stale package targets or saved safe flags', () => {
  const source = branch([pkg('widget', { risk: { fixType: 'safe-fix', breaking: false, reasons: ['Old safe label.'] } })], [dependency('widget', '^2.0.0')]);
  const input = plan(source);
  const [selected] = selectRemediationBranches(input);
  assert.equal(selected.packages[0].risk.fixType, 'breaking-upgrade');
  assert.equal(selected.packages[0].risk.breaking, true);
  assert.equal('actions' in selected.packages[0], false);
  assert.equal(selectRemediationBranches(input, { allowBreaking: false })[0].packages[0].status, 'skipped');
  assert.equal(selectRemediationBranches(input, { fixTypes: 'safe-fix' })[0].status, 'no-op');
});

test('saved breaking labels cannot override compatible canonical action evidence', () => {
  const input = plan(branch([pkg('widget', { risk: { fixType: 'breaking-upgrade', breaking: true, reasons: ['Stale breaking label.'] } })],
    [dependency('widget')]));
  const [selected] = selectRemediationBranches(input, { allowBreaking: false });
  assert.equal(selected.packages[0].risk.breaking, false);
  assert.equal(selected.packages[0].risk.fixType, 'safe-fix');
  assert.equal(selected.packages[0].status, 'ready');
  assert.doesNotMatch(selected.packages[0].risk.reasons.join(' '), /Stale breaking label/);
});

test('scoped overrides derive compatibility from complete recorded instance origins', () => {
  const savedRisk = { fixType: 'override-required', breaking: false, reasons: ['Stale saved compatibility label.'] };
  const resolutions = scopedResolutions('leaf');
  const actions = [
    { ...override('leaf', '1.2.0', ['leaf'], 'leaf@1.x'), scope: ['parent'], resolutionIds: [resolutionId('leaf', '1.0.0')] },
    { ...override('leaf', '2.2.0', ['leaf'], 'leaf@2.x'), scope: ['parent'], resolutionIds: [resolutionId('leaf', '2.0.0')] },
  ];
  const input = plan(branch([pkg('leaf', { risk: savedRisk, installedVersions: ['1.0.0', '2.0.0'], resolutions })], actions));
  const [selected] = selectRemediationBranches(input, { allowBreaking: false, fixTypes: 'override-required' });
  assert.deepEqual(names(selected), ['leaf']);
  assert.equal(selected.packages[0].risk.breaking, false);
  assert.ok(selected.packages[0].risk.reasons.every((reason) => !reason.includes('Stale saved compatibility label')));
});

test('altered override targets or ancestry cannot inherit saved compatibility', () => {
  const savedRisk = { fixType: 'override-required', breaking: false, reasons: ['Stale saved compatibility label.'] };
  const original = [
    { ...override('leaf', '1.2.0', ['leaf'], 'leaf@1.x'), scope: ['parent'], resolutionIds: [resolutionId('leaf', '1.0.0')] },
    { ...override('leaf', '2.2.0', ['leaf'], 'leaf@2.x'), scope: ['parent'], resolutionIds: [resolutionId('leaf', '2.0.0')] },
  ];
  for (const [change, expectedRisk] of [[{ targetVersion: '1.3.0' }, true], [{ scope: ['different-parent'] }, null]]) {
    const resolutions = scopedResolutions('leaf');
    const input = plan(branch([pkg('leaf', { risk: savedRisk, installedVersions: ['1.0.0', '2.0.0'], resolutions })],
      structuredClone(original)));
    input.branches[0].actions[0] = { ...original[0], ...change };
    const [selected] = selectRemediationBranches(input, { allowBreaking: false });
    assert.equal(selected.packages[0].risk.breaking, expectedRisk, JSON.stringify(selected.packages[0].risk));
    assert.equal(selected.packages[0].status, 'skipped');
    assert.deepEqual(selected.actions, []);
  }
});


test('unknown risk is neither safe nor allowed through no-breaking, even with an unrelated saved safe promise', () => {
  const input = categoryPlan();
  input.branches[0].packages = input.branches[0].packages.filter((entry) => entry.packageName === 'unknown');
  input.branches[0].actions = [lockfile('unknown')];
  input.branches[0].packages[0].risk = { fixType: 'safe-fix', breaking: false, reasons: ['Unproven display promise.'] };
  const [unrestricted] = selectRemediationBranches(input);
  assert.equal(unrestricted.packages[0].risk.breaking, null);
  assert.equal(unrestricted.packages[0].risk.fixType, 'unknown');
  assert.deepEqual(names(unrestricted), ['unknown']);
  const [guarded] = selectRemediationBranches(input, { allowBreaking: false });
  assert.equal(guarded.status, 'no-op');
  assert.deepEqual(guarded.actions, []);
  assert.match(guarded.packages[0].reasons.join(' '), /compatibility is unknown/);
  assert.equal(selectRemediationBranches(input, { fixTypes: 'safe-fix' })[0].packages[0].status, 'skipped');
});

test('skipped packages stay disclosed and nonready findings retain their original dispositions', () => {
  const input = plan(branch([
    pkg('safe'), pkg('manual', { status: 'manual-review', reasons: ['Missing evidence.'] }),
    pkg('no-fix', { status: 'no-fix' }), pkg('resolved', { status: 'resolved' }),
    pkg('absent', { status: 'not-installed', installedVersions: [] }),
  ], [dependency('safe')]));
  const [selected] = selectRemediationBranches(input, { packages: 'manual' });
  assert.equal(selected.status, 'no-op');
  assert.equal(selected.packages[0].status, 'skipped');
  assert.deepEqual(selected.packages.slice(1), input.branches[0].packages.slice(1));
  assert.deepEqual(selected.selection, { selectedPackages: [], skippedPackages: [{ packageName: 'safe',
    reasons: ['Reviewed package remediation.', 'Excluded by package selection (--packages).'] }] });
  assert.match(selected.summary, /No executable actions selected; 0 package\(s\) selected.*1 skipped.*1 require manual review.*1 have no known fix.*1 are resolved.*1 are not installed/);
  assert.doesNotMatch(selected.summary, /clean/i);
});

test('blocked source branches and blockers cannot be bypassed by selecting zero executable packages', () => {
  const input = plan(branch([pkg('safe')], [dependency('safe')], { status: 'blocked', blockers: ['Conflicting approved actions.'] }));
  const [selected] = selectRemediationBranches(input, { fixTypes: 'override-required' });
  assert.equal(selected.status, 'blocked');
  assert.deepEqual(selected.blockers, ['Conflicting approved actions.']);
  assert.equal(selected.baseCommit, baseCommit);
  assert.deepEqual(selected.actions, []);
  assert.match(selected.summary, /^Execution blocked;/);
  const withoutActions = plan(branch([pkg('safe')], [], { status: 'blocked', blockers: ['Incomplete snapshot.'] }));
  assert.equal(selectRemediationBranches(withoutActions)[0].status, 'blocked');
});

test('selection never mutates even deeply frozen input or reuses its nested finding and action objects', () => {
  const input = deepFreeze(categoryPlan());
  const before = JSON.stringify(input);
  const [selected] = selectRemediationBranches(input, { packages: 'safe,overridden', allowBreaking: false });
  assert.equal(JSON.stringify(input), before);
  assert.notEqual(selected, input.branches[0]);
  assert.notEqual(selected.packages[0].findings, input.branches[0].packages[0].findings);
  assert.notEqual(selected.actions[0], input.branches[0].actions[0]);
  selected.packages[0].findings[0].id = 'changed';
  selected.actions[0].targetRange = '^9.0.0';
  assert.equal(JSON.stringify(input), before);
});

test('unknown branches, packages scoped to other branches, and unknown fix types fail selection', () => {
  const input = plan(branch([pkg('main-only')], [dependency('main-only')]),
    branch([pkg('release-only')], [dependency('release-only')], { branch: 'release/1.x' }));
  assert.throws(() => selectRemediationBranches(input, { branches: 'missing' }), /branches.*missing/);
  assert.throws(() => selectRemediationBranches(input, { packages: 'typo' }), /packages.*typo/);
  assert.throws(() => selectRemediationBranches(input, { branches: 'main', packages: 'release-only' }), /packages.*release-only/);
  assert.throws(() => selectRemediationBranches(input, { fixTypes: 'safe-fix,imaginary' }), /Unknown fixTypes.*imaginary/);
  assert.throws(() => selectRemediationBranches(input, { fixTypes: 'unknown' }), /Unknown fixTypes/);
  assert.throws(() => selectRemediationBranches(input, { allowBreaking: 'false' }), /allowBreaking must be a boolean/);
});

test('explicitly blank, mixed-empty and nonstring selectors fail instead of silently widening selection', () => {
  const input = categoryPlan();
  for (const field of ['branches', 'packages', 'fixTypes']) {
    for (const value of ['', ' ', [], [''], ['safe-fix', ' '], 'safe-fix,', ',safe-fix', ['safe-fix', 3], 1, null]) {
      assert.throws(() => selectRemediationBranches(input, { [field]: value }), new RegExp(field));
    }
  }
});

test('missing canonical action or selected finding and resolution references cannot silently create partial fixes', () => {
  assert.throws(() => selectRemediationBranches(plan(branch([pkg('widget')], [], { status: 'ready' }))), /no canonical remediation actions/);
  const missingFinding = plan(branch([pkg('widget')], [{ ...dependency('widget'), findingIds: ['unrelated-finding'] }]));
  assert.throws(() => selectRemediationBranches(missingFinding), /no matching selected finding references/);
  const missingResolution = plan(branch([pkg('widget')], [{ ...dependency('widget'), resolutionIds: ['unrelated@1.0.0'] }]));
  assert.throws(() => selectRemediationBranches(missingResolution), /no matching selected resolution references/);
});

test('action package selectors do not replace canonical vulnerable package identity', () => {
  const dotSelector = override('leaf-dot', '1.2.0', ['leaf-dot'], '.');
  const qualifiedSelector = {
    ...override('brace-expansion', '1.1.22', ['brace-expansion'], 'brace-expansion@1.1.x'),
    resolutionIds: [resolutionId('brace-expansion', '1.1.18')],
  };
  const brace = pkg('brace-expansion', { installedVersions: ['1.1.18'], resolutions: [{
    id: resolutionId('brace-expansion', '1.1.18'), installedVersion: '1.1.18', line: '1.1',
    status: 'ready', targetVersion: '1.1.22', strategy: 'package-override',
    findingIds: [id('brace-expansion')], reasons: [], instances: [],
  }] });
  const input = plan(branch([pkg('leaf-dot'), brace], [dotSelector, qualifiedSelector]));
  const [selected] = selectRemediationBranches(input, { packages: 'leaf-dot,brace-expansion' });
  assert.deepEqual(selected.selection.selectedPackages, ['leaf-dot', 'brace-expansion']);
  assert.deepEqual(selected.actions.map((action) => action.package), ['.', 'brace-expansion@1.1.x']);
  assert.deepEqual(selected.actions.map((action) => action.packageNames), [['leaf-dot'], ['brace-expansion']]);
});

test('whole-package selection retains every selected resolution reference without package action copies', () => {
  const shared = {
    ...override('leaf-a', '1.2.0', ['leaf-a', 'leaf-b'], 'leaf-a@1.x'),
    scope: ['parent'],
    resolutionIds: [resolutionId('leaf-a', '1.0.0'), resolutionId('leaf-a', '2.0.0'), resolutionId('leaf-b')],
  };
  const input = plan(branch([pkg('leaf-a', { installedVersions: ['1.0.0', '2.0.0'] }), pkg('leaf-b')], [shared]));
  const [selected] = selectRemediationBranches(input, { packages: 'leaf-a' });
  assert.deepEqual(selected.selection.selectedPackages, ['leaf-a']);
  assert.deepEqual(selected.actions[0].packageNames, ['leaf-a']);
  assert.deepEqual(selected.actions[0].findingIds, [id('leaf-a')]);
  assert.deepEqual(selected.actions[0].resolutionIds, [resolutionId('leaf-a', '1.0.0'), resolutionId('leaf-a', '2.0.0')]);
  assert.equal('actions' in selected.packages[0], false);
  assert.equal(selected.packages[1].status, 'skipped');
});

test('saved override compatibility is not trusted without covered installed origins', () => {
  const risk = { fixType: 'override-required', breaking: false, reasons: ['Saved scoped label.'] };
  const resolution = {
    id: resolutionId('leaf'), installedVersion: '1.0.0', line: '1.0', status: 'ready',
    targetVersion: '1.2.0', strategy: 'package-override', findingIds: [id('leaf')], reasons: [], instances: [],
  };
  const input = plan(branch([pkg('leaf', { risk, resolutions: [resolution] })],
    [{ ...override('leaf', '1.2.0'), scope: ['parent'] }]));
  const [selected] = selectRemediationBranches(input, { allowBreaking: false });
  assert.equal(selected.packages[0].risk.breaking, null);
  assert.equal(selected.packages[0].status, 'skipped');
  assert.deepEqual(selected.actions, []);
});
