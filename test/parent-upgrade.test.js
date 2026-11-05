import test from 'node:test';
import assert from 'node:assert/strict';
import { buildRemediationSuggestion } from '../src/collectors/npm-audit.js';
import { generateRemediationPlan } from '../src/core/remediation-planner.js';

const parentName = 'monaco-editor';
const packageName = 'dompurify';

function parent(range, installedVersion, file = 'package.json') {
  const declaration = { range, section: 'dependencies', packageJsonPath: file };
  return { name: parentName, ...declaration, installedVersion, declarations: [declaration] };
}

function suggestion(version, roots, { safeVersion = '3.4.17', chains = [], tree = null } = {}) {
  return buildRemediationSuggestion({
    packageName, currentVersion: '3.4.8', isDirect: false, isIndirect: true,
    targetSafeVersion: safeVersion,
    fixAvailable: { name: parentName, version, isSemVerMajor: false },
  }, roots, { dependencies: { [parentName]: roots[0]?.range || '^0.57.0' } }, chains, null, null, tree);
}

function assertLeafFallback(result) {
  assert.equal(result.strategy, 'package-override');
  assert.equal(result.targetPackage, packageName);
  assert.equal(result.targetVersion, '3.4.17');
  assert.ok(result.packageJsonChanges.every((change) => change.package !== parentName));
}

for (const version of ['0.53.0', '0.57.0', '0.57.1']) {
  test(`audit parent suggestion rejects stale/lower/equal ${version} against installed 0.57.1`, () => {
    assertLeafFallback(suggestion(version, [parent('^0.57.0', '0.57.1')]));
  });
}

test('invalid parent candidate preserves the no-fix fallback without a downgrade action', () => {
  const result = suggestion('0.53.0', [parent('^0.57.0', '0.57.1')], { safeVersion: null });
  assert.equal(result.strategy, 'none');
  assert.equal(result.targetVersion, null);
  assert.deepEqual(result.packageJsonChanges, []);
});

test('missing installed parent evidence does not use a range minimum as the installed version', () => {
  assertLeafFallback(suggestion('0.53.0', [parent('^0.57.0')]));
  // A published suggestion above the minimum can still be below the installed copy.
  assertLeafFallback(suggestion('0.57.1', [parent('>=0.50.0 <0.60.0')]));
  assertLeafFallback(suggestion('0.58.0', [parent('*')]));
  const result = suggestion('0.58.0', [parent('^0.57.0')]);
  assert.equal(result.strategy, 'bump-direct-parent');
  assert.equal(result.targetVersion, '0.58.0');
});

test('one newer workspace rejects the complete parent candidate, not just its own edit', () => {
  for (const roots of [
    [parent('^0.56.0', '0.56.0'), parent('^0.57.0', '0.58.0', 'client/package.json')],
    [parent('^0.56.0', '0.56.0', 'client/package.json'), parent('^0.57.0', '0.58.0')],
  ]) assertLeafFallback(suggestion('0.57.1', roots));
});

test('saved chain evidence cannot hide a newer copy behind an older root record', () => {
  assertLeafFallback(suggestion('0.57.1', [parent('^0.56.0', '0.56.0')], {
    chains: [[{ name: parentName, version: '0.58.0' }, { name: packageName, version: '3.4.8' }]],
  }));
});

test('unlocated chain evidence does not stand in for a missing workspace baseline', () => {
  assertLeafFallback(suggestion('0.57.1', [
    parent('^0.56.0', '0.56.0'), parent('^0.57.0', undefined, 'client/package.json'),
  ], {
    chains: [[{ name: parentName, version: '0.56.0' }, { name: packageName, version: '3.4.8' }]],
  }));
});

test('live physical parent origins reject an upgrade below any workspace installed copy', () => {
  const nodes = [
    { version: '0.56.0', location: 'node_modules/monaco-editor',
      origin: { isProjectRoot: true, name: 'root', location: '' } },
    { version: '0.58.0', location: 'client/node_modules/monaco-editor',
      origin: { isWorkspace: true, name: 'client', location: 'client' } },
  ].map(({ version, location, origin }) => ({
    name: parentName, version, location,
    edgesIn: [{ from: origin, type: 'prod', rawSpec: '^0.56.0', spec: '^0.56.0' }],
  }));
  const tree = { inventory: { query: (key, name) => name === parentName ? nodes : [] } };
  assertLeafFallback(suggestion('0.57.1', [
    parent('^0.56.0', undefined), parent('^0.56.0', undefined, 'client/package.json'),
  ], { tree }));
});

test('a genuine parent upgrade retains all workspace edits', () => {
  const result = suggestion('0.58.0', [
    parent('^0.56.0', '0.56.1'), parent('~0.57.0', '0.57.1', 'client/package.json'),
  ]);
  assert.equal(result.strategy, 'bump-direct-parent');
  assert.equal(result.targetPackage, parentName);
  assert.equal(result.targetVersion, '0.58.0');
  assert.deepEqual(result.packageJsonChanges.map((change) => [change.packageJsonPath, change.to]), [
    ['package.json', '^0.58.0'], ['client/package.json', '~0.58.0'],
  ]);
});

for (const [allowOverrides, parentRange] of [[true, '0.57.0'], [false, '0.57.0'], [true, '^0.57.0']]) {
  test(`saved downward parent suggestion is not executable by the planner (${parentRange}, overrides ${allowOverrides})`, () => {
    // An exact root declaration permits the qualified fallback scope. A caret
    // root declaration independently blocks it through npm's EOVERRIDE rule.
    const pkgJson = { name: 'root', version: '1.0.0', dependencies: { [parentName]: parentRange } };
    const staleSuggestion = {
      strategy: 'bump-direct-parent', targetPackage: parentName, targetVersion: '0.53.0',
      packageJsonChanges: [{ package: parentName, section: 'dependencies', from: parentRange, to: '0.53.0', packageJsonPath: 'package.json' }],
      lockfileUpdates: [packageName],
    };
    const branch = {
      branch: 'main', baseCommit: '0123456789abcdef0123456789abcdef01234567', pkgJson,
      pkgLock: { lockfileVersion: 3, packages: {
        '': { ...pkgJson },
        'node_modules/monaco-editor': { version: '0.57.0', dependencies: { [packageName]: '3.4.8' } },
        'node_modules/dompurify': { version: '3.4.8' },
      } },
      vulnerabilities: [{
        id: 'audit:dompurify', packageName, severity: 'high', currentVersion: '3.4.8',
        vulnerableVersionRange: '<3.4.17', targetSafeVersion: '3.4.17', remediation: staleSuggestion,
      }],
    };
    const plan = generateRemediationPlan({ branches: [branch] }, {
      allowOverrides,
      publishedVersionsByBranch: new Map([['main', new Map([[packageName, { versions: ['3.4.8', '3.4.17'], error: null }]])]]),
    });
    const planned = plan.branches[0];
    assert.ok(planned.actions.every((action) => action.type !== 'update-dependency' || action.package !== parentName));
    assert.ok(!JSON.stringify(planned.actions).includes('0.53.0'));
    if (allowOverrides && parentRange === '0.57.0') {
      assert.equal(planned.packages[0].status, 'ready');
      assert.ok(planned.actions.some((action) => action.type === 'set-override' && action.targetVersion === '3.4.17'));
    } else {
      assert.equal(planned.packages[0].status, 'manual-review');
      assert.deepEqual(planned.actions, []);
      if (allowOverrides) {
        assert.ok(planned.packages[0].reasons.some((reason) => reason.includes('EOVERRIDE')));
      }
    }
  });
}
