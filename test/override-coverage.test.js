import test from 'node:test';
import assert from 'node:assert/strict';
import {
  findOverrideConflicts,
  getOverrideCoverage,
  parseOverrideSelector,
} from '../src/core/override-coverage.js';

function inventoryFor({ parentRange = '^1.0.0', childRange = '^1.0.0', childSpec = childRange } = {}) {
  const root = { name: 'example', location: '', isRoot: true, incoming: [] };
  const parent = {
    name: 'parent', version: '2.0.0', location: 'node_modules/parent', incoming: [
      { from: root, rawSpec: parentRange, spec: '2.0.0', type: 'prod' },
    ],
  };
  const child = {
    name: 'widget', version: '1.5.0', location: 'node_modules/widget', incoming: [
      { from: parent, rawSpec: childRange, spec: childSpec, type: 'prod' },
    ],
  };
  const nodes = new Map([[root.location, root], [parent.location, parent], [child.location, child]]);
  return { nodes };
}

function override(packageName, scope = [], targetVersion = '1.2.3', extra = {}) {
  return {
    type: 'set-override', file: 'package.json', package: packageName, scope,
    expectedValue: null, targetVersion, packageNames: ['widget'], findingIds: ['GHSA-widget'],
    resolutionIds: ['widget@1.0.0'], ...extra,
  };
}

const wideWidgetEdge = JSON.stringify(['node_modules/parent', 'widget', '>=1.0.0 <3.0.0']);

test('override selectors parse scoped names and semver qualifiers defensively', () => {
  assert.deepEqual(parseOverrideSelector('widget'), { name: 'widget', range: null });
  assert.deepEqual(parseOverrideSelector('widget@1.2.x'), { name: 'widget', range: '1.2.x' });
  assert.deepEqual(parseOverrideSelector('@scope/widget@^2.0.0'), { name: '@scope/widget', range: '^2.0.0' });
  for (const value of ['', '.', '@scope', 'widget@', 'widget@latest', '__proto__', 'widget/child']) {
    assert.equal(parseOverrideSelector(value), null, value);
  }
});

test('coverage uses raw semver range intersections along the incoming ancestry', () => {
  const inventory = inventoryFor({
    parentRange: '>=1.0.0 <3.0.0',
    childRange: '>=1.0.0 <3.0.0',
    childSpec: '2.0.0',
  });
  assert.deepEqual([...getOverrideCoverage(override('widget@^2.0.0', ['parent@^1.0.0']), inventory)], [wideWidgetEdge]);
  assert.deepEqual([...getOverrideCoverage(override('widget@^2.0.0', ['parent@^2.0.0']), inventory)], [wideWidgetEdge]);
  assert.deepEqual([...getOverrideCoverage(override('widget@^2.0.0'), inventory)], [wideWidgetEdge]);

  const disjointRawRange = inventoryFor({ childRange: '^1.0.0', childSpec: '2.0.0' });
  assert.deepEqual([...getOverrideCoverage(override('widget@^2.0.0'), disjointRawRange)], []);
});

test('unsupported dependency specs are not approximated as covered semver edges', () => {
  const inventory = inventoryFor({ childRange: 'git+https://example.test/widget.git#main' });
  assert.deepEqual([...getOverrideCoverage(override('widget'), inventory)], []);
  const reasons = findOverrideConflicts([override('widget')], inventory, {});
  assert.ok(reasons.some((reason) => /non-semver|not a supported semver/.test(reason)));
});

test('npm precedence preserves nested self-overrides and unrelated children', () => {
  const inventory = inventoryFor();
  const rootManifest = {
    dependencies: { parent: '^1.0.0' },
    overrides: {
      widget: '1.2.3',
      parent: { '.': '^1.0.0', widget: { '.': '1.2.3', unrelated: '4.0.0' } },
    },
  };
  const before = structuredClone(rootManifest);
  const reasons = findOverrideConflicts([override('widget', ['parent'])], inventory, rootManifest);
  assert.deepEqual(reasons, []);
  assert.deepEqual(rootManifest, before);

  rootManifest.overrides.widget = '1.1.0';
  rootManifest.overrides.parent['widget@^1.0.0'] = '1.1.0';
  const conflict = findOverrideConflicts([override('widget', ['parent'])], inventory, rootManifest);
  assert.ok(conflict.some((reason) => /competing targets/.test(reason)));
  assert.deepEqual(rootManifest.overrides.parent.widget, { '.': '1.2.3', unrelated: '4.0.0' });
  assert.equal(rootManifest.overrides.parent['.'], '^1.0.0');
});

test('overlapping semver selectors report edges with competing targets', () => {
  const inventory = inventoryFor({ childRange: '>=1.0.0 <2.0.0' });
  const reasons = findOverrideConflicts([
    override('widget@^1.0.0', [], '1.2.0'),
    override('widget@>=1.5.0 <2.0.0', [], '1.8.0'),
  ], inventory, {});
  assert.ok(reasons.some((reason) => /competing targets/.test(reason)));
});

test('a broad existing override on another installed line remains a manual conflict', () => {
  const inventory = inventoryFor({ childRange: '^2.0.0', childSpec: '^2.0.0' });
  inventory.nodes.get('node_modules/widget').version = '2.1.0';
  const reasons = findOverrideConflicts(
    [override('widget@^1.0.0', [], '1.2.3')],
    inventory,
    { overrides: { widget: '2.0.0' } },
  );
  assert.ok(reasons.some((reason) => /broader existing override/.test(reason)));
});

test('same and prefix override paths disclose incompatible edits', () => {
  const samePath = findOverrideConflicts([
    override('widget', ['parent'], '1.2.0'),
    override('.', ['parent', 'widget'], '1.3.0'),
  ], inventoryFor(), {});
  assert.ok(samePath.some((reason) => /same path/.test(reason)));

  const prefix = findOverrideConflicts([
    override('parent', [], '1.2.0'),
    override('widget', ['parent'], '1.2.0'),
  ], inventoryFor(), {});
  assert.ok(prefix.some((reason) => /overlap by prefix/.test(reason)));
});

test('root overrides that change direct dependency specs are rejected as EOVERRIDE', () => {
  const inventory = inventoryFor();
  const rootManifest = { dependencies: { widget: '^1.0.0' } };
  const action = override('widget@^1.0.0', [], '1.2.3');
  assert.ok(findOverrideConflicts([action], inventory, rootManifest).some((reason) => /EOVERRIDE/.test(reason)));
  assert.deepEqual(findOverrideConflicts([
    action,
    { type: 'update-dependency', file: 'package.json', section: 'dependencies', package: 'widget', targetRange: '1.2.3' },
  ], inventory, rootManifest), []);
});
