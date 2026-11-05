import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import {
  updatePackageJsonFile,
  detectIndentation,
  executeBranchPlan,
  validateBranchActions,
} from '../src/core/remediator.js';
import { buildDependencyInventory, findWorkspacePackageJsons, getDirectDependencies, getPackageInstances } from '../src/core/dependency-graph.js';
import { startRegistry, fixturePackage } from './fixtures/registry.js';

const findingId = 'CVE-2026-saved-plan';
const resolutionId = `${fixturePackage}@1.0.0`;
const motivation = { packageNames: [fixturePackage], findingIds: [findingId], resolutionIds: [resolutionId] };
const dependencyAction = (values = {}) => ({
  type: 'update-dependency', file: 'package.json', section: 'dependencies', package: fixturePackage,
  expectedRange: '1.0.0', targetRange: '1.0.1', ...motivation, ...values,
});
const overrideAction = (values = {}) => ({
  type: 'set-override', file: 'package.json', package: fixturePackage,
  scope: ['unused-parent'], expectedValue: null, targetVersion: '1.0.1', ...motivation, ...values,
});

function finding(id = findingId, vulnerableRange = '<1.0.1', firstPatchedVersion = '1.0.1') {
  return {
    id, cves: [], title: `${id} vulnerability`, severity: 'high', url: null,
    constraints: [{ vulnerableRange, firstPatchedVersion }], references: [],
  };
}

function unresolvedPackage(packageName, status, findingKey) {
  return {
    packageName, installedVersions: [], status, summary: `Unresolved ${packageName}.`, reasons: ['No executable target.'],
    resolutions: [], findings: [finding(findingKey)], risk: { fixType: 'unknown', breaking: null, reasons: [] },
  };
}

function branchPlan(actions = [dependencyAction()], packageValues = {}) {
  const { targetVersion = '1.0.1', findings = [finding()], instances = [{
    location: `node_modules/${fixturePackage}`,
    incoming: [{ parentName: 'fixture-app', parentVersion: '1.0.0', parentLocation: '',
      requestedRange: '1.0.0', effectiveRange: '1.0.0', type: 'prod' }],
    origins: [{ packageJsonPath: 'package.json', section: 'dependencies', workspace: null,
      chain: [{ name: fixturePackage, version: '1.0.0', location: `node_modules/${fixturePackage}`, requiredRange: '1.0.0' }] }],
  }], ...packageFields } = packageValues;
  const strategy = actions.some((action) => action.type === 'set-override') ? 'package-override'
    : actions.some((action) => action.type === 'update-dependency') ? 'bump-direct' : 'lockfile-update';
  return {
    branch: 'main', baseCommit: 'a'.repeat(40), status: actions.length ? 'ready' : 'no-op',
    summary: 'Apply saved fixture fixes.', blockers: [], actions,
    packages: actions.length ? [{
      packageName: fixturePackage, installedVersions: ['1.0.0'], status: 'ready',
      summary: 'Update fixture package.', reasons: [],
      resolutions: [{
        id: resolutionId, installedVersion: '1.0.0', line: '1.0', status: 'ready', targetVersion, strategy,
        findingIds: findings.map((entry) => entry.id), reasons: [], instances,
      }],
      findings, risk: { fixType: 'unknown', breaking: null, reasons: [] },
      ...packageFields,
    }] : [],
  };
}
function writeJson(directory, file, value, indentation = 2) {
  const absolute = path.join(directory, file);
  fs.mkdirSync(path.dirname(absolute), { recursive: true });
  const raw = JSON.stringify(value, null, indentation) + '\n';
  fs.writeFileSync(absolute, raw);
  return raw;
}
function manifest(values = {}) {
  return { name: 'fixture-app', version: '1.0.0', dependencies: { [fixturePackage]: '1.0.0' }, ...values };
}
function packageLock(version = '1.0.0', range = '1.0.0') {
  return {
    name: 'fixture-app', version: '1.0.0', lockfileVersion: 3,
    packages: {
      '': { name: 'fixture-app', version: '1.0.0', dependencies: { [fixturePackage]: range } },
      [`node_modules/${fixturePackage}`]: { version },
    },
  };
}

function savedInstances(pkgJson, pkgLock, workspaces = []) {
  const dependencyInventory = buildDependencyInventory({
    pkgJson,
    pkgLock,
    workspaces: workspaces.map(([relativePath, workspaceJson]) => ({ relativePath, pkgJson: workspaceJson })),
  });
  return getPackageInstances(fixturePackage, { dependencyInventory })
    .map(({ installedVersion: _installedVersion, ...instance }) => instance);
}

function temporary(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'remediator-plan-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

// This legacy manifest helper remains a consumer of Arborist-generated suggestions,
// but the runtime below accepts only canonical saved branch actions.
test('manifest helper preserves direct, workspace, override, and indentation behavior', (t) => {
  const directory = temporary(t);
  writeJson(directory, 'package.json', {
    name: 'monorepo', version: '1.0.0', workspaces: ['packages/*'],
    dependencies: { lodash: '^4.17.15' }, devDependencies: { mocha: '^8.0.0' },
  }, 4);
  writeJson(directory, 'packages/ui/package.json', {
    name: '@monorepo/ui', version: '1.0.0', dependencies: { 'js-yaml': '^4.1.0' },
  });
  assert.equal(detectIndentation('{\n  "name": "foo"\n}'), '  ');
  assert.equal(detectIndentation('{\n    "name": "foo"\n}'), '    ');
  assert.equal(findWorkspacePackageJsons(directory).length, 2);
  assert.equal(getDirectDependencies(JSON.parse(fs.readFileSync(path.join(directory, 'package.json'))), directory)
    .get('js-yaml').packageJsonPath, 'packages/ui/package.json');
  const { applied, pkgJson, touchedFiles } = updatePackageJsonFile(directory, [
    { package: 'lodash', section: 'dependencies', to: '^4.17.21' },
    { package: 'mocha', section: 'devDependencies', to: '^10.0.0' },
    { package: 'semver', section: 'overrides', to: '7.5.4' },
    { package: 'js-yaml', section: 'dependencies', to: '^4.3.2', packageJsonPath: 'packages/ui/package.json' },
  ]);
  assert.equal(applied.length, 4);
  assert.equal(pkgJson.dependencies.lodash, '^4.17.21');
  assert.equal(pkgJson.devDependencies.mocha, '^10.0.0');
  assert.equal(pkgJson.overrides.semver, '7.5.4');
  assert.deepEqual(touchedFiles.sort(), ['package.json', 'packages/ui/package.json']);
  assert.match(fs.readFileSync(path.join(directory, 'package.json'), 'utf8'), /\n {4}"name"/);
  assert.equal(JSON.parse(fs.readFileSync(path.join(directory, 'packages/ui/package.json'))).dependencies['js-yaml'], '^4.3.2');
});

test('saved-plan dry-run is unverified, discloses unresolved findings, and never writes', async (t) => {
  const directory = temporary(t);
  const raw = writeJson(directory, 'package.json', manifest());
  const rawLock = writeJson(directory, 'package-lock.json', packageLock());
  const plan = branchPlan();
  plan.packages.push(unresolvedPackage('unpatched', 'no-fix', 'CVE-unpatched'));
  const result = await executeBranchPlan(directory, plan, { dryRun: true });
  assert.equal(result.dryRun, true);
  assert.equal(result.verified, false);
  assert.equal(result.isClean, false);
  assert.deepEqual(result.resolved, []);
  assert.deepEqual(result.remaining, []);
  assert.deepEqual(result.touchedFiles, []);
  assert.equal(result.appliedChanges[0].package, fixturePackage);
  assert.deepEqual(result.unresolved.map((pkg) => pkg.packageName), [fixturePackage, 'unpatched']);
  assert.equal(result.postAuditSummary, null);
  assert.equal(fs.readFileSync(path.join(directory, 'package.json'), 'utf8'), raw);
  assert.equal(fs.readFileSync(path.join(directory, 'package-lock.json'), 'utf8'), rawLock);
});

test('every saved action is validated before the first manifest or lockfile write', async (t) => {
  const directory = temporary(t);
  const raw = writeJson(directory, 'package.json', manifest());
  const lock = writeJson(directory, 'package-lock.json', { untouched: true });
  const invalid = dependencyAction({ file: 'packages/missing/package.json' });
  await assert.rejects(executeBranchPlan(directory, branchPlan([dependencyAction(), invalid])));
  assert.equal(fs.readFileSync(path.join(directory, 'package.json'), 'utf8'), raw);
  assert.equal(fs.readFileSync(path.join(directory, 'package-lock.json'), 'utf8'), lock);
});

test('dependency preconditions are exact and never search another section or add declarations', (t) => {
  const directory = temporary(t);
  const raw = writeJson(directory, 'package.json', manifest({ devDependencies: { [fixturePackage]: '^1.0.0' } }));
  assert.throws(() => validateBranchActions(directory, branchPlan([
    dependencyAction({ section: 'devDependencies', expectedRange: '1.0.0' }),
  ])), /does not match a direct installed origin/);
  assert.throws(() => validateBranchActions(directory, branchPlan([
    dependencyAction({ section: 'optionalDependencies' }),
  ])), /does not match a direct installed origin/);
  assert.throws(() => validateBranchActions(directory, branchPlan([
    dependencyAction({ expectedRange: '^1.0.0' }),
  ])), /precondition conflict/);
  assert.equal(fs.readFileSync(path.join(directory, 'package.json'), 'utf8'), raw);
});

test('override policy, selectors, and direct-origin constraints reject before writes', async (t) => {
  const directory = temporary(t);
  let raw = writeJson(directory, 'package.json', manifest());
  await assert.rejects(executeBranchPlan(directory, branchPlan([dependencyAction(), overrideAction()]), { allowOverrides: false }), /overrides are disabled/);
  assert.equal(fs.readFileSync(path.join(directory, 'package.json'), 'utf8'), raw);
  for (const key of ['__proto__', 'constructor', 'prototype']) {
    assert.throws(() => validateBranchActions(directory, branchPlan([overrideAction({ scope: [key] })])), /Invalid override/);
    assert.throws(() => validateBranchActions(directory, branchPlan([overrideAction({ package: key })])), /Invalid override/);
    assert.throws(() => validateBranchActions(directory, branchPlan([dependencyAction({ package: key })])), /Invalid dependency/);
  }
  raw = writeJson(directory, 'package.json', manifest());
  assert.throws(() => validateBranchActions(directory, branchPlan([overrideAction()])), /Invalid override action scope/);
  assert.equal(fs.readFileSync(path.join(directory, 'package.json'), 'utf8'), raw);
});

test('all action shapes, traversal paths, conflicting duplicates, and blocked plans reject', (t) => {
  const directory = temporary(t);
  writeJson(directory, 'package.json', manifest());
  for (const file of ['../package.json', '/tmp/package.json', 'packages/../package.json', 'packages\\package.json', 'C:/package.json', './package.json', 'other.json']) {
    assert.throws(() => validateBranchActions(directory, branchPlan([dependencyAction({ file })])));
  }
  for (const action of [dependencyAction({ type: 'run-command' }), dependencyAction({ command: 'npm install' }),
    dependencyAction({ section: 'scripts' }), dependencyAction({ targetRange: 'not-a-range' }),
    dependencyAction({ findingIds: ['unknown-finding'] }), dependencyAction({ packageNames: ['unknown-package'] })]) {
    assert.throws(() => validateBranchActions(directory, branchPlan([action])));
  }
  assert.throws(() => validateBranchActions(directory, branchPlan([dependencyAction({ package: 'parent' })])),
    /does not match a direct installed origin/);
  for (const packageName of ['--registry=https://attacker.invalid', '-g', '--ignore-scripts=false']) {
    assert.throws(() => validateBranchActions(directory, branchPlan([
      { type: 'update-lockfile', package: packageName, ...motivation },
    ])), /Invalid lockfile update package/);
  }
  assert.throws(() => validateBranchActions(directory, branchPlan([dependencyAction(), dependencyAction({ targetRange: '1.0.2' })])), /Duplicate action|precondition conflict/);
  assert.throws(() => validateBranchActions(directory, { ...branchPlan(), status: 'blocked', blockers: ['rescan'] }), /blocked branch plan/);
});

test('manifest and lockfile symlinks cannot escape the worktree', async (t) => {
  const directory = temporary(t);
  const outside = temporary(t);
  const raw = writeJson(directory, 'package.json', manifest());
  const outsideRaw = writeJson(outside, 'package.json', manifest());
  fs.symlinkSync(outside, path.join(directory, 'outside'));
  await assert.rejects(executeBranchPlan(directory, branchPlan([
    dependencyAction(), dependencyAction({ file: 'outside/package.json' }),
  ])), /symlink escapes worktree/);
  assert.equal(fs.readFileSync(path.join(directory, 'package.json'), 'utf8'), raw);
  assert.equal(fs.readFileSync(path.join(outside, 'package.json'), 'utf8'), outsideRaw);
  const outsideLock = writeJson(outside, 'package-lock.json', { untouched: true });
  fs.symlinkSync(path.join(outside, 'package-lock.json'), path.join(directory, 'package-lock.json'));
  await assert.rejects(executeBranchPlan(directory, branchPlan()), /symlink escapes worktree/);
  assert.equal(fs.readFileSync(path.join(outside, 'package-lock.json'), 'utf8'), outsideLock);
});

test('reuse accepts only applied values and direct dependencies cannot receive transitive overrides', (t) => {
  const directory = temporary(t);
  writeJson(directory, 'package.json', manifest());
  assert.throws(() => validateBranchActions(directory, branchPlan(), { reuse: true }), /precondition conflict/);
  writeJson(directory, 'package.json', manifest({ dependencies: { [fixturePackage]: '1.0.1' } }));
  writeJson(directory, 'package-lock.json', packageLock('1.0.1', '1.0.1'));
  assert.doesNotThrow(() => validateBranchActions(directory, branchPlan(), { reuse: true }));
  assert.throws(() => validateBranchActions(directory, branchPlan()), /precondition conflict/);
  writeJson(directory, 'package.json', manifest());
  writeJson(directory, 'package-lock.json', packageLock());
  assert.throws(() => validateBranchActions(directory, branchPlan([
    dependencyAction({ targetRange: '~1.0.1' }), overrideAction({ scope: [] }),
  ])), /Invalid override action scope/);
});

test('saved plans verify physical resolution origins before execution', (t) => {
  const directory = temporary(t);
  const raw = writeJson(directory, 'package.json', manifest());
  writeJson(directory, 'package-lock.json', packageLock());
  const plan = branchPlan();
  assert.doesNotThrow(() => validateBranchActions(directory, plan));

  const alteredOrigin = structuredClone(plan);
  alteredOrigin.packages[0].resolutions[0].instances[0].origins[0].chain[0].requiredRange = '^1.0.0';
  assert.throws(() => validateBranchActions(directory, alteredOrigin), /Resolution baseline differs/);

  writeJson(directory, 'package-lock.json', packageLock('1.0.2'));
  assert.throws(() => validateBranchActions(directory, plan), /Resolution baseline differs/);
  assert.equal(fs.readFileSync(path.join(directory, 'package.json'), 'utf8'), raw);
});

test('override actions must match recorded transitive origins and exact preconditions', (t) => {
  const directory = temporary(t);
  const pkgJson = { name: 'fixture-app', version: '1.0.0', dependencies: { parent: '1.0.0' } };
  const lock = {
    name: 'fixture-app', version: '1.0.0', lockfileVersion: 3,
    packages: {
      '': { name: 'fixture-app', version: '1.0.0', dependencies: { parent: '1.0.0' } },
      'node_modules/parent': { version: '1.0.0', dependencies: { [fixturePackage]: '1.0.0' } },
      [`node_modules/parent/node_modules/${fixturePackage}`]: { version: '1.0.0' },
    },
  };
  const raw = writeJson(directory, 'package.json', pkgJson);
  writeJson(directory, 'package-lock.json', lock);
  const action = overrideAction({ package: `${fixturePackage}@1.0.x`, scope: ['parent@1.0.0'] });
  const plan = branchPlan([action], { instances: savedInstances(pkgJson, lock) });
  assert.doesNotThrow(() => validateBranchActions(directory, plan));

  const altered = structuredClone(plan);
  altered.actions[0].scope = ['unrelated-parent@1.0.0'];
  assert.throws(() => validateBranchActions(directory, altered), /Invalid override action scope/);
  const selector = `${fixturePackage}@1.0.x`;
  writeJson(directory, 'package.json', { ...pkgJson, overrides: { 'parent@1.0.0': { [selector]: null } } });
  assert.throws(() => validateBranchActions(directory, plan), /precondition conflict/);
  writeJson(directory, 'package.json', { ...pkgJson, overrides: { 'parent@1.0.0': '1.0.0' } });
  assert.throws(() => validateBranchActions(directory, plan), /Override scope is not an object/);
  writeJson(directory, 'package.json', pkgJson);
  assert.equal(fs.readFileSync(path.join(directory, 'package.json'), 'utf8'), raw);
});

test('real npm executes root/workspace actions, ignores lifecycle scripts, and re-audits reuse', async (t) => {
  const directory = temporary(t);
  const registry = await startRegistry(path.join(directory, 'registry'));
  const previous = Object.fromEntries(Object.keys(registry.env).map((key) => [key, process.env[key]]));
  Object.assign(process.env, registry.env);
  try {
    const repo = path.join(directory, 'repo');
    const rootManifest = manifest({ workspaces: ['packages/*'], scripts: {
      preinstall: 'node -e "require(\'fs\').writeFileSync(\'script-ran\', \'unsafe\')"',
    } });
    writeJson(repo, 'package.json', rootManifest, 4);
    const uiManifest = { name: 'fixture-ui', version: '1.0.0', devDependencies: { [fixturePackage]: '1.0.0' } };
    writeJson(repo, 'packages/ui/package.json', uiManifest);
    const untouched = writeJson(repo, 'packages/untouched/package.json', { name: 'untouched', version: '1.0.0' }, '\t');
    const initialLock = registry.packageLock();
    writeJson(repo, 'package-lock.json', initialLock);
    const instances = savedInstances(rootManifest, initialLock, [['packages/ui/package.json', uiManifest]]);
    const plan = branchPlan([
      dependencyAction(),
      dependencyAction({ file: 'packages/ui/package.json', section: 'devDependencies' }),
    ], { instances });
    plan.packages.push(unresolvedPackage('no-upstream-fix', 'no-fix', 'CVE-unpatched'));
    const options = { githubApiUrl: `${registry.url}/github` };
    const result = await executeBranchPlan(repo, plan, options);
    assert.equal(result.verified, true);
    assert.equal(result.isClean, false);
    assert.deepEqual(result.remaining, []);
    assert.deepEqual(result.resolved[0].installedVersions, ['1.0.1']);
    assert.equal(result.unresolved[0].packageName, 'no-upstream-fix');
    assert.deepEqual(result.touchedFiles.sort(), ['package-lock.json', 'package.json', 'packages/ui/package.json']);
    const root = JSON.parse(fs.readFileSync(path.join(repo, 'package.json')));
    const ui = JSON.parse(fs.readFileSync(path.join(repo, 'packages/ui/package.json')));
    assert.equal(root.dependencies[fixturePackage], '1.0.1');
    assert.equal(ui.devDependencies[fixturePackage], '1.0.1');
    assert.equal(root.overrides, undefined);
    assert.equal(fs.readFileSync(path.join(repo, 'packages/untouched/package.json'), 'utf8'), untouched);
    assert.match(fs.readFileSync(path.join(repo, 'package.json'), 'utf8'), /\n {4}"name"/);
    assert.equal(fs.existsSync(path.join(repo, 'script-ran')), false);
    assert.equal(fs.existsSync(path.join(repo, 'node_modules')), false);
    const lock = fs.readFileSync(path.join(repo, 'package-lock.json'), 'utf8');
    const reused = await executeBranchPlan(repo, plan, { ...options, reuse: true });
    assert.equal(reused.verified, true);
    assert.deepEqual(reused.touchedFiles, []);
    assert.equal(fs.readFileSync(path.join(repo, 'package-lock.json'), 'utf8'), lock);
    registry.state.failAudit = true;
    await assert.rejects(executeBranchPlan(repo, plan, { ...options, reuse: true }), /npm audit failed/i);
    assert.equal(fs.readFileSync(path.join(repo, 'package-lock.json'), 'utf8'), lock);
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
    await registry.close();
  }
});

test('real npm lockfile-only remediation uses no temporary overrides and preserves the manifest', async (t) => {
  const directory = temporary(t);
  const registry = await startRegistry(path.join(directory, 'registry'));
  const previous = Object.fromEntries(Object.keys(registry.env).map((key) => [key, process.env[key]]));
  Object.assign(process.env, registry.env);
  try {
    const repo = path.join(directory, 'repo');
    const pkgJson = manifest({ dependencies: { [fixturePackage]: '^1.0.0' } });
    const raw = writeJson(repo, 'package.json', pkgJson, '\t');
    const lock = registry.packageLock();
    lock.packages[''].dependencies[fixturePackage] = '^1.0.0';
    writeJson(repo, 'package-lock.json', lock);
    const plan = branchPlan([{ type: 'update-lockfile', package: fixturePackage, ...motivation }],
      { instances: savedInstances(pkgJson, lock) });
    const result = await executeBranchPlan(repo, plan, { allowOverrides: false, githubApiUrl: `${registry.url}/github` });
    assert.equal(result.verified, true);
    assert.equal(result.isClean, true);
    assert.deepEqual(result.appliedChanges, []);
    assert.deepEqual(result.lockfileUpdates, [fixturePackage]);
    assert.deepEqual(result.touchedFiles, ['package-lock.json']);
    assert.deepEqual(result.resolved[0].installedVersions, ['1.0.1']);
    assert.equal(fs.readFileSync(path.join(repo, 'package.json'), 'utf8'), raw);
    assert.equal(JSON.parse(fs.readFileSync(path.join(repo, 'package.json'))).overrides, undefined);
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
    await registry.close();
  }
});
test('execution rejects safe but unapproved versions selected after the scan', async (t) => {
  const directory = temporary(t);
  const registry = await startRegistry(path.join(directory, 'registry'), { versions: ['1.0.0', '1.0.1', '1.0.2'] });
  const previous = Object.fromEntries(Object.keys(registry.env).map((key) => [key, process.env[key]]));
  Object.assign(process.env, registry.env);
  try {
    const repo = path.join(directory, 'repo');
    writeJson(repo, 'package.json', manifest());
    writeJson(repo, 'package-lock.json', registry.packageLock());
    const plan = branchPlan([dependencyAction({ targetRange: '~1.0.1' })]);
    await assert.rejects(executeBranchPlan(repo, plan, { githubApiUrl: `${registry.url}/github` }),
      /outside the approved resolution targets \(1\.0\.1\)/);
    const lock = JSON.parse(fs.readFileSync(path.join(repo, 'package-lock.json'), 'utf8'));
    assert.equal(lock.packages[`node_modules/${fixturePackage}`].version, '1.0.2');
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
    await registry.close();
  }
});

test('execution requires every ready line target to remain represented after lockfile resolution', async (t) => {
  const directory = temporary(t);
  const registry = await startRegistry(path.join(directory, 'registry'), {
    packageNames: [fixturePackage, 'holder'],
    versions: ['1.0.0', '1.0.1', '1.1.0', '1.1.1'],
    dependenciesByPackage: { holder: { [fixturePackage]: '^1.0.0' } },
    vulnerablePackages: [fixturePackage],
  });
  const previous = Object.fromEntries(Object.keys(registry.env).map((key) => [key, process.env[key]]));
  Object.assign(process.env, registry.env);
  try {
    const repo = path.join(directory, 'repo');
    const pkgJson = manifest({ dependencies: { [fixturePackage]: '^1.0.0', holder: '1.0.0' } });
    writeJson(repo, 'package.json', pkgJson);
    const lock = registry.packageLock();
    lock.packages[''].dependencies[fixturePackage] = '^1.0.0';
    lock.packages['node_modules/holder/node_modules/security-report-fixture'] = { version: '1.1.0' };
    writeJson(repo, 'package-lock.json', lock);
    const physical = getPackageInstances(fixturePackage, {
      dependencyInventory: buildDependencyInventory({ pkgJson, pkgLock: lock }),
    });
    const instancesByVersion = new Map(physical.map(({ installedVersion, ...instance }) => [installedVersion, instance]));
    const first = finding('CVE-first-line', '<1.0.1', '1.0.1');
    const second = finding('CVE-second-line', '>=1.1.0 <1.1.1', '1.1.1');
    const firstResolutionId = `${fixturePackage}@1.0.0`;
    const secondResolutionId = `${fixturePackage}@1.1.0`;
    const plan = branchPlan([{
      type: 'update-lockfile', package: fixturePackage, packageNames: [fixturePackage],
      findingIds: [first.id, second.id], resolutionIds: [firstResolutionId, secondResolutionId],
    }], {
      findings: [first, second],
      installedVersions: ['1.0.0', '1.1.0'],
      resolutions: [
        { id: firstResolutionId, installedVersion: '1.0.0', line: '1.0', status: 'ready', targetVersion: '1.0.1',
          strategy: 'lockfile-update', findingIds: [first.id], reasons: [], instances: [instancesByVersion.get('1.0.0')] },
        { id: secondResolutionId, installedVersion: '1.1.0', line: '1.1', status: 'ready', targetVersion: '1.1.1',
          strategy: 'lockfile-update', findingIds: [second.id], reasons: [], instances: [instancesByVersion.get('1.1.0')] },
      ],
    });
    await assert.rejects(executeBranchPlan(repo, plan, { githubApiUrl: `${registry.url}/github` }),
      /approved target 1\.0\.1 .* is absent from the installed dependency graph/);
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
    await registry.close();
  }
});


test('real audit cannot resolve a planned package by different advisory ID or rewrite a no-op lockfile', async (t) => {
  const directory = temporary(t);
  const registry = await startRegistry(path.join(directory, 'registry'));
  const previous = Object.fromEntries(Object.keys(registry.env).map((key) => [key, process.env[key]]));
  Object.assign(process.env, registry.env);
  try {
    const repo = path.join(directory, 'repo');
    const raw = writeJson(repo, 'package.json', manifest());
    const lock = writeJson(repo, 'package-lock.json', registry.packageLock(), '\t');
    const plan = branchPlan([dependencyAction({ targetRange: '1.0.0' })], {
      targetVersion: '1.0.0', findings: [finding(findingId, '<1.0.0', '1.0.0')],
    });
    const options = { githubApiUrl: `${registry.url}/github` };
    await assert.rejects(executeBranchPlan(repo, plan, options), /npm audit still reports planned package/);
    assert.equal(fs.readFileSync(path.join(repo, 'package.json'), 'utf8'), raw);
    assert.equal(fs.readFileSync(path.join(repo, 'package-lock.json'), 'utf8'), lock);
    const noOp = branchPlan([]);
    noOp.packages.push(unresolvedPackage(fixturePackage, 'manual-review', findingId));
    const result = await executeBranchPlan(repo, noOp, options);
    assert.equal(result.verified, true);
    assert.equal(result.resolved.length, 0);
    assert.equal(result.unresolved.length, 1);
    assert.equal(result.remaining[0].packageName, fixturePackage);
    assert.equal(result.isClean, false);
    assert.equal(fs.readFileSync(path.join(repo, 'package-lock.json'), 'utf8'), lock);
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
    await registry.close();
  }
});

test('all installed instances and every finding major-line patch floor must verify', async (t) => {
  const directory = temporary(t);
  const registry = await startRegistry(path.join(directory, 'registry'));
  const previous = Object.fromEntries(Object.keys(registry.env).map((key) => [key, process.env[key]]));
  Object.assign(process.env, registry.env);
  try {
    const repo = path.join(directory, 'repo');
    const pkgJson = manifest({ dependencies: { [fixturePackage]: '1.0.1', holder: '1.0.0' } });
    writeJson(repo, 'package.json', pkgJson);
    const lock = registry.packageLock();
    lock.packages[''].dependencies = { [fixturePackage]: '1.0.1', holder: '1.0.0' };
    lock.packages[`node_modules/${fixturePackage}`] = { version: '1.0.1' };
    lock.packages['node_modules/holder'] = { version: '1.0.0', dependencies: { [fixturePackage]: '1.0.0' } };
    lock.packages[`node_modules/holder/node_modules/${fixturePackage}`] = registry.packageLock().packages[`node_modules/${fixturePackage}`];
    writeJson(repo, 'package-lock.json', lock);
    const instances = savedInstances(pkgJson, lock);
    await assert.rejects(executeBranchPlan(repo, branchPlan(undefined, { instances }), { reuse: true, githubApiUrl: `${registry.url}/github` }),
      /Resolution baseline differs/);
    writeJson(repo, 'package.json', manifest());
    writeJson(repo, 'package-lock.json', registry.packageLock());
    const first = finding(findingId, null, '1.0.0');
    const second = finding('CVE-second-major-line', null, '1.0.2');
    const plan = branchPlan([dependencyAction({ targetRange: '1.0.1', findingIds: [findingId, second.id] })], { findings: [first, second] });
    await assert.rejects(executeBranchPlan(repo, plan, { githubApiUrl: `${registry.url}/github` }), /not proven safe against every package finding/);
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
    await registry.close();
  }
});

test('no-breaking guard rejects an incompatible npm resolution even when the intended patch is safe', async (t) => {
  const directory = temporary(t);
  const registry = await startRegistry(path.join(directory, 'registry'), { versions: ['1.0.0', '1.0.1', '2.0.0'] });
  const previous = Object.fromEntries(Object.keys(registry.env).map((key) => [key, process.env[key]]));
  Object.assign(process.env, registry.env);
  try {
    const repo = path.join(directory, 'repo');
    const pkgJson = manifest({ dependencies: { [fixturePackage]: '*' } });
    const raw = writeJson(repo, 'package.json', pkgJson);
    const lock = registry.packageLock();
    lock.packages[''].dependencies[fixturePackage] = '*';
    writeJson(repo, 'package-lock.json', lock);
    const plan = branchPlan([{ type: 'update-lockfile', package: fixturePackage, ...motivation }],
      { instances: savedInstances(pkgJson, lock) });
    await assert.rejects(
      executeBranchPlan(repo, plan, { allowBreaking: false, githubApiUrl: `${registry.url}/github` }),
      /No-breaking verification failed/,
    );
    assert.equal(JSON.parse(fs.readFileSync(path.join(repo, 'package-lock.json'))).packages[`node_modules/${fixturePackage}`].version, '2.0.0');
    assert.equal(fs.readFileSync(path.join(repo, 'package.json'), 'utf8'), raw);
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
    await registry.close();
  }
});
