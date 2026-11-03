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
import { findWorkspacePackageJsons, getDirectDependencies } from '../src/core/dependency-graph.js';
import { startRegistry, fixturePackage } from './fixtures/registry.js';

const findingId = 'CVE-2026-saved-plan';
const motivation = { packageNames: [fixturePackage], findingIds: [findingId] };
const dependencyAction = (values = {}) => ({
  type: 'update-dependency', file: 'package.json', section: 'dependencies', package: fixturePackage,
  expectedRange: '1.0.0', targetRange: '1.0.1', ...motivation, ...values,
});
const overrideAction = (values = {}) => ({
  type: 'set-override', file: 'package.json', package: fixturePackage,
  scope: ['unused-parent'], expectedValue: null, targetVersion: '1.0.1', ...motivation, ...values,
});
function branchPlan(actions = [dependencyAction()], packageValues = {}) {
  return {
    branch: 'main', baseCommit: 'a'.repeat(40), status: actions.length ? 'ready' : 'no-op',
    summary: 'Apply saved fixture fixes.', blockers: [], actions,
    packages: actions.length ? [{
      packageName: fixturePackage, currentVersion: '1.0.0', installedVersions: ['1.0.0'],
      targetSafeVersion: '1.0.1', status: 'ready', reasons: [], dependencyPaths: [], actions,
      findings: [{ id: findingId, cve: findingId, vulnerableVersionRange: '<1.0.1',
        targetSafeVersion: '1.0.1', patchedVersions: ['1.0.1'] }],
      ...packageValues,
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
  const plan = branchPlan();
  plan.packages.push({ packageName: 'unpatched', status: 'no-fix', findings: [{ id: 'CVE-unpatched' }] });
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
  assert.equal(fs.existsSync(path.join(directory, 'package-lock.json')), false);
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
  ])), /precondition conflict/);
  assert.throws(() => validateBranchActions(directory, branchPlan([
    dependencyAction({ section: 'optionalDependencies' }),
  ])), /Missing declaration/);
  assert.throws(() => validateBranchActions(directory, branchPlan([
    dependencyAction({ expectedRange: '^1.0.0' }),
  ])), /precondition conflict/);
  assert.equal(fs.readFileSync(path.join(directory, 'package.json'), 'utf8'), raw);
});

test('override policy, exact missing values, scalar scopes, and dangerous keys reject before writes', async (t) => {
  const directory = temporary(t);
  let raw = writeJson(directory, 'package.json', manifest());
  await assert.rejects(executeBranchPlan(directory, branchPlan([dependencyAction(), overrideAction()]), { allowOverrides: false }), /overrides are disabled/);
  assert.equal(fs.readFileSync(path.join(directory, 'package.json'), 'utf8'), raw);
  for (const key of ['__proto__', 'constructor', 'prototype']) {
    assert.throws(() => validateBranchActions(directory, branchPlan([overrideAction({ scope: [key] })])), /Invalid override/);
    assert.throws(() => validateBranchActions(directory, branchPlan([overrideAction({ package: key })])), /Invalid override/);
    assert.throws(() => validateBranchActions(directory, branchPlan([dependencyAction({ package: key })])), /Invalid dependency/);
  }
  raw = writeJson(directory, 'package.json', manifest({ overrides: { 'unused-parent': { [fixturePackage]: null } } }));
  assert.throws(() => validateBranchActions(directory, branchPlan([overrideAction()])), /precondition conflict/);
  assert.equal(fs.readFileSync(path.join(directory, 'package.json'), 'utf8'), raw);
  writeJson(directory, 'package.json', manifest({ overrides: { 'unused-parent': '1.0.0' } }));
  assert.throws(() => validateBranchActions(directory, branchPlan([overrideAction()])), /scope is not an object/);
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

test('reuse accepts only already-applied values and direct overrides cannot cause EOVERRIDE', (t) => {
  const directory = temporary(t);
  writeJson(directory, 'package.json', manifest());
  assert.throws(() => validateBranchActions(directory, branchPlan(), { reuse: true }), /precondition conflict/);
  writeJson(directory, 'package.json', manifest({ dependencies: { [fixturePackage]: '1.0.1' } }));
  assert.doesNotThrow(() => validateBranchActions(directory, branchPlan(), { reuse: true }));
  assert.throws(() => validateBranchActions(directory, branchPlan()), /precondition conflict/);
  writeJson(directory, 'package.json', manifest());
  assert.throws(() => validateBranchActions(directory, branchPlan([
    dependencyAction({ targetRange: '^1.0.1' }), overrideAction({ scope: [] }),
  ])), /EOVERRIDE/);
});

test('real npm executes root/workspace/override actions, ignores lifecycle scripts, and re-audits reuse', async (t) => {
  const directory = temporary(t);
  const registry = await startRegistry(path.join(directory, 'registry'));
  const previous = Object.fromEntries(Object.keys(registry.env).map((key) => [key, process.env[key]]));
  Object.assign(process.env, registry.env);
  try {
    const repo = path.join(directory, 'repo');
    writeJson(repo, 'package.json', manifest({ workspaces: ['packages/*'], scripts: {
      preinstall: 'node -e "require(\'fs\').writeFileSync(\'script-ran\', \'unsafe\')"',
    } }), 4);
    writeJson(repo, 'packages/ui/package.json', {
      name: 'fixture-ui', version: '1.0.0', devDependencies: { [fixturePackage]: '1.0.0' },
    });
    const untouched = writeJson(repo, 'packages/untouched/package.json', { name: 'untouched', version: '1.0.0' }, '\t');
    writeJson(repo, 'package-lock.json', registry.packageLock());
    const plan = branchPlan([
      dependencyAction(),
      dependencyAction({ file: 'packages/ui/package.json', section: 'devDependencies' }),
      overrideAction(),
    ]);
    plan.packages.push({ packageName: 'no-upstream-fix', status: 'no-fix', findings: [{ id: 'CVE-unpatched' }] });
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
    assert.equal(root.overrides['unused-parent'][fixturePackage], '1.0.1');
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
    const raw = writeJson(repo, 'package.json', manifest({ dependencies: { [fixturePackage]: '^1.0.0' } }), '\t');
    const lock = registry.packageLock();
    lock.packages[''].dependencies[fixturePackage] = '^1.0.0';
    writeJson(repo, 'package-lock.json', lock);
    const plan = branchPlan([{ type: 'update-lockfile', package: fixturePackage, ...motivation }]);
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
      targetSafeVersion: '1.0.0', findings: [{ id: findingId, vulnerableVersionRange: '<1.0.0',
        targetSafeVersion: '1.0.0', patchedVersions: ['1.0.0'] }],
    });
    const options = { githubApiUrl: `${registry.url}/github` };
    await assert.rejects(executeBranchPlan(repo, plan, options), /npm audit still reports planned package/);
    assert.equal(fs.readFileSync(path.join(repo, 'package.json'), 'utf8'), raw);
    assert.equal(fs.readFileSync(path.join(repo, 'package-lock.json'), 'utf8'), lock);
    const noOp = branchPlan([]);
    noOp.packages.push({ packageName: fixturePackage, status: 'manual-review', findings: [{ id: findingId }] });
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
    writeJson(repo, 'package.json', manifest({ dependencies: { [fixturePackage]: '1.0.1', holder: '1.0.0' } }));
    const lock = registry.packageLock();
    lock.packages[''].dependencies = { [fixturePackage]: '1.0.1', holder: '1.0.0' };
    lock.packages[`node_modules/${fixturePackage}`] = { version: '1.0.1' };
    lock.packages['node_modules/holder'] = { version: '1.0.0', dependencies: { [fixturePackage]: '1.0.0' } };
    lock.packages[`node_modules/holder/node_modules/${fixturePackage}`] = registry.packageLock().packages[`node_modules/${fixturePackage}`];
    writeJson(repo, 'package-lock.json', lock);
    await assert.rejects(executeBranchPlan(repo, branchPlan(), { reuse: true, githubApiUrl: `${registry.url}/github` }),
      /1\.0\.0.*remains vulnerable/);
    writeJson(repo, 'package.json', manifest());
    writeJson(repo, 'package-lock.json', registry.packageLock());
    const first = { id: findingId, vulnerableVersionRange: '<0.9.0', patchedVersions: ['1.0.0'] };
    const second = { id: 'CVE-second-major-line', vulnerableVersionRange: '<0.8.0', patchedVersions: ['1.0.1', '2.0.0'] };
    const plan = branchPlan([dependencyAction({ targetRange: '1.0.0' })], { findings: [first, second] });
    await assert.rejects(executeBranchPlan(repo, plan, { githubApiUrl: `${registry.url}/github` }), /safe patched major line/);
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
    const raw = writeJson(repo, 'package.json', manifest({ dependencies: { [fixturePackage]: '*' } }));
    const lock = registry.packageLock();
    lock.packages[''].dependencies[fixturePackage] = '*';
    writeJson(repo, 'package-lock.json', lock);
    const plan = branchPlan([{ type: 'update-lockfile', package: fixturePackage, ...motivation }]);
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
