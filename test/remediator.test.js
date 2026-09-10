import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import {
  updatePackageJsonFile,
  detectIndentation,
  remediateBranch,
} from '../src/core/remediator.js';
import { findWorkspacePackageJsons, getDirectDependencies } from '../src/core/dependency-graph.js';
test('detectIndentation: detects 2 spaces and 4 spaces', () => {
  assert.equal(detectIndentation('{\n  "name": "foo"\n}'), '  ');
  assert.equal(detectIndentation('{\n    "name": "foo"\n}'), '    ');
});

test('updatePackageJsonFile: applies direct updates and overrides', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rem-test-'));
  try {
    const originalPkg = {
      name: 'sample-app',
      version: '1.0.0',
      dependencies: {
        express: '^4.17.1',
        lodash: '^4.17.15',
      },
      devDependencies: {
        mocha: '^8.0.0',
      },
    };

    fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify(originalPkg, null, 2) + '\n');

    const changes = [
      { package: 'lodash', section: 'dependencies', to: '^4.17.21' },
      { package: 'mocha', section: 'devDependencies', to: '^10.0.0' },
      { package: 'semver', section: 'overrides', to: '7.5.4' },
    ];

    const { applied, pkgJson } = updatePackageJsonFile(tmpDir, changes);
    assert.equal(applied.length, 3);
    assert.equal(pkgJson.dependencies.lodash, '^4.17.21');
    assert.equal(pkgJson.devDependencies.mocha, '^10.0.0');
    assert.equal(pkgJson.overrides.semver, '7.5.4');

    const reRead = JSON.parse(fs.readFileSync(path.join(tmpDir, 'package.json'), 'utf8'));
    assert.equal(reRead.dependencies.lodash, '^4.17.21');
    assert.equal(reRead.overrides.semver, '7.5.4');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('remediateBranch: dry-run mode', async () => {
  const branchReport = {
    branch: 'main',
    vulnerabilities: [
      {
        id: 'GHSA-test',
        packageName: 'lodash',
        severity: 'high',
        remediation: {
          strategy: 'bump-direct',
          packageJsonChanges: [{ package: 'lodash', section: 'dependencies', to: '^4.17.21' }],
        },
      },
    ],
  };

  const result = await remediateBranch('/dummy/path', branchReport, { dryRun: true });
  assert.equal(result.dryRun, true);
  assert.equal(result.appliedChanges.length, 1);
  assert.equal(result.appliedChanges[0].package, 'lodash');
});

test('remediateBranch: highest requested version wins and lockfile updates are collected', async () => {
  const branchReport = {
    branch: 'main',
    vulnerabilities: [
      {
        packageName: 'lodash',
        remediation: {
          strategy: 'bump-direct',
          packageJsonChanges: [{ package: 'lodash', section: 'dependencies', packageJsonPath: 'package.json', to: '^4.17.15' }],
          lockfileUpdates: [],
        },
      },
      {
        packageName: 'lodash',
        remediation: {
          strategy: 'bump-direct-and-lockfile',
          packageJsonChanges: [{ package: 'lodash', section: 'dependencies', packageJsonPath: 'package.json', to: '^4.17.21' }],
          lockfileUpdates: ['lodash'],
        },
      },
      {
        packageName: '@xmldom/xmldom',
        remediation: {
          strategy: 'lockfile-update',
          packageJsonChanges: [],
          lockfileUpdates: ['@xmldom/xmldom', 'lodash'],
        },
      },
    ],
  };

  const result = await remediateBranch('/dummy/path', branchReport, { dryRun: true });
  assert.equal(result.appliedChanges.length, 1);
  assert.equal(result.appliedChanges[0].to, '^4.17.21');
  assert.deepEqual(result.lockfileUpdates, ['lodash', '@xmldom/xmldom']);
});

test('updatePackageJsonFile: allowOverrides false suppresses overrides', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rem-no-overrides-'));
  try {
    fs.writeFileSync(
      path.join(tmpDir, 'package.json'),
      JSON.stringify({ name: 'sample-app', dependencies: { lodash: '^4.17.15' } }, null, 2) + '\n'
    );

    const { applied } = updatePackageJsonFile(
      tmpDir,
      [{ package: 'semver', section: 'overrides', to: '7.5.4' }],
      { allowOverrides: false }
    );

    assert.equal(applied.length, 0);
    const reRead = JSON.parse(fs.readFileSync(path.join(tmpDir, 'package.json'), 'utf8'));
    assert.equal(reRead.overrides, undefined);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('npm workspaces: discovers nested packages and updates workspace package.json', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ws-rem-test-'));
  try {
    // Root package.json with workspaces
    const rootPkg = {
      name: 'monorepo',
      version: '1.0.0',
      workspaces: ['packages/*'],
      devDependencies: {
        eslint: '^8.0.0',
      },
    };
    fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify(rootPkg, null, 2) + '\n');

    // Nested workspace: packages/ui
    const uiDir = path.join(tmpDir, 'packages', 'ui');
    fs.mkdirSync(uiDir, { recursive: true });
    const uiPkg = {
      name: '@monorepo/ui',
      version: '1.0.0',
      dependencies: {
        'js-yaml': '^4.1.0',
      },
    };
    fs.writeFileSync(path.join(uiDir, 'package.json'), JSON.stringify(uiPkg, null, 2) + '\n');

    // 1. Verify workspace discovery
    const workspaces = findWorkspacePackageJsons(tmpDir, rootPkg);
    assert.equal(workspaces.length, 2);
    assert.equal(workspaces[0].isRoot, true);
    assert.equal(workspaces[1].name, '@monorepo/ui');

    // 2. Verify direct dependencies across workspaces
    const directDeps = getDirectDependencies(rootPkg, tmpDir);
    assert.ok(directDeps.has('eslint'));
    assert.ok(directDeps.has('js-yaml'));
    assert.equal(directDeps.get('js-yaml').workspace, '@monorepo/ui');
    assert.equal(directDeps.get('js-yaml').packageJsonPath, 'packages/ui/package.json');

    // 3. Update dependency in nested workspace
    const changes = [
      { package: 'js-yaml', section: 'dependencies', to: '^4.3.2', packageJsonPath: 'packages/ui/package.json' },
    ];
    const { applied } = updatePackageJsonFile(tmpDir, changes);
    assert.equal(applied.length, 1);
    assert.equal(applied[0].packageJsonPath, 'packages/ui/package.json');

    const updatedUiPkg = JSON.parse(fs.readFileSync(path.join(uiDir, 'package.json'), 'utf8'));
    assert.equal(updatedUiPkg.dependencies['js-yaml'], '^4.3.2');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
