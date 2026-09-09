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
