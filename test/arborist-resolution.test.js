import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import {
  getArboristClass,
  loadArboristTree,
  lookupPackageInstalledInfo,
  traceArboristChains,
  findDirectRootsFromArborist,
} from '../src/core/dependency-graph.js';
import {
  canBeResolvedInLockfile,
  buildRemediationSuggestion,
  determinePatchedVersions,
  determineSafeVersion,
} from '../src/collectors/npm-audit.js';
import {
  updatePackageJsonFile,
} from '../src/core/remediator.js';
import {
  formatTargetFix,
  formatTransitiveDependencyPaths,
  generateMarkdownReport,
} from '../src/report/markdown-reporter.js';

test('getArboristClass: loads Arborist from local dependencies or npm global', () => {
  const Arb = getArboristClass();
  assert.ok(Arb, 'Arborist class should be successfully resolved');
  assert.equal(typeof Arb, 'function');
});

test('Scenario 1: Direct Dependency (bump-direct)', async () => {
  const pkgJson = {
    name: 'test-app',
    dependencies: {
      lodash: '^4.17.15',
    },
  };
  const pkgLock = {
    name: 'test-app',
    lockfileVersion: 2,
    packages: {
      '': { dependencies: { lodash: '^4.17.15' } },
      'node_modules/lodash': { version: '4.17.15' },
    },
  };

  const tree = await loadArboristTree({ pkgJson, pkgLock });
  assert.ok(tree, 'virtual tree loaded');
  const info = lookupPackageInstalledInfo('lodash', pkgJson, pkgLock, null, null, tree);

  assert.equal(info.isDirect, true);
  assert.equal(info.isIndirect, false);
  assert.equal(info.dependencyType, 'Direct');

  const vuln = {
    packageName: 'lodash',
    isDirect: info.isDirect,
    isIndirect: info.isIndirect,
    dependencyType: info.dependencyType,
    currentVersion: info.currentVersion,
    targetSafeVersion: '4.17.21',
    workspaceDeclarations: info.workspaceDeclarations,
  };

  const rem = buildRemediationSuggestion(vuln, info.directRoots, pkgJson, info.chains, info.directInfo, null, tree);
  assert.equal(rem.strategy, 'bump-direct');
  assert.equal(rem.packageJsonChanges.length, 1);
  assert.equal(rem.packageJsonChanges[0].package, 'lodash');
  assert.equal(rem.packageJsonChanges[0].to, '^4.17.21');
  assert.equal(rem.packageJsonChanges[0].packageJsonPath, 'package.json');
});

test('Scenario 2: Dual Direct & Indirect (bump-direct-and-lockfile)', async () => {
  const pkgJson = {
    name: 'test-app',
    dependencies: {
      'js-yaml': '^4.1.0',
      tool: '^1.0.0',
    },
  };
  const pkgLock = {
    name: 'test-app',
    lockfileVersion: 2,
    packages: {
      '': {
        dependencies: {
          'js-yaml': '^4.1.0',
          tool: '^1.0.0',
        },
      },
      'node_modules/js-yaml': { version: '4.1.0' },
      'node_modules/tool': { version: '1.0.0', dependencies: { 'js-yaml': '^3.14.1' } },
      'node_modules/tool/node_modules/js-yaml': { version: '3.14.1' },
    },
  };

  const tree = await loadArboristTree({ pkgJson, pkgLock });
  const info = lookupPackageInstalledInfo('js-yaml', pkgJson, pkgLock, null, null, tree);

  assert.equal(info.isDirect, true);
  assert.equal(info.isIndirect, true);
  assert.equal(info.dependencyType, 'Direct & Indirect');

  const vuln = {
    packageName: 'js-yaml',
    isDirect: info.isDirect,
    isIndirect: info.isIndirect,
    dependencyType: info.dependencyType,
    currentVersion: info.currentVersion,
    targetSafeVersion: '4.1.1',
    workspaceDeclarations: info.workspaceDeclarations,
  };

  const rem = buildRemediationSuggestion(vuln, info.directRoots, pkgJson, info.chains, info.directInfo, null, tree);
  assert.equal(rem.strategy, 'bump-direct-and-lockfile');
  assert.ok(rem.lockfileUpdates.includes('js-yaml'));
  assert.equal(rem.packageJsonChanges[0].to, '^4.1.1');
});

test('Scenario 3: Transitive In-Range Lockfile Update (lockfile-update)', async () => {
  const pkgJson = {
    name: 'test-app',
    dependencies: {
      parent: '^1.0.0',
    },
  };
  const pkgLock = {
    name: 'test-app',
    lockfileVersion: 2,
    packages: {
      '': { dependencies: { parent: '^1.0.0' } },
      'node_modules/parent': { version: '1.0.0', dependencies: { child: '>=0.7.0 <0.9.0' } },
      'node_modules/child': { version: '0.7.5' },
    },
  };

  const tree = await loadArboristTree({ pkgJson, pkgLock });
  const info = lookupPackageInstalledInfo('child', pkgJson, pkgLock, null, null, tree);

  assert.equal(info.isDirect, false);
  assert.equal(info.isIndirect, true);

  const canResolve = canBeResolvedInLockfile('0.8.8', 'child', tree, info.chains);
  assert.equal(canResolve, true);

  const vuln = {
    packageName: 'child',
    isDirect: false,
    isIndirect: true,
    dependencyType: 'Indirect (Transitive)',
    currentVersion: '0.7.5',
    targetSafeVersion: '0.8.8',
    workspaceDeclarations: info.workspaceDeclarations,
  };

  const rem = buildRemediationSuggestion(vuln, info.directRoots, pkgJson, info.chains, info.directInfo, null, tree);
  assert.equal(rem.strategy, 'lockfile-update');
  assert.equal(rem.packageJsonChanges.length, 0);
  assert.deepEqual(rem.lockfileUpdates, ['child']);
});

test('Scenario 4: Transitive Out-of-Range requiring Override (package-override)', async () => {
  const pkgJson = {
    name: 'test-app',
    dependencies: {
      parent: '^1.0.0',
    },
  };
  const pkgLock = {
    name: 'test-app',
    lockfileVersion: 2,
    packages: {
      '': { dependencies: { parent: '^1.0.0' } },
      'node_modules/parent': { version: '1.0.0', dependencies: { child: '~1.0.0' } },
      'node_modules/child': { version: '1.0.2' },
    },
  };

  const tree = await loadArboristTree({ pkgJson, pkgLock });
  const info = lookupPackageInstalledInfo('child', pkgJson, pkgLock, null, null, tree);

  const canResolve = canBeResolvedInLockfile('1.2.0', 'child', tree, info.chains);
  assert.equal(canResolve, false);

  const vuln = {
    packageName: 'child',
    isDirect: false,
    isIndirect: true,
    dependencyType: 'Indirect (Transitive)',
    currentVersion: '1.0.2',
    targetSafeVersion: '1.2.0',
    workspaceDeclarations: info.workspaceDeclarations,
  };

  const rem = buildRemediationSuggestion(vuln, info.directRoots, pkgJson, info.chains, info.directInfo, null, tree);
  assert.equal(rem.strategy, 'package-override');
  assert.equal(rem.packageJsonChanges.length, 1);
  assert.equal(rem.packageJsonChanges[0].section, 'overrides');
  assert.equal(rem.packageJsonChanges[0].package, 'child');
  assert.equal(rem.packageJsonChanges[0].to, '1.2.0');
});

test('Scenario 5: Monorepo Workspace Direct Scoping', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'scen5-'));
  try {
    fs.mkdirSync(path.join(tmpDir, 'packages/ui'), { recursive: true });
    fs.writeFileSync(
      path.join(tmpDir, 'package.json'),
      JSON.stringify(
        {
          name: 'monorepo',
          workspaces: ['packages/*'],
        },
        null,
        2
      )
    );
    fs.writeFileSync(
      path.join(tmpDir, 'packages/ui/package.json'),
      JSON.stringify(
        {
          name: '@mono/ui',
          version: '1.0.0',
          dependencies: {
            button: '1.0.0',
          },
        },
        null,
        2
      )
    );
    fs.writeFileSync(
      path.join(tmpDir, 'package-lock.json'),
      JSON.stringify(
        {
          name: 'monorepo',
          lockfileVersion: 2,
          packages: {
            '': { name: 'monorepo', workspaces: ['packages/*'] },
            'packages/ui': { version: '1.0.0', dependencies: { button: '1.0.0' } },
            'node_modules/@mono/ui': { resolved: 'packages/ui', link: true },
            'node_modules/button': { version: '1.0.0' },
          },
        },
        null,
        2
      )
    );

    const tree = await loadArboristTree({ dir: tmpDir });
    const pkgJson = JSON.parse(fs.readFileSync(path.join(tmpDir, 'package.json'), 'utf8'));
    const pkgLock = JSON.parse(fs.readFileSync(path.join(tmpDir, 'package-lock.json'), 'utf8'));

    const info = lookupPackageInstalledInfo('button', pkgJson, pkgLock, null, tmpDir, tree);
    assert.equal(info.isDirect, true);
    assert.ok(info.workspaceDeclarations.some((d) => d.packageJsonPath === 'packages/ui/package.json'));

    const changes = [
      { package: 'button', section: 'dependencies', to: '1.1.0', packageJsonPath: 'packages/ui/package.json' },
    ];
    const { applied, touchedFiles } = updatePackageJsonFile(tmpDir, changes);
    assert.equal(applied.length, 1);
    assert.equal(applied[0].packageJsonPath, 'packages/ui/package.json');
    assert.ok(touchedFiles.includes('packages/ui/package.json'));

    const updatedUi = JSON.parse(fs.readFileSync(path.join(tmpDir, 'packages/ui/package.json'), 'utf8'));
    assert.equal(updatedUi.dependencies.button, '1.1.0');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('Scenario 6: Monorepo Multi-Workspace Declaration Updates', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'scen6-'));
  try {
    fs.mkdirSync(path.join(tmpDir, 'packages/app-a'), { recursive: true });
    fs.mkdirSync(path.join(tmpDir, 'packages/app-b'), { recursive: true });

    fs.writeFileSync(
      path.join(tmpDir, 'package.json'),
      JSON.stringify(
        {
          name: 'monorepo',
          workspaces: ['packages/*'],
        },
        null,
        2
      )
    );

    // Custom 4-space indent in app-a, 2-space in app-b
    fs.writeFileSync(
      path.join(tmpDir, 'packages/app-a/package.json'),
      JSON.stringify(
        {
          name: '@mono/app-a',
          version: '1.0.0',
          dependencies: { lodash: '^4.17.15' },
        },
        null,
        4
      )
    );

    fs.writeFileSync(
      path.join(tmpDir, 'packages/app-b/package.json'),
      JSON.stringify(
        {
          name: '@mono/app-b',
          version: '1.0.0',
          dependencies: { lodash: '^4.17.19' },
        },
        null,
        2
      )
    );

    fs.writeFileSync(
      path.join(tmpDir, 'package-lock.json'),
      JSON.stringify(
        {
          name: 'monorepo',
          lockfileVersion: 2,
          packages: {
            '': { name: 'monorepo', workspaces: ['packages/*'] },
            'packages/app-a': { version: '1.0.0', dependencies: { lodash: '^4.17.15' } },
            'packages/app-b': { version: '1.0.0', dependencies: { lodash: '^4.17.19' } },
            'node_modules/lodash': { version: '4.17.19' },
          },
        },
        null,
        2
      )
    );

    const tree = await loadArboristTree({ dir: tmpDir });
    const pkgJson = JSON.parse(fs.readFileSync(path.join(tmpDir, 'package.json'), 'utf8'));
    const pkgLock = JSON.parse(fs.readFileSync(path.join(tmpDir, 'package-lock.json'), 'utf8'));

    const info = lookupPackageInstalledInfo('lodash', pkgJson, pkgLock, null, tmpDir, tree);
    assert.equal(info.isDirect, true);
    assert.equal(info.workspaceDeclarations.length, 2);

    const vuln = {
      packageName: 'lodash',
      isDirect: true,
      dependencyType: 'Direct',
      currentVersion: info.currentVersion,
      targetSafeVersion: '4.17.21',
      workspaceDeclarations: info.workspaceDeclarations,
    };

    const rem = buildRemediationSuggestion(vuln, info.directRoots, pkgJson, info.chains, info.directInfo, tmpDir, tree);
    assert.equal(rem.strategy, 'bump-direct');
    assert.equal(rem.packageJsonChanges.length, 2);
    assert.ok(rem.packageJsonChanges.some((c) => c.packageJsonPath === 'packages/app-a/package.json' && c.to === '^4.17.21'));
    assert.ok(rem.packageJsonChanges.some((c) => c.packageJsonPath === 'packages/app-b/package.json' && c.to === '^4.17.21'));

    const { applied } = updatePackageJsonFile(tmpDir, rem.packageJsonChanges);
    assert.equal(applied.length, 2);

    const rawA = fs.readFileSync(path.join(tmpDir, 'packages/app-a/package.json'), 'utf8');
    assert.ok(rawA.includes('    "lodash": "^4.17.21"')); // 4 spaces preserved

    const rawB = fs.readFileSync(path.join(tmpDir, 'packages/app-b/package.json'), 'utf8');
    assert.ok(rawB.includes('  "lodash": "^4.17.21"')); // 2 spaces preserved
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('Scenario 7: Monorepo Inter-Workspace Dependency Chains', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'scen7-'));
  try {
    fs.mkdirSync(path.join(tmpDir, 'packages/app-a'), { recursive: true });
    fs.mkdirSync(path.join(tmpDir, 'packages/lib-b'), { recursive: true });

    fs.writeFileSync(
      path.join(tmpDir, 'package.json'),
      JSON.stringify(
        {
          name: 'my-mono',
          workspaces: ['packages/*'],
        },
        null,
        2
      )
    );

    fs.writeFileSync(
      path.join(tmpDir, 'packages/app-a/package.json'),
      JSON.stringify(
        {
          name: '@mono/app-a',
          version: '1.0.0',
          dependencies: { '@mono/lib-b': '^1.0.0' },
        },
        null,
        2
      )
    );

    fs.writeFileSync(
      path.join(tmpDir, 'packages/lib-b/package.json'),
      JSON.stringify(
        {
          name: '@mono/lib-b',
          version: '1.0.0',
          dependencies: { msw: '0.49.0' },
        },
        null,
        2
      )
    );

    fs.writeFileSync(
      path.join(tmpDir, 'package-lock.json'),
      JSON.stringify(
        {
          name: 'my-mono',
          lockfileVersion: 2,
          packages: {
            '': { name: 'my-mono', workspaces: ['packages/*'] },
            'packages/app-a': { version: '1.0.0', dependencies: { '@mono/lib-b': '^1.0.0' } },
            'packages/lib-b': { version: '1.0.0', dependencies: { msw: '0.49.0' } },
            'node_modules/@mono/app-a': { resolved: 'packages/app-a', link: true },
            'node_modules/@mono/lib-b': { resolved: 'packages/lib-b', link: true },
            'node_modules/msw': { version: '0.49.0', dependencies: { '@xmldom/xmldom': '0.7.5' } },
            'node_modules/@xmldom/xmldom': { version: '0.7.5' },
          },
        },
        null,
        2
      )
    );

    const tree = await loadArboristTree({ dir: tmpDir });
    const xmldomNodes = Array.from(tree.inventory.query('name', '@xmldom/xmldom'));
    assert.equal(xmldomNodes.length, 1);

    const chains = traceArboristChains(xmldomNodes[0]);
    assert.ok(chains.length > 0);

    const chainStr = chains[0].map((c) => c.specifier).join(' -> ');
    assert.equal(
      chainStr,
      '@mono/app-a (packages/app-a/package.json) -> @mono/lib-b (packages/lib-b/package.json) -> msw@0.49.0 -> @xmldom/xmldom@0.7.5'
    );

    const directRoots = findDirectRootsFromArborist(chains);
    assert.equal(directRoots.length, 1);
    assert.equal(directRoots[0].name, 'msw');
    assert.equal(directRoots[0].packageJsonPath, 'packages/lib-b/package.json');
    assert.equal(directRoots[0].workspace, '@mono/lib-b');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('Scenario 8: Monorepo Workspace-Scoped Override in Root', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'scen8-'));
  try {
    fs.mkdirSync(path.join(tmpDir, 'packages/app-a'), { recursive: true });
    fs.mkdirSync(path.join(tmpDir, 'packages/app-b'), { recursive: true });

    fs.writeFileSync(
      path.join(tmpDir, 'package.json'),
      JSON.stringify(
        {
          name: 'monorepo',
          workspaces: ['packages/*'],
        },
        null,
        2
      )
    );

    fs.writeFileSync(
      path.join(tmpDir, 'packages/app-a/package.json'),
      JSON.stringify(
        {
          name: '@mono/app-a',
          version: '1.0.0',
        },
        null,
        2
      )
    );

    fs.writeFileSync(
      path.join(tmpDir, 'packages/app-b/package.json'),
      JSON.stringify(
        {
          name: '@mono/app-b',
          version: '1.0.0',
        },
        null,
        2
      )
    );

    const changes = [
      {
        package: 'vuln-pkg',
        section: 'overrides',
        workspaceScope: '@mono/app-a',
        to: '1.2.3',
        packageJsonPath: 'package.json',
      },
    ];

    const { applied, touchedFiles } = updatePackageJsonFile(tmpDir, changes);
    assert.equal(applied.length, 1);
    assert.equal(touchedFiles.length, 1);
    assert.equal(touchedFiles[0], 'package.json');

    const rootPkg = JSON.parse(fs.readFileSync(path.join(tmpDir, 'package.json'), 'utf8'));
    assert.deepEqual(rootPkg.overrides, {
      '@mono/app-a': {
        'vuln-pkg': '1.2.3',
      },
    });

    // Verify sibling workspace was unmodified
    const appBPkg = JSON.parse(fs.readFileSync(path.join(tmpDir, 'packages/app-b/package.json'), 'utf8'));
    assert.equal(appBPkg.overrides, undefined);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('Vulnerability with no known patched version formats as No fix and calls out in detailed findings', () => {
  // When carrier parent has fixAvailable but target package has no fix (e.g. braces)
  const fixAvailable = { name: 'http-proxy-middleware', version: '0.2.0', isSemVerMajor: true };
  const patched = determinePatchedVersions('*', fixAvailable, 'braces');
  assert.deepEqual(patched, [], 'Parent package fixAvailable must not be applied to child target package');

  const safeVer = determineSafeVersion('*', '3.0.3', fixAvailable, 'braces');
  assert.equal(safeVer, null, 'Safe version must be null when no patch exists');

  const vuln = {
    packageName: 'braces',
    severity: 'high',
    currentVersion: '3.0.3',
    targetSafeVersion: null,
    patchedVersions: [],
    dependencyType: 'Indirect (Transitive)',
    isDirect: false,
    isIndirect: true,
    cves: ['CVE-2026-93687'],
    dependencyPaths: ['[root] -> http-proxy-middleware@4.1.1 -> micromatch@4.0.8 -> braces@3.0.3'],
  };

  const rem = buildRemediationSuggestion(vuln, [{ name: 'http-proxy-middleware', section: 'dependencies' }], {});
  assert.equal(rem.strategy, 'none');
  assert.equal(rem.targetVersion, null);
  assert.ok(rem.note.includes('No known patched version is currently available for braces'));

  vuln.remediation = rem;
  const targetFixStr = formatTargetFix(vuln);
  assert.equal(targetFixStr, '_No fix_');

  const md = generateMarkdownReport({
    branches: [{ branch: 'main', summary: { total: 1 }, vulnerabilities: [vuln] }],
  });
  assert.ok(md.includes('| _No fix_ |'));
  assert.ok(md.includes('- **Target Fix Version:** _No fix available_'));
  assert.ok(md.includes('> ⚠️ **No fix available**: No known patched version is currently available for `braces`.'));
  assert.ok(md.includes('**Consolidated Remediation Plan (none):**'));
  assert.ok(md.includes('> ⚠️ **No fix available**: No patched release of `braces` currently exists.'));
});

test('Transitive dependency path formatting: maps [root] to direct parent and sorts root before workspaces', () => {
  const vuln = {
    packageName: 'braces',
    directRoots: [
      { name: 'http-proxy-middleware', section: 'dependencies', packageJsonPath: 'package.json' },
      { name: 'msw', section: 'devDependencies', packageJsonPath: 'client/package.json', workspace: '@mono/client' },
      { name: 'ts-checker-rspack-plugin', section: 'devDependencies', packageJsonPath: 'client/package.json', workspace: '@mono/client' },
      { name: 'cypress-tags', section: 'devDependencies', packageJsonPath: 'cypress/package.json', workspace: '@mono/cypress' },
    ],
    dependencyPaths: [
      '@mono/client (client/package.json) -> ts-checker-rspack-plugin@1.6.1 -> chokidar@3.6.0 -> braces@3.0.3',
      '@mono/cypress (cypress/package.json) -> cypress-tags@1.2.2 -> watchify@4.0.0 -> chokidar@3.6.0 -> braces@3.0.3',
      '[root] -> http-proxy-middleware@4.1.1 -> micromatch@4.0.8 -> braces@3.0.3',
      '@mono/client (client/package.json) -> msw@1.3.5 -> chokidar@3.6.0 -> braces@3.0.3',
    ],
  };

  const paths = formatTransitiveDependencyPaths(vuln);
  assert.equal(paths.length, 4);
  // Verify [root] was replaced with http-proxy-middleware
  assert.ok(!paths.some((p) => p.includes('[root]')));

  // Verify sort order: package.json before workspaces, client before cypress
  assert.equal(paths[0], 'package.json/dependencies/http-proxy-middleware/.../braces@3.0.3');
  assert.equal(paths[1], 'client/package.json/devDependencies/msw/.../braces@3.0.3');
  assert.equal(paths[2], 'client/package.json/devDependencies/ts-checker-rspack-plugin/.../braces@3.0.3');
  assert.equal(paths[3], 'cypress/package.json/devDependencies/cypress-tags/.../braces@3.0.3');
});
