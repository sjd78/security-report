import test from 'node:test';
import assert from 'node:assert/strict';
import {
  determineSafeVersion,
  buildRemediationSuggestion,
  extractCveFromText,
  canBeResolvedInLockfile,
} from '../src/collectors/npm-audit.js';
import {
  extractDependencyChains,
  findDirectRoots,
  getDirectDependencies,
  tracePathsFromPackageLock,
} from '../src/core/dependency-graph.js';
import { generateJsonReport } from '../src/report/json-reporter.js';
import { generateMarkdownReport } from '../src/report/markdown-reporter.js';

test('determineSafeVersion: range parsing', () => {
  assert.equal(determineSafeVersion('< 2.1.4', '2.1.0'), '2.1.4');
  assert.equal(determineSafeVersion('<= 1.0.0', '1.0.0'), '1.0.1');
  assert.equal(determineSafeVersion('>= 0.0.0', '1.0.0', { version: '2.0.0' }), '2.0.0');
});

test('extractCveFromText: extracts CVE correctly', () => {
  assert.equal(extractCveFromText('https://nvd.nist.gov/vuln/detail/CVE-2023-26136'), 'CVE-2023-26136');
  assert.equal(extractCveFromText('Prototype Pollution in tough-cookie (cve-2023-26136)'), 'CVE-2023-26136');
  assert.equal(extractCveFromText('No CVE here'), null);
});

test('extractDependencyChains: reconstructs direct and indirect hierarchy', () => {
  const pkgJson = {
    dependencies: {
      'request-lib': '^1.0.0',
    },
  };
  const pkgLock = {
    packages: {
      '': {},
      'node_modules/request-lib': { version: '1.2.0' },
      'node_modules/request-lib/node_modules/sub-dep': { version: '0.4.1' },
      'node_modules/request-lib/node_modules/sub-dep/node_modules/tough-cookie': { version: '2.5.0' },
    },
  };
  const directDeps = getDirectDependencies(pkgJson);

  const vulnData = {
    name: 'tough-cookie',
    severity: 'high',
    range: '< 4.1.3',
    nodes: ['node_modules/request-lib/node_modules/sub-dep/node_modules/tough-cookie'],
  };

  const chains = extractDependencyChains(vulnData, pkgLock, directDeps);
  assert.equal(chains.length, 1);
  assert.equal(chains[0].length, 3);
  assert.equal(chains[0][0].specifier, 'request-lib@1.2.0');
  assert.equal(chains[0][1].specifier, 'sub-dep@0.4.1');
  assert.equal(chains[0][2].specifier, 'tough-cookie@2.5.0');

  const roots = findDirectRoots(chains, directDeps);
  assert.equal(roots.length, 1);
  assert.equal(roots[0].name, 'request-lib');
  assert.equal(roots[0].currentRange, '^1.0.0');
});

test('buildRemediationSuggestion: direct dependency bump', () => {
  const directRoots = [{ name: 'lodash', currentRange: '^4.17.15', section: 'dependencies' }];
  const vuln = {
    isDirect: true,
    packageName: 'lodash',
    currentVersion: '4.17.15',
    targetSafeVersion: '4.17.21',
  };
  const rem = buildRemediationSuggestion(vuln, directRoots, {});
  assert.equal(rem.strategy, 'bump-direct');
  assert.equal(rem.packageJsonChanges[0].to, '^4.17.21');
});

test('extractDependencyChains: traces hoisted transitive dependency (e.g. msw -> @xmldom/xmldom)', () => {
  const pkgJson = {
    devDependencies: {
      msw: '^1.2.1',
    },
  };

  const pkgLock = {
    packages: {
      '': {
        devDependencies: { msw: '^1.2.1' },
      },
      'node_modules/msw': {
        version: '1.2.1',
        dependencies: { '@mswjs/interceptors': '^0.17.5' },
      },
      'node_modules/@mswjs/interceptors': {
        version: '0.17.5',
        dependencies: { '@xmldom/xmldom': '>=0.7.0 <0.9.0' },
      },
      'node_modules/@xmldom/xmldom': {
        version: '0.7.5',
      },
    },
  };

  const directDeps = getDirectDependencies(pkgJson);
  const vulnData = {
    name: '@xmldom/xmldom',
    severity: 'high',
    range: '< 0.8.8',
    nodes: ['node_modules/@xmldom/xmldom'],
  };

  const chains = extractDependencyChains(vulnData, pkgLock, directDeps);
  assert.ok(chains.length > 0);
  assert.equal(chains[0][0].name, 'msw');
  assert.equal(chains[0][1].name, '@mswjs/interceptors');
  assert.equal(chains[0][2].name, '@xmldom/xmldom');

  const roots = findDirectRoots(chains, directDeps);
  assert.equal(roots.length, 1);
  assert.equal(roots[0].name, 'msw');

  // Check remediation suggestion
  const vuln = {
    isDirect: false,
    packageName: '@xmldom/xmldom',
    currentVersion: '0.7.5',
    targetSafeVersion: '0.8.8',
  };
  const rem = buildRemediationSuggestion(vuln, roots, pkgJson, chains);
  assert.equal(rem.strategy, 'lockfile-update');
  assert.equal(rem.packageJsonChanges.length, 0);
  assert.ok(rem.lockfileActions[0].includes('npm install @xmldom/xmldom@0.8.8 --package-lock-only'));
});

test('generateJsonReport and generateMarkdownReport', () => {
  const repo = { name: 'demo-repo', org: 'acme' };
  const branchReports = [
    {
      branch: 'main',
      summary: { critical: 1, high: 0, moderate: 0, low: 0, total: 1 },
      vulnerabilities: [
        {
          id: 'GHSA-xxxx',
          cve: 'CVE-2023-9999',
          packageName: 'vuln-lib',
          severity: 'critical',
          title: 'Remote Code Execution',
          url: 'https://github.com/advisories/GHSA-xxxx',
          isDirect: false,
          currentVersion: '1.0.0',
          targetSafeVersion: '1.1.0',
          dependencyPaths: ['root-pkg@1.0.0 -> vuln-lib@1.0.0'],
          remediation: {
            strategy: 'package-override',
            packageJsonChanges: [{ package: 'vuln-lib', section: 'overrides', to: '1.1.0' }],
            lockfileActions: ['npm install --package-lock-only'],
          },
        },
      ],
    },
  ];

  const jsonReport = generateJsonReport(repo, branchReports);
  assert.equal(jsonReport.summary.totalVulnerabilities, 1);

  const mdReport = generateMarkdownReport(jsonReport);
  assert.ok(mdReport.includes('Remote Code Execution'));
  assert.ok(mdReport.includes('CVE-2023-9999'));
  assert.ok(mdReport.includes('package-override'));
});
