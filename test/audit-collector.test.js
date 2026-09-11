import test from 'node:test';
import assert from 'node:assert/strict';
import {
  determineSafeVersion,
  determinePatchedVersions,
  buildRemediationSuggestion,
  extractCveFromText,
  canBeResolvedInLockfile,
  parseAuditVulnerabilities,
  resolveAuditAdvisories,
} from '../src/collectors/npm-audit.js';
import { selectBestRemediationVersion } from '../src/core/blender.js';
import {
  extractDependencyChains,
  findDirectRoots,
  getDirectDependencies,
  tracePathsFromPackageLock,
} from '../src/core/dependency-graph.js';
import { generateJsonReport } from '../src/report/json-reporter.js';
import { generateMarkdownReport, formatCompactDependencyPaths, formatCves, formatSources, formatTargetFix } from '../src/report/markdown-reporter.js';

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
  assert.deepEqual(rem.lockfileUpdates, ['@xmldom/xmldom']);
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
            lockfileUpdates: ['vuln-lib'],
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
  assert.ok(mdReport.includes('npm update vuln-lib --package-lock-only'));
  assert.ok(mdReport.includes('| Package | Severity | Type | Current Version | Target Fix | CVEs | Sources |'));
  assert.ok(mdReport.includes('| **`vuln-lib`** | **CRITICAL** | Indirect (Transitive) | `1.0.0` | `1.1.0` | `CVE-2023-9999` | [npm audit](https://github.com/advisories/GHSA-xxxx) |'));
});

test('generateMarkdownReport: table renders multiple CVEs and multiple sources with <br>', () => {
  const repo = { name: 'demo-repo', org: 'acme' };
  const branchReports = [
    {
      branch: 'main',
      summary: { critical: 0, high: 1, moderate: 0, low: 0, total: 1 },
      vulnerabilities: [
        {
          id: 'GHSA-multi',
          cves: ['CVE-2023-1111', 'CVE-2023-2222'],
          packageName: 'multi-vuln-pkg',
          severity: 'high',
          title: 'Multiple Flaws',
          currentVersion: '2.0.0',
          targetSafeVersion: '2.1.0',
          sources: {
            npmAudit: { advisoryId: '123' },
            jira: { ticketKey: 'MTA-5000', url: 'https://jira/MTA-5000' },
            dependabot: { alertNumber: 99, url: 'https://github/alert/99' },
          },
        },
      ],
    },
  ];

  const jsonReport = generateJsonReport(repo, branchReports);
  const mdReport = generateMarkdownReport(jsonReport);
  assert.ok(
    mdReport.includes(
      '| **`multi-vuln-pkg`** | **HIGH** | Indirect (Transitive) | `2.0.0` | `2.1.0` | `CVE-2023-1111`<br>`CVE-2023-2222` | npm audit<br>[MTA-5000](https://jira/MTA-5000)<br>[#99](https://github/alert/99) |'
    )
  );
});

test('formatCves: formats single, multiple with <br>, none, and deduplicates', () => {
  assert.equal(formatCves({ cve: 'CVE-2023-1111' }), '`CVE-2023-1111`');
  assert.equal(
    formatCves({ cves: ['CVE-2023-1111', 'CVE-2023-2222'] }),
    '`CVE-2023-1111`<br>`CVE-2023-2222`'
  );
  assert.equal(
    formatCves({ cve: 'CVE-2023-1111', cves: ['CVE-2023-1111', 'CVE-2023-2222'] }),
    '`CVE-2023-1111`<br>`CVE-2023-2222`'
  );
  assert.equal(formatCves({}), '_None_');
  assert.equal(formatCves({ id: 'GHSA-xxxx' }), '_None_');
  assert.equal(formatCves({ id: 'CVE-2024-5555' }), '`CVE-2024-5555`');
  assert.equal(
    formatCves({
      advisories: [
        { cve: 'CVE-2023-1001' },
        { cves: ['CVE-2023-1002', 'CVE-2023-1001'] },
      ],
    }),
    '`CVE-2023-1001`<br>`CVE-2023-1002`'
  );
});

test('formatSources: formats npm audit, jira link, dependabot link, and multiple sources', () => {
  // Standalone npm audit
  assert.equal(
    formatSources({ sources: { npmAudit: { advisoryId: '123' } } }),
    'npm audit'
  );

  // Standalone npm audit with GitHub advisory URL
  assert.equal(
    formatSources({ sources: { npmAudit: { advisoryId: 'GHSA-xxxx', url: 'https://github.com/advisories/GHSA-xxxx' } } }),
    '[npm audit](https://github.com/advisories/GHSA-xxxx)'
  );

  // Standalone npm audit with multiple GitHub advisory URLs
  assert.equal(
    formatSources({
      sources: {
        npmAudit: {
          urls: ['https://github.com/advisories/GHSA-1111', 'https://github.com/advisories/GHSA-2222'],
        },
      },
    }),
    '[npm audit (GHSA-1111)](https://github.com/advisories/GHSA-1111)<br>[npm audit (GHSA-2222)](https://github.com/advisories/GHSA-2222)'
  );

  // Default fallback to npm audit when no sources defined
  assert.equal(formatSources({ id: 'GHSA-1234' }), 'npm audit');

  // Standalone Jira ticket
  assert.equal(
    formatSources({
      sources: {
        jira: { ticketKey: 'MTA-7680', url: 'https://issues.redhat.com/browse/MTA-7680' },
      },
    }),
    '[MTA-7680](https://issues.redhat.com/browse/MTA-7680)'
  );

  // Standalone Dependabot alert
  assert.equal(
    formatSources({
      sources: {
        dependabot: { alertNumber: 42, url: 'https://github.com/org/repo/security/dependabot/42' },
      },
    }),
    '[#42](https://github.com/org/repo/security/dependabot/42)'
  );

  // Multiple sources: npm audit, Jira, and Dependabot
  assert.equal(
    formatSources({
      sources: {
        npmAudit: { advisoryId: '123' },
        jira: { ticketKey: 'MTA-7680', url: 'https://issues.redhat.com/browse/MTA-7680' },
        dependabot: { alertNumber: 42, url: 'https://github.com/org/repo/security/dependabot/42' },
      },
    }),
    'npm audit<br>[MTA-7680](https://issues.redhat.com/browse/MTA-7680)<br>[#42](https://github.com/org/repo/security/dependabot/42)'
  );

  // Multiple Jira tickets and Dependabot alerts
  assert.equal(
    formatSources({
      sources: {
        jiraTickets: [
          { ticketKey: 'MTA-1', url: 'https://issues/MTA-1' },
          { ticketKey: 'MTA-2', url: 'https://issues/MTA-2' },
        ],
        dependabotAlerts: [
          { alertNumber: 10, url: 'https://github/10' },
          { alertNumber: 11, url: 'https://github/11' },
        ],
      },
    }),
    '[MTA-1](https://issues/MTA-1)<br>[MTA-2](https://issues/MTA-2)<br>[#10](https://github/10)<br>[#11](https://github/11)'
  );
});

test('formatCompactDependencyPaths: formats direct and transitive paths compactly', () => {
  const vuln = {
    packageName: 'js-yaml',
    isDirect: true,
    workspaceDeclarations: [
      { packageJsonPath: 'client/package.json', section: 'dependencies', range: '^4.3.0' },
      { packageJsonPath: 'cypress/package.json', section: 'devDependencies', range: '^4.3.0' },
    ],
    directRoots: [
      { name: 'eslint', section: 'devDependencies', packageJsonPath: 'package.json' },
    ],
    dependencyPaths: [
      '@konveyor-ui/cypress (devDependencies) -> js-yaml@^4.3.0',
      '@konveyor-ui/client (dependencies) -> js-yaml@^4.3.0',
      'eslint@9.39.4 -> @eslint/eslintrc@3.3.5 -> js-yaml@3.15.1',
      '@konveyor-ui/client (client/package.json) -> jest@29.7.0 -> @jest/core@29.7.0 -> js-yaml@3.15.1',
    ],
  };

  const compact = formatCompactDependencyPaths(vuln);
  assert.ok(compact.includes('client/package.json/dependencies/js-yaml@^4.3.0'));
  assert.ok(compact.includes('cypress/package.json/devDependencies/js-yaml@^4.3.0'));
  assert.ok(compact.includes('package.json/devDependencies/eslint/.../js-yaml@3.15.1'));
  assert.ok(compact.includes('client/package.json/dependencies/jest/.../js-yaml@3.15.1'));
});

test('parseAuditVulnerabilities: ignores intermediate packages and only includes packages with advisories', async () => {
  const auditJson = {
    vulnerabilities: {
      cookie: {
        name: 'cookie',
        severity: 'low',
        isDirect: false,
        via: [
          {
            source: 1095000,
            name: 'cookie',
            dependency: 'cookie',
            title: 'Cookie vulnerability',
            url: 'https://github.com/advisories/GHSA-cookie',
            severity: 'low',
            cve: 'CVE-2024-1234',
            range: '< 0.5.0',
          },
        ],
        range: '< 0.5.0',
        nodes: ['node_modules/intermediate-lib/node_modules/cookie'],
        fixAvailable: false,
      },
      'intermediate-lib': {
        name: 'intermediate-lib',
        severity: 'low',
        isDirect: false,
        via: ['cookie'],
        range: '>=1.0.0',
        nodes: ['node_modules/intermediate-lib'],
        fixAvailable: false,
      },
      'root-lib': {
        name: 'root-lib',
        severity: 'low',
        isDirect: true,
        via: ['intermediate-lib'],
        range: '>=1.0.0',
        nodes: ['node_modules/root-lib'],
        fixAvailable: false,
      },
      'other-direct-vuln': {
        name: 'other-direct-vuln',
        severity: 'high',
        isDirect: true,
        via: [
          {
            source: 1096000,
            name: 'other-direct-vuln',
            dependency: 'other-direct-vuln',
            title: 'Other direct flaw',
            url: 'https://github.com/advisories/GHSA-other',
            severity: 'high',
            range: '< 2.1.0',
          },
        ],
        range: '< 2.1.0',
        nodes: ['node_modules/other-direct-vuln'],
        fixAvailable: true,
      },
    },
  };

  const pkgJson = {
    dependencies: {
      'root-lib': '^1.0.0',
      'other-direct-vuln': '^2.0.0',
    },
  };

  const pkgLock = {
    packages: {
      '': {
        dependencies: {
          'root-lib': '^1.0.0',
          'other-direct-vuln': '^2.0.0',
        },
      },
      'node_modules/root-lib': {
        version: '1.0.0',
        dependencies: {
          'intermediate-lib': '^1.0.0',
        },
      },
      'node_modules/intermediate-lib': {
        version: '1.0.0',
        dependencies: {
          cookie: '^0.4.0',
        },
      },
      'node_modules/cookie': {
        version: '0.4.0',
      },
      'node_modules/other-direct-vuln': {
        version: '2.0.0',
      },
    },
  };

  const result = await parseAuditVulnerabilities(auditJson, pkgJson, pkgLock, null, null, 'main');

  // Exactly 2 vulnerabilities: cookie and other-direct-vuln (intermediate-lib and root-lib skipped)
  assert.equal(result.vulnerabilities.length, 2);
  const pkgNames = result.vulnerabilities.map((v) => v.packageName);
  assert.ok(pkgNames.includes('cookie'));
  assert.ok(pkgNames.includes('other-direct-vuln'));
  assert.ok(!pkgNames.includes('intermediate-lib'));
  assert.ok(!pkgNames.includes('root-lib'));

  // Summary reflects only the real vulnerabilities
  assert.equal(result.summary.total, 2);
  assert.equal(result.summary.high, 1);
  assert.equal(result.summary.low, 1);

  // The leaf vulnerability retains its ancestor chain through the intermediate packages
  const cookieVuln = result.vulnerabilities.find((v) => v.packageName === 'cookie');
  assert.ok(cookieVuln);
  assert.equal(cookieVuln.cve, 'CVE-2024-1234');
  assert.ok(cookieVuln.dependencyPaths.length > 0);
  assert.ok(cookieVuln.dependencyPaths[0].includes('root-lib'));
  assert.ok(cookieVuln.dependencyPaths[0].includes('intermediate-lib'));
  assert.ok(cookieVuln.dependencyPaths[0].includes('cookie'));
  assert.equal(cookieVuln.directRoots.length, 1);
  assert.equal(cookieVuln.directRoots[0].name, 'root-lib');
});

test('parseAuditVulnerabilities: retains package if it has both its own advisory and intermediate references in via', async () => {
  const auditJson = {
    vulnerabilities: {
      'hybrid-lib': {
        name: 'hybrid-lib',
        severity: 'moderate',
        isDirect: true,
        via: [
          {
            source: 999999,
            name: 'hybrid-lib',
            dependency: 'hybrid-lib',
            title: 'Hybrid vulnerability',
            url: 'https://github.com/advisories/GHSA-hybrid',
            severity: 'moderate',
          },
          'child-lib',
        ],
      },
    },
  };

  const result = await parseAuditVulnerabilities(auditJson, { dependencies: { 'hybrid-lib': '^1.0.0' } }, { packages: { '': {} } });
  assert.equal(result.vulnerabilities.length, 1);
  assert.equal(result.vulnerabilities[0].packageName, 'hybrid-lib');
});

test('resolveAuditAdvisories: enriches npm audit vulnerability with CVE, target fix, and advisory URL', async () => {
  const vulns = [
    {
      id: 'GHSA-test-1234',
      packageName: 'demo-pkg',
      severity: 'high',
      currentVersion: '1.0.0',
      targetSafeVersion: null,
      cve: null,
      cves: [],
      url: 'https://github.com/advisories/GHSA-test-1234',
      sources: {
        npmAudit: {
          advisoryId: 'GHSA-test-1234',
          url: 'https://github.com/advisories/GHSA-test-1234',
        },
      },
      remediation: {
        strategy: 'bump-direct',
        targetVersion: null,
        packageJsonChanges: [{ package: 'demo-pkg', from: '^1.0.0', to: null }],
      },
    },
  ];

  const advisoryCache = new Map();
  advisoryCache.set('GHSA-TEST-1234', Promise.resolve({
    id: 'GHSA-test-1234',
    ghsaId: 'GHSA-TEST-1234',
    cve: 'CVE-2024-99999',
    targetSafeVersion: '1.2.0',
    url: 'https://github.com/advisories/GHSA-test-1234',
  }));

  await resolveAuditAdvisories(vulns, { advisoryCache });

  assert.equal(vulns[0].cve, 'CVE-2024-99999');
  assert.deepEqual(vulns[0].cves, ['CVE-2024-99999']);
  assert.equal(vulns[0].targetSafeVersion, '1.2.0');
  assert.equal(vulns[0].remediation.targetVersion, '1.2.0');
  assert.equal(vulns[0].remediation.packageJsonChanges[0].to, '^1.2.0');

  // Verify in Markdown report
  const md = generateMarkdownReport({
    branches: [{ branch: 'main', summary: { total: 1 }, vulnerabilities: vulns }],
  });
  assert.ok(md.includes('| **`demo-pkg`** | **HIGH** | Indirect (Transitive) | `1.0.0` | `1.2.0` | `CVE-2024-99999` | [npm audit](https://github.com/advisories/GHSA-test-1234) |'));
});

test('parseAuditVulnerabilities: automatically resolves and enriches CVE and target fix via options.advisoryCache', async () => {
  const auditJson = {
    vulnerabilities: {
      cookie: {
        name: 'cookie',
        severity: 'low',
        isDirect: true,
        via: [
          {
            source: 1103907,
            name: 'cookie',
            title: 'cookie vulnerability',
            url: 'https://github.com/advisories/GHSA-pxg6-pf52-xh8x',
            severity: 'low',
            range: '<0.7.0',
          },
        ],
        range: '<0.7.0',
        fixAvailable: false,
      },
    },
  };

  const advisoryCache = new Map();
  advisoryCache.set('GHSA-PXG6-PF52-XH8X', Promise.resolve({
    id: 'GHSA-pxg6-pf52-xh8x',
    ghsaId: 'GHSA-PXG6-PF52-XH8X',
    cve: 'CVE-2024-47764',
    targetSafeVersion: '0.7.0',
    url: 'https://github.com/advisories/GHSA-pxg6-pf52-xh8x',
  }));

  const pkgJson = { dependencies: { cookie: '0.4.0' } };
  const pkgLock = { packages: { '': {}, 'node_modules/cookie': { version: '0.4.0' } } };

  const result = await parseAuditVulnerabilities(auditJson, pkgJson, pkgLock, null, null, 'main', { advisoryCache });
  assert.equal(result.vulnerabilities.length, 1);
  const cookie = result.vulnerabilities[0];
  assert.equal(cookie.cve, 'CVE-2024-47764');
  assert.equal(cookie.targetSafeVersion, '0.7.0');
  assert.equal(cookie.sources.npmAudit.url, 'https://github.com/advisories/GHSA-pxg6-pf52-xh8x');

  const md = generateMarkdownReport({
    branches: [result],
  });
  assert.ok(md.includes('| **`cookie`** | **LOW** | Direct | `0.4.0` | `0.7.0` | `CVE-2024-47764` | [npm audit](https://github.com/advisories/GHSA-pxg6-pf52-xh8x) |'));
});

test('determinePatchedVersions: extracts all patched versions across major version lines from semver ranges', () => {
  const versions = determinePatchedVersions('<2.4.5 || >=3.0.0 <3.1.6 || >=4.0.0 <4.1.3');
  assert.deepEqual(versions, ['2.4.5', '3.1.6', '4.1.3']);
});

test('selectBestRemediationVersion: selects safe in-major fix or minimal breaking upgrade', () => {
  const candidates = ['2.4.5', '3.1.6', '4.1.3'];
  assert.equal(selectBestRemediationVersion('2.4.2', candidates), '2.4.5');
  assert.equal(selectBestRemediationVersion('3.1.3', candidates), '3.1.6');
  assert.equal(selectBestRemediationVersion('4.0.1', candidates), '4.1.3');
  assert.equal(selectBestRemediationVersion('1.0.0', candidates), '2.4.5');
  assert.equal(selectBestRemediationVersion('unknown', candidates), '4.1.3');
});

test('formatTargetFix: formats single version, multiple versions with <br>, and none', () => {
  assert.equal(formatTargetFix({ targetSafeVersion: '2.1.4' }), '`2.1.4`');
  assert.equal(
    formatTargetFix({
      patchedVersions: ['2.4.5', '3.1.6', '4.1.3'],
    }),
    '`2.4.5`<br>`3.1.6`<br>`4.1.3`'
  );
  assert.equal(
    formatTargetFix({
      advisories: [
        { patchedVersions: ['2.4.5', '3.1.6'] },
        { targetSafeVersion: '4.1.3' },
      ],
    }),
    '`2.4.5`<br>`3.1.6`<br>`4.1.3`'
  );
  assert.equal(formatTargetFix({}), '_No fix_');
});

test('generateMarkdownReport: lists all major version line fixes under Target Fix for multi-line advisories like fast-uri', () => {
  const vuln = {
    packageName: 'fast-uri',
    severity: 'high',
    currentVersion: '2.4.2',
    targetSafeVersion: '2.4.5',
    patchedVersions: ['2.4.5', '3.1.6', '4.1.3'],
    cve: 'CVE-2026-75931',
    url: 'https://github.com/advisories/GHSA-5jgf-p345-68v8',
    sources: {
      npmAudit: { url: 'https://github.com/advisories/GHSA-5jgf-p345-68v8' },
    },
    isDirect: true,
  };

  const md = generateMarkdownReport({
    branches: [{ branch: 'main', summary: { total: 1 }, vulnerabilities: [vuln] }],
  });

  assert.ok(
    md.includes(
      '| **`fast-uri`** | **HIGH** | Direct | `2.4.2` | `2.4.5`<br>`3.1.6`<br>`4.1.3` | `CVE-2026-75931` | [npm audit](https://github.com/advisories/GHSA-5jgf-p345-68v8) |'
    )
  );
});
