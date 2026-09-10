import test from 'node:test';
import assert from 'node:assert/strict';
import { parseJiraIssues, createJiraAuthHeader, groupJiraTicketsByBranch } from '../src/collectors/jira.js';
import { parseDependabotAlerts, groupDependabotAlertsByBranch } from '../src/collectors/dependabot.js';
import { extractGhsaId, extractCveId } from '../src/collectors/advisories.js';
import { blendVulnerabilitySources, matchJiraTicket, matchDependabotAlert, isVersionCompatible, consolidateVulnerabilitiesByPackage, calculateOptimalSafeVersion, sortVulnerabilities } from '../src/core/blender.js';
import { parseBranchMap, parseCollectorSettings, loadConfig } from '../src/config.js';
import { lookupPackageInstalledInfo } from '../src/core/dependency-graph.js';

test('createJiraAuthHeader: Basic Auth and Bearer token', () => {
  const basic = createJiraAuthHeader({ jira: { email: 'user@example.com', apiToken: 'secret123' } });
  assert.ok(basic.startsWith('Basic '));

  const bearer = createJiraAuthHeader({ jira: { apiToken: 'patToken' } });
  assert.equal(bearer, 'Bearer patToken');
});

test('parseJiraIssues: extracts CVE and package names', () => {
  const sampleData = {
    issues: [
      {
        key: 'SEC-1042',
        fields: {
          summary: 'Fix CVE-2023-26136 in tough-cookie package',
          description: 'High severity prototype pollution vulnerability in tough-cookie.',
          status: { name: 'In Progress' },
        },
      },
    ],
  };

  const tickets = parseJiraIssues(sampleData, 'https://jira.example.com');
  assert.equal(tickets.length, 1);
  assert.equal(tickets[0].ticketKey, 'SEC-1042');
  assert.equal(tickets[0].cve, 'CVE-2023-26136');
  assert.equal(tickets[0].packageName, 'tough-cookie');
  assert.equal(tickets[0].url, 'https://jira.example.com/browse/SEC-1042');
});

test('parseDependabotAlerts: parses GitHub Dependabot alert structure', () => {
  const sampleAlerts = [
    {
      number: 42,
      html_url: 'https://github.com/org/repo/security/dependabot/42',
      state: 'open',
      dependency: {
        package: { name: 'lodash', ecosystem: 'npm' },
        manifest_path: 'package.json',
      },
      security_advisory: {
        ghsa_id: 'GHSA-35jh-r3h4-6jhm',
        cve_id: 'CVE-2021-23337',
        summary: 'Command Injection in lodash',
        severity: 'high',
      },
      security_vulnerability: {
        vulnerable_version_range: '< 4.17.21',
        first_patched_version: { identifier: '4.17.21' },
      },
    },
  ];

  const parsed = parseDependabotAlerts(sampleAlerts);
  assert.equal(parsed.length, 1);
  assert.equal(parsed[0].alertNumber, 42);
  assert.equal(parsed[0].packageName, 'lodash');
  assert.equal(parsed[0].ghsaId, 'GHSA-35jh-r3h4-6jhm');
  assert.equal(parsed[0].cve, 'CVE-2021-23337');
  assert.equal(parsed[0].targetSafeVersion, '4.17.21');
});

test('groupJiraTicketsByBranch: groups tickets into branch sections', () => {
  const tickets = [
    { ticketKey: 'MTA-1', affectsVersions: ['8.2', 'mta-8.2'] },
    { ticketKey: 'MTA-2', affectsVersions: ['8.1', 'mta-8.1'] },
    { ticketKey: 'MTA-3', affectsVersions: ['9.0'] },
  ];
  const branchMap = {
    'release-0.11': ['8.2'],
    'release-0.10': ['8.1'],
  };
  const grouped = groupJiraTicketsByBranch(tickets, ['release-0.11', 'release-0.10'], branchMap);
  assert.equal(grouped.branches.length, 2);
  assert.equal(grouped.branches[0].branch, 'release-0.11');
  assert.equal(grouped.branches[0].tickets.length, 1);
  assert.equal(grouped.branches[0].tickets[0].ticketKey, 'MTA-1');
  assert.equal(grouped.branches[1].tickets[0].ticketKey, 'MTA-2');
  assert.equal(grouped.unassigned.length, 1);
  assert.equal(grouped.unassigned[0].ticketKey, 'MTA-3');
});

test('groupDependabotAlertsByBranch: assigns alerts to default branch and notes others', () => {
  const alerts = [{ alertNumber: 1, packageName: 'lodash' }];
  const grouped = groupDependabotAlertsByBranch(alerts, ['main', 'release-0.11'], 'main');
  assert.equal(grouped.branches.length, 2);
  assert.equal(grouped.branches[0].branch, 'main');
  assert.equal(grouped.branches[0].alerts.length, 1);
  assert.equal(grouped.branches[1].branch, 'release-0.11');
  assert.equal(grouped.branches[1].alerts.length, 0);
  assert.ok(grouped.branches[1].note);
});

test('blendVulnerabilitySources: enriches npm audit with Jira and Dependabot', () => {
  const branchReports = [
    {
      branch: 'main',
      vulnerabilities: [
        {
          id: 'GHSA-35jh-r3h4-6jhm',
          cve: null,
          packageName: 'lodash',
          severity: 'high',
          currentVersion: '4.17.15',
          targetSafeVersion: null,
        },
      ],
    },
  ];

  const jiraTickets = [
    {
      ticketKey: 'SEC-500',
      summary: 'Address lodash vulnerability',
      cve: 'CVE-2021-23337',
      packageName: 'lodash',
      url: 'https://jira.example.com/browse/SEC-500',
      status: 'Open',
    },
  ];

  const dependabotAlerts = [
    {
      alertNumber: 99,
      url: 'https://github.com/org/repo/security/dependabot/99',
      ghsaId: 'GHSA-35jh-r3h4-6jhm',
      cve: 'CVE-2021-23337',
      packageName: 'lodash',
      targetSafeVersion: '4.17.21',
    },
  ];

  const blended = blendVulnerabilitySources(branchReports, { jiraTickets, dependabotAlerts });
  const vuln = blended[0].vulnerabilities[0];

  assert.equal(vuln.cve, 'CVE-2021-23337');
  assert.equal(vuln.targetSafeVersion, '4.17.21');
  assert.equal(vuln.sources.jira.ticketKey, 'SEC-500');
  assert.equal(vuln.sources.dependabot.alertNumber, 99);
});

test('parseBranchMap: parses key=val and JSON string formats', () => {
  const parsedStr = parseBranchMap('main=8.3,release-0.11=8.2,release-0.10=8.1');
  assert.deepEqual(parsedStr.main, ['8.3']);
  assert.deepEqual(parsedStr['release-0.11'], ['8.2']);

  const parsedJson = parseBranchMap('{"main":["8.3"],"release-0.11":["8.2"]}');
  assert.deepEqual(parsedJson.main, ['8.3']);
});

test('isVersionCompatible: matches version strings correctly', () => {
  assert.equal(isVersionCompatible(['MTA 8.2.0', 'mta-8.2'], ['8.2.x', '8.2']), true);
  assert.equal(isVersionCompatible(['MTA 8.1.0'], ['8.2.x', '8.2']), false);
  assert.equal(isVersionCompatible(['MTA 8.1.0'], ['8.1']), true);
});

test('blendVulnerabilitySources: filters Jira tickets based on branch translation table', () => {
  const branchReports = [
    {
      branch: 'release-0.11',
      vulnerabilities: [{ id: 'GHSA-qs', packageName: 'qs', severity: 'high', cve: 'CVE-2026-82417' }],
    },
    {
      branch: 'release-0.10',
      vulnerabilities: [{ id: 'GHSA-qs', packageName: 'qs', severity: 'high', cve: 'CVE-2026-82417' }],
    },
  ];

  const jiraTickets = [
    {
      ticketKey: 'MTA-7680',
      summary: 'qs vulnerability [mta-8.2]',
      cve: 'CVE-2026-82417',
      packageName: 'qs',
      affectsVersions: ['MTA 8.2.0', 'mta-8.2', '8.2'],
      url: 'https://jira.example.com/browse/MTA-7680',
    },
    {
      ticketKey: 'MTA-7679',
      summary: 'qs vulnerability [mta-8.1]',
      cve: 'CVE-2026-82417',
      packageName: 'qs',
      affectsVersions: ['MTA 8.1.0', 'mta-8.1', '8.1'],
      url: 'https://jira.example.com/browse/MTA-7679',
    },
  ];

  const branchMap = {
    'release-0.11': ['8.2', 'mta-8.2', 'MTA 8.2'],
    'release-0.10': ['8.1', 'mta-8.1', 'MTA 8.1'],
  };

  const blended = blendVulnerabilitySources(branchReports, { jiraTickets, branchMap });

  // On release-0.11, it should match MTA-7680 (8.2)
  assert.equal(blended[0].vulnerabilities[0].sources.jira.ticketKey, 'MTA-7680');

  // On release-0.10, it should match MTA-7679 (8.1)
  assert.equal(blended[1].vulnerabilities[0].sources.jira.ticketKey, 'MTA-7679');
});

test('parseCollectorSettings: enables/disables collectors correctly', () => {
  // Default: all true
  assert.deepEqual(parseCollectorSettings({}, {}), { npmAudit: true, jira: true, dependabot: true });

  // Just Jira
  assert.deepEqual(parseCollectorSettings({ collectors: 'jira' }, {}), { npmAudit: false, jira: true, dependabot: false });

  // Just npm-audit
  assert.deepEqual(parseCollectorSettings({ collectors: 'npm-audit' }, {}), { npmAudit: true, jira: false, dependabot: false });

  // npm-audit and jira
  assert.deepEqual(parseCollectorSettings({ collectors: 'npm-audit,jira' }, {}), { npmAudit: true, jira: true, dependabot: false });

  // Disable flags
  assert.deepEqual(parseCollectorSettings({ noJira: true }, {}), { npmAudit: true, jira: false, dependabot: true });
  assert.deepEqual(parseCollectorSettings({ noNpmAudit: true }, {}), { npmAudit: false, jira: true, dependabot: true });

  // From file config array
  assert.deepEqual(parseCollectorSettings({}, { collectors: ['jira'] }), { npmAudit: false, jira: true, dependabot: false });
});

test('blendVulnerabilitySources: Jira-only run populates branch findings', () => {
  const branchReports = [
    {
      branch: 'release-0.11',
      vulnerabilities: [],
    },
  ];

  const jiraTickets = {
    branches: [
      {
        branch: 'release-0.11',
        tickets: [
          {
            ticketKey: 'MTA-7680',
            summary: 'CVE-2026-82417 qs vulnerability [mta-8.2]',
            cve: 'CVE-2026-82417',
            packageName: 'qs',
            status: 'New',
            affectsVersions: ['8.2'],
            url: 'https://jira.example.com/browse/MTA-7680',
          },
        ],
      },
    ],
  };

  const blended = blendVulnerabilitySources(branchReports, { jiraTickets, dependabotAlerts: [] });
  assert.equal(blended[0].vulnerabilities.length, 1);
  assert.equal(blended[0].vulnerabilities[0].id, 'MTA-7680');
  assert.equal(blended[0].vulnerabilities[0].cve, 'CVE-2026-82417');
  assert.equal(blended[0].vulnerabilities[0].packageName, 'qs');
  assert.equal(blended[0].summary.total, 1);
});

test('consolidateVulnerabilitiesByPackage: groups multiple CVEs and Jira tickets under one package', () => {
  const rawFindings = [
    {
      id: 'GHSA-1',
      cve: 'CVE-2026-67314',
      packageName: 'axios',
      severity: 'high',
      currentVersion: '1.6.0',
      targetSafeVersion: '1.7.4',
      title: 'Prototype Pollution in Basic Auth',
      sources: { jira: { ticketKey: 'MTA-7574', url: 'https://jira/MTA-7574' } },
      remediation: { strategy: 'bump-direct', targetPackage: 'axios', targetVersion: '1.7.4' },
    },
    {
      id: 'GHSA-2',
      cve: 'CVE-2026-67320',
      packageName: 'axios',
      severity: 'high',
      currentVersion: '1.6.0',
      targetSafeVersion: '1.7.2',
      title: 'Information disclosure in HTTP adapter',
      sources: { jira: { ticketKey: 'MTA-7573', url: 'https://jira/MTA-7573' } },
      remediation: { strategy: 'bump-direct', targetPackage: 'axios', targetVersion: '1.7.2' },
    },
  ];

  const consolidated = consolidateVulnerabilitiesByPackage(rawFindings);
  assert.equal(consolidated.length, 1);

  const axiosPkg = consolidated[0];
  assert.equal(axiosPkg.packageName, 'axios');
  assert.equal(axiosPkg.severity, 'high');
  assert.equal(axiosPkg.targetSafeVersion, '1.7.4');
  assert.equal(axiosPkg.cves.length, 2);
  assert.ok(axiosPkg.cves.includes('CVE-2026-67314'));
  assert.ok(axiosPkg.cves.includes('CVE-2026-67320'));
  assert.equal(axiosPkg.sources.jiraTickets.length, 2);
  assert.equal(axiosPkg.advisories.length, 2);
  assert.equal(axiosPkg.remediation.targetVersion, '1.7.4');
});

test('extractGhsaId and extractCveId: parses identifiers from URLs and text', () => {
  assert.equal(
    extractGhsaId('https://github.com/nodeca/js-yaml/security/advisories/GHSA-2883-xcg3-v3hh'),
    'GHSA-2883-XCG3-V3HH'
  );
  assert.equal(extractGhsaId('GHSA-4mjr-xmp4-gh2g in summary'), 'GHSA-4MJR-XMP4-GH2G');
  assert.equal(extractCveId('https://www.cve.org/CVERecord?id=CVE-2026-82417'), 'CVE-2026-82417');
});

test('calculateOptimalSafeVersion: picks highest patched version satisfying all advisories', () => {
  const advisories = [
    { targetSafeVersion: '1.7.2' },
    { targetSafeVersion: '1.7.4' },
    { targetSafeVersion: '1.6.8' },
  ];
  const optimal = calculateOptimalSafeVersion('1.6.0', advisories);
  assert.equal(optimal, '1.7.4');
});
test('lookupPackageInstalledInfo: detects dual Direct & Indirect dependency (like js-yaml)', () => {
  const pkgJson = {
    dependencies: {
      'js-yaml': '^4.1.0',
      'some-tool': '^1.0.0',
    },
  };

  const pkgLock = {
    packages: {
      '': {
        dependencies: { 'js-yaml': '^4.1.0', 'some-tool': '^1.0.0' },
      },
      'node_modules/js-yaml': {
        version: '4.1.0',
      },
      'node_modules/some-tool': {
        version: '1.0.0',
        dependencies: { 'js-yaml': '^3.14.1' },
      },
      'node_modules/some-tool/node_modules/js-yaml': {
        version: '3.14.1',
      },
    },
  };

  const info = lookupPackageInstalledInfo('js-yaml', pkgJson, pkgLock);
  assert.equal(info.isDirect, true);
  assert.equal(info.isIndirect, true);
  assert.equal(info.dependencyType, 'Direct & Indirect');
  assert.ok(info.currentVersion.includes('4.1.0'));
  assert.ok(info.currentVersion.includes('3.14.1'));
});

test('blendVulnerabilitySources: Jira findings assess actual lockfile versions and dual remediation', () => {
  const pkgJson = {
    dependencies: {
      'js-yaml': '^4.1.0',
      'some-tool': '^1.0.0',
    },
  };

  const pkgLock = {
    packages: {
      '': {
        dependencies: { 'js-yaml': '^4.1.0', 'some-tool': '^1.0.0' },
      },
      'node_modules/js-yaml': {
        version: '4.1.0',
      },
      'node_modules/some-tool': {
        version: '1.0.0',
        dependencies: { 'js-yaml': '^3.14.1' },
      },
      'node_modules/some-tool/node_modules/js-yaml': {
        version: '3.14.1',
      },
    },
  };

  const branchReports = [
    {
      branch: 'release-0.10',
      vulnerabilities: [],
      pkgJson,
      pkgLock,
    },
  ];

  const jiraTickets = {
    branches: [
      {
        branch: 'release-0.10',
        tickets: [
          {
            ticketKey: 'MTA-7652',
            summary: 'CVE-2026-84375 js-yaml DoS [mta-8.2]',
            cve: 'CVE-2026-84375',
            packageName: 'js-yaml',
            status: 'POST',
            affectsVersions: ['8.2'],
            targetSafeVersion: '4.3.2',
            url: 'https://jira.example.com/browse/MTA-7652',
          },
        ],
      },
    ],
  };

  const blended = blendVulnerabilitySources(branchReports, { jiraTickets, dependabotAlerts: [] });
  assert.equal(blended[0].vulnerabilities.length, 1);

  const jsYaml = blended[0].vulnerabilities[0];
  assert.equal(jsYaml.packageName, 'js-yaml');
  assert.equal(jsYaml.dependencyType, 'Direct & Indirect');
  assert.ok(jsYaml.currentVersion.includes('4.1.0'));
  assert.equal(jsYaml.targetSafeVersion, '4.3.2');
  assert.equal(jsYaml.remediation.strategy, 'bump-direct-and-lockfile');
  assert.equal(jsYaml.remediation.packageJsonChanges.length, 1);
  assert.equal(jsYaml.remediation.packageJsonChanges[0].package, 'js-yaml');
  assert.equal(jsYaml.remediation.packageJsonChanges[0].to, '^4.3.2');
  assert.ok(jsYaml.remediation.lockfileActions[0].includes('npm install js-yaml@^4.3.2 --package-lock-only'));
});

test('loadConfig: disables Jira collector when Jira configuration is incomplete', () => {
  // Missing baseUrl
  const confNoBase = loadConfig({
    collectors: 'jira',
    jiraBaseUrl: '',
    jiraApiToken: 'my-token',
  });
  assert.equal(confNoBase.collectors.jira, false);

  // Missing apiToken
  const confNoToken = loadConfig({
    collectors: 'jira',
    jiraBaseUrl: 'https://jira.example.com',
    jiraApiToken: '',
  });
  assert.equal(confNoToken.collectors.jira, false);

  // Complete configuration
  const confComplete = loadConfig({
    collectors: 'jira',
    jiraBaseUrl: 'https://jira.example.com',
    jiraApiToken: 'my-token',
  });
  assert.equal(confComplete.collectors.jira, true);
});

test('sortVulnerabilities: sorts by severity descending and package name ascending', () => {
  const items = [
    { packageName: 'zebra', severity: 'low' },
    { packageName: 'qs', severity: 'high' },
    { packageName: 'axios', severity: 'high' },
    { packageName: 'beta', severity: 'critical' },
    { packageName: 'alpha', severity: 'critical' },
  ];

  items.sort(sortVulnerabilities);
  assert.equal(items[0].packageName, 'alpha');
  assert.equal(items[1].packageName, 'beta');
  assert.equal(items[2].packageName, 'axios');
  assert.equal(items[3].packageName, 'qs');
  assert.equal(items[4].packageName, 'zebra');
});
