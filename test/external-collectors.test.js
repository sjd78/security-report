import test from 'node:test';
import assert from 'node:assert/strict';
import { parseJiraIssues, createJiraAuthHeader } from '../src/collectors/jira.js';
import { parseDependabotAlerts } from '../src/collectors/dependabot.js';
import { blendVulnerabilitySources, matchJiraTicket, matchDependabotAlert, isVersionCompatible } from '../src/core/blender.js';
import { parseBranchMap } from '../src/config.js';

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
