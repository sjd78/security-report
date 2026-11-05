import test from 'node:test';
import assert from 'node:assert/strict';
import { fetchJiraCveTickets, groupJiraTicketsByBranch, parseJiraIssues } from '../src/collectors/jira.js';
import { getBranchFindings } from '../src/collectors/collection.js';

const repository = { owner: 'example', name: 'app', url: 'https://github.com/example/app' };

test('Jira uses structured package identity for CVE links and disambiguates only validated hints', async (t) => {
  for (const scenario of [
    { name: 'CVE link corrects text guess', hint: 'versions', cveLink: true, names: ['proxy-addr'], expected: 'proxy-addr' },
    { name: 'multi-package advisory validates a hint', hint: 'proxy-addr', names: ['other', 'proxy-addr'], expected: 'proxy-addr' },
    { name: 'multi-package advisory cannot guess without a hint', names: ['other', 'proxy-addr'], expected: null },
    { name: 'unavailable advisory preserves text fallback', hint: 'proxy-addr', unavailable: true, expected: 'proxy-addr' },
    { name: 'description advisory link corrects text guess', hint: 'versions', descriptionLink: true, names: ['proxy-addr'], expected: 'proxy-addr' },
  ]) {
    await t.test(scenario.name, async (t) => {
      const ghsa = 'GHSA-35JH-R3H4-6JHM';
      t.mock.method(globalThis, 'fetch', async (url) => {
        if (url.includes('/search/jql?')) return Response.json({ issues: [{
          key: 'SEC-700', fields: {
            summary: `${scenario.hint ? `Fix in ${scenario.hint}` : 'Security tracking'} [8.2]`,
            description: scenario.descriptionLink ? `https://github.com/advisories/${ghsa}` : '',
          },
        }] });
        if (url.endsWith('/remotelink')) return Response.json(scenario.descriptionLink ? [] : [{
          object: { url: scenario.cveLink ? 'https://www.cve.org/CVERecord?id=CVE-2026-12345' : `https://github.com/advisories/${ghsa}` },
        }]);
        if (scenario.unavailable) return new Response(null, { status: 503 });
        if (url.startsWith('https://api.osv.dev/v1/vulns/')) {
          assert.equal(url, 'https://api.osv.dev/v1/vulns/CVE-2026-12345');
          return Response.json({ id: 'CVE-2026-12345', affected: scenario.names.map((name) => ({
            package: { ecosystem: 'npm', name },
            ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '2.0.8' }] }],
          })) });
        }
        assert.equal(url, `https://github.example.test/advisories/${ghsa}`);
        return Response.json({ ghsa_id: ghsa, vulnerabilities: scenario.names.map((name) => ({
          package: { ecosystem: 'npm', name }, vulnerable_version_range: '<2.0.8',
          first_patched_version: '2.0.8',
        })) });
      });
      const collection = await fetchJiraCveTickets({
        jira: { baseUrl: 'https://jira.example.test', apiToken: 'test-only' },
        githubApiUrl: 'https://github.example.test', githubToken: '',
        branchMap: { release: ['8.2'] },
      }, { branches: ['release'] });
      assert.equal(collection.branches[0].packages[0].packageName, scenario.expected);
      const [finding] = getBranchFindings(collection, 'release');
      assert.equal(finding.ticketKey, 'SEC-700');
      if (!scenario.unavailable && scenario.expected) assert.equal(finding.targetSafeVersion, '2.0.8');
    });
  }
});

test('tracker titles identify the package before description prose can supply a false name', () => {
  for (const packageName of ['proxy-addr', '@scope/proxy-addr']) {
    for (const suffix of [' vulnerability', ': vulnerability']) {
      const tickets = parseJiraIssues({ issues: [{
        key: 'SEC-600',
        fields: {
          summary: `CVE-2026-12345 product/ui: ${packageName}${suffix} [mta-8.2]`,
          description: 'In versions 1.0.0 through 2.0.0, a vulnerability exists.',
        },
      }] }, 'https://jira.example.test');
      const collection = groupJiraTicketsByBranch(tickets, ['release'], { release: ['8.2'] });
      assert.equal(collection.branches[0].packages[0].packageName, packageName);
      assert.equal(getBranchFindings(collection, 'release')[0].ticketKey, 'SEC-600');
    }
  }
});

test('Jira collection groups native tickets by repository, branch and package without flat copies', () => {
  const tickets = parseJiraIssues({
    issues: [
      {
        key: 'SEC-101',
        fields: {
          summary: 'Fix CVE-2021-23337 in lodash [mta-8.2]',
          description: { type: 'doc', content: [{ type: 'paragraph', content: [{ type: 'text', text: 'Security tracking' }] }] },
          status: { name: 'In Progress' },
          labels: ['Security'],
          versions: [{ name: 'MTA 8.2' }],
        },
      },
      {
        key: 'SEC-102',
        fields: {
          summary: 'Fix CVE-2020-8203 in lodash',
          versions: [{ name: 'MTA 8.2' }],
        },
      },
      {
        key: 'SEC-103',
        fields: {
          summary: 'Fix CVE-2019-10744 in lodash',
          versions: [{ name: 'MTA 8.1' }],
        },
      },
    ],
  }, 'https://jira.example.test');
  const collection = groupJiraTicketsByBranch(tickets, ['release-0.11', 'release-0.10'], {
    'release-0.11': ['8.2'],
    'release-0.10': '8.1',
  }, repository);

  assert.equal(collection.repository, repository);
  assert.equal(collection.totalTickets, 3);
  assert.equal(Object.hasOwn(collection, 'allTickets'), false);
  assert.deepEqual(collection.unassigned, []);
  assert.deepEqual(collection.branches.map(({ branch, mappedVersions, ticketCount }) => ({ branch, mappedVersions, ticketCount })), [
    { branch: 'release-0.11', mappedVersions: ['8.2'], ticketCount: 2 },
    { branch: 'release-0.10', mappedVersions: ['8.1'], ticketCount: 1 },
  ]);
  assert.equal(collection.branches[0].packages.length, 1);
  assert.equal(collection.branches[0].packages[0].packageName, 'lodash');
  assert.deepEqual(collection.branches[0].packages[0].findings.map(({ ticketKey }) => ticketKey), ['SEC-101', 'SEC-102']);
  assert.deepEqual(collection.branches[1].packages[0].findings.map(({ ticketKey }) => ticketKey), ['SEC-103']);
  assert.deepEqual(getBranchFindings(collection, 'release-0.11'), tickets.slice(0, 2));
  assert.deepEqual(getBranchFindings(collection, 'release-0.10'), tickets.slice(2));
  assert.deepEqual(getBranchFindings(collection, 'missing'), []);

  for (const branch of collection.branches) {
    assert.equal(Object.hasOwn(branch, 'tickets'), false);
    for (const { findings } of branch.packages) {
      for (const finding of findings) {
        assert.equal(Object.hasOwn(finding, 'packageName'), false);
        assert.deepEqual(Object.keys(finding).filter((key) => /cve/i.test(key)), ['cve']);
        assert.match(finding.cve, /^CVE-/);
      }
    }
  }
  assert.equal(tickets[0].packageName, 'lodash');
  assert.equal(tickets[0].cve, 'CVE-2021-23337');
  assert.equal(tickets[0].status, 'In Progress');
  assert.equal(tickets[0].url, 'https://jira.example.test/browse/SEC-101');
  assert.deepEqual(tickets[0].labels, ['Security']);
  assert.ok(tickets[0].affectsVersions.includes('mta-8.2'));
});

test('Jira collection does not broadcast tickets without mapped version evidence', () => {
  const tickets = [
    { ticketKey: 'SEC-201', packageName: 'lodash', cve: 'CVE-2021-23337', affectsVersions: ['8.2'] },
    { ticketKey: 'SEC-202', packageName: 'lodash', cve: 'CVE-2020-8203', affectsVersions: [] },
    { ticketKey: 'SEC-203', packageName: 'lodash', cve: 'CVE-2019-10744' },
    { ticketKey: 'SEC-204', packageName: 'lodash', cve: 'CVE-2018-16487', affectsVersions: [' ', ''] },
  ];
  const branches = ['main', 'release-0.11', 'empty-map'];
  const withoutMap = groupJiraTicketsByBranch(tickets, branches);
  assert.equal(withoutMap.repository, null);
  assert.ok(withoutMap.branches.every(({ ticketCount, packages }) => ticketCount === 0 && packages.length === 0));
  assert.deepEqual(withoutMap.unassigned[0].findings.map(({ ticketKey }) => ticketKey), tickets.map(({ ticketKey }) => ticketKey));

  const collection = groupJiraTicketsByBranch(tickets, branches, {
    'release-0.11': ['8.2'],
    'empty-map': ['', ' '],
  });
  assert.deepEqual(getBranchFindings(collection, 'main'), []);
  assert.deepEqual(getBranchFindings(collection, 'empty-map'), []);
  assert.deepEqual(getBranchFindings(collection, 'release-0.11'), [tickets[0]]);
  assert.deepEqual(collection.unassigned[0].findings.map(({ ticketKey }) => ticketKey), ['SEC-202', 'SEC-203', 'SEC-204']);
});

test('explicit Jira branch context matches exactly and cannot leak into a compatible different branch', () => {
  const tickets = [
    { ticketKey: 'SEC-301', packageName: 'lodash', branch: 'main', cve: 'CVE-2021-23337' },
    { ticketKey: 'SEC-302', packageName: 'lodash', branch: 'release-0.10', affectsVersions: ['8.2'], cve: 'CVE-2020-8203' },
    { ticketKey: 'SEC-303', packageName: 'lodash', branch: 'not-requested', affectsVersions: ['8.2'], cve: 'CVE-2019-10744' },
  ];
  const collection = groupJiraTicketsByBranch(tickets, ['main', 'release-0.11', 'release-0.10'], {
    'release-0.11': ['8.2'],
    'release-0.10': ['8.1'],
  });
  assert.deepEqual(getBranchFindings(collection, 'main'), [tickets[0]]);
  assert.deepEqual(getBranchFindings(collection, 'release-0.11'), []);
  assert.deepEqual(getBranchFindings(collection, 'release-0.10'), [tickets[1]]);
  assert.deepEqual(collection.unassigned, [{
    packageName: 'lodash',
    findings: [{ ticketKey: 'SEC-303', branch: 'not-requested', affectsVersions: ['8.2'], cve: 'CVE-2019-10744' }],
  }]);
});

test('Jira collection retains unmatched and unknown-package evidence, even without ticket keys', () => {
  const tickets = [
    { ticketKey: 'SEC-401', packageName: 'zod', affectsVersions: ['9.0'], cve: 'CVE-2026-10001', remoteLinks: ['https://example.test/evidence'] },
    { ticketKey: 'SEC-402', packageName: null, affectsVersions: ['9.0'], cve: 'CVE-2026-10002' },
    { packageName: 'lodash', affectsVersions: ['8.2'], cve: 'CVE-2021-23337' },
    { affectsVersions: ['9.0'], cve: 'CVE-2026-10003' },
    { ticketKey: 'SEC-403', packageName: null, affectsVersions: ['8.2'], cve: 'CVE-2026-10004' },
  ];
  const collection = groupJiraTicketsByBranch(tickets, ['release-0.11'], { 'release-0.11': ['8.2'] });
  assert.equal(collection.totalTickets, 5);
  assert.deepEqual(collection.unassigned, [
    {
      packageName: null,
      findings: [
        { ticketKey: 'SEC-402', affectsVersions: ['9.0'], cve: 'CVE-2026-10002' },
        { affectsVersions: ['9.0'], cve: 'CVE-2026-10003' },
      ],
    },
    {
      packageName: 'zod',
      findings: [{ ticketKey: 'SEC-401', affectsVersions: ['9.0'], cve: 'CVE-2026-10001', remoteLinks: ['https://example.test/evidence'] }],
    },
  ]);
  assert.deepEqual(collection.branches[0].packages.map(({ packageName }) => packageName), [null, 'lodash']);
  assert.deepEqual(getBranchFindings(collection, 'release-0.11'), [tickets[4], tickets[2]]);
});

test('fetchJiraCveTickets preserves repository and grouped native advisory enrichment', async (t) => {
  const ghsaId = 'GHSA-35JH-R3H4-6JHM';
  const advisoryUrl = `https://github.com/advisories/${ghsaId}`;
  const remoteLinkKeys = [];
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    if (url.startsWith('https://jira.example.test/rest/api/3/search/jql?')) {
      assert.equal(options.headers.Authorization, 'Bearer test-only-token');
      return Response.json({ issues: [
        { key: 'SEC-501', fields: { summary: 'Fix in versions [8.2]', labels: ['Security'], versions: [{ name: 'MTA 8.2' }] } },
        { key: 'SEC-502', fields: { summary: 'Security tracking [8.2]', versions: [{ name: 'MTA 8.2' }] } },
        { key: 'SEC-503', fields: { summary: 'Update dependency lodash [8.2]', versions: [{ name: 'MTA 8.2' }] } },
      ] });
    }
    const issue = url.match(/^https:\/\/jira\.example\.test\/rest\/api\/3\/issue\/(SEC-50[123])\/remotelink$/);
    if (issue) {
      remoteLinkKeys.push(issue[1]);
      return Response.json([{ object: { url: advisoryUrl } }, { object: { url: 'https://example.test/context' } }]);
    }
    if (url === `https://github.example.test/advisories/${ghsaId}`) {
      return Response.json({
        ghsa_id: ghsaId,
        cve_id: 'CVE-2021-23337',
        html_url: advisoryUrl,
        severity: 'high',
        vulnerabilities: [{
          package: { ecosystem: 'npm', name: 'lodash' },
          vulnerable_version_range: '<4.17.21',
          first_patched_version: '4.17.21',
        }],
      });
    }
    assert.fail(`Unexpected external request: ${url}`);
  });

  const collection = await fetchJiraCveTickets({
    jira: { baseUrl: 'https://jira.example.test/', apiToken: 'test-only-token' },
    githubToken: '',
    githubApiUrl: 'https://github.example.test',
    branchMap: { 'release-0.11': ['8.2'], 'release-0.10': ['8.1'] },
  }, { repository, branches: ['release-0.11', 'release-0.10'] });

  assert.equal(collection.repository, repository);
  assert.equal(collection.totalTickets, 3);
  assert.equal(Object.hasOwn(collection, 'allTickets'), false);
  assert.deepEqual(collection.unassigned, []);
  assert.deepEqual(remoteLinkKeys.sort(), ['SEC-501', 'SEC-502', 'SEC-503']);
  assert.equal(collection.branches[0].packages.length, 1);
  assert.equal(collection.branches[0].packages[0].packageName, 'lodash');
  assert.equal(collection.branches[0].ticketCount, 3);
  assert.deepEqual(getBranchFindings(collection, 'release-0.10'), []);
  const findings = getBranchFindings(collection, 'release-0.11');
  assert.deepEqual(findings.map(({ ticketKey }) => ticketKey), ['SEC-501', 'SEC-502', 'SEC-503']);
  for (const finding of findings) {
    assert.equal(finding.cve, 'CVE-2021-23337');
    assert.equal(finding.ghsaId, ghsaId);
    assert.equal(finding.advisoryUrl, advisoryUrl);
    assert.equal(finding.vulnerableVersionRange, '<4.17.21');
    assert.deepEqual(finding.affectedVersions, [{ vulnerableRange: '<4.17.21', firstPatchedVersion: '4.17.21' }]);
    assert.equal(finding.targetSafeVersion, '4.17.21');
    assert.deepEqual(finding.remoteLinks, [advisoryUrl, 'https://example.test/context']);
    assert.deepEqual(Object.keys(finding).filter((key) => /cve/i.test(key)), ['cve']);
  }
});

test('fetchJiraCveTickets preserves repository in empty, disabled and failed collections', async (t) => {
  for (const scenario of [
    { name: 'missing base URL', jira: {}, requests: 0 },
    { name: 'missing credentials', jira: { baseUrl: 'https://jira.example.test' }, requests: 0 },
    { name: 'empty search', jira: { baseUrl: 'https://jira.example.test', apiToken: 'test-only-token' }, requests: 1, status: 200 },
    { name: 'authentication failure', jira: { baseUrl: 'https://jira.example.test', apiToken: 'test-only-token' }, requests: 1, status: 401 },
    { name: 'transport failure', jira: { baseUrl: 'https://jira.example.test', apiToken: 'test-only-token' }, requests: 1 },
  ]) {
    await t.test(scenario.name, async (t) => {
      let requests = 0;
      t.mock.method(console, 'warn', () => {});
      t.mock.method(globalThis, 'fetch', async () => {
        requests += 1;
        if (!scenario.status) throw new Error('Jira is unavailable');
        return Response.json({ issues: [] }, { status: scenario.status });
      });
      const collection = await fetchJiraCveTickets({
        jira: scenario.jira,
        branchMap: { main: ['8.2'] },
      }, { repository, branches: ['main'] });
      assert.equal(requests, scenario.requests);
      assert.deepEqual(collection, {
        repository,
        branches: [{ branch: 'main', mappedVersions: ['8.2'], ticketCount: 0, packages: [] }],
        unassigned: [],
        totalTickets: 0,
      });
    });
  }
});
