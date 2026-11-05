import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { fetchDependabotAlerts, groupDependabotAlertsByBranch, parseDependabotAlerts } from '../src/collectors/dependabot.js';
import { getBranchFindings } from '../src/collectors/collection.js';

const rawAlerts = [
  {
    number: 42,
    html_url: 'https://github.com/acme/app/security/dependabot/42',
    state: 'open',
    dependency: {
      package: { name: 'lodash', ecosystem: 'npm' },
      manifest_path: 'client/package.json',
    },
    security_advisory: {
      ghsa_id: 'GHSA-35jh-r3h4-6jhm',
      cve_id: 'CVE-2021-23337',
      summary: 'Command injection in lodash',
      severity: 'high',
    },
    security_vulnerability: {
      vulnerable_version_range: '< 4.17.21',
      first_patched_version: { identifier: '4.17.21' },
    },
  },
];

async function startGitHub(t, { metadata = { default_branch: 'main' }, metadataStatus = 200, alertsStatus = 200 } = {}) {
  const requests = [];
  const server = http.createServer((request, response) => {
    request.resume();
    requests.push({ url: request.url, headers: request.headers });
    response.setHeader('Content-Type', 'application/json');
    if (request.url === '/repos/acme/app') {
      response.writeHead(metadataStatus);
      response.end(JSON.stringify(metadata));
    } else if (request.url === '/repos/acme/app/dependabot/alerts?state=open&per_page=100') {
      response.writeHead(alertsStatus);
      response.end(JSON.stringify(alertsStatus === 200 ? rawAlerts : { message: 'Not Found' }));
    } else {
      response.writeHead(404);
      response.end(JSON.stringify({ message: 'Unexpected request' }));
    }
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  t.after(async () => {
    const closing = new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    server.closeAllConnections();
    await closing;
  });
  return {
    requests,
    options: {
      org: 'acme',
      name: 'app',
      githubToken: 'loopback-only-token',
      githubApiUrl: `http://127.0.0.1:${server.address().port}`,
    },
  };
}

function assertSingleCopy(collection, defaultBranch, expectedFindings = parseDependabotAlerts(rawAlerts)) {
  assert.equal(collection.defaultBranch, defaultBranch);
  assert.equal(collection.totalAlerts, expectedFindings.length);
  assert.equal(Object.hasOwn(collection, 'allAlerts'), false);
  assert.equal(collection.branches.filter((branch) => branch.isDefaultBranch).length, 1);
  let findingCount = 0;
  for (const branch of collection.branches) {
    assert.equal(Object.hasOwn(branch, 'alerts'), false);
    assert.equal(branch.isDefaultBranch, branch.branch === defaultBranch);
    const findings = getBranchFindings(collection, branch.branch);
    assert.deepEqual(findings, branch.isDefaultBranch ? expectedFindings : []);
    assert.equal(branch.alertCount, findings.length);
    findingCount += findings.length;
    for (const pkg of branch.packages) {
      for (const finding of pkg.findings) {
        assert.equal(Object.hasOwn(finding, 'packageName'), false);
        assert.equal(Object.hasOwn(finding, 'cves'), false);
      }
    }
    if (!branch.isDefaultBranch) assert.match(branch.note, new RegExp(defaultBranch));
  }
  assert.equal(findingCount, expectedFindings.length);
}

test('Dependabot groups each native finding once under repository, branch, and sorted package', () => {
  const repository = { org: 'acme', name: 'app', fullName: 'acme/app' };
  const alerts = [
    { packageName: 'zod', alertNumber: 3, cve: null },
    { packageName: 'lodash', alertNumber: 1, cve: 'CVE-2021-23337' },
    { packageName: null, alertNumber: 4, summary: 'Unknown package evidence' },
    { packageName: 'lodash', alertNumber: 2, vulnerableVersionRange: '<4.17.21' },
  ];
  const collection = groupDependabotAlertsByBranch(alerts, ['main', 'main', 'release-0.10'], 'main', repository);
  assert.equal(collection.repository, repository);
  assert.deepEqual(collection.branches.map((branch) => branch.branch), ['main', 'release-0.10']);
  assert.deepEqual(collection.branches[0].packages.map((pkg) => pkg.packageName), [null, 'lodash', 'zod']);
  assertSingleCopy(collection, 'main', [alerts[2], alerts[1], alerts[3], alerts[0]]);
  assert.equal(alerts[1].packageName, 'lodash');
});

test('Dependabot does not treat main and master as interchangeable default branches', () => {
  const alerts = parseDependabotAlerts(rawAlerts);
  for (const defaultBranch of ['main', 'master']) {
    const collection = groupDependabotAlertsByBranch(alerts, ['master', 'main'], defaultBranch);
    assertSingleCopy(collection, defaultBranch, alerts);
  }
  const masterOnly = groupDependabotAlertsByBranch(alerts, ['master']);
  assert.deepEqual(masterOnly.branches.map((branch) => branch.branch), ['master', 'main']);
  assertSingleCopy(masterOnly, 'main', alerts);
});

test('Dependabot release-first scans discover the API default with the configured API and authentication', async (t) => {
  const { options, requests } = await startGitHub(t);
  const collection = await fetchDependabotAlerts({ ...options, branches: ['release-0.10', 'main', 'master'] });
  assertSingleCopy(collection, 'main');
  assert.deepEqual(collection.repository, { org: 'acme', name: 'app', fullName: 'acme/app' });
  assert.deepEqual(requests.map((request) => request.url), [
    '/repos/acme/app',
    '/repos/acme/app/dependabot/alerts?state=open&per_page=100',
  ]);
  for (const request of requests) {
    assert.equal(request.headers.authorization, 'Bearer loopback-only-token');
    assert.equal(request.headers.accept, 'application/vnd.github+json');
    assert.equal(request.headers['x-github-api-version'], '2022-11-28');
  }
});

test('Dependabot discovers custom default branches instead of assuming main or master', async (t) => {
  const { options } = await startGitHub(t, { metadata: { default_branch: 'develop' } });
  const collection = await fetchDependabotAlerts({ ...options, branches: ['release-0.10', 'main', 'master', 'develop'] });
  assertSingleCopy(collection, 'develop');
});

test('Dependabot retains the real default branch when only release branches are selected', async (t) => {
  const { options } = await startGitHub(t, { metadata: { default_branch: 'trunk' } });
  const collection = await fetchDependabotAlerts({ ...options, branches: ['release-0.10', 'release-0.11'] });
  assert.deepEqual(collection.branches.map((branch) => branch.branch), ['release-0.10', 'release-0.11', 'trunk']);
  assertSingleCopy(collection, 'trunk');
});

test('Dependabot trusts an explicitly supplied default and preserves the supplied repository', async (t) => {
  const { options, requests } = await startGitHub(t, { metadataStatus: 503 });
  const repository = { org: 'acme', name: 'app', fullName: 'acme/app', localPath: '/example/app' };
  const collection = await fetchDependabotAlerts({
    ...options,
    repository,
    branches: ['release-0.10', 'main', 'master'],
    defaultBranch: 'stable',
  });
  assertSingleCopy(collection, 'stable');
  assert.equal(collection.repository, repository);
  assert.deepEqual(requests.map((request) => request.url), ['/repos/acme/app/dependabot/alerts?state=open&per_page=100']);
  assert.equal(Object.hasOwn(collection, 'note'), false);
});

test('Dependabot metadata failures disclose a main fallback without assigning findings to a requested release', async (t) => {
  for (const scenario of [
    { metadataStatus: 503, expectedNote: /HTTP 503/ },
    { metadata: {}, expectedNote: /did not include a default branch/ },
  ]) {
    await t.test(scenario.expectedNote.source, async (t) => {
      const { options } = await startGitHub(t, scenario);
      const collection = await fetchDependabotAlerts({ ...options, branches: ['release-0.10'] });
      assertSingleCopy(collection, 'main');
      assert.match(collection.note, scenario.expectedNote);
      assert.match(collection.note, /Falling back to main/);
    });
  }
});

test('Dependabot skips network access without repository coordinates or a token', async (t) => {
  const { options, requests } = await startGitHub(t);
  for (const missing of [{ githubToken: '' }, { org: null }, { name: null }]) {
    const collection = await fetchDependabotAlerts({ ...options, ...missing, branches: ['release-0.10'] });
    assertSingleCopy(collection, 'main', []);
  }
  const collection = await fetchDependabotAlerts({ ...options, githubToken: '', defaultBranch: 'stable' });
  assertSingleCopy(collection, 'stable', []);
  assert.deepEqual(requests, []);
});

test('Dependabot preserves discovered default branch metadata when alerts are unavailable', async (t) => {
  const { options } = await startGitHub(t, { metadata: { default_branch: 'master' }, alertsStatus: 404 });
  const collection = await fetchDependabotAlerts({ ...options, branches: ['main'] });
  assertSingleCopy(collection, 'master', []);
});
