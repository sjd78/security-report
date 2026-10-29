import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { renderPrTitle, generatePullRequestBody, publishPullRequest } from '../src/core/pull-request.js';

const token = 'private-test-token-never-print';
const prUrl = 'https://github.example.test/example-org/project/pull/42';
const publishOptions = {
  org: 'example-org', name: 'project',
  head: 'security-remediation/release-1.0-abc', base: 'release/1.0',
  title: 'fix(deps): remediate security findings', body: 'Motivating findings and observed verification.',
  githubToken: token,
};

async function createApi(t, handler) {
  const requests = [];
  const failures = [];
  const server = http.createServer(async (request, response) => {
    try {
      let body = '';
      for await (const chunk of request) body += chunk;
      const captured = { method: request.method, url: new URL(request.url, 'http://localhost'), headers: request.headers, body: body ? JSON.parse(body) : undefined };
      requests.push(captured);
      const result = await handler(captured, response, request);
      if (response.destroyed || response.writableEnded) return;
      response.writeHead(result?.status || 200, result?.headers || { 'Content-Type': 'application/json' });
      response.end(result?.raw !== undefined ? result.raw : JSON.stringify(result?.body));
    } catch (error) {
      failures.push(error);
      if (!response.destroyed && !response.writableEnded) {
        response.writeHead(500, { 'Content-Type': 'application/json' });
        response.end(JSON.stringify({ message: 'Protocol assertion failed' }));
      }
    }
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    const closing = new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    server.closeAllConnections();
    await closing;
    assert.deepEqual(failures, []);
  });
  return { githubApiUrl: `http://127.0.0.1:${server.address().port}/api/v3/`, requests };
}

function branchPlan() {
  return {
    branch: 'release/1.0', baseCommit: 'a'.repeat(40), status: 'ready',
    summary: 'Update vulnerable package and parent dependency.',
    packages: [{
      packageName: 'vulnerable-package', status: 'ready', currentVersion: '1.0.0',
      installedVersions: ['1.0.0', '1.1.0'], targetSafeVersion: '1.2.0',
      dependencyPaths: ['packages/app/package.json/dependencies/parent/vulnerable-package'],
      findings: [{
        id: 'GHSA-abcd-efgh-2345', title: 'Prototype pollution', severity: 'high',
        cve: 'CVE-2026-12345', cves: ['CVE-2026-12345', 'CVE-2026-23456'],
        vulnerableVersionRange: '<1.2.0', patchedVersions: ['1.2.0'],
        url: 'https://github.com/advisories/GHSA-abcd-efgh-2345',
        sources: {
          npmAudit: [{ url: 'https://www.npmjs.com/advisories/1001' }, { urls: ['https://www.npmjs.com/advisories/1002'], advisories: [{ url: 'https://advisories.example.test/npm' }] }],
          jira: { ticketKey: ['SEC-1', 'SEC-2'], url: ['https://jira.example.test/browse/SEC-1', 'https://jira.example.test/browse/SEC-2'] },
          jiraTickets: [{ ticketKey: 'SEC-3', url: 'https://jira.example.test/browse/SEC-3' }],
          dependabot: { alertNumber: 7, url: 'https://github.example.test/org/repo/security/dependabot/7' },
          dependabotAlerts: [{ alertNumber: 8, url: 'https://github.example.test/org/repo/security/dependabot/8' }],
          advisoryUrls: ['https://advisories.example.test/merged'],
        },
      }, {
        id: 'second-advisory', title: 'Resource exhaustion', severity: 'moderate',
        url: 'https://advisories.example.test/second',
        sources: [{ source: 'jira', ticketKey: 'SEC-4', url: 'https://jira.example.test/browse/SEC-4' }],
      }],
    }, {
      packageName: 'unfixable', status: 'no-fix', reasons: ['No patched release exists.'],
      findings: [{ id: 'no-fix', title: 'Unpatched issue', url: 'https://advisories.example.test/no-fix' }],
    }, {
      packageName: 'manual-package', status: 'manual-review', reasons: ['Parent dependency needs manual review.'],
      findings: [{ id: 'manual', sources: { jira: { ticketKey: 'SEC-5', url: 'https://jira.example.test/browse/SEC-5' } } }],
    }, {
      packageName: 'absent-package', status: 'not-installed', reasons: ['Absent from scanned dependency graph.'], findings: [],
    }],
    actions: [{
      type: 'update-dependency', file: 'packages/app/package.json', section: 'dependencies', package: 'parent',
      expectedRange: '^2.0.0', targetRange: '^2.1.0', packageNames: ['vulnerable-package'], findingIds: ['GHSA-abcd-efgh-2345'],
    }, {
      type: 'set-override', file: 'package.json', package: 'vulnerable-package', scope: ['parent'],
      expectedValue: null, targetVersion: '1.2.0', packageNames: ['vulnerable-package'], findingIds: ['second-advisory'],
    }, { type: 'update-lockfile', package: 'vulnerable-package', packageNames: ['vulnerable-package'], findingIds: [] }],
  };
}

function executionResult() {
  return {
    branch: 'release/1.0', dryRun: false, verified: true,
    resolved: [{ ...branchPlan().packages[0], installedVersions: ['1.3.0', '1.4.0'] }],
    appliedChanges: [{ file: 'packages/app/package.json', package: 'parent', section: 'dependencies', from: '^2.0.0', to: '^2.1.0' }],
    lockfileUpdates: ['vulnerable-package'], touchedFiles: ['packages/app/package.json', 'package-lock.json'],
    remaining: [], unresolved: branchPlan().packages.slice(1), isClean: true,
    postAuditSummary: { critical: 0, high: 0, moderate: 0, low: 0, total: 0 },
  };
}

test('renderPrTitle substitutes only supported tokens without config or environment lookups', () => {
  const values = { targetBranch: 'release/1.0', targetPackages: ['@scope/one', 'two'], summary: 'patch two vulnerabilities' };
  assert.equal(renderPrTitle('  fix: {summary} on {targetBranch} [{targetPackages}]  ', values), 'fix: patch two vulnerabilities on release/1.0 [@scope/one, two]');
  assert.equal(renderPrTitle('{targetBranch}: {summary}; {summary}', values), 'release/1.0: patch two vulnerabilities; patch two vulnerabilities');
  assert.equal(renderPrTitle('A literal dependency title'), 'A literal dependency title');
  assert.equal(renderPrTitle('{summary}', { summary: 'literal {targetBranch}' }), 'literal {targetBranch}');
});

test('renderPrTitle rejects unknown or malformed tokens and empty or multiline output', () => {
  for (const template of ['{branch}', '{targetPackage}', '{}', '{{summary}}', '{summary', 'summary}', '{summary.toUpperCase()}']) {
    assert.throws(() => renderPrTitle(template, { summary: 'fix' }), /template token/);
  }
  for (const summary of ['', '   ', 'first\nsecond', 'first\rsecond', 'first\u2028second', 'first\u2029second']) {
    assert.throws(() => renderPrTitle('{summary}', { summary }), /non-empty and single-line/);
  }
  assert.throws(() => renderPrTitle('{summary}'), /Missing pull request title value: summary/);
  assert.throws(() => renderPrTitle(null), /template must be a string/);
  assert.throws(() => renderPrTitle('line one\n{summary}', { summary: 'line two' }), /single-line/);
});

test('generatePullRequestBody preserves all motivations across singular, array, and merged sources', () => {
  const body = generatePullRequestBody(branchPlan(), executionResult());
  for (const expected of [
    'a'.repeat(40), 'release/1.0', 'vulnerable-package', 'Prototype pollution', 'Resource exhaustion',
    'https://github.com/advisories/GHSA-abcd-efgh-2345',
    'https://nvd.nist.gov/vuln/detail/CVE-2026-12345', 'https://nvd.nist.gov/vuln/detail/CVE-2026-23456',
    'https://www.npmjs.com/advisories/1001', 'https://www.npmjs.com/advisories/1002',
    'https://advisories.example.test/npm', 'https://advisories.example.test/merged', 'https://advisories.example.test/second',
    ...[1, 2, 3, 4, 5].map((number) => `https://jira.example.test/browse/SEC-${number}`),
    ...[7, 8].map((number) => `https://github.example.test/org/repo/security/dependabot/${number}`),
    'packages/app/package.json', '^2.0.0', '^2.1.0', 'overrides / parent / vulnerable-package',
    'No patched release exists.', 'manual-review', 'not-installed', 'https://advisories.example.test/no-fix',
  ]) assert.ok(body.includes(expected), `Missing body motivation/detail: ${expected}`);
  assert.match(body, /npm audit/);
  assert.match(body, /Jira SEC-1, SEC-2/);
  assert.match(body, /Dependabot #7/);
  assert.match(body, /observed installed versions: `1\.3\.0`, `1\.4\.0`/);
  assert.doesNotMatch(body, /observed installed versions: `1\.2\.0`/);
  assert.match(body, /reported \*\*0\*\* remaining vulnerability findings/);
  assert.match(body, /does not close or resolve external Jira or Dependabot records/);
  assert.equal((body.match(/### `unfixable`/g) || []).length, 1);
});

test('generatePullRequestBody discloses remaining audit findings instead of claiming repository-wide success', () => {
  const result = executionResult();
  result.isClean = false;
  result.remaining = [{ packageName: 'other-package', id: 'CVE-2026-99999', title: 'Unplanned issue', severity: 'critical', url: 'https://advisories.example.test/unplanned' }];
  result.postAuditSummary = { critical: 1, high: 0, moderate: 0, low: 0, total: 1 };
  const body = generatePullRequestBody(branchPlan(), result);
  assert.match(body, /reported \*\*1\*\* remaining vulnerability finding/);
  assert.match(body, /other-package/);
  assert.match(body, /Unplanned issue/);
  assert.ok(body.includes('https://advisories.example.test/unplanned'));
  assert.doesNotMatch(body, /reported \*\*0\*\*/);
});

test('generatePullRequestBody treats dry runs and absent verification as unverified regardless of supplied success fields', () => {
  for (const overrides of [{ dryRun: true }, { verified: false }, { verified: undefined }]) {
    const body = generatePullRequestBody(branchPlan(), { ...executionResult(), ...overrides });
    assert.match(body, /unverified/i);
    assert.doesNotMatch(body, /observed installed versions|reported \*\*0\*\*|Observed manifest changes/);
    assert.match(body, /Planned safe target: `1\.2\.0`/);
    assert.match(body, /No patched release exists/);
  }
});

test('generatePullRequestBody does not infer a zero audit from isClean or missing remaining findings', () => {
  for (const overrides of [{ postAuditSummary: undefined }, { remaining: undefined }, { isClean: false }, { remaining: [{ packageName: 'unexpected' }] }]) {
    const body = generatePullRequestBody(branchPlan(), { ...executionResult(), ...overrides });
    assert.doesNotMatch(body, /reported \*\*0\*\*/);
    assert.match(body, /no repository-wide clean-audit claim is made/);
  }
});

test('generatePullRequestBody preserves normalized source arrays at the Finding.sources root', () => {
  const plan = branchPlan();
  plan.packages[0].findings = [{
    id: 'CVE-2026-11111', title: 'Array sources',
    sources: [
      { jira: [{ ticketKey: 'SEC-10', url: 'https://jira.example.test/browse/SEC-10' }, { ticketKey: 'SEC-11', url: 'https://jira.example.test/browse/SEC-11' }] },
      { dependabot: [{ alertNumber: 10, url: 'https://github.example.test/org/repo/security/dependabot/10' }] },
      { npmAudit: { url: ['https://advisories.example.test/a', 'https://advisories.example.test/b'] } },
    ],
  }];
  const body = generatePullRequestBody(plan);
  for (const url of ['https://jira.example.test/browse/SEC-10', 'https://jira.example.test/browse/SEC-11', 'https://github.example.test/org/repo/security/dependabot/10', 'https://advisories.example.test/a', 'https://advisories.example.test/b', 'https://nvd.nist.gov/vuln/detail/CVE-2026-11111']) assert.ok(body.includes(url));
});

test('generatePullRequestBody retains additional executor disclosures when the saved plan already contains the package', () => {
  const result = executionResult();
  result.unresolved = [{
    packageName: 'unfixable', status: 'no-fix',
    reasons: ['The registry still has no safe version.'],
    findings: [{ id: 'additional-finding', url: 'https://advisories.example.test/additional' }],
  }];
  const body = generatePullRequestBody(branchPlan(), result);
  assert.match(body, /No patched release exists/);
  assert.match(body, /The registry still has no safe version/);
  assert.ok(body.includes('https://advisories.example.test/no-fix'));
  assert.ok(body.includes('https://advisories.example.test/additional'));
  assert.equal((body.match(/### `unfixable`/g) || []).length, 1);
});

test('generatePullRequestBody escapes reference URL delimiters without dropping the link', () => {
  const plan = branchPlan();
  plan.packages[0].findings = [{ id: 'url-delimiters', url: 'https://advisories.example.test/finding(detail)' }];
  assert.ok(generatePullRequestBody(plan).includes('https://advisories.example.test/finding%28detail%29'));
});

test('generatePullRequestBody rejects unknown saved-plan action types rather than inventing applied behavior', () => {
  const plan = branchPlan();
  plan.actions = [{ type: 'shell-command', command: 'npm install' }];
  assert.throws(() => generatePullRequestBody(plan), /Unsupported saved-plan action/);
});

test('publishPullRequest creates once then updates the matching open PR through Enterprise REST', async (t) => {
  let stored;
  const api = await createApi(t, ({ method, url, headers, body }) => {
    assert.equal(headers.authorization, `Bearer ${token}`);
    assert.equal(headers.accept, 'application/vnd.github+json');
    assert.equal(headers['x-github-api-version'], '2022-11-28');
    if (method === 'GET') {
      assert.equal(url.pathname, '/api/v3/repos/example-org/project/pulls');
      assert.equal(url.searchParams.get('state'), 'open');
      assert.equal(url.searchParams.get('head'), `example-org:${publishOptions.head}`);
      assert.equal(url.searchParams.get('base'), publishOptions.base);
      assert.equal(url.searchParams.get('per_page'), '100');
      assert.equal(body, undefined);
      return { body: stored ? [stored] : [] };
    }
    assert.equal(headers['content-type'], 'application/json');
    if (method === 'POST') {
      assert.equal(stored, undefined, 'must not duplicate an existing PR');
      assert.equal(url.pathname, '/api/v3/repos/example-org/project/pulls');
      assert.deepEqual(body, { head: publishOptions.head, base: publishOptions.base, title: publishOptions.title, body: publishOptions.body });
      stored = { number: 42, html_url: prUrl, state: 'open', head: { ref: body.head }, base: { ref: body.base } };
      return { status: 201, body: stored };
    }
    assert.equal(method, 'PATCH');
    assert.equal(url.pathname, '/api/v3/repos/example-org/project/pulls/42');
    assert.deepEqual(body, { title: 'Updated security title', body: 'Updated verified findings.' });
    return { body: stored };
  });
  assert.deepEqual(await publishPullRequest({ ...publishOptions, githubApiUrl: api.githubApiUrl }), { number: 42, url: prUrl, created: true });
  assert.deepEqual(await publishPullRequest({ ...publishOptions, title: 'Updated security title', body: 'Updated verified findings.', githubApiUrl: api.githubApiUrl }), { number: 42, url: prUrl, created: false });
  assert.deepEqual(api.requests.map(({ method }) => method), ['GET', 'POST', 'GET', 'PATCH']);
});

test('publishPullRequest rejects HTTP failures without including response contents, status text, or credentials', async (t) => {
  for (const phase of ['lookup', 'creation', 'update']) {
    await t.test(phase, async (t) => {
      const api = await createApi(t, ({ method }, response) => {
        if (method === 'GET' && phase !== 'lookup') return { body: phase === 'update' ? [{ number: 42, html_url: prUrl }] : [] };
        response.statusMessage = `Server echoed ${token}`;
        return { status: phase === 'lookup' ? 401 : phase === 'creation' ? 422 : 503, body: { message: `Authorization: Bearer ${token}` } };
      });
      await assert.rejects(publishPullRequest({ ...publishOptions, githubApiUrl: api.githubApiUrl }), (error) => {
        assert.match(error.message, new RegExp(`pull request ${phase} failed \\(HTTP (401|422|503)\\)`));
        assert.ok(!String(error.stack).includes(token));
        assert.doesNotMatch(error.message, /Authorization|Server echoed/);
        return true;
      });
      assert.equal(api.requests.length, phase === 'lookup' ? 1 : 2);
    });
  }
});

test('publishPullRequest rejects malformed JSON and malformed lookup or mutation responses', async (t) => {
  const cases = [
    { label: 'lookup JSON', lookup: { raw: `{not json ${token}` } },
    { label: 'lookup object', lookup: { body: { number: 42 } } },
    { label: 'lookup null item', lookup: { body: [null] } },
    { label: 'lookup invalid number', lookup: { body: [{ number: 0, html_url: prUrl }] } },
    { label: 'lookup missing URL', lookup: { body: [{ number: 42 }] } },
    { label: 'lookup unsafe URL', lookup: { body: [{ number: 42, html_url: 'javascript:alert(1)' }] } },
    { label: 'lookup credential URL', lookup: { body: [{ number: 42, html_url: 'https://secret@example.test/pr/42' }] } },
    { label: 'lookup wrong head', lookup: { body: [{ number: 42, html_url: prUrl, head: { ref: 'unrelated' } }] } },
    { label: 'lookup wrong base', lookup: { body: [{ number: 42, html_url: prUrl, base: { ref: 'unrelated' } }] } },
    { label: 'lookup closed PR', lookup: { body: [{ number: 42, html_url: prUrl, state: 'closed' }] } },
    { label: 'duplicate matches', lookup: { body: [{ number: 42, html_url: prUrl }, { number: 43, html_url: prUrl }] } },
    { label: 'creation JSON', lookup: { body: [] }, mutation: { raw: 'not JSON' } },
    { label: 'creation shape', lookup: { body: [] }, mutation: { body: { html_url: prUrl } } },
    { label: 'creation URL', lookup: { body: [] }, mutation: { body: { number: 42, html_url: 'not-a-url' } } },
    { label: 'creation closed PR', lookup: { body: [] }, mutation: { body: { number: 42, html_url: prUrl, state: 'closed' } } },
    { label: 'creation wrong head', lookup: { body: [] }, mutation: { body: { number: 42, html_url: prUrl, head: { ref: 'other-branch' } } } },
    { label: 'update changes number', lookup: { body: [{ number: 42, html_url: prUrl }] }, mutation: { body: { number: 43, html_url: prUrl } } },
  ];
  for (const scenario of cases) {
    await t.test(scenario.label, async (t) => {
      const api = await createApi(t, ({ method }) => method === 'GET' ? scenario.lookup : scenario.mutation);
      await assert.rejects(publishPullRequest({ ...publishOptions, githubApiUrl: api.githubApiUrl }), (error) => {
        assert.match(error.message, /malformed|multiple matching/);
        assert.ok(!String(error.stack).includes(token));
        return true;
      });
      assert.equal(api.requests.length, scenario.mutation ? 2 : 1);
    });
  }
});

test('publishPullRequest does not follow redirects or leak network failure details', async (t) => {
  await t.test('redirect', async (t) => {
    const api = await createApi(t, () => ({ status: 302, headers: { Location: `/capture/${token}` }, body: {} }));
    await assert.rejects(publishPullRequest({ ...publishOptions, githubApiUrl: api.githubApiUrl }), (error) => {
      assert.match(error.message, /lookup request failed/);
      assert.ok(!String(error.stack).includes(token));
      return true;
    });
    assert.equal(api.requests.length, 1);
  });
  await t.test('connection closed', async (t) => {
    const api = await createApi(t, (_, response) => { response.destroy(); });
    await assert.rejects(publishPullRequest({ ...publishOptions, githubApiUrl: api.githubApiUrl }), (error) => {
      assert.match(error.message, /lookup request failed/);
      assert.ok(!String(error.stack).includes(token));
      return true;
    });
    assert.equal(api.requests.length, 1);
  });
});

test('publishPullRequest validates inputs before any API request', async (t) => {
  const api = await createApi(t, () => ({ body: [] }));
  for (const overrides of [
    { org: '' }, { org: '../escape' }, { name: '..' }, { name: 'repo/escape' },
    { head: '' }, { head: 'bad\nbranch' }, { head: 'bad:branch' }, { head: '../escape' }, { head: 'branch.lock' },
    { base: 'bad branch' }, { base: publishOptions.head }, { title: '' }, { title: 'line\none' },
    { body: '' }, { githubToken: '' }, { githubToken: 'secret\nheader' },
    { githubApiUrl: 'file:///tmp/api' }, { githubApiUrl: 'https://secret@example.test/api' },
    { githubApiUrl: `${api.githubApiUrl}?secret=${token}` }, { githubApiUrl: `${api.githubApiUrl}#fragment` },
  ]) {
    await assert.rejects(publishPullRequest({ ...publishOptions, githubApiUrl: api.githubApiUrl, ...overrides }));
  }
  assert.equal(api.requests.length, 0);
});
