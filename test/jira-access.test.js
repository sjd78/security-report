import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { fetchJiraCveTickets } from '../src/collectors/jira.js';

test('Jira access failures explicitly disclose that reports exclude Jira data', async (t) => {
  for (const scenario of [
    { name: 'expired token', statuses: [401], status: 401 },
    { name: 'forbidden', statuses: [403], status: 403 },
    { name: 'fallback authentication failure', statuses: [410, 401], status: 401 },
    { name: 'unavailable service', statuses: [503, 502], status: 502 },
    { name: 'network failure', statuses: [null] },
    { name: 'successful empty search', statuses: [200], success: true },
    { name: 'successful fallback', statuses: [410, 200], success: true },
  ]) {
    await t.test(scenario.name, async (t) => {
      let requests = 0;
      const warnings = [];
      t.mock.method(console, 'warn', (message) => warnings.push(message));
      const server = http.createServer((request, response) => {
        request.resume();
        const status = scenario.statuses[requests++];
        if (status === null) return response.destroy();
        response.writeHead(status ?? 500, { 'content-type': 'application/json' });
        response.end(JSON.stringify(status === 200 ? { issues: [] } : { errorMessages: ['Do not log response bodies or credentials'] }));
      });
      await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
      try {
        const result = await fetchJiraCveTickets({
          jira: { baseUrl: `http://127.0.0.1:${server.address().port}`, apiToken: 'expired-test-secret' },
          defaultBranches: ['main'],
        });
        assert.equal(result.totalTickets, 0);
        assert.equal(requests, scenario.statuses.length);
        if (scenario.success) assert.deepEqual(warnings, []);
        else {
          assert.equal(warnings.length, 1);
          assert.match(warnings[0], /could not access Jira/i);
          assert.match(warnings[0], /results will not include any data from Jira/i);
          if (scenario.status) assert.ok(warnings[0].includes(`HTTP ${scenario.status}`));
          assert.ok(!warnings[0].includes('expired-test-secret'));
          assert.ok(!warnings[0].includes('Do not log response bodies'));
        }
      } finally {
        await new Promise((resolve) => server.close(resolve));
      }
    });
  }
});
