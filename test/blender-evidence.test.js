import test from 'node:test';
import assert from 'node:assert/strict';
import { blendVulnerabilitySources } from '../src/core/blender.js';
import { groupJiraTicketsByBranch } from '../src/collectors/jira.js';
import { groupDependabotAlertsByBranch } from '../src/collectors/dependabot.js';
import { generateRemediationPlan } from '../src/core/remediation-planner.js';
import { generateMarkdownReport, formatTargetFix } from '../src/report/markdown-reporter.js';

const ghsa = 'GHSA-2345-6789-CFGH';
const interval = (vulnerableRange, firstPatchedVersion) => ({ vulnerableRange, firstPatchedVersion });
function branch(name) {
  return {
    branch: name, baseCommit: 'a'.repeat(40),
    pkgJson: { name: 'app', dependencies: { leaf: '1.0.0', parent: '1.0.0' } },
    pkgLock: { lockfileVersion: 3, packages: {
      '': { name: 'app', dependencies: { leaf: '1.0.0', parent: '1.0.0' } },
      'node_modules/leaf': { version: '1.0.0' },
      'node_modules/parent': { version: '1.0.0', dependencies: { leaf: '^5.0.0' } },
      'node_modules/parent/node_modules/leaf': { version: '5.0.0' },
    } },
    vulnerabilities: [{ packageName: 'leaf', id: ghsa, currentVersion: '1.0.0',
      advisories: [{ id: ghsa, title: 'Leaf vulnerability', severity: 'moderate',
        vulnerableVersionRange: '<1.0.2', targetSafeVersion: '1.0.2' }],
      sources: { npmAudit: { advisoryId: ghsa, url: `https://github.com/advisories/${ghsa}` } },
    }],
  };
}

test('blender collates branch-local interval/patch pairs across all sources before planning', () => {
  const reports = [branch('main'), branch('release')];
  const before = JSON.stringify(reports);
  const jiraTickets = groupJiraTicketsByBranch([{
    ticketKey: 'SEC-1', packageName: 'leaf', ghsaId: ghsa, affectsVersions: ['2.0'],
    affectedVersions: [interval('>= 5.0.0, < 5.0.3', '5.0.3')],
    url: 'https://jira.example.test/browse/SEC-1',
  }], ['main', 'release'], { main: ['2.0'], release: ['1.0'] });
  const dependabotAlerts = groupDependabotAlertsByBranch([{
    alertNumber: 7, packageName: 'leaf', ghsaId: ghsa, severity: 'critical',
    affectedVersions: [interval('< 1.0.2', '1.0.2')],
    url: 'https://github.example.test/security/dependabot/7',
  }], ['release', 'main']);
  const blended = blendVulnerabilitySources(reports, { jiraTickets, dependabotAlerts });
  const pkg = blended[0].vulnerabilities[0];
  assert.equal(pkg.findings.length, 1);
  assert.equal(pkg.findings[0].severity, 'critical');
  assert.deepEqual(pkg.affectedVersions, [interval('<1.0.2', '1.0.2'), interval('>=5.0.0 <5.0.3', '5.0.3')]);
  assert.deepEqual(pkg.findings[0].constraints, pkg.affectedVersions);
  for (const source of ['npm-audit', 'jira', 'dependabot']) {
    assert.ok(pkg.findings[0].references.some((reference) => reference.source === source));
  }
  assert.deepEqual(blended[1].vulnerabilities[0].affectedVersions, [interval('<1.0.2', '1.0.2')]);
  assert.equal(JSON.stringify(reports), before, 'blending must not contaminate raw collector evidence');
  const report = { repository: {}, branches: blended };
  const plan = generateRemediationPlan(report, { publishedVersionsByBranch: new Map([
    ['main', new Map([['leaf', { versions: ['1.0.0', '1.0.2', '5.0.0', '5.0.3'], error: null }]])],
  ]) });
  assert.deepEqual(plan.branches[0].packages[0].resolutions.map(({ installedVersion, targetVersion }) => [installedVersion, targetVersion]),
    [['1.0.0', '1.0.2'], ['5.0.0', '5.0.3']]);
  assert.deepEqual(plan.branches[0].packages[0].findings, pkg.findings);
  const md = generateMarkdownReport(report);
  assert.ok(md.includes('>=5.0.0 <5.0.3'));
  assert.ok(md.includes('5.0.3'));
});

test('blender preserves range-only, contradictory and invalid evidence instead of inventing patch floors', () => {
  const raw = branch('main');
  raw.vulnerabilities[0].advisories = [{ id: ghsa, vulnerableVersionRange: '<1.0.4' }];
  const jiraTickets = groupJiraTicketsByBranch([{
    ticketKey: 'SEC-2', packageName: 'leaf', ghsaId: ghsa, branch: 'main',
    affectedVersions: [interval('<1.0.2', '1.0.2'), interval('invalid range', null)],
  }], ['main']);
  const [blended] = blendVulnerabilitySources([raw], { jiraTickets });
  const pkg = blended.vulnerabilities[0];
  assert.deepEqual(pkg.affectedVersions, [interval('<1.0.2', '1.0.2'), interval('<1.0.4', null), interval('invalid range', null)]);
  const plan = generateRemediationPlan({ repository: {}, branches: [blended] });
  assert.equal(plan.branches[0].packages[0].status, 'manual-review');
  assert.deepEqual(plan.branches[0].actions, []);
  assert.equal(formatTargetFix({ ...pkg, patchedVersions: ['99.0.0'], targetSafeVersion: '99.0.0' }), '_No fix_');
});
