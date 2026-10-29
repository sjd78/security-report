import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { execGit, withWorktree } from '../src/core/git-manager.js';
import { scanRepository, remediateRepository } from '../src/index.js';
import { startRegistry, fixturePackage } from './fixtures/registry.js';

test('Multi-branch scan writes reports and collector diagnostics', async () => {
  const tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-e2e-'));
  const localRepoPath = path.join(tmpBase, 'my-repo');
  const reportsDir = path.join(tmpBase, 'reports');
  const reposDir = path.join(tmpBase, 'REPOS');

  try {
    // 1. Initialize local mock repository
    fs.mkdirSync(localRepoPath, { recursive: true });
    await execGit(['init', '-b', 'main'], localRepoPath);
    await execGit(['config', 'user.name', 'Security Bot'], localRepoPath);
    await execGit(['config', 'user.email', 'bot@example.com'], localRepoPath);

    // Initial package.json and package-lock.json on main
    const mainPkg = {
      name: 'vulnerable-app',
      version: '1.0.0',
      dependencies: {
        semver: '5.0.0',
      },
    };
    const mainLock = {
      name: 'vulnerable-app',
      version: '1.0.0',
      lockfileVersion: 3,
      packages: {
        '': {
          name: 'vulnerable-app',
          version: '1.0.0',
          dependencies: { semver: '5.0.0' },
        },
        'node_modules/semver': {
          version: '5.0.0',
        },
      },
    };

    fs.writeFileSync(path.join(localRepoPath, 'package.json'), JSON.stringify(mainPkg, null, 2));
    fs.writeFileSync(path.join(localRepoPath, 'package-lock.json'), JSON.stringify(mainLock, null, 2));
    await execGit(['add', '.'], localRepoPath);
    await execGit(['commit', '-m', 'Initial commit on main'], localRepoPath);

    // Create branch release/1.0
    await execGit(['checkout', '-b', 'release/1.0'], localRepoPath);
    const releasePkg = {
      name: 'vulnerable-app',
      version: '0.9.0',
      dependencies: {
        semver: '5.0.0',
      },
    };
    fs.writeFileSync(path.join(localRepoPath, 'package.json'), JSON.stringify(releasePkg, null, 2));
    await execGit(['add', '.'], localRepoPath);
    await execGit(['commit', '-m', 'Release 1.0 commit'], localRepoPath);

    // Switch back to main
    await execGit(['checkout', 'main'], localRepoPath);

    // 2. Run scanRepository
    const scanResult = await scanRepository(localRepoPath, {
      branches: 'main,release/1.0',
      reposDir,
      reportsDir,
      debug: true,
      // Reporting integration is offline; collector behavior has dedicated fixtures.
      noConfigFile: true,
      collectors: 'none',
      githubToken: '',
    });

    assert.ok(scanResult);
    assert.equal(scanResult.report.summary.totalBranches, 2);
    assert.ok(fs.existsSync(scanResult.jsonPath));
    assert.ok(fs.existsSync(scanResult.mdPath));

    const jsonReport = JSON.parse(fs.readFileSync(scanResult.jsonPath, 'utf8'));
    assert.equal(jsonReport.branches.length, 2);
    // Verify debug collector outputs
    assert.ok(fs.existsSync(path.join(reportsDir, 'security-jira-collection.json')));
    assert.ok(fs.existsSync(path.join(reportsDir, 'security-dependabot-collection.json')));
    assert.ok(fs.existsSync(path.join(reportsDir, 'security-npm-audit-collection.json')));

  } finally {
    fs.rmSync(tmpBase, { recursive: true, force: true });
  }
});

test('scan snapshots preserve retained edits and record executable-plan base commits', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-plan-snapshot-'));
  const repo = path.join(tmp, 'repo');
  fs.mkdirSync(repo);
  try {
    await execGit(['init', '-b', 'main'], repo);
    await execGit(['config', 'user.name', 'Security Bot'], repo);
    await execGit(['config', 'user.email', 'bot@example.com'], repo);
    const pkg = { name: 'snapshot-app', version: '1.0.0' };
    fs.writeFileSync(path.join(repo, 'package.json'), JSON.stringify(pkg));
    fs.writeFileSync(path.join(repo, 'package-lock.json'), JSON.stringify({
      name: pkg.name, version: pkg.version, lockfileVersion: 3, packages: { '': pkg },
    }));
    await execGit(['add', '.'], repo);
    await execGit(['commit', '-m', 'Initial snapshot'], repo);
    await execGit(['branch', 'review'], repo);
    const { stdout: baseCommit } = await execGit(['rev-parse', 'main'], repo);
    let retained;
    await withWorktree(repo, 'review', async (dir) => {
      retained = dir;
      fs.writeFileSync(path.join(dir, 'retained-fix.txt'), 'uncommitted fix');
    }, { keepWorktree: true });

    const result = await scanRepository(repo, {
      noConfigFile: true, collectors: 'none', githubToken: '',
      branches: 'main,review', reportsDir: path.join(tmp, 'reports'),
    });
    const plan = JSON.parse(fs.readFileSync(result.remediationPlanPath, 'utf8'));
    assert.deepEqual(plan.branches.map((branch) => branch.baseCommit), [baseCommit, baseCommit]);
    assert.ok(plan.branches.every((branch) => branch.status === 'no-op'));
    assert.equal(fs.readFileSync(path.join(retained, 'retained-fix.txt'), 'utf8'), 'uncommitted fix');
    assert.equal((await execGit(['rev-parse', 'main'], repo)).stdout, baseCommit);
    assert.equal((await execGit(['rev-parse', 'review'], repo)).stdout, baseCommit);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('real npm scan produces actionable plans and preserves audit failures', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-plan-registry-'));
  const registry = await startRegistry(path.join(tmp, 'registry'));
  const previousEnv = Object.fromEntries(Object.keys(registry.env).map((key) => [key, process.env[key]]));
  Object.assign(process.env, registry.env);
  const repo = path.join(tmp, 'repo');
  fs.mkdirSync(repo);
  try {
    await execGit(['init', '-b', 'main'], repo);
    await execGit(['config', 'user.name', 'Security Bot'], repo);
    await execGit(['config', 'user.email', 'bot@example.com'], repo);
    const pkg = { name: 'fixture-app', version: '1.0.0', dependencies: { [fixturePackage]: '1.0.0' } };
    fs.writeFileSync(path.join(repo, 'package.json'), JSON.stringify(pkg));
    fs.writeFileSync(path.join(repo, 'package-lock.json'), JSON.stringify(registry.packageLock()));
    await execGit(['add', '.'], repo);
    await execGit(['commit', '-m', 'Vulnerable dependency'], repo);
    const { stdout: baseCommit } = await execGit(['rev-parse', 'HEAD'], repo);
    const options = {
      noConfigFile: true, collectors: 'npm-audit', githubToken: '',
      githubApiUrl: `${registry.url}/github`, branches: 'main', reportsDir: path.join(tmp, 'reports'),
    };
    const result = await scanRepository(repo, options);
    const [branch] = result.remediationPlan.branches;
    assert.equal(branch.baseCommit, baseCommit);
    assert.equal(branch.status, 'ready');
    assert.equal(branch.packages[0].status, 'ready');
    assert.ok(branch.packages[0].findings.some((finding) => finding.cve === 'CVE-2026-12345'));
    assert.ok(branch.actions.some((action) => action.type === 'update-dependency'
      && action.package === fixturePackage && action.expectedRange === '1.0.0' && action.targetRange === '1.0.1'));
    assert.equal(JSON.parse(fs.readFileSync(path.join(repo, 'package.json'))).dependencies[fixturePackage], '1.0.0');
    registry.state.failAudit = true;
    const failed = await scanRepository(repo, options);
    assert.equal(failed.remediationPlan.branches[0].status, 'blocked');
    assert.ok(failed.remediationPlan.branches[0].blockers.some((reason) => /audit/i.test(reason)));
  } finally {
    for (const [key, value] of Object.entries(previousEnv)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
    await registry.close();
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('saved plans publish verified PRs idempotently, reject stale bases, and retain failed verification', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-execution-e2e-'));
  const registry = await startRegistry(path.join(tmp, 'registry'));
  const previousEnv = Object.fromEntries(Object.keys(registry.env).map((key) => [key, process.env[key]]));
  Object.assign(process.env, registry.env);
  const repo = path.join(tmp, 'repo');
  const remote = path.join(tmp, 'remote.git');
  fs.mkdirSync(repo);
  fs.mkdirSync(remote);
  try {
    await execGit(['init', '--bare', '-b', 'main'], remote);
    await execGit(['init', '-b', 'main'], repo);
    await execGit(['config', 'user.name', 'Security Bot'], repo);
    await execGit(['config', 'user.email', 'bot@example.com'], repo);
    fs.writeFileSync(path.join(repo, 'package.json'), JSON.stringify({
      name: 'fixture-app', version: '1.0.0', dependencies: { [fixturePackage]: '1.0.0' },
      scripts: { prepare: `node -e "require('fs').writeFileSync('${path.join(tmp, 'unexpected-script')}', 'ran')"` },
    }));
    fs.writeFileSync(path.join(repo, 'package-lock.json'), JSON.stringify(registry.packageLock()));
    await execGit(['add', '.'], repo);
    await execGit(['commit', '-m', 'Vulnerable dependency'], repo);
    await execGit(['remote', 'add', 'origin', 'https://github.com/fixture/app.git'], repo);
    await execGit(['config', `url.file://${remote}.insteadOf`, 'https://github.com/fixture/app.git'], repo);
    await execGit(['push', '-u', 'origin', 'main'], repo);
    const { stdout: base } = await execGit(['rev-parse', 'main'], repo);
    const options = {
      noConfigFile: true, collectors: 'npm-audit', githubToken: '', branches: 'main',
      githubApiUrl: `${registry.url}/github`, reportsDir: path.join(tmp, 'reports'),
    };
    const scanned = await scanRepository(repo, options);
    const executeOptions = { ...options, plan: scanned.remediationPlanPath, createPr: true, githubToken: 'fixture-token',
      prTitleTemplate: '{targetBranch}: fix {targetPackages} — {summary}' };
    const dry = await remediateRepository(repo, { ...executeOptions, dryRun: true });
    assert.equal(dry.results.branches[0].verified, false);
    assert.equal(registry.state.pullRequests.length, 0);
    assert.equal((await execGit(['rev-parse', 'main'], repo)).stdout, base);

    const published = await remediateRepository(repo, executeOptions);
    const result = published.results.branches[0];
    assert.equal(result.status, 'published');
    assert.equal(result.execution.verified, true);
    assert.deepEqual(result.execution.resolved[0].installedVersions, ['1.0.1']);
    assert.equal((await execGit(['rev-parse', 'main'], remote)).stdout, base);
    const headManifest = JSON.parse((await execGit(['show', `${result.head}:package.json`], remote)).stdout);
    const headLock = JSON.parse((await execGit(['show', `${result.head}:package-lock.json`], remote)).stdout);
    assert.equal(headManifest.dependencies[fixturePackage], '1.0.1');
    assert.equal(headLock.packages[`node_modules/${fixturePackage}`].version, '1.0.1');
    assert.equal(registry.state.pullRequests[0].base.ref, 'main');
    assert.ok(registry.state.pullRequests[0].title.startsWith(`main: fix ${fixturePackage}`));
    assert.ok(registry.state.pullRequests[0].body.includes('CVE-2026-12345'));
    assert.ok(registry.state.pullRequests[0].body.includes('GHSA-2345-6789-CFGH'));
    assert.equal(fs.existsSync(path.join(tmp, 'unexpected-script')), false);

    const repeated = await remediateRepository(repo, {
      ...executeOptions, prTitleTemplate: 'Reviewed {targetBranch}: {targetPackages}',
    });
    assert.equal(registry.state.pullRequests.length, 1);
    assert.equal(registry.state.pullRequests[0].title, `Reviewed main: ${fixturePackage}`);
    assert.equal(repeated.results.branches[0].pullRequest.created, false);
    assert.equal(repeated.results.branches[0].commit.commitHash, result.commit.commitHash);

    // An ownership trailer is not permission to publish unrelated edits in the same manifest.
    await execGit(['checkout', result.head], repo);
    const ownedMessage = (await execGit(['log', '-1', '--format=%B'], repo)).stdout;
    const changedManifest = JSON.parse(fs.readFileSync(path.join(repo, 'package.json')));
    changedManifest.description = 'Unplanned user edits';
    fs.writeFileSync(path.join(repo, 'package.json'), JSON.stringify(changedManifest));
    await execGit(['add', 'package.json'], repo);
    await execGit(['commit', '-m', ownedMessage], repo);
    const tamperedCommit = (await execGit(['rev-parse', 'HEAD'], repo)).stdout;
    await execGit(['checkout', '--detach'], repo);
    await assert.rejects(() => remediateRepository(repo, executeOptions), /unplanned manifest changes/);
    assert.equal(registry.state.pullRequests[0].title, `Reviewed main: ${fixturePackage}`);
    await execGit(['update-ref', `refs/heads/${result.head}`, result.commit.commitHash, tamperedCommit], repo);

    await execGit(['checkout', 'main'], repo);
    fs.writeFileSync(path.join(repo, 'README.md'), 'New upstream commit');
    await execGit(['add', 'README.md'], repo);
    await execGit(['commit', '-m', 'Upstream changed'], repo);
    await execGit(['push', 'origin', 'main'], repo);
    await assert.rejects(() => remediateRepository(repo, executeOptions), /Stale remediation plan/);
    assert.equal(registry.state.pullRequests.length, 1);
    const fresh = await scanRepository(repo, options);
    registry.state.failAudit = true;
    await assert.rejects(() => remediateRepository(repo, {
      ...executeOptions, plan: fresh.remediationPlanPath,
    }), /audit/i);
    const failure = JSON.parse(fs.readFileSync(path.join(tmp, 'reports/security-remediation-results.json')));
    assert.equal(failure.branches[0].status, 'failed');
    assert.ok(fs.existsSync(failure.branches[0].worktreeDir));
    assert.equal(registry.state.pullRequests.length, 1);
  } finally {
    for (const [key, value] of Object.entries(previousEnv)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
    await registry.close();
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
