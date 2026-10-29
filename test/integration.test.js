import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { execGit, withWorktree, stageAndCommit } from '../src/core/git-manager.js';
import { scanRepository } from '../src/index.js';
import { generateCommitMessage } from '../src/core/commit-generator.js';
import { remediateBranch } from '../src/core/remediator.js';
import { startRegistry, fixturePackage } from './fixtures/registry.js';

test('End-to-End: Multi-branch scan, report, and commit message flow', async () => {
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

    // 3. Test Commit Message generation with mock remediation
    const mockRemResult = {
      resolved: [
        {
          id: 'GHSA-c2qf-rxjj-qqgw',
          cve: 'CVE-2022-25883',
          packageName: 'semver',
          severity: 'high',
          currentVersion: '5.0.0',
          targetSafeVersion: '7.5.4',
          title: 'Regular Expression Denial of Service in semver',
          url: 'https://github.com/advisories/GHSA-c2qf-rxjj-qqgw',
          dependencyPaths: ['semver@5.0.0'],
          sources: {
            jira: { ticketKey: 'SEC-101', url: 'https://jira.corp/browse/SEC-101' },
            dependabot: { alertNumber: 5, url: 'https://github.com/org/repo/security/dependabot/5' },
          },
        },
      ],
      appliedChanges: [
        { package: 'semver', section: 'dependencies', from: '5.0.0', to: '^7.5.4' },
      ],
      remaining: [],
    };

    const commitMsg = generateCommitMessage('main', mockRemResult);
    assert.ok(commitMsg.includes('fix(deps): remediate 1 vulnerable package on branch main'));
    assert.ok(commitMsg.includes('CVE-2022-25883'));
    assert.ok(commitMsg.includes('SEC-101'));
    assert.ok(commitMsg.includes('Dependabot: #5'));
    assert.ok(commitMsg.includes('Updated semver 5.0.0 -> ^7.5.4 in dependencies'));

    // 4. Test worktree remediation & commit execution on main
    await withWorktree(localRepoPath, 'main', async (wtPath) => {
      const branchReport = {
        branch: 'main',
        vulnerabilities: mockRemResult.resolved.map((r) => ({
          ...r,
          remediation: {
            strategy: 'bump-direct',
            packageJsonChanges: mockRemResult.appliedChanges,
          },
        })),
      };

      const remResult = await remediateBranch(wtPath, branchReport, { dryRun: true });
      assert.equal(remResult.appliedChanges.length, 1);
      assert.equal(remResult.appliedChanges[0].package, 'semver');

      // Actual modification & commit
      const pkgPath = path.join(wtPath, 'package.json');
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      pkg.dependencies.semver = '^7.5.4';
      fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2));

      const commitResult = await stageAndCommit(wtPath, {
        message: commitMsg,
        files: ['package.json'],
        branch: 'main',
      });

      assert.equal(commitResult.committed, true);
      assert.ok(commitResult.commitHash);
    });

    // The branch ref itself must carry the commit, not just the worktree HEAD.
    const { stdout: logOut } = await execGit(['log', '-n', '1', '--oneline', 'main'], localRepoPath);
    assert.ok(logOut.includes('fix(deps): remediate 1 vulnerable package on branch main'));
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
