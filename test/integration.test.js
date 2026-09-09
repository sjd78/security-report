import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { execGit, withWorktree, stageAndCommit } from '../src/core/git-manager.js';
import { scanRepository } from '../src/index.js';
import { generateCommitMessage } from '../src/core/commit-generator.js';
import { remediateBranch } from '../src/core/remediator.js';

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

    // Verify commit on main branch
    const { stdout: logOut } = await execGit(['log', '-n', '1', '--oneline'], localRepoPath);
    assert.ok(logOut.includes('fix(deps): remediate 1 vulnerable package on branch main'));
  } finally {
    fs.rmSync(tmpBase, { recursive: true, force: true });
  }
});
