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
    for (const kind of ['jira', 'dependabot', 'npm-audit']) {
      const collection = JSON.parse(fs.readFileSync(path.join(reportsDir, `debug-collection-${kind}.json`), 'utf8'));
      assert.equal(collection.repository.fullName, 'local/my-repo');
      assert.deepEqual(collection.branches.map(({ branch }) => branch), ['main', 'release/1.0']);
      assert.ok(collection.branches.every(({ packages }) => packages.length === 0));
    }
    const blended = JSON.parse(fs.readFileSync(path.join(reportsDir, 'debug-blended.json'), 'utf8'));
    assert.equal(blended.repository.fullName, 'local/my-repo');
    assert.deepEqual(blended.branches.map(({ branch }) => branch), ['main', 'release/1.0']);
    assert.ok(blended.branches.every(({ packages, baseCommit }) => packages.length === 0 && baseCommit));
    for (const filename of ['collection-jira.json', 'collection-dependabot.json', 'collection-npm-audit.json']) {
      assert.equal(fs.existsSync(path.join(reportsDir, filename)), false);
    }

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
    for (const filename of ['debug-collection-jira.json', 'debug-collection-dependabot.json', 'debug-collection-npm-audit.json', 'debug-blended.json']) {
      assert.equal(fs.existsSync(path.join(tmp, 'reports', filename)), false);
    }
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
      noConfigFile: true, collectors: 'npm-audit', githubToken: '', debug: true,
      githubApiUrl: `${registry.url}/github`, branches: 'main', reportsDir: path.join(tmp, 'reports'),
    };
    const result = await scanRepository(repo, options);
    const [branch] = result.remediationPlan.branches;
    assert.equal(branch.baseCommit, baseCommit);
    assert.equal(branch.status, 'ready');
    assert.equal(branch.packages[0].status, 'ready');
    assert.ok(branch.packages[0].findings.some((finding) => finding.cves.includes('CVE-2026-12345')));
    assert.ok(branch.actions.some((action) => action.type === 'update-dependency'
      && action.package === fixturePackage && action.expectedRange === '1.0.0' && action.targetRange === '1.0.1'));
    assert.ok(registry.requests.some((request) => request.method === 'GET' && request.path.startsWith(`/${fixturePackage}`)),
      'scan resolves the branch npm release catalog while the worktree registry config is active');
    assert.equal(JSON.parse(fs.readFileSync(path.join(repo, 'package.json'))).dependencies[fixturePackage], '1.0.0');
    const collectionPath = path.join(options.reportsDir, 'debug-collection-npm-audit.json');
    const collection = JSON.parse(fs.readFileSync(collectionPath, 'utf8'));
    const collectedBranch = collection.branches[0];
    assert.equal(collectedBranch.branch, 'main');
    assert.equal(collectedBranch.baseCommit, baseCommit);
    assert.equal(collection.repository.fullName, 'local/repo');
    assert.equal(collectedBranch.packages[0].packageName, fixturePackage);
    assert.deepEqual(collectedBranch.packages[0].installedVersions, ['1.0.0']);
    assert.equal(collectedBranch.packages[0].instances[0].location, `node_modules/${fixturePackage}`);
    assert.equal(collectedBranch.packages[0].instances[0].origins[0].packageJsonPath, 'package.json');
    assert.deepEqual(collectedBranch.packages[0].findings.flatMap(({ cves }) => cves), ['CVE-2026-12345']);
    assert.equal('pkgLock' in collectedBranch, false);
    assert.equal('arboristTree' in collectedBranch, false);
    const blendedPath = path.join(options.reportsDir, 'debug-blended.json');
    const blended = JSON.parse(fs.readFileSync(blendedPath, 'utf8'));
    assert.deepEqual(blended.repository, collection.repository);
    const [blendedBranch] = blended.branches;
    assert.equal(blendedBranch.branch, 'main');
    assert.equal(blendedBranch.baseCommit, baseCommit);
    assert.equal('pkgLock' in blendedBranch, false);
    assert.equal('arboristTree' in blendedBranch, false);
    const [blendedPackage] = blendedBranch.packages;
    assert.equal(blendedPackage.packageName, fixturePackage);
    assert.deepEqual(blendedPackage.findings, branch.packages[0].findings);
    const reportPackage = result.report.branches[0].vulnerabilities.find(({ packageName }) => packageName === fixturePackage);
    assert.deepEqual(blendedPackage.findings, reportPackage.findings);
    assert.deepEqual(blendedPackage.affectedVersions, reportPackage.affectedVersions);
    assert.ok(blendedPackage.affectedVersions.some(({ vulnerableRange, firstPatchedVersion }) =>
      vulnerableRange && firstPatchedVersion === '1.0.1'));
    assert.deepEqual(blendedPackage.affectedVersions, blendedPackage.findings
      .flatMap(({ constraints }) => constraints)
      .filter((constraint, index, all) => all.findIndex((other) =>
        other.vulnerableRange === constraint.vulnerableRange
        && other.firstPatchedVersion === constraint.firstPatchedVersion) === index));
    registry.state.failAudit = true;
    const failed = await scanRepository(repo, options);
    assert.equal(failed.remediationPlan.branches[0].status, 'blocked');
    assert.ok(failed.remediationPlan.branches[0].blockers.some((reason) => /audit/i.test(reason)));
    const failedCollection = JSON.parse(fs.readFileSync(collectionPath, 'utf8'));
    assert.deepEqual(failedCollection.branches[0].packages, []);
    assert.match(failedCollection.branches[0].error, /audit/i);
    const failedBlended = JSON.parse(fs.readFileSync(blendedPath, 'utf8'));
    assert.deepEqual(failedBlended.branches[0].packages, []);
    assert.match(failedBlended.branches[0].error, /audit/i);
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

test('branch/package/type filters publish only selected fixes and disclose excluded packages', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-selected-e2e-'));
  const otherPackage = 'security-report-other-fixture';
  const registry = await startRegistry(path.join(tmp, 'registry'), { packageNames: [fixturePackage, otherPackage] });
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
    const lock = registry.packageLock();
    fs.writeFileSync(path.join(repo, 'package.json'), JSON.stringify(lock.packages['']));
    fs.writeFileSync(path.join(repo, 'package-lock.json'), JSON.stringify(lock));
    await execGit(['add', '.'], repo);
    await execGit(['commit', '-m', 'Two vulnerable dependencies'], repo);
    await execGit(['branch', 'release/1.0'], repo);
    await execGit(['remote', 'add', 'origin', 'https://github.com/fixture/app.git'], repo);
    await execGit(['config', `url.file://${remote}.insteadOf`, 'https://github.com/fixture/app.git'], repo);
    await execGit(['push', 'origin', 'main', 'release/1.0'], repo);
    const base = (await execGit(['rev-parse', 'main'], repo)).stdout;
    const options = {
      noConfigFile: true, collectors: 'npm-audit', githubToken: '',
      githubApiUrl: `${registry.url}/github`, branches: 'main,release/1.0', reportsDir: path.join(tmp, 'reports'),
    };
    const scanned = await scanRepository(repo, options);
    const savedBytes = fs.readFileSync(scanned.remediationPlanPath, 'utf8');
    const executionOptions = { ...options, plan: scanned.remediationPlanPath, branches: 'release/1.0' };
    await assert.rejects(() => remediateRepository(repo, {
      ...executionOptions, packages: 'misspelled-package', dryRun: true,
    }), /package/i);
    const noMatches = await remediateRepository(repo, {
      ...executionOptions, createPr: true, fixTypes: 'override-required',
    });
    assert.equal(noMatches.results.branches[0].status, 'no-op');
    assert.equal(noMatches.results.branches[0].verified, false);
    assert.ok(noMatches.results.branches[0].unresolved.every((pkg) => pkg.status === 'skipped'));
    assert.equal(registry.state.pullRequests.length, 0);

    const published = await remediateRepository(repo, {
      ...executionOptions, createPr: true, githubToken: 'fixture-token',
      packages: fixturePackage, fixTypes: 'safe-fix', allowBreaking: false,
      prTitleTemplate: '{targetBranch}: {targetPackages}',
    });
    assert.equal(published.results.branches.length, 1);
    const result = published.results.branches[0];
    assert.equal(result.branch, 'release/1.0');
    assert.deepEqual(result.selection.selectedPackages, [fixturePackage]);
    assert.deepEqual(result.execution.resolved.map((pkg) => pkg.packageName), [fixturePackage]);
    assert.equal(result.execution.unresolved.find((pkg) => pkg.packageName === otherPackage).status, 'skipped');
    assert.equal(result.execution.isClean, false);
    assert.ok(result.execution.remaining.some((pkg) => pkg.packageName === otherPackage));
    const headManifest = JSON.parse((await execGit(['show', `${result.head}:package.json`], remote)).stdout);
    const headLock = JSON.parse((await execGit(['show', `${result.head}:package-lock.json`], remote)).stdout);
    assert.equal(headManifest.dependencies[fixturePackage], '1.0.1');
    assert.equal(headManifest.dependencies[otherPackage], '1.0.0');
    assert.equal(headLock.packages[`node_modules/${otherPackage}`].version, '1.0.0');
    assert.equal(registry.state.pullRequests.length, 1);
    assert.equal(registry.state.pullRequests[0].title, `release/1.0: ${fixturePackage}`);
    assert.ok(registry.state.pullRequests[0].body.includes(otherPackage));
    assert.ok(registry.state.pullRequests[0].body.includes('skipped'));
    assert.equal((await execGit(['rev-parse', 'main'], remote)).stdout, base);
    assert.equal((await execGit(['rev-parse', 'release/1.0'], remote)).stdout, base);
    assert.equal(fs.readFileSync(scanned.remediationPlanPath, 'utf8'), savedBytes);
  } finally {
    for (const [key, value] of Object.entries(previousEnv)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
    await registry.close();
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('override-only selection fixes a range-forbidden transitive package without editing an excluded safe fix', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-override-selected-'));
  const otherPackage = 'security-report-other-fixture';
  const holder = 'fixture-holder';
  const registry = await startRegistry(path.join(tmp, 'registry'), {
    packageNames: [fixturePackage, otherPackage, holder],
    vulnerablePackages: [fixturePackage, otherPackage],
    dependenciesByPackage: { [holder]: { [fixturePackage]: '1.0.0' } },
  });
  const previousEnv = Object.fromEntries(Object.keys(registry.env).map((key) => [key, process.env[key]]));
  Object.assign(process.env, registry.env);
  const repo = path.join(tmp, 'repo');
  fs.mkdirSync(repo);
  try {
    await execGit(['init', '-b', 'main'], repo);
    await execGit(['config', 'user.name', 'Security Bot'], repo);
    await execGit(['config', 'user.email', 'bot@example.com'], repo);
    const lock = registry.packageLock();
    delete lock.packages[''].dependencies[fixturePackage];
    fs.writeFileSync(path.join(repo, 'package.json'), JSON.stringify(lock.packages['']));
    fs.writeFileSync(path.join(repo, 'package-lock.json'), JSON.stringify(lock));
    await execGit(['add', '.'], repo);
    await execGit(['commit', '-m', 'Transitive and direct findings'], repo);
    const options = {
      noConfigFile: true, collectors: 'npm-audit', githubToken: '', branches: 'main',
      githubApiUrl: `${registry.url}/github`, reportsDir: path.join(tmp, 'reports'),
    };
    const scanned = await scanRepository(repo, options);
    const executed = await remediateRepository(repo, {
      ...options, plan: scanned.remediationPlanPath,
      fixTypes: 'override-required', allowBreaking: false, commit: true,
    });
    const result = executed.results.branches[0];
    assert.equal(result.status, 'committed');
    assert.deepEqual(result.selection.selectedPackages, [fixturePackage]);
    const manifest = JSON.parse((await execGit(['show', `${result.head}:package.json`], repo)).stdout);
    const fixedLock = JSON.parse((await execGit(['show', `${result.head}:package-lock.json`], repo)).stdout);
    assert.equal(manifest.overrides[`${holder}@1.0.0`][`${fixturePackage}@1.0.x`], '1.0.1');
    assert.equal(manifest.dependencies[fixturePackage], undefined);
    assert.equal(manifest.dependencies[otherPackage], '1.0.0');
    assert.equal(fixedLock.packages[`node_modules/${fixturePackage}`].version, '1.0.1');
    assert.equal(fixedLock.packages[`node_modules/${otherPackage}`].version, '1.0.0');
    assert.equal(result.execution.unresolved.find((pkg) => pkg.packageName === otherPackage).status, 'skipped');
  } finally {
    for (const [key, value] of Object.entries(previousEnv)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
    await registry.close();
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('fork publishing keeps upstream refs untouched and reuses only the fork head', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-fork-e2e-'));
  const registry = await startRegistry(path.join(tmp, 'registry'));
  const previousEnv = Object.fromEntries(Object.keys(registry.env).map((key) => [key, process.env[key]]));
  Object.assign(process.env, registry.env);
  const repo = path.join(tmp, 'repo');
  const upstream = path.join(tmp, 'upstream.git');
  const fork = path.join(tmp, 'fork.git');
  for (const directory of [repo, upstream, fork]) fs.mkdirSync(directory);
  try {
    await execGit(['init', '--bare', '-b', 'main'], upstream);
    await execGit(['init', '--bare', '-b', 'main'], fork);
    await execGit(['init', '-b', 'main'], repo);
    await execGit(['config', 'user.name', 'Security Bot'], repo);
    await execGit(['config', 'user.email', 'bot@example.com'], repo);
    fs.writeFileSync(path.join(repo, 'package.json'), JSON.stringify(registry.packageLock().packages['']));
    fs.writeFileSync(path.join(repo, 'package-lock.json'), JSON.stringify(registry.packageLock()));
    await execGit(['add', '.'], repo);
    await execGit(['commit', '-m', 'Shared fork base'], repo);
    const forkBase = (await execGit(['rev-parse', 'main'], repo)).stdout;
    await execGit(['remote', 'add', 'origin', 'https://github.com/fixture/app.git'], repo);
    await execGit(['config', `url.file://${upstream}.insteadOf`, 'https://github.com/fixture/app.git'], repo);
    await execGit(['config', `url.file://${fork}.insteadOf`, 'https://github.com/sjd78/app.git'], repo);
    await execGit(['push', 'origin', 'main'], repo);
    await execGit(['push', 'https://github.com/sjd78/app.git', 'main'], repo);
    fs.writeFileSync(path.join(repo, 'README.md'), 'Upstream is ahead of the fork');
    await execGit(['add', 'README.md'], repo);
    await execGit(['commit', '-m', 'Upstream advanced'], repo);
    await execGit(['branch', 'release/1.0'], repo);
    await execGit(['push', 'origin', 'main', 'release/1.0'], repo);
    const base = (await execGit(['rev-parse', 'main'], repo)).stdout;
    const upstreamRefs = (await execGit(['for-each-ref', '--format=%(refname) %(objectname)', 'refs/heads'], upstream)).stdout;
    const originalRemotes = (await execGit(['remote', '-v'], repo)).stdout;
    const options = {
      noConfigFile: true, collectors: 'npm-audit', githubToken: '', branches: 'main,release/1.0',
      githubApiUrl: `${registry.url}/github`, reportsDir: path.join(tmp, 'reports'),
    };
    const scanned = await scanRepository(repo, options);
    const executeOptions = { ...options, plan: scanned.remediationPlanPath, createPr: true,
      githubToken: 'fixture-token', forkRepo: 'sjd78/app', branches: 'main' };
    const dry = await remediateRepository(repo, { ...executeOptions, dryRun: true });
    assert.equal(dry.results.branches[0].publication.headRepository, 'sjd78/app');
    assert.equal(dry.results.branches[0].publication.baseRepository, 'fixture/app');
    assert.equal((await execGit(['for-each-ref', '--format=%(refname)', 'refs/heads'], fork)).stdout, 'refs/heads/main');

    const published = await remediateRepository(repo, executeOptions);
    const result = published.results.branches[0];
    const forkHead = (await execGit(['rev-parse', result.head], fork)).stdout;
    assert.equal(result.status, 'published');
    assert.equal(result.publication.headRef, `sjd78:${result.head}`);
    assert.equal(result.commit.commitHash, forkHead);
    assert.equal((await execGit(['rev-parse', 'main'], fork)).stdout, forkBase);
    assert.equal((await execGit(['rev-parse', 'main'], upstream)).stdout, base);
    assert.equal((await execGit(['for-each-ref', '--format=%(refname) %(objectname)', 'refs/heads'], upstream)).stdout, upstreamRefs);
    assert.equal((await execGit(['remote', '-v'], repo)).stdout, originalRemotes);
    const fixed = JSON.parse((await execGit(['show', `${result.head}:package.json`], fork)).stdout);
    assert.equal(fixed.dependencies[fixturePackage], '1.0.1');
    assert.equal(registry.state.pullRequests[0].head.repo.full_name, 'sjd78/app');
    assert.equal(registry.state.pullRequests[0].base.repo.full_name, 'fixture/app');
    assert.ok(registry.state.pullRequests[0].body.includes('CVE-2026-12345'));

    // Upstream has an unrelated branch with the same name; fork replay must ignore it.
    await execGit(['update-ref', `refs/heads/${result.head}`, base], upstream);
    await execGit(['branch', '-D', result.head], repo);
    const repeated = await remediateRepository(repo, { ...executeOptions, prTitleTemplate: 'Reviewed {targetBranch}: {targetPackages}' });
    assert.equal(repeated.results.branches[0].commit.commitHash, forkHead);
    assert.equal(repeated.results.branches[0].pullRequest.created, false);
    assert.equal(registry.state.pullRequests.length, 1);
    assert.equal((await execGit(['rev-parse', result.head], upstream)).stdout, base);
    assert.equal((await execGit(['rev-parse', result.head], fork)).stdout, forkHead);
    assert.equal((await execGit(['remote', '-v'], repo)).stdout, originalRemotes);

    // Fork write failures must not cause a fallback push or PR from origin.
    fs.writeFileSync(path.join(fork, 'hooks', 'pre-receive'), ['#!/bin/sh', 'echo "Fork write denied" >&2', 'exit 1', ''].join('\n'));
    fs.chmodSync(path.join(fork, 'hooks', 'pre-receive'), 0o755);
    const beforeFailure = (await execGit(['for-each-ref', '--format=%(refname) %(objectname)', 'refs/heads'], upstream)).stdout;
    await assert.rejects(() => remediateRepository(repo, { ...executeOptions, branches: 'release/1.0' }), /Fork write denied|hook declined|rejected/);
    const failure = JSON.parse(fs.readFileSync(path.join(tmp, 'reports/security-remediation-results.json')));
    assert.equal(failure.branches[0].status, 'failed');
    assert.ok(fs.existsSync(failure.branches[0].worktreeDir));
    await assert.rejects(() => execGit(['rev-parse', '--verify', `refs/heads/${failure.branches[0].head}`], fork));
    assert.equal((await execGit(['for-each-ref', '--format=%(refname) %(objectname)', 'refs/heads'], upstream)).stdout, beforeFailure);
    assert.equal(registry.state.pullRequests.length, 1);
  } finally {
    for (const [key, value] of Object.entries(previousEnv)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
    await registry.close();
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
