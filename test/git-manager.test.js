import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import {
  parseRepoSpec,
  execGit,
  gitAuthEnv,
  ensureRepo,
  createWorktree,
  removeWorktree,
  withWorktree,
  stageAndCommit,
} from '../src/core/git-manager.js';

test('parseRepoSpec: GitHub org/repo shorthand', () => {
  const parsed = parseRepoSpec('my-org/my-app');
  assert.equal(parsed.type, 'github');
  assert.equal(parsed.org, 'my-org');
  assert.equal(parsed.name, 'my-app');
  assert.equal(parsed.cloneUrl, 'https://github.com/my-org/my-app.git');
});

test('parseRepoSpec: GitHub URL', () => {
  const parsed = parseRepoSpec('https://github.com/acme/backend.git');
  assert.equal(parsed.type, 'url');
  assert.equal(parsed.org, 'acme');
  assert.equal(parsed.name, 'backend');
});

test('parseRepoSpec: Local directory', () => {
  const parsed = parseRepoSpec(process.cwd());
  assert.equal(parsed.type, 'local');
  assert.equal(parsed.name, 'security-report');
});

test('parseRepoSpec: never embeds the GitHub token in the clone URL', () => {
  const parsed = parseRepoSpec('my-org/my-app', { githubToken: 's3cr3t-token' });
  assert.equal(parsed.cloneUrl, 'https://github.com/my-org/my-app.git');
  assert.ok(!parsed.cloneUrl.includes('s3cr3t-token'));

  const env = gitAuthEnv(parsed.cloneUrl, 's3cr3t-token');
  assert.equal(env.GIT_CONFIG_KEY_0, 'http.https://github.com/.extraHeader');
  assert.equal(
    env.GIT_CONFIG_VALUE_0,
    `Authorization: Basic ${Buffer.from('x-access-token:s3cr3t-token').toString('base64')}`
  );
  assert.deepEqual(gitAuthEnv('git@github.com:my-org/my-app.git', 's3cr3t-token'), {});
});

test('execGit: redacts credentials from failure messages', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'git-redact-test-'));
  try {
    await assert.rejects(
      () => execGit(['frobnicate', 'https://x-access-token:s3cr3t-token@github.com/o/r.git'], tmpDir),
      (err) => {
        assert.ok(!err.message.includes('s3cr3t-token'), `token leaked: ${err.message}`);
        assert.ok(err.message.includes('//***@github.com'));
        return true;
      }
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('Git Worktree and commit lifecycle', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'git-mgr-test-'));
  try {
    // Initialize a test git repo
    await execGit(['init', '-b', 'main'], tmpDir);
    await execGit(['config', 'user.name', 'Test Runner'], tmpDir);
    await execGit(['config', 'user.email', 'test@example.com'], tmpDir);

    // Initial commit
    fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({ name: 'test-app', version: '1.0.0' }, null, 2));
    await execGit(['add', '.'], tmpDir);
    await execGit(['commit', '-m', 'Initial commit'], tmpDir);

    // Create a branch
    await execGit(['branch', 'feature/update'], tmpDir);

    // Test withWorktree
    let worktreeObserved = false;
    const result = await withWorktree(tmpDir, 'feature/update', async (wtPath) => {
      assert.ok(fs.existsSync(path.join(wtPath, 'package.json')));
      worktreeObserved = true;

      // Make a modification
      const pkg = JSON.parse(fs.readFileSync(path.join(wtPath, 'package.json'), 'utf8'));
      pkg.version = '1.1.0';
      fs.writeFileSync(path.join(wtPath, 'package.json'), JSON.stringify(pkg, null, 2));

      // Stage and commit
      const commitRes = await stageAndCommit(wtPath, {
        message: 'chore: bump version to 1.1.0',
        files: ['package.json'],
      });

      assert.equal(commitRes.committed, true);
      assert.ok(commitRes.commitHash);
      return commitRes;
    });

    assert.ok(worktreeObserved);
    assert.ok(result.committed);

    // Verify worktree cleanup
    const wtDir = path.resolve(tmpDir, '.worktrees', 'feature_update');
    assert.equal(fs.existsSync(wtDir), false);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('createWorktree: resets local branch to latest fetched remote origin/branch HEAD', async () => {
  const tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), 'git-sync-test-'));
  const remoteDir = path.join(tmpBase, 'remote');
  const cloneDir = path.join(tmpBase, 'clone');

  try {
    // 1. Initialize mock remote repo
    fs.mkdirSync(remoteDir, { recursive: true });
    await execGit(['init', '-b', 'main'], remoteDir);
    await execGit(['config', 'user.name', 'Remote Bot'], remoteDir);
    await execGit(['config', 'user.email', 'bot@example.com'], remoteDir);

    fs.writeFileSync(path.join(remoteDir, 'file.txt'), 'v1');
    await execGit(['add', '.'], remoteDir);
    await execGit(['commit', '-m', 'commit 1'], remoteDir);

    // 2. Clone to local cloneDir
    await execGit(['clone', remoteDir, cloneDir], tmpBase);
    await execGit(['checkout', '--detach'], cloneDir);

    // 3. Push new commit on remote
    fs.writeFileSync(path.join(remoteDir, 'file.txt'), 'v2');
    await execGit(['add', '.'], remoteDir);
    await execGit(['commit', '-m', 'commit 2'], remoteDir);
    const { stdout: remoteHead } = await execGit(['rev-parse', 'HEAD'], remoteDir);

    // 4. Fetch in cloneDir
    await execGit(['fetch', '--all', '--prune'], cloneDir);

    // 5. Create worktree on main
    await withWorktree(cloneDir, 'main', async (wtPath) => {
      const content = fs.readFileSync(path.join(wtPath, 'file.txt'), 'utf8');
      assert.equal(content, 'v2');

      const { stdout: wtHead } = await execGit(['rev-parse', 'HEAD'], wtPath);
      assert.equal(wtHead.trim(), remoteHead.trim());
    });
  } finally {
    fs.rmSync(tmpBase, { recursive: true, force: true });
  }
});

async function initRepo(dir, branch = 'main') {
  await execGit(['init', '-b', branch], dir);
  await execGit(['config', 'user.name', 'Test Runner'], dir);
  await execGit(['config', 'user.email', 'test@example.com'], dir);
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'app', version: '1.0.0' }, null, 2));
  await execGit(['add', '.'], dir);
  await execGit(['commit', '-m', 'Initial commit'], dir);
}

test('ensureRepo: detaches a local repo so branch commits land on refs/heads/<branch>', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'git-local-detach-'));
  try {
    await initRepo(tmpDir);

    const info = await ensureRepo(tmpDir, { reposDir: tmpDir });
    assert.equal(info.repoPath, path.resolve(tmpDir));
    // HEAD detached => "main" is free for a worktree instead of forcing the detached fallback.
    await assert.rejects(() => execGit(['symbolic-ref', '-q', 'HEAD'], tmpDir));

    const { stdout: before } = await execGit(['rev-parse', 'refs/heads/main'], tmpDir);

    await withWorktree(info.repoPath, 'main', async (wtPath) => {
      fs.writeFileSync(path.join(wtPath, 'package.json'), JSON.stringify({ name: 'app', version: '1.1.0' }, null, 2));
      const res = await stageAndCommit(wtPath, {
        message: 'fix(deps): remediate 1 vulnerable package on branch main',
        files: ['package.json'],
        branch: 'main',
      });
      assert.equal(res.committed, true);
    });

    const { stdout: after } = await execGit(['rev-parse', 'refs/heads/main'], tmpDir);
    assert.notEqual(after, before);
    const { stdout: log } = await execGit(['log', '-n', '1', '--oneline', 'main'], tmpDir);
    assert.ok(log.includes('fix(deps): remediate 1 vulnerable package on branch main'));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('stageAndCommit: refuses to move a branch checked out in another worktree', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'git-branch-guard-'));
  let worktreeDir;
  try {
    await initRepo(tmpDir);
    const { stdout: before } = await execGit(['rev-parse', 'refs/heads/main'], tmpDir);

    // "main" is checked out in the base repo, so the worktree is detached.
    worktreeDir = await createWorktree(tmpDir, 'main');
    fs.writeFileSync(path.join(worktreeDir, 'package.json'), JSON.stringify({ name: 'app', version: '2.0.0' }, null, 2));

    await assert.rejects(
      () => stageAndCommit(worktreeDir, { message: 'fix(deps): bump', files: ['package.json'], branch: 'main' }),
      /checked out at/
    );

    const { stdout: after } = await execGit(['rev-parse', 'refs/heads/main'], tmpDir);
    assert.equal(after, before);
  } finally {
    if (worktreeDir) await removeWorktree(tmpDir, worktreeDir);
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('withWorktree: retains the worktree when requested and when the callback throws', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'git-keep-worktree-'));
  const worktreeDir = path.resolve(tmpDir, '.worktrees', 'feature_update');
  try {
    await initRepo(tmpDir);
    await execGit(['branch', 'feature/update'], tmpDir);

    await withWorktree(tmpDir, 'feature/update', async (wtPath) => {
      fs.writeFileSync(path.join(wtPath, 'applied.txt'), 'remediated');
    }, { keepWorktree: true });
    assert.ok(fs.existsSync(path.join(worktreeDir, 'applied.txt')));

    await assert.rejects(() =>
      withWorktree(tmpDir, 'feature/update', async (wtPath) => {
        fs.writeFileSync(path.join(wtPath, 'partial.txt'), 'half-applied');
        throw new Error('remediation blew up');
      })
    );
    assert.ok(fs.existsSync(path.join(worktreeDir, 'partial.txt')));
  } finally {
    await removeWorktree(tmpDir, worktreeDir);
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
