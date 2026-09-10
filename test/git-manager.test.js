import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import {
  parseRepoSpec,
  execGit,
  createWorktree,
  removeWorktree,
  withWorktree,
  stageAndCommit,
} from '../src/core/git-manager.js';
import { loadConfig } from '../src/config.js';

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

test('loadConfig: extracts repo from options and config file', () => {
  const conf = loadConfig({ repo: 'konveyor/tackle2-ui' });
  assert.equal(conf.repo, 'konveyor/tackle2-ui');
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
