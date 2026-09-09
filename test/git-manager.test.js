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
