import path from 'node:path';
import fs from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

export async function execGit(args, cwd, env = {}) {
  try {
    const { stdout, stderr } = await execFileAsync('git', args, {
      cwd,
      env: { ...process.env, ...env },
      maxBuffer: 20 * 1024 * 1024,
    });
    return { stdout: stdout.trim(), stderr: stderr.trim() };
  } catch (err) {
    const error = new Error(`git ${args.join(' ')} failed in ${cwd}: ${err.stderr || err.message}`);
    error.code = err.code;
    error.stdout = err.stdout;
    error.stderr = err.stderr;
    throw error;
  }
}

export function parseRepoSpec(spec, options = {}) {
  const protocol = options.gitProtocol || 'https';
  const token = options.githubToken || '';

  // Case 1: Local directory path
  if (fs.existsSync(spec) && fs.statSync(spec).isDirectory()) {
    const absPath = path.resolve(spec);
    const name = path.basename(absPath);
    return {
      type: 'local',
      raw: spec,
      org: 'local',
      name,
      fullName: `local/${name}`,
      localPath: absPath,
      cloneUrl: null,
    };
  }

  // Case 2: Full Git URL (https:// or git@ or ssh://)
  if (spec.startsWith('http://') || spec.startsWith('https://') || spec.startsWith('git@') || spec.startsWith('ssh://')) {
    const cleanUrl = spec.replace(/\.git$/, '');
    let org = 'unknown';
    let name = 'repo';

    const matchHttp = cleanUrl.match(/https?:\/\/[^/]+\/([^/]+)\/([^/]+)/);
    const matchSsh = cleanUrl.match(/git@[^:]+:([^/]+)\/([^/]+)/);

    if (matchHttp) {
      org = matchHttp[1];
      name = matchHttp[2];
    } else if (matchSsh) {
      org = matchSsh[1];
      name = matchSsh[2];
    }

    return {
      type: 'url',
      raw: spec,
      org,
      name,
      fullName: `${org}/${name}`,
      cloneUrl: spec,
    };
  }

  // Case 3: GitHub style org/name (e.g. facebook/react)
  const parts = spec.split('/');
  if (parts.length === 2 && parts[0] && parts[1]) {
    const [org, name] = parts;
    let cloneUrl;
    if (protocol === 'ssh') {
      cloneUrl = `git@github.com:${org}/${name}.git`;
    } else if (token) {
      cloneUrl = `https://x-access-token:${token}@github.com/${org}/${name}.git`;
    } else {
      cloneUrl = `https://github.com/${org}/${name}.git`;
    }

    return {
      type: 'github',
      raw: spec,
      org,
      name,
      fullName: `${org}/${name}`,
      cloneUrl,
    };
  }

  throw new Error(`Invalid repository specification: "${spec}". Expected "org/repo", git URL, or local path.`);
}

export async function ensureRepo(spec, config = {}) {
  const parsed = parseRepoSpec(spec, config);
  const reposDir = config.reposDir || path.resolve(process.cwd(), 'REPOS');

  if (parsed.type === 'local') {
    return {
      ...parsed,
      repoPath: parsed.localPath,
    };
  }

  const targetDir = path.resolve(reposDir, parsed.org, parsed.name);

  if (fs.existsSync(path.join(targetDir, '.git'))) {
    // Repo already exists, fetch latest references
    try {
      await execGit(['fetch', '--all', '--prune', '--tags'], targetDir);
      await execGit(['checkout', '--detach'], targetDir).catch(() => {});
    } catch (err) {
      console.warn(`[GitManager] Warning: 'git fetch' failed in ${targetDir}: ${err.message}`);
    }
    return {
      ...parsed,
      repoPath: targetDir,
    };
  }

  // Ensure parent directory exists
  fs.mkdirSync(path.dirname(targetDir), { recursive: true });

  // Clone repo
  await execGit(['clone', parsed.cloneUrl, targetDir], path.dirname(targetDir));
  // Detach base repo HEAD so all branch names are free for worktrees
  await execGit(['checkout', '--detach'], targetDir).catch(() => {});

  return {
    ...parsed,
    repoPath: targetDir,
  };
}

export async function listBranches(repoPath) {
  const { stdout } = await execGit(['branch', '-a', '--format=%(refname:short)'], repoPath);
  const lines = stdout.split('\n').map((l) => l.trim()).filter(Boolean);
  const branches = new Set();

  for (const b of lines) {
    if (b.startsWith('origin/')) {
      const name = b.replace(/^origin\//, '');
      if (name !== 'HEAD') branches.add(name);
    } else {
      branches.add(b);
    }
  }

  return Array.from(branches);
}

export function sanitizeBranchName(branch) {
  return branch.replace(/[^a-zA-Z0-9._-]/g, '_');
}

export async function createWorktree(repoPath, branch, customPath = null) {
  const sanitized = sanitizeBranchName(branch);
  const worktreeDir = customPath || path.resolve(repoPath, '.worktrees', sanitized);

  // Clean up existing worktree if stale
  if (fs.existsSync(worktreeDir)) {
    try {
      await execGit(['worktree', 'remove', '--force', worktreeDir], repoPath);
    } catch {
      try {
        fs.rmSync(worktreeDir, { recursive: true, force: true });
        await execGit(['worktree', 'prune'], repoPath);
      } catch {
        // ignore
      }
    }
  }

  fs.mkdirSync(path.dirname(worktreeDir), { recursive: true });

  // Check if branch exists locally or remotely
  const { stdout: localBranches } = await execGit(['branch', '--list', branch], repoPath);
  const branchExists = Boolean(localBranches.trim());

  try {
    if (branchExists) {
      await execGit(['worktree', 'add', worktreeDir, branch], repoPath);
    } else {
      // Try checkout from origin/<branch> or create branch
      try {
        await execGit(['worktree', 'add', '-B', branch, worktreeDir, `origin/${branch}`], repoPath);
      } catch {
        await execGit(['worktree', 'add', '-b', branch, worktreeDir], repoPath);
      }
    }
  } catch (err) {
    // If failed because branch is currently checked out at repo root, use --detach
    if (err.stderr?.includes('already used by worktree') || err.message?.includes('already used by worktree')) {
      await execGit(['worktree', 'add', '--detach', worktreeDir, branch], repoPath);
    } else {
      throw err;
    }
  }

  return worktreeDir;
}

export async function removeWorktree(repoPath, worktreeDir) {
  try {
    if (fs.existsSync(worktreeDir)) {
      await execGit(['worktree', 'remove', '--force', worktreeDir], repoPath);
    }
  } catch {
    if (fs.existsSync(worktreeDir)) {
      fs.rmSync(worktreeDir, { recursive: true, force: true });
    }
  } finally {
    try {
      await execGit(['worktree', 'prune'], repoPath);
    } catch {
      // ignore
    }
  }
}

export async function withWorktree(repoPath, branch, fn, options = {}) {
  const worktreeDir = await createWorktree(repoPath, branch, options.worktreeDir);
  try {
    return await fn(worktreeDir);
  } finally {
    if (!options.keepWorktree) {
      await removeWorktree(repoPath, worktreeDir);
    }
  }
}

export async function stageAndCommit(worktreeDir, { message, files = ['.'], allowEmpty = false, branch = null }) {
  await execGit(['add', ...files], worktreeDir);

  const { stdout: status } = await execGit(['status', '--porcelain'], worktreeDir);
  if (!status.trim() && !allowEmpty) {
    return { committed: false, commitHash: null, reason: 'No changes to commit' };
  }

  const commitArgs = ['commit', '-m', message];
  if (allowEmpty) commitArgs.push('--allow-empty');

  await execGit(commitArgs, worktreeDir);
  const { stdout: commitHash } = await execGit(['rev-parse', 'HEAD'], worktreeDir);
  const hash = commitHash.trim();

  // If target branch is specified, ensure its ref is updated
  if (branch) {
    try {
      await execGit(['update-ref', `refs/heads/${branch}`, hash], worktreeDir);
    } catch (err) {
      console.warn(`[GitManager] Warning updating branch ref ${branch}: ${err.message}`);
    }
  }

  return {
    committed: true,
    commitHash: hash,
    message,
  };
}

export async function pushBranch(worktreeDir, branch, remote = 'origin', force = false) {
  const args = ['push', remote, branch];
  if (force) args.push('--force');
  return await execGit(args, worktreeDir);
}
