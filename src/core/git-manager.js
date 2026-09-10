import path from 'node:path';
import fs from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

const CREDENTIAL_IN_URL = /\/\/[^@/\s]*@/g;

export function redactCredentials(value) {
  return String(value ?? '').replace(CREDENTIAL_IN_URL, '//***@');
}

/**
 * Per-invocation credentials for an https remote. The token is passed through
 * GIT_CONFIG_* environment variables so it never reaches argv (visible in `ps`)
 * nor `.git/config` (plaintext secret at rest).
 */
export function gitAuthEnv(url, token) {
  if (!token || !url || !url.startsWith('https://')) return {};
  let origin;
  try {
    origin = new URL(url).origin;
  } catch {
    return {};
  }
  const basic = Buffer.from(`x-access-token:${token}`).toString('base64');
  return {
    GIT_CONFIG_COUNT: '1',
    GIT_CONFIG_KEY_0: `http.${origin}/.extraHeader`,
    GIT_CONFIG_VALUE_0: `Authorization: Basic ${basic}`,
  };
}

export async function execGit(args, cwd, env = {}) {
  try {
    const { stdout, stderr } = await execFileAsync('git', args, {
      cwd,
      env: { ...process.env, GIT_TERMINAL_PROMPT: '0', ...env },
      maxBuffer: 20 * 1024 * 1024,
    });
    return { stdout: stdout.trim(), stderr: stderr.trim() };
  } catch (err) {
    const detail = redactCredentials(err.stderr || err.message);
    const error = new Error(`git ${redactCredentials(args.join(' '))} failed in ${cwd}: ${detail}`);
    error.code = err.code;
    error.stdout = err.stdout;
    error.stderr = err.stderr;
    throw error;
  }
}

export function parseRepoSpec(spec, options = {}) {
  const protocol = options.gitProtocol || 'https';

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
    const cloneUrl = protocol === 'ssh'
      ? `git@github.com:${org}/${name}.git`
      : `https://github.com/${org}/${name}.git`;

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

/**
 * Detaches HEAD so every branch name stays available for worktrees.
 * Returns true when this call performed the detachment.
 */
export async function detachHead(repoPath) {
  const { stdout } = await execGit(['symbolic-ref', '-q', 'HEAD'], repoPath).catch(() => ({ stdout: '' }));
  if (!stdout.trim()) return false;
  try {
    await execGit(['checkout', '--detach'], repoPath);
    return true;
  } catch (err) {
    console.warn(`[GitManager] Warning: could not detach HEAD in ${repoPath}: ${err.message}`);
    return false;
  }
}

export async function ensureRepo(spec, config = {}) {
  const parsed = parseRepoSpec(spec, config);
  const reposDir = config.reposDir || path.resolve(process.cwd(), 'REPOS');
  const authEnv = gitAuthEnv(parsed.cloneUrl, config.githubToken);

  if (parsed.type === 'local') {
    try {
      await execGit(['fetch', '--all', '--prune', '--tags'], parsed.localPath);
    } catch {
      // ignore if offline or no remotes
    }
    // Detach so a branch checked out here cannot force worktrees onto a detached
    // HEAD, which would strand remediation commits outside refs/heads/<branch>.
    if (await detachHead(parsed.localPath)) {
      console.log(`ℹ️ [GitManager] Detached HEAD in ${parsed.localPath} so all branches are available for worktrees.`);
    }
    return {
      ...parsed,
      repoPath: parsed.localPath,
    };
  }

  const targetDir = path.resolve(reposDir, parsed.org, parsed.name);

  if (fs.existsSync(path.join(targetDir, '.git'))) {
    // Repo already exists, fetch latest references
    try {
      await execGit(['fetch', '--all', '--prune', '--tags'], targetDir, authEnv);
      await detachHead(targetDir);
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
  await execGit(['clone', parsed.cloneUrl, targetDir], path.dirname(targetDir), authEnv);
  // Detach base repo HEAD so all branch names are free for worktrees
  await detachHead(targetDir);

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

  // Check if origin/<branch> exists remotely
  let hasRemoteBranch = false;
  try {
    const { stdout } = await execGit(['rev-parse', '--verify', `origin/${branch}`], repoPath);
    hasRemoteBranch = Boolean(stdout.trim());
  } catch {
    hasRemoteBranch = false;
  }

  // Check if branch exists locally
  const { stdout: localBranches } = await execGit(['branch', '--list', branch], repoPath);
  const branchExists = Boolean(localBranches.trim());

  try {
    if (hasRemoteBranch) {
      // Force local branch ref to match the latest fetched remote HEAD (origin/<branch>)
      await execGit(['worktree', 'add', '-B', branch, worktreeDir, `origin/${branch}`], repoPath);
    } else if (branchExists) {
      await execGit(['worktree', 'add', worktreeDir, branch], repoPath);
    } else {
      await execGit(['worktree', 'add', '-b', branch, worktreeDir], repoPath);
    }
  } catch (err) {
    // If failed because branch is currently checked out at repo root, use --detach
    if (err.stderr?.includes('already used by worktree') || err.message?.includes('already used by worktree')) {
      const startPoint = hasRemoteBranch ? `origin/${branch}` : branch;
      await execGit(['worktree', 'add', '--detach', worktreeDir, startPoint], repoPath);
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
  let succeeded = false;
  try {
    const result = await fn(worktreeDir);
    succeeded = true;
    return result;
  } finally {
    // Keep the worktree when the caller asked for it, and whenever the callback
    // failed: removing it would destroy edits that were already written to disk.
    if (succeeded && !options.keepWorktree) {
      await removeWorktree(repoPath, worktreeDir);
    }
  }
}

async function resolveRef(cwd, ref) {
  const { stdout } = await execGit(['rev-parse', '--verify', '--quiet', ref], cwd).catch(() => ({ stdout: '' }));
  return stdout.trim() || null;
}

function realPath(p) {
  try {
    return fs.realpathSync(p);
  } catch {
    return path.resolve(p);
  }
}

/** Path of another worktree that currently has <branch> checked out, if any. */
async function findWorktreeHolding(cwd, branch, selfDir) {
  const { stdout } = await execGit(['worktree', 'list', '--porcelain'], cwd).catch(() => ({ stdout: '' }));
  const self = realPath(selfDir);
  let current = null;
  for (const line of stdout.split('\n')) {
    if (line.startsWith('worktree ')) current = line.slice('worktree '.length).trim();
    else if (line.trim() === `branch refs/heads/${branch}` && current && realPath(current) !== self) return current;
  }
  return null;
}

export async function stageAndCommit(worktreeDir, { message, files = ['.'], allowEmpty = false, branch = null }) {
  await execGit(['add', '--', ...files], worktreeDir);

  const { stdout: status } = await execGit(['status', '--porcelain'], worktreeDir);
  if (!status.trim() && !allowEmpty) {
    return { committed: false, commitHash: null, reason: 'No changes to commit' };
  }

  const refName = branch ? `refs/heads/${branch}` : null;
  const refBefore = refName ? await resolveRef(worktreeDir, refName) : null;

  const commitArgs = ['commit', '-m', message];
  if (allowEmpty) commitArgs.push('--allow-empty');

  await execGit(commitArgs, worktreeDir);
  const { stdout: commitHash } = await execGit(['rev-parse', 'HEAD'], worktreeDir);
  const hash = commitHash.trim();

  if (refName) {
    // An attached worktree already advanced the branch; a detached one did not.
    const refAfter = await resolveRef(worktreeDir, refName);
    if (refAfter !== hash) {
      const holder = await findWorktreeHolding(worktreeDir, branch, worktreeDir);
      if (holder) {
        throw new Error(
          `Commit ${hash} was created on a detached HEAD because branch "${branch}" is checked out at ${holder}. ` +
          `Refusing to move refs/heads/${branch} underneath it — release that checkout and re-run.`
        );
      }
      // Compare-and-swap: fails loudly if the branch moved since the commit started.
      await execGit(['update-ref', refName, hash, refBefore ?? ''], worktreeDir);
    }
  }

  return {
    committed: true,
    commitHash: hash,
    branch,
    message,
  };
}

export async function pushBranch(worktreeDir, branch, remote = 'origin', force = false) {
  const args = ['push', remote, branch];
  if (force) args.push('--force');
  return await execGit(args, worktreeDir);
}
